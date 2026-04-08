/// vHSM Secure Storage Daemon — host-side crypto service for guest VMs.
///
/// Listens on vsock (and optionally TCP) for guest connections.
/// All crypto operations are performed via HsmCryptoProvider — keys
/// never leave this process (or the hardware HSM on production).
///
/// Usage:
///   vhsm-ssd --keystore <path> [--port <vsock_port>] [--tcp [addr:]port]

use std::path::PathBuf;
use std::sync::Arc;

use hsm::linux::LinuxSimHsm;
use hsm::{HsmCryptoProvider, HsmProvider};

use vhsm_ssd::codec;
use vhsm_ssd::handler;
use vhsm_ssd::session::SessionManager;
use vhsm_ssd::transport::{TcpTransport, Transport, VsockListener};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut keystore_path: Option<PathBuf> = None;
    let mut vsock_port: Option<u32> = None;
    let mut tcp_addr: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--keystore" if i + 1 < args.len() => {
                keystore_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                vsock_port = Some(args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("invalid --port: {}", args[i + 1]);
                    std::process::exit(1);
                }));
                i += 2;
            }
            "--tcp" if i + 1 < args.len() => {
                tcp_addr = Some(args[i + 1].to_string());
                i += 2;
            }
            "--tcp" => {
                tcp_addr = Some("127.0.0.1:5555".to_string());
                i += 1;
            }
            "--help" | "-h" => {
                eprintln!("Usage: vhsm-ssd --keystore <path> [--port <vsock_port>] [--tcp [addr:]port]");
                eprintln!();
                eprintln!("  --keystore <path>   HSM keystore directory (required)");
                eprintln!("  --port <port>       vsock port (default: 5555)");
                eprintln!("  --tcp [addr:]port   Also listen on TCP (default: 127.0.0.1:5555)");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let keystore_path = keystore_path.unwrap_or_else(|| {
        eprintln!("error: --keystore is required");
        std::process::exit(1);
    });

    // Default: vsock port 5555 if no transport specified
    if vsock_port.is_none() && tcp_addr.is_none() {
        vsock_port = Some(5555);
    }

    // Create HSM provider (reads keys from keystore)
    let hsm = LinuxSimHsm::new(
        PathBuf::from("unused"), // daemon_bin not used
        keystore_path.clone(),
        vsock_port.unwrap_or(5555) as u16,
        Vec::new(), // provisioning authority not needed for crypto service
    );

    if !hsm.is_provisioned().unwrap_or(false) {
        eprintln!(
            "error: keystore at {} is not provisioned",
            keystore_path.display()
        );
        eprintln!("       Run HSM provisioning first (sumo-campaign flash hsm ...)");
        std::process::exit(1);
    }

    let key_count = hsm.list_keys().map(|k| k.len() as u32).unwrap_or(0);
    let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

    tracing::info!(
        keystore = %keystore_path.display(),
        keys = key_count,
        "vhsm-ssd starting"
    );

    // Build transport list
    let mut transports: Vec<Transport> = Vec::new();

    if let Some(port) = vsock_port {
        match VsockListener::bind(port) {
            Ok(listener) => {
                tracing::info!(port, "listening on vsock");
                transports.push(Transport::Vsock(listener));
            }
            Err(e) => {
                tracing::warn!(port, error = %e, "vsock bind failed (AF_VSOCK not available?)");
            }
        }
    }

    if let Some(ref addr) = tcp_addr {
        match TcpTransport::bind(addr) {
            Ok(listener) => {
                tracing::info!(addr, "listening on TCP");
                transports.push(Transport::Tcp(listener));
            }
            Err(e) => {
                // Non-fatal if vsock is already listening
                if transports.is_empty() {
                    eprintln!("error: TCP bind to {addr} failed: {e}");
                    std::process::exit(1);
                } else {
                    tracing::warn!(addr, error = %e, "TCP bind failed, continuing with vsock only");
                }
            }
        }
    }

    if transports.is_empty() {
        eprintln!("error: no transport available (vsock failed and no --tcp)");
        std::process::exit(1);
    }

    // For single-transport: simple accept loop
    // For multiple: use threads
    if transports.len() == 1 {
        let transport = transports.pop().unwrap();
        accept_loop(&transport, &*crypto, key_count);
    } else {
        let crypto = Arc::clone(&crypto);
        let handles: Vec<_> = transports
            .into_iter()
            .map(|transport| {
                let crypto = Arc::clone(&crypto);
                std::thread::spawn(move || {
                    accept_loop(&transport, &*crypto, key_count);
                })
            })
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

fn accept_loop(transport: &Transport, crypto: &dyn HsmCryptoProvider, key_count: u32) {
    let start_time = std::time::Instant::now();

    loop {
        let mut conn = match transport.accept() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    transport = transport.name(),
                    error = %e,
                    "accept failed, retrying"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };

        let mut sessions = SessionManager::new(start_time);

        loop {
            let req = match codec::read_request(conn.reader()) {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    tracing::debug!(error = %e, "connection closed");
                    break;
                }
            };

            tracing::debug!(
                op = req.op,
                seq = req.seq,
                key_id = %req.key_id,
                "request"
            );

            let resp = handler::handle_request(&req, &mut sessions, crypto, key_count);

            if let Err(e) = codec::write_response(conn.writer(), &resp) {
                tracing::warn!(error = %e, "write error, closing connection");
                break;
            }
        }
    }
}
