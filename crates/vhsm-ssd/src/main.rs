/// vHSM Secure Storage Daemon (v2) — host-side crypto service for guest VMs.
///
/// Listens on vsock for guest connections. Identity is derived from the
/// peer vsock CID. Access controlled by a per-CID policy.
///
/// Usage:
///   vhsm-ssd --keystore <path> [--port <vsock_port>] [--policy <path>]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hsm::linux::LinuxSimHsm;
use hsm::{HsmCryptoProvider, HsmProvider};

use vhsm_ssd::codec;
use vhsm_ssd::handle_table::HandleTable;
use vhsm_ssd::handler;
use vhsm_ssd::policy::Policy;
use vhsm_ssd::proto::*;
use vhsm_ssd::transport::VsockListener;

use secstore::{FileBackend, LinuxSimEncryptor, Secstore, KeyMetadata};

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
    let mut policy_path: Option<PathBuf> = None;
    let mut allow_cids: Vec<u32> = Vec::new();
    let mut persist_dir: Option<PathBuf> = None;

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
            "--policy" if i + 1 < args.len() => {
                policy_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--persist-dir" if i + 1 < args.len() => {
                persist_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--allow-cid" if i + 1 < args.len() => {
                let cid: u32 = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("invalid --allow-cid: {}", args[i + 1]);
                    std::process::exit(1);
                });
                allow_cids.push(cid);
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("Usage: vhsm-ssd --keystore <path> [--port <vsock_port>] [--policy <path>] [--allow-cid <cid>]...");
                eprintln!();
                eprintln!("  --keystore <path>   HSM keystore directory (required)");
                eprintln!("  --port <port>       vsock port (default: {})", VHSM_PORT);
                eprintln!("  --policy <path>     Binary policy file");
                eprintln!("  --persist-dir <dir>  Persist dynamic handles to this directory");
                eprintln!("  --allow-cid <cid>   Allow this CID all operations (repeatable, dev/test)");
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

    let port = vsock_port.unwrap_or(VHSM_PORT);

    // Create HSM provider (reads keys from keystore)
    let hsm = LinuxSimHsm::new(
        PathBuf::from("unused"),
        keystore_path.clone(),
        port as u16,
        Vec::new(),
    );

    if !hsm.is_provisioned().unwrap_or(false) {
        eprintln!(
            "error: keystore at {} is not provisioned",
            keystore_path.display()
        );
        eprintln!("       Run HSM provisioning first (sumo-campaign flash hsm ...)");
        std::process::exit(1);
    }

    let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

    // Load policy
    let policy = if let Some(ref path) = policy_path {
        match Policy::load_from_file(path, false) {
            Ok(p) => {
                tracing::info!(
                    path = %path.display(),
                    entries = p.num_entries(),
                    "policy loaded"
                );
                p
            }
            Err(e) => {
                eprintln!("error: failed to load policy: {e}");
                std::process::exit(1);
            }
        }
    } else if !allow_cids.is_empty() {
        tracing::info!("using --allow-cid policy: {:?}", allow_cids);
        Policy::allow_all(&allow_cids)
    } else {
        eprintln!("error: no --policy or --allow-cid specified");
        eprintln!("       Use --policy <file> for production, or --allow-cid <cid> for dev/test");
        std::process::exit(1);
    };
    let policy = Arc::new(policy);

    // Initialize handle table with well-known handles from keystore
    let mut table = init_handle_table(&*crypto);

    // Set up secstore for dynamic handle persistence (optional)
    let store: Option<Arc<Secstore<LinuxSimEncryptor, FileBackend>>> =
        persist_dir.as_ref().map(|dir| {
            let s = Secstore::new(
                LinuxSimEncryptor::default_test(),
                FileBackend::new(dir),
            );
            // Load persisted dynamic handles
            match s.load_all() {
                Ok(metas) => {
                    for m in &metas {
                        let mut label = [0u8; LABEL_LEN];
                        let bytes = m.label.as_bytes();
                        let copy_len = bytes.len().min(LABEL_LEN - 1);
                        label[..copy_len].copy_from_slice(&bytes[..copy_len]);
                        table.allocate(
                            &m.key_id, m.algorithm, m.permitted_ops,
                            m.owner_cid, m.persistent, &label,
                        );
                    }
                    tracing::info!(count = metas.len(), "loaded persisted handles");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load persisted handles");
                }
            }
            Arc::new(s)
        });

    let handle_table = Arc::new(Mutex::new(table));

    tracing::info!(
        keystore = %keystore_path.display(),
        handles = handle_table.lock().unwrap().len(),
        persist = persist_dir.is_some(),
        "vhsm-ssd v2 starting"
    );

    // Bind vsock
    let listener = match VsockListener::bind(port) {
        Ok(l) => {
            tracing::info!(port, "listening on vsock");
            l
        }
        Err(e) => {
            eprintln!("error: vsock bind to port {port} failed: {e}");
            eprintln!("       Is vhost_vsock loaded? (modprobe vhost_vsock)");
            std::process::exit(1);
        }
    };

    // Accept loop
    loop {
        let mut conn = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };

        let peer_cid = conn.peer_cid();

        loop {
            let req = match codec::read_request(conn.reader()) {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    tracing::debug!(cid = peer_cid, error = %e, "connection closed");
                    break;
                }
            };

            tracing::debug!(
                cid = peer_cid,
                op = req.op,
                session_id = req.session_id,
                "request"
            );

            let table_len_before = handle_table.lock().unwrap().len();

            let resp = {
                let mut table = handle_table.lock().unwrap();
                handler::handle_request(&req, peer_cid, &mut table, &policy, &*crypto)
            };

            // Persist if a dynamic handle was added (KEY_GENERATE success)
            if let Some(ref s) = store {
                let table = handle_table.lock().unwrap();
                if table.len() > table_len_before {
                    // New handle was added — find and persist it
                    if let Some(entry) = table.last() {
                        if entry.persistent {
                            let label_str = std::str::from_utf8(&entry.label)
                                .unwrap_or("")
                                .trim_end_matches('\0')
                                .to_string();
                            let meta = KeyMetadata {
                                vhsm_handle: entry.handle,
                                key_id: entry.key_id.clone(),
                                algorithm: entry.algorithm,
                                permitted_ops: entry.permitted_ops,
                                owner_cid: entry.owner_cid,
                                persistent: true,
                                label: label_str,
                            };
                            if let Err(e) = s.store(&meta) {
                                tracing::warn!(handle = entry.handle, error = %e, "failed to persist handle");
                            }
                        }
                    }
                }
            }

            if let Err(e) = codec::write_response(conn.writer(), &resp) {
                tracing::warn!(cid = peer_cid, error = %e, "write error, closing connection");
                break;
            }
        }

        // Clean up dynamic handles for disconnected VM
        handle_table.lock().unwrap().remove_by_cid(peer_cid);
        tracing::info!(cid = peer_cid, "connection closed, dynamic handles released");
    }
}

/// Populate handle table with well-known handles from the keystore.
fn init_handle_table(crypto: &dyn HsmCryptoProvider) -> HandleTable {
    let mut table = HandleTable::new();

    // Map well-known handles to keystore key_ids.
    // These match KeyRole in hsm/src/types.rs.
    let well_known = [
        (HANDLE_KEK, "kek", ALG_ECC_P256, PERM_ENCRYPT | PERM_DECRYPT),
        (HANDLE_SW_AUTHORITY, "sw-authority", ALG_ECC_P256, PERM_VERIFY),
        (HANDLE_DEVICE_DECRYPT, "device-decrypt", ALG_ECC_P256, PERM_DECRYPT | PERM_GET_PUBKEY),
        (HANDLE_ECU_SIGNING, "ecu-signing", ALG_ECC_P256, PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY | PERM_GET_CERT),
        (HANDLE_JWT_SIGNING, "jwt-signing", ALG_ECC_P256, PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY),
        (HANDLE_STORAGE, "storage-key", ALG_AES_256, PERM_ENCRYPT | PERM_DECRYPT),
    ];

    for (handle, key_id, alg, perms) in &well_known {
        // Only register if the key exists in the keystore
        if crypto.get_key_info(key_id).is_ok() {
            table.register_well_known(*handle, key_id, *alg, *perms);
            tracing::debug!(handle, key_id, "registered well-known handle");
        }
    }

    table
}
