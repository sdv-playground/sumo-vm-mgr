/// vm-service — VM lifecycle daemon.
///
/// Reads static YAML config at startup, exposes a control API on a Unix socket.
/// Knows nothing about firmware updates, banking, or diagnostics — just runs VMs.
///
/// Usage:
///   vm-service --config /etc/vm-service/config.yaml

mod api;
mod config;
mod health;
#[cfg(target_os = "linux")]
mod ivshmem;
mod manager;
mod runner;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_path = args.get(i).map(PathBuf::from);
            }
            "--help" | "-h" => {
                eprintln!("Usage: vm-service --config <path.yaml>");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!("Usage: vm-service --config <path.yaml>");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    config_path.unwrap_or_else(|| {
        eprintln!("Usage: vm-service --config <path.yaml>");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config_path = parse_args();

    let config = match config::VmServiceConfig::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    let socket_path = config.socket.clone();
    #[cfg(not(target_os = "linux"))]
    let tcp_port = config.tcp_port;
    let vm_count = config.vms.len();

    // Collect auto-start VM names before config is consumed
    let auto_start_vms: Vec<String> = config
        .vms
        .iter()
        .filter(|(_, def)| def.auto_start)
        .map(|(name, _)| name.clone())
        .collect();

    tracing::info!(
        "loaded config: {} VMs, socket: {}",
        vm_count,
        socket_path.display()
    );

    let manager = Arc::new(Mutex::new(manager::VmManager::new(config)));

    // Auto-start VMs that have auto_start: true
    if !auto_start_vms.is_empty() {
        let mut mgr = manager.lock().await;
        for name in &auto_start_vms {
            tracing::info!("auto-starting VM {name}");
            if let Err(e) = mgr.start_vm(name) {
                tracing::warn!("auto-start {name} failed: {e}");
            }
        }
    }

    let manager_shutdown = manager.clone();

    let app = api::router(manager);

    // Platform-specific listener: Unix socket on Linux, TCP on QNX
    #[cfg(target_os = "linux")]
    {
        // Clean stale socket file
        let _ = std::fs::remove_file(&socket_path);

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match tokio::net::UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("failed to bind {}: {e}", socket_path.display());
                std::process::exit(1);
            }
        };

        tracing::info!("listening on {}", socket_path.display());

        // Graceful shutdown on SIGTERM/SIGINT
        let shutdown = async move {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to register SIGTERM");

            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM");
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received SIGINT");
                }
            }

            tracing::info!("shutting down, stopping all VMs...");
            manager_shutdown.lock().await.stop_all();

            // Clean up socket
            let _ = std::fs::remove_file(&socket_path);
        };

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    {
        let port = tcp_port.unwrap_or(9100);
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("failed to bind {addr}: {e}");
                std::process::exit(1);
            }
        };

        tracing::info!("listening on {addr}");

        let shutdown = async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("received shutdown signal");
            tracing::info!("shutting down, stopping all VMs...");
            manager_shutdown.lock().await.stop_all();
        };

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .unwrap();
    }
}
