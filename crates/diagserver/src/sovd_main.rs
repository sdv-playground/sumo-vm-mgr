use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::NvBootState;

use vm_diagserver::sovd::router::create_router;
use vm_diagserver::sovd::state::{AppState, UploadStore};
use vm_diagserver::suit_provider::SuitProvider;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vm_sovd=info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: vm-sovd <nv-store-path> <trust-anchor-path> [bind-addr]");
        eprintln!();
        eprintln!("  trust-anchor-path: COSE_Key public key file (CBOR bytes)");
        eprintln!("  bind-addr defaults to 0.0.0.0:8080");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  vm-sovd /tmp/vm-mgr-nv.bin example/keys/signing.pub");
        eprintln!("  vm-sovd /tmp/vm-mgr-nv.bin example/keys/signing.pub 127.0.0.1:9090");
        std::process::exit(1);
    }

    let nv_path = PathBuf::from(&args[1]);
    let trust_anchor_path = PathBuf::from(&args[2]);
    let bind_addr = args
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("0.0.0.0:8080");

    // Load trust anchor (signing public key)
    let trust_anchor = std::fs::read(&trust_anchor_path).unwrap_or_else(|e| {
        eprintln!("failed to read trust anchor {}: {e}", trust_anchor_path.display());
        std::process::exit(1);
    });
    let manifest_provider = Arc::new(SuitProvider::new(trust_anchor));

    let dev = if nv_path.exists() {
        FileBlockDevice::open(&nv_path).expect("failed to open NV store")
    } else {
        tracing::info!("creating NV store: {}", nv_path.display());
        FileBlockDevice::create(&nv_path, MIN_NV_DEVICE_SIZE).expect("failed to create NV store")
    };

    let mut nv = NvStore::new(dev);
    if nv.read_boot_state().is_none() {
        let mut state = NvBootState::default();
        nv.write_boot_state(&mut state).unwrap();
        tracing::info!("initialized boot state");
    }

    let state = AppState {
        nv: Arc::new(Mutex::new(nv)),
        uploads: Arc::new(Mutex::new(UploadStore::new())),
        manifest_provider,
    };
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        });

    tracing::info!("vm-sovd listening on {bind_addr}");
    tracing::info!("  NV store: {}", nv_path.display());
    tracing::info!("  trust anchor: {}", trust_anchor_path.display());
    tracing::info!("  components: hyp, os1, os2");
    tracing::info!("  try: curl http://{bind_addr}/vehicle/v1/components");

    axum::serve(listener, router).await.unwrap();
}
