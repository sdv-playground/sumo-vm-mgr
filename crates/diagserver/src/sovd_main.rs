use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{BankSet, NvBootState};

use sovd_core::DiagnosticBackend;

use vm_diagserver::backend::{VmBackend, ComponentConfig};
use vm_diagserver::sovd::security::TestSecurityProvider;
use vm_diagserver::suit_provider::SuitProvider;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: vm-sovd <nv-store-path> <trust-anchor-path> [--device-key <path>] [--images-dir <path>] [--vm-service-socket <path>] [bind-addr]");
        eprintln!();
        eprintln!("  trust-anchor-path: COSE_Key public key file (CBOR bytes)");
        eprintln!("  --device-key:      ECDH P-256 private key for firmware decryption");
        eprintln!("  --images-dir:      directory for bank image files (enables real image OTA)");
        eprintln!("  --vm-service-socket: Unix socket for vm-service lifecycle control");
        eprintln!("  bind-addr defaults to 0.0.0.0:8080");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  vm-sovd /tmp/vm-mgr-nv.bin example/keys/signing.pub --device-key example/keys/device.key");
        std::process::exit(1);
    }

    let nv_path = PathBuf::from(&args[1]);
    let trust_anchor_path = PathBuf::from(&args[2]);

    // Parse remaining args
    let mut device_key_path: Option<PathBuf> = None;
    let mut images_dir: Option<PathBuf> = None;
    let mut vm_service_socket: Option<PathBuf> = None;
    let mut bind_addr = "0.0.0.0:8080";
    let mut i = 3;
    while i < args.len() {
        if args[i] == "--device-key" && i + 1 < args.len() {
            device_key_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--images-dir" && i + 1 < args.len() {
            images_dir = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--vm-service-socket" && i + 1 < args.len() {
            vm_service_socket = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            bind_addr = &args[i];
            i += 1;
        }
    }

    // Load trust anchor
    let trust_anchor = std::fs::read(&trust_anchor_path).unwrap_or_else(|e| {
        eprintln!("failed to read trust anchor {}: {e}", trust_anchor_path.display());
        std::process::exit(1);
    });

    // Load device key (optional — required for encrypted firmware)
    let mut provider = SuitProvider::new(trust_anchor);
    if let Some(ref dk_path) = device_key_path {
        let dk = std::fs::read(dk_path).unwrap_or_else(|e| {
            eprintln!("failed to read device key {}: {e}", dk_path.display());
            std::process::exit(1);
        });
        provider = provider.with_device_key(dk);
        tracing::info!("device key loaded: {}", dk_path.display());
    }
    let manifest_provider = Arc::new(provider);
    let security_provider = Arc::new(TestSecurityProvider);

    // Open/create NV store
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

    let nv = Arc::new(Mutex::new(nv));

    // Create one backend per bank set
    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        ("hyp", BankSet::Hypervisor, ComponentConfig {
            entity_type: "hpc".into(), ..ComponentConfig::default()
        }),
        ("os1", BankSet::Os1, ComponentConfig::default()),
        ("os2", BankSet::Os2, ComponentConfig::default()),
        ("hsm", BankSet::Hsm, ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            ..ComponentConfig::default()
        }),
        ("qtd", BankSet::Qtd, ComponentConfig::default()),
    ];

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    for (id, set, config) in components {
        let backend = VmBackend::with_options(
            set,
            nv.clone(),
            manifest_provider.clone(),
            security_provider.clone(),
            config,
            vm_service_socket.clone(),
            images_dir.clone(),
        );
        backends.insert(id.to_string(), Arc::new(backend));
    }

    let state = sovd_api::AppState::new(backends);
    let router = sovd_api::create_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        });

    tracing::info!("vm-sovd listening on {bind_addr}");
    tracing::info!("  NV store: {}", nv_path.display());
    tracing::info!("  trust anchor: {}", trust_anchor_path.display());
    if let Some(ref dir) = images_dir {
        tracing::info!("  images dir: {} (real image OTA enabled)", dir.display());
    }
    if let Some(ref sock) = vm_service_socket {
        tracing::info!("  vm-service socket: {}", sock.display());
    }
    tracing::info!("  components: hyp, os1, os2, hsm, qtd");
    tracing::info!("  try: curl http://{bind_addr}/vehicle/v1/components");

    axum::serve(listener, router).await.unwrap();
}
