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

use axum::response::IntoResponse;
use hsm::{HsmProvider, KeyRole};
use hsm::linux::LinuxSimHsm;

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
        eprintln!("Usage: vm-sovd <nv-store-path> <provisioning-authority-path> [options] [bind-addr]");
        eprintln!();
        eprintln!("  provisioning-authority-path: COSE_Key public key for HSM key envelope validation");
        eprintln!("  --images-dir:      directory for bank image files (enables real image OTA)");
        eprintln!("  --vm-service-socket: Unix socket for vm-service lifecycle control");
        eprintln!("  --hsm-daemon:      path to vhsm-test-ssd binary");
        eprintln!("  --hsm-keystore:    HSM keystore directory (default: /tmp/vhsm-keys)");
        eprintln!("  --hsm-port:        HSM vsock port (default: 5100)");
        eprintln!("  bind-addr defaults to 0.0.0.0:8080");
        eprintln!();
        eprintln!("Software authority and device decryption keys are loaded from HSM after provisioning.");
        eprintln!("Firmware flash is rejected until HSM is provisioned.");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  vm-sovd /tmp/vm-mgr-nv.bin keys/signing.pub");
        std::process::exit(1);
    }

    let nv_path = PathBuf::from(&args[1]);
    let provisioning_authority_path = PathBuf::from(&args[2]);

    // Parse remaining args
    let mut images_dir: Option<PathBuf> = None;
    let mut vm_service_socket: Option<PathBuf> = None;
    let mut hsm_daemon_path: Option<PathBuf> = None;
    let mut hsm_keystore_path = PathBuf::from("/tmp/vhsm-keys");
    let mut hsm_port: u16 = 5100;
    let mut bind_addr = "0.0.0.0:8080";
    let mut i = 3;
    while i < args.len() {
        if args[i] == "--images-dir" && i + 1 < args.len() {
            images_dir = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--vm-service-socket" && i + 1 < args.len() {
            vm_service_socket = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--hsm-daemon" && i + 1 < args.len() {
            hsm_daemon_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--hsm-keystore" && i + 1 < args.len() {
            hsm_keystore_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i] == "--hsm-port" && i + 1 < args.len() {
            hsm_port = args[i + 1].parse().unwrap_or_else(|_| {
                eprintln!("invalid --hsm-port: {}", args[i + 1]);
                std::process::exit(1);
            });
            i += 2;
        } else {
            bind_addr = &args[i];
            i += 1;
        }
    }

    // Load provisioning authority (validates HSM key envelopes)
    let provisioning_authority = std::fs::read(&provisioning_authority_path).unwrap_or_else(|e| {
        eprintln!("failed to read provisioning authority {}: {e}", provisioning_authority_path.display());
        std::process::exit(1);
    });

    // Create SuitProvider with provisioning authority only.
    // Software authority and device key will be loaded from HSM after provisioning.
    let provider = SuitProvider::new(provisioning_authority.clone());
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

    // Create HSM provider
    let hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>> = {
        let daemon_bin = hsm_daemon_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("vhsm-test-ssd"));
        let provider = LinuxSimHsm::new(
            daemon_bin.clone(),
            hsm_keystore_path.clone(),
            hsm_port,
            provisioning_authority,
        );

        if hsm_daemon_path.is_some() {
            tracing::info!(
                "HSM provider: daemon={}, keystore={}, port={}",
                daemon_bin.display(),
                hsm_keystore_path.display(),
                hsm_port,
            );
        } else {
            tracing::info!(
                "HSM provider: keystore={}, port={} (no daemon path, provision-only)",
                hsm_keystore_path.display(),
                hsm_port,
            );
        }

        // If HSM is already provisioned, load software authority + device key
        if provider.is_provisioned().unwrap_or(false) {
            match (
                provider.get_public_key(KeyRole::SoftwareAuthority),
                provider.get_private_key(KeyRole::DeviceDecryption),
            ) {
                (Ok(sw_key), Ok(dk)) => {
                    manifest_provider.update_keys(sw_key, Some(dk));
                    tracing::info!("loaded software authority and device key from HSM keystore");
                }
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!("HSM provisioned but failed to load keys: {e}");
                    tracing::warn!("firmware flash will be rejected until keys are available");
                }
            }
        } else {
            tracing::info!("HSM not yet provisioned — firmware flash disabled until HSM provisioning");
        }

        // Ensure device key pair exists (generates on first boot)
        if let Err(e) = provider.ensure_device_key() {
            tracing::warn!("failed to ensure device key: {e}");
        }

        Some(Arc::new(Mutex::new(provider)))
    };

    // Create one backend per bank set
    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        ("hypervisor", BankSet::Hypervisor, ComponentConfig {
            entity_type: "hpc".into(), ..ComponentConfig::default()
        }),
        ("vm1", BankSet::Vm1, ComponentConfig::default()),
        ("vm2", BankSet::Vm2, ComponentConfig::default()),
        ("hsm", BankSet::Hsm, ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            ..ComponentConfig::default()
        }),
    ];

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    for (id, set, config) in components {
        let mut backend = VmBackend::with_options(
            set,
            nv.clone(),
            manifest_provider.clone(),
            security_provider.clone(),
            config,
            vm_service_socket.clone(),
            images_dir.clone(),
        );
        // Read display_name from per-bank vm-config.yaml if available
        if let Some(ref dir) = images_dir {
            let config_path = dir.join(id).join("current").join("vm-config.yaml");
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                // Lightweight parse — just extract display_name
                if let Ok(map) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    if let Some(name) = map.get("display_name").and_then(|v| v.as_str()) {
                        backend = backend.with_display_name(name.to_string());
                    }
                }
            }
        }
        // Wire HSM provider into the HSM backend
        if set == BankSet::Hsm {
            if let Some(ref provider) = hsm_provider {
                backend = backend.with_hsm_provider(provider.clone());
            }
        }
        backends.insert(id.to_string(), Arc::new(backend));
    }

    let state = sovd_api::AppState::new(backends);
    let router = sovd_api::create_router(state);

    // Add CSR endpoint for device provisioning (gated by UNPROVISIONED state)
    let csr_hsm = hsm_provider.clone();
    let csr_keystore = hsm_keystore_path.clone();
    let csr_port = hsm_port;
    let router = router.route(
        "/vehicle/v1/components/hsm/csr",
        axum::routing::get(move || {
            let hsm = csr_hsm.clone();
            let keystore = csr_keystore.clone();
            async move {
                let Some(hsm) = hsm else {
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "HSM provider not configured".to_string(),
                    ).into_response();
                };
                let state = hsm.lock().unwrap().provisioning_state();
                match state {
                    Ok(hsm::ProvisioningState::Provisioned) => {
                        (axum::http::StatusCode::FORBIDDEN, "device already provisioned".to_string())
                            .into_response()
                    }
                    Ok(hsm::ProvisioningState::Unprovisioned) => {
                        // Create a temporary crypto provider to generate the CSR
                        let tmp_hsm = LinuxSimHsm::new(
                            PathBuf::from("unused"),
                            keystore,
                            csr_port,
                            Vec::new(),
                        );
                        use hsm::HsmCryptoProvider;
                        match tmp_hsm.generate_csr("device-decrypt", "cvc-vm-device") {
                            Ok(csr_der) => {
                                tracing::info!("CSR generated for device-decrypt ({} bytes)", csr_der.len());
                                (
                                    [(axum::http::header::CONTENT_TYPE, "application/pkcs10")],
                                    csr_der,
                                ).into_response()
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "CSR generation failed");
                                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("CSR error: {e}"))
                                    .into_response()
                            }
                        }
                    }
                    Err(e) => {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("HSM error: {e}"))
                            .into_response()
                    }
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        });

    tracing::info!("vm-sovd listening on {bind_addr}");
    tracing::info!("  NV store: {}", nv_path.display());
    tracing::info!("  provisioning authority: {}", provisioning_authority_path.display());
    tracing::info!("  software authority: {}", if manifest_provider.has_software_authority() { "loaded from HSM" } else { "not yet available (awaiting HSM provisioning)" });
    if let Some(ref dir) = images_dir {
        tracing::info!("  images dir: {} (real image OTA enabled)", dir.display());
    }
    if let Some(ref sock) = vm_service_socket {
        tracing::info!("  vm-service socket: {}", sock.display());
    }
    tracing::info!("  HSM keystore: {}", hsm_keystore_path.display());
    tracing::info!("  components: hypervisor, vm1, vm2, hsm");
    tracing::info!("  try: curl http://{bind_addr}/vehicle/v1/components");

    axum::serve(listener, router).await.unwrap();
}
