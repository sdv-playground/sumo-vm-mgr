use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{BankSet, NvBootState};

use sovd_core::DiagnosticBackend;

use vm_mgr::backend::{ComponentConfig, VmBackend};
use vm_mgr::component_adapter::VmBackendComponent;
use vm_mgr::diag_backend::ComponentDiagBackend;
use vm_mgr::sovd::security::TestSecurityProvider;
use vm_mgr::suit_provider::SuitProvider;

use machine_mgr::{Machine, MachineRegistry};
use sovd_core::EntityInfo;

use axum::response::IntoResponse;
use hsm::sim::SimHsm;
use hsm::{HsmProvider, KeyRole};

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
        eprintln!(
            "Usage: vm-sovd <nv-store-path> <provisioning-authority-path> [options] [bind-addr]"
        );
        eprintln!();
        eprintln!("Positional:");
        eprintln!("  nv-store-path              NV store file (created if missing)");
        eprintln!(
            "  provisioning-authority-path COSE_Key public key for HSM key envelope validation"
        );
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --images-dir <path>        Directory for A/B bank image files (enables real image OTA)");
        eprintln!("  --vm-service-socket <path> Unix socket / TCP address for vm-service lifecycle control");
        eprintln!("  --hsm-daemon <path>        Path to vhsm-test-ssd binary");
        eprintln!("  --hsm-keystore <path>      HSM keystore directory (default: /tmp/vhsm-keys)");
        eprintln!("  --hsm-port <port>          HSM vsock port (default: 5100)");
        eprintln!("  --boot-device <path>       Boot partition block device for IFS activation (e.g. /dev/hd0t177)");
        eprintln!("  --boot-mount <path>        Boot partition mount point (default: /mnt/boot)");
        eprintln!("  bind-addr                  Listen address (default: 0.0.0.0:4000)");
        eprintln!();
        eprintln!(
            "Software authority and device decryption keys are loaded from HSM after provisioning."
        );
        eprintln!("Firmware flash is rejected until HSM is provisioned.");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  vm-sovd /tmp/nv.bin keys/signing.pub");
        eprintln!("  vm-sovd /data/nv.bin /data/signing.pub --images-dir /data/images --hsm-keystore /data/vhsm-keys");
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
    let mut boot_device: Option<String> = None;
    let mut boot_mount = PathBuf::from("/mnt/boot");
    let mut bind_addr = "0.0.0.0:4000";
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
        } else if args[i] == "--boot-device" && i + 1 < args.len() {
            boot_device = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--boot-mount" && i + 1 < args.len() {
            boot_mount = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            bind_addr = &args[i];
            i += 1;
        }
    }

    // Load provisioning authority (validates HSM key envelopes)
    let provisioning_authority = std::fs::read(&provisioning_authority_path).unwrap_or_else(|e| {
        eprintln!(
            "failed to read provisioning authority {}: {e}",
            provisioning_authority_path.display()
        );
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
        let provider = SimHsm::new(
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
            tracing::info!(
                "HSM not yet provisioned — firmware flash disabled until HSM provisioning"
            );
        }

        // Ensure device key pair exists (generates on first boot)
        if let Err(e) = provider.ensure_device_key() {
            tracing::warn!("failed to ensure device key: {e}");
        }

        Some(Arc::new(Mutex::new(provider)))
    };

    // Create one backend per bank set
    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        (
            "host-os",
            BankSet::HostOs,
            ComponentConfig {
                entity_type: "host_os".into(),
                ..ComponentConfig::default()
            },
        ),
        ("vm1", BankSet::Vm1, ComponentConfig::default()),
        ("vm2", BankSet::Vm2, ComponentConfig::default()),
        (
            "hsm",
            BankSet::Hsm,
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".into(),
                ..ComponentConfig::default()
            },
        ),
    ];

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    let mut machine_builder = MachineRegistry::builder(EntityInfo {
        id: "vehicle".into(),
        name: "Vehicle".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/vehicle/v1".into(),
        status: None,
    });
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
        // Wire IFS activator into the boot backend
        if set == BankSet::HostOs {
            if let Some(ref dev) = boot_device {
                let activator =
                    host_os_mgr::ifs::dev::DevIfsActivator::new(dev.clone(), boot_mount.clone());
                backend = backend.with_ifs_activator(Arc::new(activator));
            }
        }
        // Wrap as ComponentDiagBackend so wired Component methods route through
        // machine-mgr; everything else falls through to the underlying VmBackend.
        let backend_arc: Arc<VmBackend<_>> = Arc::new(backend);
        let mut component_inner = VmBackendComponent::new(backend_arc.clone());
        // Wire CSR signing for the HSM component so the route below can
        // call machine.component("hsm").get_csr() instead of building a
        // transient SimHsm at request time.
        if set == BankSet::Hsm {
            component_inner =
                component_inner.with_csr_keystore(hsm_keystore_path.clone(), hsm_port);
        }
        let component: Arc<dyn machine_mgr::Component> = Arc::new(component_inner);

        machine_builder = machine_builder.with_arc(component.clone());

        let fallback: Arc<dyn DiagnosticBackend> = backend_arc.clone();
        let diag = ComponentDiagBackend::new(component, fallback);
        backends.insert(id.to_string(), Arc::new(diag) as Arc<dyn DiagnosticBackend>);
    }

    let machine: Arc<dyn Machine> = Arc::new(machine_builder.build());

    let state = sovd_api::AppState::new(backends);
    let router = sovd_api::create_router(state);

    // CSR endpoint for device provisioning. Routes through the Machine so
    // the actual CSR-signing logic lives in `VmBackendComponent::get_csr`,
    // not inline here.
    let csr_machine = machine.clone();
    let router = router.route(
        "/vehicle/v1/components/hsm/csr",
        axum::routing::get(move || {
            let machine = csr_machine.clone();
            async move {
                let Some(comp) = machine.component("hsm") else {
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "no hsm component".to_string(),
                    )
                        .into_response();
                };
                match comp.get_csr().await {
                    Ok(csr) => {
                        tracing::info!("CSR generated for device-decrypt ({} bytes)", csr.0.len());
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/pkcs10")],
                            csr.0.to_vec(),
                        )
                            .into_response()
                    }
                    Err(machine_mgr::MachineError::PolicyRejected(s)) => {
                        (axum::http::StatusCode::FORBIDDEN, s).into_response()
                    }
                    Err(machine_mgr::MachineError::NotSupported(_)) => (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "CSR not configured".to_string(),
                    )
                        .into_response(),
                    Err(e) => {
                        tracing::error!(error = %e, "CSR generation failed");
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("CSR error: {e}"),
                        )
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
    tracing::info!(
        "  provisioning authority: {}",
        provisioning_authority_path.display()
    );
    tracing::info!(
        "  software authority: {}",
        if manifest_provider.has_software_authority() {
            "loaded from HSM"
        } else {
            "not yet available (awaiting HSM provisioning)"
        }
    );
    if let Some(ref dir) = images_dir {
        tracing::info!("  images dir: {} (real image OTA enabled)", dir.display());
    }
    if let Some(ref sock) = vm_service_socket {
        tracing::info!("  vm-service socket: {}", sock.display());
    }
    tracing::info!("  HSM keystore: {}", hsm_keystore_path.display());
    if let Some(ref dev) = boot_device {
        tracing::info!("  boot device: {} (IFS activation enabled)", dev);
        tracing::info!("  boot mount: {}", boot_mount.display());
    }
    tracing::info!("  components: hypervisor, vm1, vm2, hsm, boot");
    tracing::info!("  try: curl http://{bind_addr}/vehicle/v1/components");

    axum::serve(listener, router).await.unwrap();
}
