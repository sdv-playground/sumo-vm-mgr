use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use machine_mgr::Component;
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::BankSet;

use vm_mgr::backend::{ComponentConfig, VmBackend};
use vm_mgr::component_adapter::VmBackendComponent;
use vm_mgr::manifest_provider::ManifestProvider;
use vm_mgr::sovd::security::SecurityProvider;

/// Declarative component specification — parsed from YAML config.
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentSpec {
    pub id: String,

    #[serde(rename = "type")]
    pub component_type: String,

    #[serde(default = "default_true")]
    pub rollback: bool,

    #[serde(default)]
    pub single_bank: bool,

    /// Storage path for this component's firmware images / bank directories.
    #[serde(default)]
    pub storage_path: Option<PathBuf>,

    /// Base path for app-type components (A/B bank root with `current` symlink).
    #[serde(default)]
    pub base_path: Option<PathBuf>,

    /// Override the bank-set this component plugs into. Optional —
    /// when absent, defaults to whichever `BankSet` matches `id`
    /// (see [`bank_set_for_id`]). Use this when the component id
    /// is deployment-specific (e.g. `"rt"`) and shouldn't have an
    /// alias hardcoded into the generic factory; configure as
    /// `bank_set: custom` in YAML.
    #[serde(default)]
    pub bank_set: Option<String>,
}

/// Result of building a component — includes the Component trait object,
/// optionally a SOVD diagnostic backend for wire-level access, an
/// optional probe that returns whether a flash session is currently
/// in flight (used by destructive ops such as factory_reset), and an
/// optional callback to drop any in-flight flash session state
/// (used by factory_reset before wiping banks).
pub struct BuiltComponent {
    pub component: Arc<dyn Component>,
    pub diag_backend: Option<Arc<dyn sovd_core::DiagnosticBackend>>,
    pub flash_probe: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub flash_clear: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// Shared dependencies passed to the factory for all components.
pub struct FactoryDeps<D: BlockDevice> {
    pub nv: Arc<Mutex<NvStore<D>>>,
    pub manifest_provider: Arc<dyn ManifestProvider>,
    pub security_provider: Arc<dyn SecurityProvider>,
    pub vm_service_addr: Option<String>,
    pub hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    pub hsm_keystore: Option<PathBuf>,
    pub hsm_port: u16,
    pub ifs_activator: Option<Arc<dyn host_os_mgr::ifs::IfsActivator>>,
}

pub fn bank_set_for_id(id: &str) -> Option<BankSet> {
    match id {
        "host-os" => Some(BankSet::HostOs),
        "vm1" => Some(BankSet::Vm1),
        "vm2" => Some(BankSet::Vm2),
        "hsm" => Some(BankSet::Hsm),
        "app" | "supernova" => Some(BankSet::App),
        _ => None,
    }
}

/// Resolve the bank-set for a `ComponentSpec`. Explicit `bank_set`
/// field wins; falls back to id-based mapping via [`bank_set_for_id`].
/// Returns `None` if neither resolves — caller decides whether that's
/// fatal (most components require a bank-set; pure-runtime ones can
/// be `None`).
pub fn resolve_bank_set(spec: &ComponentSpec) -> Option<BankSet> {
    if let Some(ref s) = spec.bank_set {
        BankSet::from_str(s)
    } else {
        bank_set_for_id(&spec.id)
    }
}

/// Build a single component from its spec and shared dependencies.
pub fn build_component<D: BlockDevice + Send + Sync + 'static>(
    spec: &ComponentSpec,
    deps: &FactoryDeps<D>,
) -> Option<BuiltComponent> {
    let Some(bank_set) = resolve_bank_set(spec) else {
        tracing::warn!(
            "no bank-set for component id '{}' (no `bank_set:` override and \
             id doesn't match a well-known set) — skipping",
            spec.id,
        );
        return None;
    };

    match spec.component_type.as_str() {
        "app" => {
            let base_path = spec
                .base_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("/data/supernova"));
            let config = app_mgr::AppConfig {
                id: spec.id.clone(),
                base_path: base_path.clone(),
            };
            let comp = app_mgr::AppComponent::new(config, deps.nv.clone());
            let bank = comp.boot_check();
            tracing::info!(bank = ?bank, path = %base_path.display(), "app: boot check complete");

            let comp_config = ComponentConfig {
                entity_type: "app".into(),
                supports_rollback: spec.rollback,
                single_bank: false,
                ..ComponentConfig::default()
            };
            let backend = VmBackend::with_options(
                bank_set,
                deps.nv.clone(),
                deps.manifest_provider.clone(),
                deps.security_provider.clone(),
                comp_config,
                deps.vm_service_addr.clone(),
                spec.storage_path.clone().or_else(|| spec.base_path.clone()),
            );
            let backend_arc: Arc<VmBackend<_>> = Arc::new(backend);
            let component: Arc<dyn Component> = Arc::new(comp);

            let flash_probe: Arc<dyn Fn() -> bool + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.flash_in_progress())
            };
            let flash_clear: Arc<dyn Fn() + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.clear_flash_session())
            };

            let fallback: Arc<dyn sovd_core::DiagnosticBackend> = backend_arc;
            let diag = vm_mgr::diag_backend::ComponentDiagBackend::new(
                component.clone(),
                fallback,
            );

            Some(BuiltComponent {
                component,
                diag_backend: Some(Arc::new(diag)),
                flash_probe: Some(flash_probe),
                flash_clear: Some(flash_clear),
            })
        }
        "vm" | "hpc" | "hsm" => {
            let comp_config = ComponentConfig {
                entity_type: spec.component_type.clone(),
                supports_rollback: spec.rollback,
                single_bank: spec.single_bank,
                ..ComponentConfig::default()
            };

            let images_dir = spec.storage_path.clone();

            let mut backend = VmBackend::with_options(
                bank_set,
                deps.nv.clone(),
                deps.manifest_provider.clone(),
                deps.security_provider.clone(),
                comp_config,
                deps.vm_service_addr.clone(),
                images_dir,
            );

            if bank_set == BankSet::Hsm {
                if let Some(ref provider) = deps.hsm_provider {
                    backend = backend.with_hsm_provider(provider.clone());
                }
            }

            if bank_set == BankSet::HostOs {
                if let Some(ref activator) = deps.ifs_activator {
                    backend = backend.with_ifs_activator(activator.clone());
                }
            }

            let backend_arc: Arc<VmBackend<_>> = Arc::new(backend);
            let mut component_inner = VmBackendComponent::new(backend_arc.clone());

            if bank_set == BankSet::Hsm {
                if let Some(ref keystore) = deps.hsm_keystore {
                    component_inner = component_inner.with_csr_keystore(keystore.clone(), deps.hsm_port);
                }
            }

            let component: Arc<dyn Component> = Arc::new(component_inner);

            let flash_probe: Arc<dyn Fn() -> bool + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.flash_in_progress())
            };
            let flash_clear: Arc<dyn Fn() + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.clear_flash_session())
            };

            let fallback: Arc<dyn sovd_core::DiagnosticBackend> = backend_arc;
            let diag = vm_mgr::diag_backend::ComponentDiagBackend::new(
                component.clone(),
                fallback,
            );

            Some(BuiltComponent {
                component,
                diag_backend: Some(Arc::new(diag)),
                flash_probe: Some(flash_probe),
                flash_clear: Some(flash_clear),
            })
        }
        other => {
            tracing::warn!("unknown component type '{other}' for id '{}'", spec.id);
            None
        }
    }
}

fn default_true() -> bool {
    true
}
