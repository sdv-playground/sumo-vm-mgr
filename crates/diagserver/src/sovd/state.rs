use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::BankSet;

use crate::manifest_provider::{ManifestProvider, ValidatedFirmware};
use crate::sovd::security::SecurityProvider;

// ---------------------------------------------------------------------------
// Session / security state (per component)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Default,
    Programming,
}

impl SessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionState::Default => "default",
            SessionState::Programming => "programming",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "default" => Some(SessionState::Default),
            "programming" => Some(SessionState::Programming),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPhase {
    Locked,
    SeedAvailable,
    Unlocked,
}

#[derive(Debug, Clone)]
pub struct SecurityAccessState {
    pub phase: SecurityPhase,
    pub level: u8,
    pub pending_seed: Option<Vec<u8>>,
}

impl Default for SecurityAccessState {
    fn default() -> Self {
        Self {
            phase: SecurityPhase::Locked,
            level: 0,
            pending_seed: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComponentMode {
    pub session: SessionState,
    pub security: SecurityAccessState,
}

impl Default for ComponentMode {
    fn default() -> Self {
        Self {
            session: SessionState::Default,
            security: SecurityAccessState::default(),
        }
    }
}

pub struct ModeStore {
    modes: HashMap<BankSet, ComponentMode>,
}

impl ModeStore {
    pub fn new() -> Self {
        let mut modes = HashMap::new();
        for set in [BankSet::Hypervisor, BankSet::Os1, BankSet::Os2] {
            modes.insert(set, ComponentMode::default());
        }
        Self { modes }
    }

    pub fn get(&self, set: BankSet) -> &ComponentMode {
        self.modes.get(&set).expect("all bank sets initialized")
    }

    pub fn get_mut(&mut self, set: BankSet) -> &mut ComponentMode {
        self.modes.get_mut(&set).expect("all bank sets initialized")
    }

    /// Set session, resetting security (ISO 14229).
    pub fn set_session(&mut self, set: BankSet, session: SessionState) {
        let mode = self.get_mut(set);
        mode.session = session;
        // Security resets on session change
        mode.security = SecurityAccessState::default();
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

pub struct AppState<D: BlockDevice> {
    pub nv: Arc<Mutex<NvStore<D>>>,
    pub uploads: Arc<Mutex<UploadStore>>,
    pub manifest_provider: Arc<dyn ManifestProvider>,
    pub modes: Arc<Mutex<ModeStore>>,
    pub security_provider: Arc<dyn SecurityProvider>,
}

impl<D: BlockDevice> Clone for AppState<D> {
    fn clone(&self) -> Self {
        Self {
            nv: self.nv.clone(),
            uploads: self.uploads.clone(),
            manifest_provider: self.manifest_provider.clone(),
            modes: self.modes.clone(),
            security_provider: self.security_provider.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Upload / transfer state
// ---------------------------------------------------------------------------

pub struct UploadStore {
    pub files: HashMap<String, UploadEntry>,
    pub transfers: HashMap<String, TransferState>,
    next_id: u64,
}

impl UploadStore {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            transfers: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn next_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id += 1;
        id.to_string()
    }
}

pub struct UploadEntry {
    pub id: String,
    pub component: BankSet,
    pub state: UploadPhase,
    pub validated: ValidatedFirmware,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UploadPhase {
    Uploaded,
    Verified,
}

impl UploadPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            UploadPhase::Uploaded => "uploaded",
            UploadPhase::Verified => "verified",
        }
    }
}

pub struct TransferState {
    pub id: String,
    pub upload_id: String,
    pub component: BankSet,
    pub state: TransferPhase,
    pub version: String,
    pub target_bank: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransferPhase {
    Completed,
}

impl TransferPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransferPhase::Completed => "completed",
        }
    }
}
