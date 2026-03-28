use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::BankSet;

use crate::manifest_provider::{ManifestProvider, ValidatedFirmware};

pub struct AppState<D: BlockDevice> {
    pub nv: Arc<Mutex<NvStore<D>>>,
    pub uploads: Arc<Mutex<UploadStore>>,
    pub manifest_provider: Arc<dyn ManifestProvider>,
}

// Manual Clone — Arc<Mutex<..>> is always Clone regardless of D.
impl<D: BlockDevice> Clone for AppState<D> {
    fn clone(&self) -> Self {
        Self {
            nv: self.nv.clone(),
            uploads: self.uploads.clone(),
            manifest_provider: self.manifest_provider.clone(),
        }
    }
}

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
