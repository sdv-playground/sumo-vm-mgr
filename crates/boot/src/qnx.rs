/// QNX boot backend — stub for qvm integration.
///
/// TODO: Implement when QNX team defines the qvm configuration interface.
/// This backend would:
/// 1. Generate qvm guest config pointing to the correct bank partition
/// 2. Map shared memory regions for ivshmem devices
/// 3. Start the guest via qvm APIs

use nv_store::types::{Bank, BankSet};
use crate::backend::*;
use crate::config::*;

pub struct QnxBackend;

impl QnxBackend {
    pub fn new() -> Self {
        Self
    }
}

impl BootBackend for QnxBackend {
    fn start_vm(
        &mut self,
        _profile: &VmProfile,
        _set: BankSet,
        _bank: Bank,
        _image_dir: &std::path::Path,
    ) -> Result<VmHandle, BackendError> {
        Err(BackendError::Config(
            "QNX backend not yet implemented".into(),
        ))
    }

    fn stop_vm(&mut self, _handle: &VmHandle) -> Result<(), BackendError> {
        Err(BackendError::Config(
            "QNX backend not yet implemented".into(),
        ))
    }

    fn is_running(&self, _handle: &VmHandle) -> bool {
        false
    }

    fn build_command(
        &self,
        _profile: &VmProfile,
        _set: BankSet,
        _bank: Bank,
        _image_dir: &std::path::Path,
    ) -> Result<Vec<String>, BackendError> {
        Err(BackendError::Config(
            "QNX backend not yet implemented".into(),
        ))
    }

    fn wait_vm(&mut self, _handle: &VmHandle) -> Result<Option<i32>, BackendError> {
        Err(BackendError::Config(
            "QNX backend not yet implemented".into(),
        ))
    }

    fn cleanup(&mut self) {}
}
