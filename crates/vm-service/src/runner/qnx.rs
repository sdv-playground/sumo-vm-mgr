/// QNX qvm runner — stub for future Linux-on-QNX VM management.

use super::*;

pub struct QnxRunner;

impl QnxRunner {
    pub fn new() -> Self {
        Self
    }
}

impl VmRunner for QnxRunner {
    fn start(&mut self, _name: &str, _def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        Err(RunnerError::Config("QNX runner not yet implemented".into()))
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        Err(RunnerError::Config("QNX runner not yet implemented".into()))
    }

    fn is_running(&self, _handle: &VmHandle) -> bool {
        false
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        Err(RunnerError::Config("QNX runner not yet implemented".into()))
    }

    fn cleanup(&mut self) {}
}
