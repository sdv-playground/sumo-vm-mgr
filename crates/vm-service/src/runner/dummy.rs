/// Dummy runner — no-op backend for components without a real VM process.

use super::*;

pub struct DummyRunner;

impl DummyRunner {
    pub fn new() -> Self {
        Self
    }
}

impl VmRunner for DummyRunner {
    fn start(&mut self, name: &str, _def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        Ok(VmHandle { name: name.to_string(), pid: None })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        Ok(())
    }

    fn is_running(&self, _handle: &VmHandle) -> bool {
        false
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        Ok(Some(0))
    }

    fn cleanup(&mut self) {}
}
