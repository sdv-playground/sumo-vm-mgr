//! Hardware IFS activator stub for real ECU platforms.
//!
//! On real hardware, IFS activation may involve flash writes or
//! platform-specific bootloader APIs. This stub returns NotImplemented
//! until a concrete implementation is provided.

use std::path::Path;

use super::{IfsActivator, IfsError};

/// Stub IFS activator for hardware platforms.
pub struct HardwareIfsActivator;

impl IfsActivator for HardwareIfsActivator {
    fn activate(&self, _ifs_source: &Path) -> Result<(), IfsError> {
        Err(IfsError::NotImplemented(
            "hardware IFS activation not yet implemented".to_string(),
        ))
    }
}
