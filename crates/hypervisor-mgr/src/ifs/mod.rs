//! IFS (Initial Filesystem) activation backends.
//!
//! QNX IPL loads the IFS from a fixed path on the boot partition
//! (`/.boot/primary_boot_image.bin`). Unlike rootfs images, IFS cannot
//! use symlink-based A/B switching because IPL does not follow symlinks.
//!
//! Each backend implements `IfsActivator` — the trait that copies a new
//! IFS bank image to the active boot location.

pub mod dev;
pub mod hardware;

use std::path::Path;

/// Errors from IFS activation.
#[derive(Debug)]
pub enum IfsError {
    Io(std::io::Error),
    NotMounted(String),
    NotImplemented(String),
}

impl std::fmt::Display for IfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IfsError::Io(e) => write!(f, "IFS I/O error: {e}"),
            IfsError::NotMounted(msg) => write!(f, "boot partition not mounted: {msg}"),
            IfsError::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
        }
    }
}

impl From<std::io::Error> for IfsError {
    fn from(e: std::io::Error) -> Self {
        IfsError::Io(e)
    }
}

/// Trait for activating a new IFS boot image.
///
/// Implementors copy the IFS from the staged bank location to the
/// platform-specific boot path. After activation, a reboot will load
/// the new IFS.
pub trait IfsActivator: Send + Sync {
    /// Copy the IFS from `ifs_source` to the active boot location.
    fn activate(&self, ifs_source: &Path) -> Result<(), IfsError>;
}
