//! Development IFS activator for QEMU / file-backed boot partitions.
//!
//! Mounts the boot partition read-write (if not already mounted),
//! copies the new IFS to a temp file on the same filesystem, then
//! renames it into place for atomic activation.

use std::path::{Path, PathBuf};

use super::{IfsActivator, IfsError};

/// IFS activator for development (QEMU with QNX6 boot partition).
///
/// Activates by mounting the boot partition and copying the IFS
/// to `{mount_point}/.boot/primary_boot_image.bin`.
pub struct DevIfsActivator {
    /// Block device for the boot partition (e.g. `/dev/hd0t177`).
    boot_device: String,
    /// Where to mount the boot partition (e.g. `/mnt/boot`).
    mount_point: PathBuf,
    /// Relative path within the boot partition (e.g. `.boot/primary_boot_image.bin`).
    boot_image_rel: String,
}

impl DevIfsActivator {
    pub fn new(boot_device: String, mount_point: PathBuf) -> Self {
        Self {
            boot_device,
            mount_point,
            boot_image_rel: ".boot/primary_boot_image.bin".to_string(),
        }
    }
}

impl IfsActivator for DevIfsActivator {
    fn activate(&self, ifs_source: &Path) -> Result<(), IfsError> {
        // Ensure mount point exists
        std::fs::create_dir_all(&self.mount_point)?;

        // Mount the boot partition read-write if not already mounted
        let mount_check = std::process::Command::new("mount")
            .output()
            .map_err(IfsError::Io)?;
        let mount_output = String::from_utf8_lossy(&mount_check.stdout);
        let mp_str = self.mount_point.to_string_lossy();

        if !mount_output.contains(mp_str.as_ref()) {
            tracing::info!("mounting boot partition {} at {}", self.boot_device, mp_str);
            let status = std::process::Command::new("mount")
                .args(["-t", "qnx6", &self.boot_device, &mp_str])
                .status()
                .map_err(IfsError::Io)?;
            if !status.success() {
                return Err(IfsError::NotMounted(format!(
                    "mount {} failed (exit {})",
                    self.boot_device,
                    status.code().unwrap_or(-1)
                )));
            }
        }

        let target = self.mount_point.join(&self.boot_image_rel);
        let target_dir = target.parent().unwrap();

        // Ensure target directory exists
        std::fs::create_dir_all(target_dir)?;

        // Copy to temp file on same filesystem, then rename for atomicity
        let tmp_path = target_dir.join("primary_boot_image.bin.tmp");
        tracing::info!(
            "activating IFS: {} -> {}",
            ifs_source.display(),
            target.display()
        );
        std::fs::copy(ifs_source, &tmp_path)?;
        std::fs::rename(&tmp_path, &target)?;

        // Sync to ensure data hits disk before reboot
        let _ = std::process::Command::new("sync").status();

        tracing::info!("IFS activated — reboot required");
        Ok(())
    }
}
