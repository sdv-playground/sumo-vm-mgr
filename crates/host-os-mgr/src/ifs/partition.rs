//! Raw partition IFS activator for production hardware.
//!
//! Writes the IFS directly to a raw block device partition.
//! Used on real ECUs where the boot partition isn't a filesystem
//! but a raw image slot.

use std::path::Path;

use super::{IfsActivator, IfsError};

pub struct PartitionIfsActivator {
    boot_partition: String,
}

impl PartitionIfsActivator {
    pub fn new(boot_partition: String) -> Self {
        Self { boot_partition }
    }
}

impl IfsActivator for PartitionIfsActivator {
    fn activate(&self, ifs_source: &Path) -> Result<(), IfsError> {
        let image_data = std::fs::read(ifs_source)?;

        tracing::info!(
            "writing IFS ({} bytes) to raw partition {}",
            image_data.len(),
            self.boot_partition
        );

        std::fs::write(&self.boot_partition, &image_data)?;

        let _ = std::process::Command::new("sync").status();

        tracing::info!("IFS written to partition — reboot required");
        Ok(())
    }
}
