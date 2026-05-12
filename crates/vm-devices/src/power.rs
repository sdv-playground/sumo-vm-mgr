//! Power-command device — host → guest control channel.
//!
//! Wire types ([`PowerCommand`], [`PowerCommandFrame`]) live in the
//! [`vm_wire`] contract crate. This module only carries the
//! **host-side wrapper** ([`PowerCommandDevice`]) that owns the
//! monotonic seq counter and writes encoded frames to a `DeviceChannel`.
//!
//! Re-exports the wire types so existing host callers
//! (`use vm_devices::power::PowerCommand;`) keep working.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::transport::{DeviceChannel, TransportError};

// Re-export wire types from the contract crate.
pub use vm_wire::{PowerCommand, PowerCommandFrame, POWER_WIRE_SIZE};

/// Host → guest power-command channel. Owns the monotonic next_seq.
pub struct PowerCommandDevice {
    channel: Arc<dyn DeviceChannel>,
    next_seq: AtomicU32,
}

impl PowerCommandDevice {
    pub fn new(channel: Arc<dyn DeviceChannel>) -> Self {
        Self {
            channel,
            next_seq: AtomicU32::new(1),
        }
    }

    pub fn send(&self, cmd: PowerCommand) -> Result<u32, TransportError> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let frame = PowerCommandFrame { seq, cmd };
        self.channel.write(&frame.to_bytes())?;
        self.channel.notify()?;
        Ok(seq)
    }

    pub fn read(&self) -> Option<PowerCommandFrame> {
        let bytes = self.channel.read().ok()?;
        PowerCommandFrame::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::MemTransport;
    use crate::transport::DeviceTransport;

    fn make_devices() -> (PowerCommandDevice, PowerCommandDevice) {
        let transport = MemTransport::new();
        let ch_host = transport
            .open_channel("vm2", "power", "cmd", POWER_WIRE_SIZE)
            .unwrap();
        let ch_guest = transport
            .open_channel("vm2", "power", "cmd", POWER_WIRE_SIZE)
            .unwrap();
        (
            PowerCommandDevice::new(ch_host),
            PowerCommandDevice::new(ch_guest),
        )
    }

    #[test]
    fn fresh_channel_read_returns_none() {
        let (_host, guest) = make_devices();
        assert!(guest.read().is_none());
    }

    #[test]
    fn send_then_read_roundtrip() {
        let (host, guest) = make_devices();
        let seq = host.send(PowerCommand::Shutdown).unwrap();
        let frame = guest.read().expect("read should see the write");
        assert_eq!(frame.seq, seq);
        assert_eq!(frame.cmd, PowerCommand::Shutdown);
    }

    #[test]
    fn send_increments_seq_monotonically() {
        let (host, guest) = make_devices();
        let s1 = host.send(PowerCommand::Reboot).unwrap();
        let s2 = host.send(PowerCommand::Shutdown).unwrap();
        let s3 = host.send(PowerCommand::Suspend).unwrap();

        assert_eq!(s2, s1 + 1);
        assert_eq!(s3, s2 + 1);

        let frame = guest.read().unwrap();
        assert_eq!(frame.seq, s3);
        assert_eq!(frame.cmd, PowerCommand::Suspend);
    }
}
