//! Power-command device — host → guest control channel.
//!
//! ## Wire format ownership
//!
//! Same pattern as `heartbeat.rs`: canonical types live in
//! `guest-vm-spec/crates/vm-wire-format/src/power.rs`; this file holds a
//! host-side duplicate plus the device wrapper. The `canonical_wire_bytes`
//! fixture is pinned to match the spec — drift fails on both sides.
//! See `heartbeat.rs` for the rationale on duplication vs. shared crate.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::transport::{DeviceChannel, TransportError};

/// Wire size in bytes.
pub const POWER_WIRE_SIZE: usize = 8;

/// Power command codes. Numeric values must match `vm-wire-format` in spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PowerCommand {
    None = 0,
    Shutdown = 1,
    Reboot = 2,
    Suspend = 3,
    Hibernate = 4,
    Freeze = 5,
}

impl PowerCommand {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Shutdown),
            2 => Some(Self::Reboot),
            3 => Some(Self::Suspend),
            4 => Some(Self::Hibernate),
            5 => Some(Self::Freeze),
            _ => None,
        }
    }
}

/// One frame on the wire — what the host published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerCommandFrame {
    pub seq: u32,
    pub cmd: PowerCommand,
}

impl PowerCommandFrame {
    pub fn to_bytes(&self) -> [u8; POWER_WIRE_SIZE] {
        let mut buf = [0u8; POWER_WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.seq.to_le_bytes());
        buf[4..8].copy_from_slice(&(self.cmd as u32).to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < POWER_WIRE_SIZE {
            return None;
        }
        let seq = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let cmd = PowerCommand::from_u32(u32::from_le_bytes(data[4..8].try_into().ok()?))?;
        Some(Self { seq, cmd })
    }
}

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

    /// Pinned canonical bytes — same fixture as
    /// `vm-wire-format::power::tests::canonical_wire_bytes_shutdown` in spec.
    #[test]
    fn canonical_wire_bytes_shutdown() {
        let frame = PowerCommandFrame { seq: 0x0000_0007, cmd: PowerCommand::Shutdown };
        let bytes = frame.to_bytes();
        let expected: [u8; 8] = [
            0x07, 0x00, 0x00, 0x00, // seq
            0x01, 0x00, 0x00, 0x00, // cmd = Shutdown
        ];
        assert_eq!(bytes, expected);
    }
}
