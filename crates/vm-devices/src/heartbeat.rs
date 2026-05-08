//! Heartbeat device — guest → host liveness signal.
//!
//! ## Wire format ownership
//!
//! The canonical wire format is documented and authoritative in
//! **`guest-vm-spec/crates/vm-wire-format/src/heartbeat.rs`**. This file
//! holds a host-side duplicate of the same types plus the device wrapper.
//! Both sides agree on the byte layout via the `canonical_wire_bytes`
//! fixture pinned in this file's tests; the same fixture exists in the
//! spec's vm-wire-format crate. If either fails, host and guest have
//! drifted and both must be updated together.
//!
//! Why duplicate instead of share via crate dep? guest-vm-spec is a
//! private (Traton GitLab) repo; sumo-machine-manager is public (GitHub).
//! Adding a private dep to the public repo's Cargo.toml leaks the URL
//! and breaks public-clone builds. The duplicate-with-pinned-fixtures
//! pattern keeps both tractable: spec owns the contract, host has its
//! own canonical types, fixtures catch drift.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::transport::{DeviceChannel, TransportError};

/// Magic at offset 0 of the heartbeat wire format.
pub const HEARTBEAT_MAGIC: u32 = 0x48425448; // "HBTH"

/// Wire format version. Reader rejects anything else.
pub const HEARTBEAT_VERSION: u32 = 1;

/// Wire size in bytes — fixed by the on-the-wire format.
pub const HEARTBEAT_WIRE_SIZE: usize = 32;

/// Bit flag set by guest when all critical services are up.
pub const HB_FLAG_SERVICES_READY: u32 = 1 << 0;

/// Guest-reported state values. Numeric values are part of the wire
/// format and must match `vm-wire-format` in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState {
    Booting = 0,
    Running = 1,
    Degraded = 2,
    ShuttingDown = 3,
}

impl GuestState {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Booting),
            1 => Some(Self::Running),
            2 => Some(Self::Degraded),
            3 => Some(Self::ShuttingDown),
            _ => None,
        }
    }
}

/// One heartbeat snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    pub seq: u32,
    pub state: GuestState,
    pub mono_ns: u64,
    pub flags: u32,
    pub boot_id: u32,
}

impl Heartbeat {
    pub fn to_bytes(&self) -> [u8; HEARTBEAT_WIRE_SIZE] {
        let mut buf = [0u8; HEARTBEAT_WIRE_SIZE];
        buf[0..4].copy_from_slice(&HEARTBEAT_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&HEARTBEAT_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&self.seq.to_le_bytes());
        buf[12..16].copy_from_slice(&(self.state as u32).to_le_bytes());
        buf[16..24].copy_from_slice(&self.mono_ns.to_le_bytes());
        buf[24..28].copy_from_slice(&self.flags.to_le_bytes());
        buf[28..32].copy_from_slice(&self.boot_id.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HEARTBEAT_WIRE_SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if magic != HEARTBEAT_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
        if version != HEARTBEAT_VERSION {
            return None;
        }
        let seq = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let state = GuestState::from_u32(u32::from_le_bytes(data[12..16].try_into().ok()?))?;
        let mono_ns = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let flags = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let boot_id = u32::from_le_bytes(data[28..32].try_into().ok()?);
        Some(Self { seq, state, mono_ns, flags, boot_id })
    }
}

/// Host-side wrapper around a single `DeviceChannel` carrying heartbeats.
pub struct HeartbeatDevice {
    channel: Arc<dyn DeviceChannel>,
}

impl HeartbeatDevice {
    pub fn new(channel: Arc<dyn DeviceChannel>) -> Self {
        Self { channel }
    }

    pub fn read(&self) -> Option<Heartbeat> {
        let bytes = self.channel.read().ok()?;
        Heartbeat::from_bytes(&bytes)
    }

    pub fn write(&self, hb: &Heartbeat) -> Result<(), TransportError> {
        self.channel.write(&hb.to_bytes())?;
        self.channel.notify()?;
        Ok(())
    }

    /// Block until the guest reports `target` state with an advanced seq,
    /// or `timeout` elapses. Pure poll loop — see file-level docs for why
    /// channel.wait is not used.
    pub fn wait_for_state(&self, target: GuestState, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let initial_seq = self.read().map(|h| h.seq);

        loop {
            if let Some(hb) = self.read() {
                let seq_advanced = initial_seq.map(|s| hb.seq != s).unwrap_or(true);
                if seq_advanced && hb.state == target {
                    return true;
                }
            }

            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let slice = (deadline - now).min(Duration::from_millis(100));
            std::thread::sleep(slice);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::MemTransport;
    use crate::transport::DeviceTransport;

    fn make_device() -> (HeartbeatDevice, HeartbeatDevice, MemTransport) {
        let transport = MemTransport::new();
        let ch_host = transport
            .open_channel("vm2", "heartbeat", "data", HEARTBEAT_WIRE_SIZE)
            .unwrap();
        let ch_guest = transport
            .open_channel("vm2", "heartbeat", "data", HEARTBEAT_WIRE_SIZE)
            .unwrap();
        (
            HeartbeatDevice::new(ch_host),
            HeartbeatDevice::new(ch_guest),
            transport,
        )
    }

    fn sample_hb() -> Heartbeat {
        Heartbeat {
            seq: 42,
            state: GuestState::Running,
            mono_ns: 1_500_000_000,
            flags: HB_FLAG_SERVICES_READY,
            boot_id: 0xDEAD_BEEF,
        }
    }

    #[test]
    fn read_before_write_returns_none() {
        let (host, _guest, _t) = make_device();
        assert!(host.read().is_none());
    }

    #[test]
    fn write_then_read_roundtrip() {
        let (host, guest, _t) = make_device();
        let hb = sample_hb();
        guest.write(&hb).unwrap();
        let got = host.read().expect("read should see the write");
        assert_eq!(got, hb);
    }

    #[test]
    fn wire_format_size_is_32_bytes() {
        let hb = sample_hb();
        assert_eq!(hb.to_bytes().len(), HEARTBEAT_WIRE_SIZE);
        assert_eq!(HEARTBEAT_WIRE_SIZE, 32);
    }

    #[test]
    fn from_bytes_rejects_short_buffer() {
        assert!(Heartbeat::from_bytes(&[0u8; HEARTBEAT_WIRE_SIZE - 1]).is_none());
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let mut bytes = sample_hb().to_bytes();
        bytes[0] ^= 0xFF;
        assert!(Heartbeat::from_bytes(&bytes).is_none());
    }

    #[test]
    fn wait_for_state_returns_false_on_timeout() {
        let (host, _guest, _t) = make_device();
        assert!(!host.wait_for_state(GuestState::Running, Duration::from_millis(20)));
    }

    #[test]
    fn wait_for_state_returns_true_when_state_appears() {
        let (host, guest, _t) = make_device();

        let mut hb = sample_hb();
        hb.state = GuestState::Booting;
        hb.seq = 1;
        guest.write(&hb).unwrap();

        let waiter = std::thread::spawn(move || {
            host.wait_for_state(GuestState::Running, Duration::from_secs(5))
        });

        std::thread::sleep(Duration::from_millis(20));
        let mut hb_running = sample_hb();
        hb_running.state = GuestState::Running;
        hb_running.seq = 2;
        guest.write(&hb_running).unwrap();

        assert!(waiter.join().expect("waiter panicked"));
    }

    /// Pinned canonical bytes — same fixture as
    /// `vm-wire-format::heartbeat::tests::canonical_wire_bytes` in spec.
    /// Either failing means host and guest have drifted on the wire format
    /// — update both together.
    #[test]
    fn canonical_wire_bytes() {
        let hb = Heartbeat {
            seq: 0x0000_0001,
            state: GuestState::Running,
            mono_ns: 0x0000_0000_3B9A_CA00, // 1 second
            flags: 0x0000_0001,
            boot_id: 0x0000_0042,
        };
        let bytes = hb.to_bytes();
        let expected: [u8; 32] = [
            0x48, 0x54, 0x42, 0x48, // magic "HBTH"
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x00, 0x00, 0x00, // seq
            0x01, 0x00, 0x00, 0x00, // state = Running
            0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00, // mono_ns
            0x01, 0x00, 0x00, 0x00, // flags
            0x42, 0x00, 0x00, 0x00, // boot_id
        ];
        assert_eq!(bytes, expected);
    }
}
