//! Heartbeat device — guest → host liveness signal.
//!
//! ## Wire format
//!
//! Wire types ([`Heartbeat`], [`GuestState`], the constants) live in the
//! [`vm_wire`] contract crate. This module only carries the
//! **host-side wrapper** ([`HeartbeatDevice`]) that ties a `DeviceChannel`
//! to the wire-format codec. Guests use [`vm_guest_lib::HeartbeatClient`]
//! against the same wire type.
//!
//! Re-exports the wire types so existing host callers
//! (`use vm_devices::heartbeat::Heartbeat;`) keep working without import
//! churn.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::transport::{DeviceChannel, TransportError};

// Re-export wire types from the contract crate.
pub use vm_wire::{
    GuestState, Heartbeat, HB_FLAG_SERVICES_READY, HEARTBEAT_MAGIC, HEARTBEAT_VERSION,
    HEARTBEAT_WIRE_SIZE,
};

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
    /// or `timeout` elapses. Pure poll loop.
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
}
