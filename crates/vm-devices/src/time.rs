//! Time device simulator.
//!
//! Updates shared memory time registers at a configurable interval (default 10 Hz)
//! using the seqcount protocol, and handles TIME_ADJUST commands from the guest.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use std::sync::Arc;

use crate::clock::Clock;
use crate::regs::time as r;
use crate::transport::{seqcount_write, Doorbell, SharedMemory};

/// Time device simulator.
pub struct TimeSim<S: SharedMemory, D: Doorbell, C: Clock> {
    shm: S,
    doorbell: D,
    clock: Arc<C>,
    interval: Duration,
    /// Only this guest ID may issue TIME_ADJUST (0 = allow all).
    sync_guest_id: u32,
    /// Minimum interval between adjustments.
    min_adjust_interval: Duration,
    /// Maximum correction magnitude (ns).
    max_correction_ns: i64,
    /// Current wall offset correction (accumulated from TIME_ADJUST commands).
    wall_correction_ns: i64,
    /// Last adjustment time.
    last_adjust: Option<Instant>,
    /// Last seen guest command sequence number.
    last_cmd_seq: u32,
}

impl<S: SharedMemory, D: Doorbell, C: Clock> TimeSim<S, D, C> {
    pub fn new(shm: S, doorbell: D, clock: Arc<C>) -> Self {
        Self {
            shm,
            doorbell,
            clock,
            interval: Duration::from_millis(100), // 10 Hz
            sync_guest_id: 1,
            min_adjust_interval: Duration::from_secs(10),
            max_correction_ns: 3_600_000_000_000, // 1 hour
            wall_correction_ns: 0,
            last_adjust: None,
            last_cmd_seq: 0,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_sync_guest_id(mut self, id: u32) -> Self {
        self.sync_guest_id = id;
        self
    }

    pub fn with_min_adjust_interval(mut self, d: Duration) -> Self {
        self.min_adjust_interval = d;
        self
    }

    /// Initialize shared memory header.
    pub fn init(&self) {
        self.shm.write_u32(r::OFF_MAGIC, r::MAGIC);
        self.shm.write_u32(r::OFF_VERSION, r::VERSION);
        self.shm.write_u32(r::OFF_UPDATE_SEQ, 0);
        self.shm.write_u32(r::OFF_FLAGS, 0);
        self.shm.write_u32(r::OFF_SYNC_SOURCE, r::SRC_NONE);
        self.shm.write_u32(r::OFF_SYNC_QUALITY, r::QUALITY_UNKNOWN);
    }

    /// Run the simulator loop. Blocks until `cancel` is set.
    pub fn run(&mut self, cancel: &AtomicBool) {
        self.init();

        while !cancel.load(Ordering::Relaxed) {
            self.update_time();
            self.check_adjust();
            let _ = self.doorbell.notify();
            std::thread::sleep(self.interval);
        }
    }

    /// Write current time registers using seqcount protocol.
    pub fn update_time(&self) {
        let mono_ns = self.clock.now_mono_ns();
        let wall_offset = self.clock.wall_offset_ns() + self.wall_correction_ns;

        seqcount_write(&self.shm, r::OFF_UPDATE_SEQ, || {
            self.shm.write_u64(r::OFF_MONO_NS, mono_ns);
            self.shm.write_i64(r::OFF_WALL_OFFSET_NS, wall_offset);
        });
    }

    /// Check for and process TIME_ADJUST commands from the guest.
    pub fn check_adjust(&mut self) {
        let cmd_seq = self.shm.read_u32(r::CMD_OFF_SEQ);
        if cmd_seq == self.last_cmd_seq {
            return;
        }
        self.last_cmd_seq = cmd_seq;

        let op = self.shm.read_u32(r::CMD_OFF_OP) as u8;
        if op != r::CMD_ADJUST {
            return;
        }

        let guest_id = self.shm.read_u32(r::CMD_OFF_GUEST_ID);
        let correction = self.shm.read_i64(r::CMD_OFF_CORRECTION_NS);

        // Authorization check
        if self.sync_guest_id != 0 && guest_id != self.sync_guest_id {
            self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_UNAUTHORIZED);
            let _ = self.doorbell.notify();
            return;
        }

        // Rate limit check
        if let Some(last) = self.last_adjust {
            if last.elapsed() < self.min_adjust_interval {
                self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_RATE_LIMITED);
                let _ = self.doorbell.notify();
                return;
            }
        }

        // Magnitude check
        if correction.abs() > self.max_correction_ns {
            self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_REJECTED);
            let _ = self.doorbell.notify();
            return;
        }

        // Apply correction
        self.wall_correction_ns += correction;

        // Anti-rollback floor check
        let min_wall = self.shm.read_u64(r::OFF_MIN_WALL_NS);
        if min_wall > 0 {
            let mono = self.clock.now_mono_ns();
            let new_wall = mono as i64 + self.clock.wall_offset_ns() + self.wall_correction_ns;
            if (new_wall as u64) < min_wall {
                self.wall_correction_ns -= correction; // undo
                self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_REJECTED);
                let _ = self.doorbell.notify();
                return;
            }
        }

        // Update sync metadata
        let source = self.shm.read_u32(r::CMD_OFF_SYNC_SOURCE);
        let quality = self.shm.read_u32(r::CMD_OFF_SYNC_QUALITY);
        self.shm.write_u32(r::OFF_SYNC_SOURCE, source);
        self.shm.write_u32(r::OFF_SYNC_QUALITY, quality);
        self.shm.write_u64(r::OFF_LAST_SYNC_MONO_NS, self.clock.now_mono_ns());
        self.shm.write_u32(r::OFF_FLAGS, r::FLAG_SYNC_VALID);

        self.last_adjust = Some(Instant::now());
        self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_APPLIED);

        // Write updated time immediately
        self.update_time();
        let _ = self.doorbell.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::{MemDoorbell, MemSharedMemory};

    struct FixedClock { mono: u64, wall_off: i64 }
    impl Clock for FixedClock {
        fn now_mono_ns(&self) -> u64 { self.mono }
        fn wall_offset_ns(&self) -> i64 { self.wall_off }
    }

    fn make_sim() -> TimeSim<MemSharedMemory, MemDoorbell, FixedClock> {
        let shm = MemSharedMemory::new(r::REGION_SIZE);
        let clock = Arc::new(FixedClock {
            mono: 5_000_000_000,
            wall_off: 1_700_000_000_000_000_000, // ~2023 epoch offset
        });
        TimeSim::new(shm, MemDoorbell, clock)
            .with_min_adjust_interval(Duration::ZERO)
    }

    #[test]
    fn init_writes_header() {
        let sim = make_sim();
        sim.init();

        assert_eq!(sim.shm.read_u32(r::OFF_MAGIC), r::MAGIC);
        assert_eq!(sim.shm.read_u32(r::OFF_VERSION), r::VERSION);
    }

    #[test]
    fn update_time_writes_registers() {
        let sim = make_sim();
        sim.init();
        sim.update_time();

        assert_eq!(sim.shm.read_u64(r::OFF_MONO_NS), 5_000_000_000);
        let wall_off = sim.shm.read_i64(r::OFF_WALL_OFFSET_NS);
        assert_eq!(wall_off, 1_700_000_000_000_000_000);
    }

    #[test]
    fn update_time_increments_seqcount() {
        let sim = make_sim();
        sim.init();

        let seq_before = sim.shm.read_u32(r::OFF_UPDATE_SEQ);
        sim.update_time();
        let seq_after = sim.shm.read_u32(r::OFF_UPDATE_SEQ);

        assert_eq!(seq_after, seq_before + 2);
        assert_eq!(seq_after % 2, 0);
    }

    #[test]
    fn adjust_applies_correction() {
        let mut sim = make_sim();
        sim.init();
        sim.update_time();

        // Simulate guest writing TIME_ADJUST command
        sim.shm.write_u32(r::CMD_OFF_SEQ, 1);
        sim.shm.write_u32(r::CMD_OFF_OP, r::CMD_ADJUST as u32);
        sim.shm.write_i64(r::CMD_OFF_CORRECTION_NS, 1_000_000); // +1ms
        sim.shm.write_u32(r::CMD_OFF_SYNC_SOURCE, r::SRC_NTP);
        sim.shm.write_u32(r::CMD_OFF_SYNC_QUALITY, r::QUALITY_MEDIUM);
        sim.shm.write_u32(r::CMD_OFF_GUEST_ID, 1);

        sim.check_adjust();

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_STATUS), r::STATUS_APPLIED);
        assert_eq!(sim.shm.read_u32(r::OFF_SYNC_SOURCE), r::SRC_NTP);
        assert_eq!(sim.shm.read_u32(r::OFF_FLAGS), r::FLAG_SYNC_VALID);

        // Wall offset should include correction
        let wall_off = sim.shm.read_i64(r::OFF_WALL_OFFSET_NS);
        assert_eq!(wall_off, 1_700_000_000_000_000_000 + 1_000_000);
    }

    #[test]
    fn adjust_rejects_unauthorized_guest() {
        let mut sim = make_sim();
        sim.init();

        sim.shm.write_u32(r::CMD_OFF_SEQ, 1);
        sim.shm.write_u32(r::CMD_OFF_OP, r::CMD_ADJUST as u32);
        sim.shm.write_i64(r::CMD_OFF_CORRECTION_NS, 1_000_000);
        sim.shm.write_u32(r::CMD_OFF_GUEST_ID, 99); // wrong guest

        sim.check_adjust();

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_STATUS), r::STATUS_UNAUTHORIZED);
    }

    #[test]
    fn adjust_rejects_excessive_correction() {
        let mut sim = make_sim();
        sim.init();

        // More than 1 hour correction
        sim.shm.write_u32(r::CMD_OFF_SEQ, 1);
        sim.shm.write_u32(r::CMD_OFF_OP, r::CMD_ADJUST as u32);
        sim.shm.write_i64(r::CMD_OFF_CORRECTION_NS, 4_000_000_000_000); // 4 hours
        sim.shm.write_u32(r::CMD_OFF_GUEST_ID, 1);

        sim.check_adjust();

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_STATUS), r::STATUS_REJECTED);
    }
}
