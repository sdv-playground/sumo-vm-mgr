//! Health device simulator.
//!
//! Writes sensor data to shared memory at a configurable interval (default 1 Hz),
//! monitors the guest heartbeat, and can send power commands.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::clock::Clock;
use crate::regs::health as r;
use crate::transport::{seqcount_write, Doorbell, SharedMemory};

/// Sensor configuration for the simulator.
#[derive(Clone)]
pub struct SensorConfig {
    pub sensor_type: u16,
    pub sensor_id: u16,
    pub base_value: i32,
    pub amplitude: i32,
    pub value_min: i32,
    pub value_max: i32,
    pub threshold_warn: i32,
    pub threshold_crit: i32,
}

/// Guest heartbeat state read from shared memory.
#[derive(Debug, Clone)]
pub struct Heartbeat {
    pub seq: u32,
    pub guest_state: u32,
    pub mono_ns: u64,
    pub flags: u32,
    pub boot_id: u32,
}

/// Power command to send to the guest.
#[derive(Debug, Clone, Copy)]
pub enum PowerCommand {
    Shutdown,
    Reboot,
    Suspend,
    Hibernate,
    Freeze,
}

impl PowerCommand {
    fn to_reg(self) -> u32 {
        match self {
            PowerCommand::Shutdown => r::CMD_SHUTDOWN,
            PowerCommand::Reboot => r::CMD_REBOOT,
            PowerCommand::Suspend => r::CMD_SUSPEND,
            PowerCommand::Hibernate => r::CMD_HIBERNATE,
            PowerCommand::Freeze => r::CMD_FREEZE,
        }
    }
}

/// Health device simulator.
///
/// Writes sensor readings and monitors guest heartbeat via shared memory.
pub struct HealthSim<S: SharedMemory, D: Doorbell, C: Clock> {
    shm: S,
    doorbell: D,
    clock: Arc<C>,
    sensors: Vec<SensorConfig>,
    interval: Duration,
}

impl<S: SharedMemory, D: Doorbell, C: Clock> HealthSim<S, D, C> {
    pub fn new(shm: S, doorbell: D, clock: Arc<C>, sensors: Vec<SensorConfig>) -> Self {
        Self {
            shm,
            doorbell,
            clock,
            sensors,
            interval: Duration::from_secs(1),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Initialize the shared memory header.
    pub fn init(&self) {
        self.shm.write_u32(r::OFF_MAGIC, r::MAGIC);
        self.shm.write_u32(r::OFF_VERSION, r::VERSION);
        self.shm.write_u32(r::OFF_NUM_SENSORS, self.sensors.len() as u32);
        self.shm.write_u32(r::OFF_UPDATE_SEQ, 0);
        self.shm.write_u32(r::OFF_FLAGS, r::FLAG_ACTIVE);

        // Write static sensor metadata
        for (i, s) in self.sensors.iter().enumerate() {
            let base = r::SENSOR_BASE + i * r::SENSOR_SIZE;
            self.shm.write_u16(base + r::SENSOR_OFF_TYPE, s.sensor_type);
            self.shm.write_u16(base + r::SENSOR_OFF_ID, s.sensor_id);
            self.shm.write_u32(
                base + r::SENSOR_OFF_VALUE_MIN,
                s.value_min as u32,
            );
            self.shm.write_u32(
                base + r::SENSOR_OFF_VALUE_MAX,
                s.value_max as u32,
            );
            self.shm.write_u32(
                base + r::SENSOR_OFF_THRESH_WARN,
                s.threshold_warn as u32,
            );
            self.shm.write_u32(
                base + r::SENSOR_OFF_THRESH_CRIT,
                s.threshold_crit as u32,
            );
            self.shm.write_u32(base + r::SENSOR_OFF_FLAGS, r::SENSOR_FLAG_VALID);
        }
    }

    /// Run the simulator loop. Blocks until `cancel` is set.
    pub fn run(&self, cancel: &AtomicBool) {
        self.init();

        let mut tick: u64 = 0;
        while !cancel.load(std::sync::atomic::Ordering::Relaxed) {
            self.update_sensors(tick);
            let _ = self.doorbell.notify();
            tick += 1;
            std::thread::sleep(self.interval);
        }
    }

    /// Single tick: update sensor values using seqcount protocol.
    pub fn update_sensors(&self, tick: u64) {
        let mono_ns = self.clock.now_mono_ns();

        seqcount_write(&self.shm, r::OFF_UPDATE_SEQ, || {
            self.shm.write_u64(r::OFF_MONO_NS, mono_ns);

            for (i, s) in self.sensors.iter().enumerate() {
                let base = r::SENSOR_BASE + i * r::SENSOR_SIZE;
                // Sine-wave variation around base value
                let phase = (tick as f64) * 0.1;
                let variation = (phase.sin() * s.amplitude as f64) as i32;
                let value = s.base_value + variation;
                self.shm.write_u32(base + r::SENSOR_OFF_VALUE, value as u32);

                // Update threshold exceeded flag
                let exceeded = value >= s.threshold_warn;
                let flags = r::SENSOR_FLAG_VALID
                    | if exceeded { r::SENSOR_FLAG_THRESH_EXCEEDED } else { 0 };
                self.shm.write_u32(base + r::SENSOR_OFF_FLAGS, flags);
            }
        });
    }

    /// Read guest heartbeat from shared memory.
    pub fn read_heartbeat(&self) -> Option<Heartbeat> {
        let magic = self.shm.read_u32(r::HB_OFF_MAGIC);
        if magic != r::HB_MAGIC {
            return None;
        }
        Some(Heartbeat {
            seq: self.shm.read_u32(r::HB_OFF_SEQ),
            guest_state: self.shm.read_u32(r::HB_OFF_GUEST_STATE),
            mono_ns: self.shm.read_u64(r::HB_OFF_MONO_NS),
            flags: self.shm.read_u32(r::HB_OFF_FLAGS),
            boot_id: self.shm.read_u32(r::HB_OFF_BOOT_ID),
        })
    }

    /// Send a power command to the guest.
    pub fn send_command(&self, cmd: PowerCommand) {
        let seq = self.shm.read_u32(r::CMD_OFF_SEQ);
        self.shm.write_u32(r::CMD_OFF_CMD, cmd.to_reg());
        self.shm.fence(std::sync::atomic::Ordering::Release);
        self.shm.write_u32(r::CMD_OFF_SEQ, seq.wrapping_add(1));
        let _ = self.doorbell.notify();
    }
}

/// Default sensor configuration matching the C health-sim.
pub fn default_sensors() -> Vec<SensorConfig> {
    vec![
        SensorConfig {
            sensor_type: r::TYPE_TEMP_SOC,
            sensor_id: 0,
            base_value: 45000,     // 45°C in millidegrees
            amplitude: 5000,       // ±5°C
            value_min: -40000,
            value_max: 125000,
            threshold_warn: 85000,
            threshold_crit: 95000,
        },
        SensorConfig {
            sensor_type: r::TYPE_TEMP_BOARD,
            sensor_id: 1,
            base_value: 35000,
            amplitude: 3000,
            value_min: -40000,
            value_max: 85000,
            threshold_warn: 70000,
            threshold_crit: 80000,
        },
        SensorConfig {
            sensor_type: r::TYPE_VOLTAGE_CORE,
            sensor_id: 0,
            base_value: 1100,      // 1.1V in millivolts
            amplitude: 50,
            value_min: 900,
            value_max: 1300,
            threshold_warn: 1250,
            threshold_crit: 1300,
        },
        SensorConfig {
            sensor_type: r::TYPE_VOLTAGE_IO,
            sensor_id: 1,
            base_value: 3300,      // 3.3V
            amplitude: 100,
            value_min: 2700,
            value_max: 3600,
            threshold_warn: 3500,
            threshold_crit: 3600,
        },
        SensorConfig {
            sensor_type: r::TYPE_STORAGE_WEAR,
            sensor_id: 0,
            base_value: 5,         // 5% wear
            amplitude: 0,
            value_min: 0,
            value_max: 100,
            threshold_warn: 80,
            threshold_crit: 95,
        },
        SensorConfig {
            sensor_type: r::TYPE_TEMP_STORAGE,
            sensor_id: 2,
            base_value: 40000,     // 40°C
            amplitude: 2000,
            value_min: -40000,
            value_max: 85000,
            threshold_warn: 70000,
            threshold_crit: 80000,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::{MemDoorbell, MemSharedMemory};

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_mono_ns(&self) -> u64 { self.0 }
        fn wall_offset_ns(&self) -> i64 { 0 }
    }

    fn make_sim() -> HealthSim<MemSharedMemory, MemDoorbell, FixedClock> {
        let shm = MemSharedMemory::new(4096);
        let clock = Arc::new(FixedClock(1_000_000_000));
        HealthSim::new(shm, MemDoorbell, clock, default_sensors())
    }

    #[test]
    fn init_writes_header() {
        let sim = make_sim();
        sim.init();

        assert_eq!(sim.shm.read_u32(r::OFF_MAGIC), r::MAGIC);
        assert_eq!(sim.shm.read_u32(r::OFF_VERSION), r::VERSION);
        assert_eq!(sim.shm.read_u32(r::OFF_NUM_SENSORS), 6);
        assert_eq!(sim.shm.read_u32(r::OFF_FLAGS), r::FLAG_ACTIVE);
    }

    #[test]
    fn init_writes_sensor_metadata() {
        let sim = make_sim();
        sim.init();

        // First sensor: SoC temperature
        let base = r::SENSOR_BASE;
        assert_eq!(sim.shm.read_u16(base + r::SENSOR_OFF_TYPE), r::TYPE_TEMP_SOC);
        assert_eq!(sim.shm.read_u16(base + r::SENSOR_OFF_ID), 0);
        assert_eq!(sim.shm.read_u32(base + r::SENSOR_OFF_FLAGS), r::SENSOR_FLAG_VALID);
    }

    #[test]
    fn update_sensors_writes_values() {
        let sim = make_sim();
        sim.init();
        sim.update_sensors(0);

        // After tick 0, sin(0) = 0, so value should be base_value
        let base = r::SENSOR_BASE;
        let value = sim.shm.read_u32(base + r::SENSOR_OFF_VALUE) as i32;
        assert_eq!(value, 45000); // base SoC temp

        // Mono timestamp should be written
        assert_eq!(sim.shm.read_u64(r::OFF_MONO_NS), 1_000_000_000);
    }

    #[test]
    fn update_sensors_increments_seqcount() {
        let sim = make_sim();
        sim.init();

        let seq_before = sim.shm.read_u32(r::OFF_UPDATE_SEQ);
        sim.update_sensors(0);
        let seq_after = sim.shm.read_u32(r::OFF_UPDATE_SEQ);

        // Seqcount advances by 2 (odd during write, even when done)
        assert_eq!(seq_after, seq_before + 2);
        assert_eq!(seq_after % 2, 0); // even = consistent
    }

    #[test]
    fn read_heartbeat_returns_none_before_guest_writes() {
        let sim = make_sim();
        sim.init();
        assert!(sim.read_heartbeat().is_none());
    }

    #[test]
    fn read_heartbeat_returns_data_after_guest_writes() {
        let sim = make_sim();
        sim.init();

        // Simulate guest writing heartbeat
        sim.shm.write_u32(r::HB_OFF_MAGIC, r::HB_MAGIC);
        sim.shm.write_u32(r::HB_OFF_SEQ, 42);
        sim.shm.write_u32(r::HB_OFF_GUEST_STATE, r::GUEST_RUNNING);
        sim.shm.write_u32(r::HB_OFF_BOOT_ID, 0xDEADBEEF);

        let hb = sim.read_heartbeat().unwrap();
        assert_eq!(hb.seq, 42);
        assert_eq!(hb.guest_state, r::GUEST_RUNNING);
        assert_eq!(hb.boot_id, 0xDEADBEEF);
    }

    #[test]
    fn send_command_writes_and_increments_seq() {
        let sim = make_sim();
        sim.init();

        let seq_before = sim.shm.read_u32(r::CMD_OFF_SEQ);
        sim.send_command(PowerCommand::Shutdown);

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_CMD), r::CMD_SHUTDOWN);
        assert_eq!(sim.shm.read_u32(r::CMD_OFF_SEQ), seq_before + 1);
    }

    #[test]
    fn sensor_values_vary_with_ticks() {
        let sim = make_sim();
        sim.init();

        sim.update_sensors(0);
        let v0 = sim.shm.read_u32(r::SENSOR_BASE + r::SENSOR_OFF_VALUE) as i32;

        // At tick ~15 (sin(1.5) ≈ 0.997), amplitude should be near max
        sim.update_sensors(15);
        let v15 = sim.shm.read_u32(r::SENSOR_BASE + r::SENSOR_OFF_VALUE) as i32;

        assert_ne!(v0, v15);
    }
}
