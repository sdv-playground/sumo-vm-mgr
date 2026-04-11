//! Simulation stepping integration test.
//!
//! Validates dSPACE-like co-simulation: the host controls time via
//! SimController, device simulators update shared memory only when
//! stepped, and the guest sees exactly the time we set.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use vm_devices::clock::simulation::{SimController, SimulationClock};
use vm_devices::clock::Clock;
use vm_devices::health::{self, HealthSim};
use vm_devices::regs::{health as hr, time as tr};
use vm_devices::time::TimeSim;
use vm_devices::transport::mem::{MemDoorbell, MemSharedMemory};
use vm_devices::transport::SharedMemory;

const STEP_NS: u64 = 100_000_000; // 100ms steps
const INITIAL_MONO: u64 = 1_000_000_000; // 1 second
const WALL_OFFSET: i64 = 1_700_000_000_000_000_000; // ~2023 epoch

/// Wrapper to use Arc<MemSharedMemory> as SharedMemory (for shared access).
struct ShmRef(Arc<MemSharedMemory>);

impl SharedMemory for ShmRef {
    fn len(&self) -> usize { self.0.len() }
    fn read_u16(&self, o: usize) -> u16 { self.0.read_u16(o) }
    fn write_u16(&self, o: usize, v: u16) { self.0.write_u16(o, v) }
    fn read_u32(&self, o: usize) -> u32 { self.0.read_u32(o) }
    fn write_u32(&self, o: usize, v: u32) { self.0.write_u32(o, v) }
    fn read_u64(&self, o: usize) -> u64 { self.0.read_u64(o) }
    fn write_u64(&self, o: usize, v: u64) { self.0.write_u64(o, v) }
    fn read_bytes(&self, o: usize, b: &mut [u8]) { self.0.read_bytes(o, b) }
    fn write_bytes(&self, o: usize, d: &[u8]) { self.0.write_bytes(o, d) }
    fn fence(&self, ord: Ordering) { self.0.fence(ord) }
}

// =============================================================================
// Time simulator stepping
// =============================================================================

#[test]
fn time_frozen_between_steps() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let shm = Arc::new(MemSharedMemory::new(tr::REGION_SIZE));
    let sim = TimeSim::new(ShmRef(shm.clone()), MemDoorbell, clock.clone());
    sim.init();

    sim.update_time();
    let t1 = shm.read_u64(tr::OFF_MONO_NS);
    assert_eq!(t1, INITIAL_MONO);

    // Without stepping — time should be identical
    sim.update_time();
    let t2 = shm.read_u64(tr::OFF_MONO_NS);
    assert_eq!(t2, t1, "time should be frozen between steps");
}

#[test]
fn time_advances_exactly_by_step_size() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let ctrl = SimController::new(clock.clone(), STEP_NS);
    let shm = Arc::new(MemSharedMemory::new(tr::REGION_SIZE));
    let sim = TimeSim::new(ShmRef(shm.clone()), MemDoorbell, clock.clone());
    sim.init();

    ctrl.step();
    sim.update_time();
    assert_eq!(shm.read_u64(tr::OFF_MONO_NS), INITIAL_MONO + STEP_NS);

    ctrl.step();
    sim.update_time();
    assert_eq!(shm.read_u64(tr::OFF_MONO_NS), INITIAL_MONO + 2 * STEP_NS);

    ctrl.step_n(10);
    sim.update_time();
    assert_eq!(shm.read_u64(tr::OFF_MONO_NS), INITIAL_MONO + 12 * STEP_NS);
}

#[test]
fn wall_offset_controllable() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let shm = Arc::new(MemSharedMemory::new(tr::REGION_SIZE));
    let sim = TimeSim::new(ShmRef(shm.clone()), MemDoorbell, clock.clone());
    sim.init();

    sim.update_time();
    assert_eq!(shm.read_i64(tr::OFF_WALL_OFFSET_NS), WALL_OFFSET);

    // Simulate gPTP correction
    clock.set_wall_offset(WALL_OFFSET + 500_000);
    sim.update_time();
    assert_eq!(shm.read_i64(tr::OFF_WALL_OFFSET_NS), WALL_OFFSET + 500_000);
}

#[test]
fn seqcount_always_consistent() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let ctrl = SimController::new(clock.clone(), STEP_NS);
    let shm = Arc::new(MemSharedMemory::new(tr::REGION_SIZE));
    let sim = TimeSim::new(ShmRef(shm.clone()), MemDoorbell, clock.clone());
    sim.init();

    for _ in 0..20 {
        ctrl.step();
        sim.update_time();
        let seq = shm.read_u32(tr::OFF_UPDATE_SEQ);
        assert_eq!(seq % 2, 0, "seqcount must be even after update");
    }
}

// =============================================================================
// Health simulator stepping
// =============================================================================

#[test]
fn health_mono_tracks_sim_clock() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let ctrl = SimController::new(clock.clone(), STEP_NS);
    let shm = Arc::new(MemSharedMemory::new(4096));
    let sim = HealthSim::new(ShmRef(shm.clone()), MemDoorbell, clock.clone(), health::default_sensors());
    sim.init();

    ctrl.step();
    sim.update_sensors(0);
    assert_eq!(shm.read_u64(hr::OFF_MONO_NS), INITIAL_MONO + STEP_NS);

    ctrl.step_n(5);
    sim.update_sensors(1);
    assert_eq!(shm.read_u64(hr::OFF_MONO_NS), INITIAL_MONO + 6 * STEP_NS);
}

#[test]
fn health_deterministic_at_same_tick() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, 0));
    let shm = Arc::new(MemSharedMemory::new(4096));
    let sim = HealthSim::new(ShmRef(shm.clone()), MemDoorbell, clock.clone(), health::default_sensors());
    sim.init();

    sim.update_sensors(0);
    let v1 = shm.read_u32(hr::SENSOR_BASE + hr::SENSOR_OFF_VALUE) as i32;

    sim.update_sensors(0);
    let v2 = shm.read_u32(hr::SENSOR_BASE + hr::SENSOR_OFF_VALUE) as i32;
    assert_eq!(v1, v2, "same tick = same value");

    sim.update_sensors(15);
    let v3 = shm.read_u32(hr::SENSOR_BASE + hr::SENSOR_OFF_VALUE) as i32;
    assert_ne!(v1, v3, "different tick = different value");
}

// =============================================================================
// Coordinated stepping (time + health on same clock)
// =============================================================================

#[test]
fn coordinated_devices_share_time() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let ctrl = SimController::new(clock.clone(), STEP_NS);

    let time_shm = Arc::new(MemSharedMemory::new(tr::REGION_SIZE));
    let health_shm = Arc::new(MemSharedMemory::new(4096));

    let time_sim = TimeSim::new(ShmRef(time_shm.clone()), MemDoorbell, clock.clone());
    let health_sim = HealthSim::new(ShmRef(health_shm.clone()), MemDoorbell, clock.clone(), health::default_sensors());
    time_sim.init();
    health_sim.init();

    for tick in 0..10u64 {
        ctrl.step();
        time_sim.update_time();
        health_sim.update_sensors(tick);
    }

    let expected = INITIAL_MONO + 10 * STEP_NS;
    assert_eq!(time_shm.read_u64(tr::OFF_MONO_NS), expected);
    assert_eq!(health_shm.read_u64(hr::OFF_MONO_NS), expected);
    assert_eq!(clock.now_wall_ns(), (expected as i64 + WALL_OFFSET) as u64);
}

// =============================================================================
// Threaded stepping (device loop blocks on wait_tick)
// =============================================================================

#[test]
fn threaded_time_sim_waits_for_steps() {
    let clock = Arc::new(SimulationClock::new(INITIAL_MONO, WALL_OFFSET));
    let ctrl = SimController::new(clock.clone(), STEP_NS);

    let shm = Arc::new(MemSharedMemory::new(tr::REGION_SIZE));
    let shm_writer = ShmRef(shm.clone());
    let clock_thread = clock.clone();

    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    // Spawn sim thread that blocks on wait_tick
    let handle = std::thread::spawn(move || {
        let sim = TimeSim::new(shm_writer, MemDoorbell, clock_thread.clone());
        sim.init();
        loop {
            match clock_thread.wait_tick_timeout(std::time::Duration::from_millis(100)) {
                Some(_) => {
                    if cancel_clone.load(Ordering::Relaxed) { break; }
                    sim.update_time();
                }
                None => {
                    if cancel_clone.load(Ordering::Relaxed) { break; }
                }
            }
        }
    });

    // Step 5 times with small delay for thread processing
    for _ in 0..5 {
        ctrl.step();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    // Verify
    let mono = shm.read_u64(tr::OFF_MONO_NS);
    assert_eq!(mono, INITIAL_MONO + 5 * STEP_NS);

    // Shut down
    cancel.store(true, Ordering::Relaxed);
    ctrl.step(); // wake thread
    handle.join().unwrap();
}
