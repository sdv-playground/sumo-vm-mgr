//! Discrete-stepped simulation clock.
//!
//! Time advances only when the SimController calls `step()`. All device
//! simulator loops block on `wait_tick()` between iterations, enabling
//! deterministic co-simulation with external tools (Simulink, dSPACE, CARLA).
//!
//! Also supports fast-forward (step 1000x) for soak testing and
//! freeze/inspect at a known time point.

use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::sync::{Condvar, Mutex};

use super::Clock;

/// Simulation clock with discrete time stepping.
///
/// Time starts at a configurable epoch and advances in fixed increments
/// when the controller calls `step()`. Reading `now_mono_ns()` between
/// steps returns the same value (time is frozen).
pub struct SimulationClock {
    mono_ns: AtomicU64,
    wall_offset_ns: AtomicI64,
    /// Tick counter — incremented by controller, waited on by devices.
    tick: Mutex<u64>,
    tick_cv: Condvar,
}

impl SimulationClock {
    /// Create a simulation clock starting at the given monotonic time.
    pub fn new(initial_mono_ns: u64, wall_offset_ns: i64) -> Self {
        Self {
            mono_ns: AtomicU64::new(initial_mono_ns),
            wall_offset_ns: AtomicI64::new(wall_offset_ns),
            tick: Mutex::new(0),
            tick_cv: Condvar::new(),
        }
    }

    /// Advance time by `delta_ns` nanoseconds and wake all waiting devices.
    pub fn advance(&self, delta_ns: u64) {
        self.mono_ns.fetch_add(delta_ns, Ordering::Relaxed);
        let mut tick = self.tick.lock().unwrap();
        *tick += 1;
        self.tick_cv.notify_all();
    }

    /// Block until the next simulation tick. Returns the new monotonic time.
    ///
    /// Device simulator loops call this instead of `thread::sleep()`.
    pub fn wait_tick(&self) -> u64 {
        let mut tick = self.tick.lock().unwrap();
        let current = *tick;
        while *tick == current {
            tick = self.tick_cv.wait(tick).unwrap();
        }
        self.mono_ns.load(Ordering::Relaxed)
    }

    /// Wait with timeout (returns None if timed out).
    pub fn wait_tick_timeout(&self, timeout: std::time::Duration) -> Option<u64> {
        let mut tick = self.tick.lock().unwrap();
        let current = *tick;
        while *tick == current {
            let (guard, result) = self.tick_cv.wait_timeout(tick, timeout).unwrap();
            tick = guard;
            if result.timed_out() && *tick == current {
                return None;
            }
        }
        Some(self.mono_ns.load(Ordering::Relaxed))
    }

    /// Set the wall clock offset (for simulating gPTP corrections).
    pub fn set_wall_offset(&self, offset_ns: i64) {
        self.wall_offset_ns.store(offset_ns, Ordering::Relaxed);
    }

    /// Get the current tick count.
    pub fn tick_count(&self) -> u64 {
        *self.tick.lock().unwrap()
    }
}

impl Clock for SimulationClock {
    fn now_mono_ns(&self) -> u64 {
        self.mono_ns.load(Ordering::Relaxed)
    }

    fn wall_offset_ns(&self) -> i64 {
        self.wall_offset_ns.load(Ordering::Relaxed)
    }
}

/// Coordinates time-stepped simulation across all device simulators.
///
/// Holds a `SimulationClock` and provides methods to advance time.
/// All device loops block on `clock.wait_tick()` between iterations.
pub struct SimController {
    clock: std::sync::Arc<SimulationClock>,
    step_ns: u64,
}

impl SimController {
    /// Create a controller with a fixed step size.
    pub fn new(clock: std::sync::Arc<SimulationClock>, step_ns: u64) -> Self {
        Self { clock, step_ns }
    }

    /// Advance by one step.
    pub fn step(&self) {
        self.clock.advance(self.step_ns);
    }

    /// Advance by N steps.
    pub fn step_n(&self, n: u64) {
        for _ in 0..n {
            self.clock.advance(self.step_ns);
        }
    }

    /// Get current simulation time.
    pub fn now_ns(&self) -> u64 {
        self.clock.now_mono_ns()
    }

    /// Get the shared clock (pass to device constructors).
    pub fn clock(&self) -> std::sync::Arc<SimulationClock> {
        self.clock.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn advance_increments_time() {
        let clock = SimulationClock::new(1_000_000_000, 0);
        assert_eq!(clock.now_mono_ns(), 1_000_000_000);
        clock.advance(100_000_000);
        assert_eq!(clock.now_mono_ns(), 1_100_000_000);
    }

    #[test]
    fn wait_tick_blocks_until_advance() {
        let clock = Arc::new(SimulationClock::new(0, 0));
        let clock2 = clock.clone();

        let handle = std::thread::spawn(move || {
            clock2.wait_tick()
        });

        // Small sleep to ensure thread is waiting
        std::thread::sleep(std::time::Duration::from_millis(10));
        clock.advance(1_000_000); // 1ms

        let result = handle.join().unwrap();
        assert_eq!(result, 1_000_000);
    }

    #[test]
    fn wait_tick_timeout_returns_none() {
        let clock = SimulationClock::new(0, 0);
        let result = clock.wait_tick_timeout(std::time::Duration::from_millis(10));
        assert!(result.is_none());
    }

    #[test]
    fn controller_steps() {
        let clock = Arc::new(SimulationClock::new(0, 0));
        let ctrl = SimController::new(clock.clone(), 100_000_000); // 100ms steps

        ctrl.step();
        assert_eq!(clock.now_mono_ns(), 100_000_000);

        ctrl.step_n(3);
        assert_eq!(clock.now_mono_ns(), 400_000_000);
    }

    #[test]
    fn wall_offset_adjustable() {
        let clock = SimulationClock::new(1_000_000_000, 1_700_000_000_000_000_000);
        assert_eq!(clock.now_wall_ns(), 1_700_000_001_000_000_000);

        clock.set_wall_offset(1_700_000_000_500_000_000);
        assert_eq!(clock.now_wall_ns(), 1_700_000_001_500_000_000);
    }
}
