//! Host-side device simulators for virtual CAN, health, and time.
//!
//! Abstracts transport (ivshmem vs QNX native shm) and clock (real-time
//! vs simulation stepping vs gPTP) so the same device code runs on both
//! Linux/QEMU development and QNX production hosts.

pub mod transport;
pub mod clock;
pub mod regs;

#[cfg(feature = "health")]
pub mod health;

#[cfg(feature = "time")]
pub mod time;
