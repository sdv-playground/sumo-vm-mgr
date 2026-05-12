//! Cross-VM transport contract.
//!
//! The byte-portable, role-neutral definition of how host and guest
//! agree to talk. Both sides depend on this crate; their implementations
//! sit on top.
//!
//! ## Two trait shapes
//!
//! - [`DeviceChannel`] — register-style: read latest snapshot, write
//!   replaces, notify, wait. Fits heartbeat, power-command, time-sync.
//! - [`StreamChannel`] — FIFO sibling: send_frame / recv_frame /
//!   try_recv_frame. Fits CAN frames, audio buffers, log records.
//!
//! Implementations of these traits live in:
//! - **`vm-devices`** (host wrappers + IvshmemTransport)
//! - **`qnx-devices`** (libhyp, qvm-shmem host transport — proprietary)
//! - **`guest-vm-spec/crates/vm-guest-lib`** (portable guest-side: HTTP, TCP)
//! - **`guest-vm-spec/crates/qvm-shmem`** (Linux-guest qvm-shmem)
//! - **`guest-vm-qnx/crates/ivshmem-guest`** (QNX-guest MAP_PHYS)
//!
//! ## Wire formats
//!
//! [`Heartbeat`] and [`PowerCommandFrame`] are the byte-exact payloads
//! crossing channels. They live here so host and guest never disagree
//! on layout. Pinned by `canonical_wire_bytes` fixtures in their tests.
//!
//! ## Layering
//!
//! ```text
//!     vm-wire (this crate)                 ← traits + wire formats
//!         ▲             ▲
//!         │             │
//!     ┌───┴────┐    ┌───┴───────────────┐
//!     │ host   │    │ guest             │
//!     │ impls  │    │ impls             │
//!     └────────┘    └───────────────────┘
//! ```

pub mod heartbeat;
pub mod power;
pub mod time;
pub mod transport;

pub use heartbeat::{
    GuestState, Heartbeat, HB_FLAG_SERVICES_READY, HEARTBEAT_MAGIC, HEARTBEAT_VERSION,
    HEARTBEAT_WIRE_SIZE,
};
pub use power::{PowerCommand, PowerCommandFrame, POWER_WIRE_SIZE};
pub use time::{
    SyncQuality, SyncSource, VtimeCmd, VtimeRegs, VTIME_CMD_ADJUST, VTIME_CMD_OFFSET,
    VTIME_CMD_SIZE, VTIME_FLAG_RTC_PRESENT, VTIME_FLAG_SYNC_VALID, VTIME_MAGIC, VTIME_REGS_SIZE,
    VTIME_STATUS_APPLIED, VTIME_STATUS_PENDING, VTIME_STATUS_RATE_LIMITED, VTIME_STATUS_REJECTED,
    VTIME_STATUS_UNAUTHORIZED, VTIME_VERSION, VTIME_WIRE_SIZE,
};
pub use transport::{
    seqcount_write, DeviceChannel, DeviceTransport, Doorbell, SharedMemory, StreamChannel,
    TransportError,
};
