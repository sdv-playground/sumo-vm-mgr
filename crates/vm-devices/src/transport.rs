//! Transport abstractions for host↔guest shared memory communication.

pub mod mem;
#[cfg(target_os = "linux")]
pub mod ivshmem;

use std::sync::atomic::Ordering;

/// Error type for transport operations.
#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    OutOfBounds { offset: usize, len: usize, size: usize },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport I/O: {e}"),
            TransportError::OutOfBounds { offset, len, size } => {
                write!(f, "out of bounds: offset={offset} len={len} size={size}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// A region of shared memory accessible by both host and guest.
///
/// Implementations handle platform-specific mapping:
/// - Linux/QEMU: mmap of `/dev/shm/ivshmem-*`
/// - QNX: `shm_open` + `mmap`
/// - Tests: heap-allocated buffer
///
/// All reads/writes use volatile semantics to prevent compiler reordering.
pub trait SharedMemory: Send + Sync {
    /// Size of the shared region in bytes.
    fn len(&self) -> usize;

    /// Read a little-endian u32 at the given byte offset (volatile).
    fn read_u32(&self, offset: usize) -> u32;

    /// Write a little-endian u32 at the given byte offset (volatile).
    fn write_u32(&self, offset: usize, value: u32);

    /// Read a little-endian u64 at the given byte offset (volatile).
    fn read_u64(&self, offset: usize) -> u64;

    /// Write a little-endian u64 at the given byte offset (volatile).
    fn write_u64(&self, offset: usize, value: u64);

    /// Read a little-endian i64 at the given byte offset (volatile).
    fn read_i64(&self, offset: usize) -> i64 {
        self.read_u64(offset) as i64
    }

    /// Write a little-endian i64 at the given byte offset (volatile).
    fn write_i64(&self, offset: usize, value: i64) {
        self.write_u64(offset, value as u64);
    }

    /// Read a little-endian u16 at the given byte offset (volatile).
    fn read_u16(&self, offset: usize) -> u16;

    /// Write a little-endian u16 at the given byte offset (volatile).
    fn write_u16(&self, offset: usize, value: u16);

    /// Read a byte slice from the given offset (non-atomic, for bulk data).
    fn read_bytes(&self, offset: usize, buf: &mut [u8]);

    /// Write a byte slice to the given offset (non-atomic, for bulk data).
    fn write_bytes(&self, offset: usize, data: &[u8]);

    /// Memory fence (compiler + hardware barrier).
    fn fence(&self, ordering: Ordering);
}

/// Doorbell mechanism for notifying the peer (guest or host).
pub trait Doorbell: Send + Sync {
    /// Ring the doorbell (notify the guest that data is ready).
    fn notify(&self) -> Result<(), TransportError>;

    /// Wait for a doorbell from the peer. Blocks until notification.
    fn wait(&self) -> Result<(), TransportError>;

    /// Non-blocking check if a doorbell is pending.
    fn try_wait(&self) -> Result<bool, TransportError>;
}

/// Seqcount write helper for lock-free multi-word updates.
///
/// Increments the sequence counter to odd (writing), executes the closure,
/// then increments to even (done). Readers retry if they see an odd seq
/// or if seq changed between start and end of their read.
pub fn seqcount_write(shm: &dyn SharedMemory, seq_offset: usize, write_fn: impl FnOnce()) {
    let seq = shm.read_u32(seq_offset);
    shm.write_u32(seq_offset, seq.wrapping_add(1)); // odd = writing
    shm.fence(Ordering::Release);

    write_fn();

    shm.fence(Ordering::Release);
    shm.write_u32(seq_offset, seq.wrapping_add(2)); // even = done
}
