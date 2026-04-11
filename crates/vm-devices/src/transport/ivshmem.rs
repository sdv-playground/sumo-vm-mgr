//! ivshmem shared memory transport for Linux/QEMU.
//!
//! Maps `/dev/shm/ivshmem-{vm}-{label}` into the process address space
//! using mmap. All reads/writes use volatile semantics to match the
//! seqcount protocol expected by guest kernel drivers.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use super::{Doorbell, SharedMemory, TransportError};

/// Shared memory backed by an mmap'd file in `/dev/shm/`.
///
/// Created by ivshmem-server during VM startup. The file persists
/// for the lifetime of the ivshmem-server process.
pub struct IvshmemSharedMemory {
    ptr: *mut u8,
    size: usize,
    _path: PathBuf,
}

// SAFETY: The shared memory region is accessed via volatile operations
// and explicit fences. The mmap'd region is valid for the process lifetime.
unsafe impl Send for IvshmemSharedMemory {}
unsafe impl Sync for IvshmemSharedMemory {}

impl IvshmemSharedMemory {
    /// Open an existing ivshmem shared memory region.
    ///
    /// The file at `path` must already exist (created by ivshmem-server).
    pub fn open(path: &Path) -> Result<Self, TransportError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(TransportError::Io)?;

        let size = file.metadata().map_err(TransportError::Io)?.len() as usize;
        if size == 0 {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shared memory file is empty",
            )));
        }

        let fd = {
            use std::os::unix::io::AsRawFd;
            file.as_raw_fd()
        };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }

        // Keep the file open by leaking it — the mmap holds a reference
        // to the underlying inode, so the fd can be closed. But we keep
        // the File alive for safety.
        std::mem::forget(file);

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            _path: path.to_path_buf(),
        })
    }

    /// Open by VM name and label (standard naming convention).
    pub fn open_by_name(vm_name: &str, label: &str) -> Result<Self, TransportError> {
        let path = PathBuf::from(format!("/dev/shm/ivshmem-{vm_name}-{label}"));
        Self::open(&path)
    }
}

impl Drop for IvshmemSharedMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
        }
    }
}

impl SharedMemory for IvshmemSharedMemory {
    fn len(&self) -> usize {
        self.size
    }

    fn read_u16(&self, offset: usize) -> u16 {
        assert!(offset + 2 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *const u16;
            core::ptr::read_volatile(p).to_le()
        }
    }

    fn write_u16(&self, offset: usize, value: u16) {
        assert!(offset + 2 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *mut u16;
            core::ptr::write_volatile(p, value.to_le());
        }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *const u32;
            core::ptr::read_volatile(p).to_le()
        }
    }

    fn write_u32(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *mut u32;
            core::ptr::write_volatile(p, value.to_le());
        }
    }

    fn read_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *const u64;
            core::ptr::read_volatile(p).to_le()
        }
    }

    fn write_u64(&self, offset: usize, value: u64) {
        assert!(offset + 8 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *mut u64;
            core::ptr::write_volatile(p, value.to_le());
        }
    }

    fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        assert!(offset + buf.len() <= self.size);
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
        }
    }

    fn write_bytes(&self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.size);
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
        }
    }

    fn fence(&self, ordering: Ordering) {
        std::sync::atomic::fence(ordering);
    }
}

/// Eventfd-based doorbell.
///
/// The eventfd is obtained from the ivshmem-server socket protocol.
/// For now, this is a simple wrapper around a raw fd.
pub struct EventfdDoorbell {
    fd: i32,
}

impl EventfdDoorbell {
    /// Create from a raw eventfd file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid eventfd descriptor.
    pub unsafe fn from_raw_fd(fd: i32) -> Self {
        Self { fd }
    }
}

impl Drop for EventfdDoorbell {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

impl Doorbell for EventfdDoorbell {
    fn notify(&self) -> Result<(), TransportError> {
        let val: u64 = 1;
        let ret = unsafe {
            libc::write(self.fd, &val as *const u64 as *const libc::c_void, 8)
        };
        if ret != 8 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn wait(&self) -> Result<(), TransportError> {
        let mut val: u64 = 0;
        let ret = unsafe {
            libc::read(self.fd, &mut val as *mut u64 as *mut libc::c_void, 8)
        };
        if ret != 8 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn try_wait(&self) -> Result<bool, TransportError> {
        // Non-blocking check via poll
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        if ret < 0 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            // Consume the event
            let _ = self.wait();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Null doorbell — does nothing. Used when the ivshmem-server socket
/// protocol isn't available or not needed (health/time use polling).
pub struct NullDoorbell;

impl Doorbell for NullDoorbell {
    fn notify(&self) -> Result<(), TransportError> { Ok(()) }
    fn wait(&self) -> Result<(), TransportError> { Ok(()) }
    fn try_wait(&self) -> Result<bool, TransportError> { Ok(false) }
}
