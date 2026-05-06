//! POSIX shared memory transport + QNX pulse doorbell.
//!
//! `PosixSharedMemory` uses shm_open + mmap — works on Linux and QNX.
//! `QnxPulseDoorbell` uses MsgSendPulse (QNX-only, no-op on Linux).

use std::sync::atomic::Ordering;

use crate::transport::{Doorbell, SharedMemory, TransportError};

/// POSIX shared memory region (shm_open + mmap).
pub struct PosixSharedMemory {
    ptr: *mut u8,
    size: usize,
    #[allow(dead_code)]
    name: String,
}

unsafe impl Send for PosixSharedMemory {}
unsafe impl Sync for PosixSharedMemory {}

impl PosixSharedMemory {
    /// Open an existing shared memory object by name.
    pub fn open(name: &str, size: usize) -> Result<Self, std::io::Error> {
        let c_name = std::ffi::CString::new(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad shm name"))?;

        let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0o666) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

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
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            name: name.to_string(),
        })
    }

    /// Create a new shared memory object.
    pub fn create(name: &str, size: usize) -> Result<Self, std::io::Error> {
        let c_name = std::ffi::CString::new(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad shm name"))?;

        let fd = unsafe {
            libc::shm_open(c_name.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o666)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::ftruncate(fd, size as libc::off_t) };

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
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            name: name.to_string(),
        })
    }
}

impl Drop for PosixSharedMemory {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) };
    }
}

impl SharedMemory for PosixSharedMemory {
    fn len(&self) -> usize { self.size }

    fn read_u16(&self, offset: usize) -> u16 {
        assert!(offset + 2 <= self.size);
        unsafe { core::ptr::read_volatile(self.ptr.add(offset) as *const u16) }
    }

    fn write_u16(&self, offset: usize, value: u16) {
        assert!(offset + 2 <= self.size);
        unsafe { core::ptr::write_volatile(self.ptr.add(offset) as *mut u16, value) }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.size);
        unsafe { core::ptr::read_volatile(self.ptr.add(offset) as *const u32) }
    }

    fn write_u32(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= self.size);
        unsafe { core::ptr::write_volatile(self.ptr.add(offset) as *mut u32, value) }
    }

    fn read_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= self.size);
        unsafe { core::ptr::read_volatile(self.ptr.add(offset) as *const u64) }
    }

    fn write_u64(&self, offset: usize, value: u64) {
        assert!(offset + 8 <= self.size);
        unsafe { core::ptr::write_volatile(self.ptr.add(offset) as *mut u64, value) }
    }

    fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        assert!(offset + buf.len() <= self.size);
        unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len()) }
    }

    fn write_bytes(&self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.size);
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len()) }
    }

    fn fence(&self, ordering: Ordering) {
        std::sync::atomic::fence(ordering);
    }
}

/// QNX pulse-based doorbell.
///
/// On QNX, sends a pulse to the guest's channel via MsgSendPulse.
/// On other platforms, this is a no-op (for cross-compilation testing).
pub struct QnxPulseDoorbell {
    #[allow(dead_code)]
    coid: i32,
    #[allow(dead_code)]
    pulse_code: i8,
}

impl QnxPulseDoorbell {
    pub fn new(coid: i32, pulse_code: i8) -> Self {
        Self { coid, pulse_code }
    }

    #[cfg(target_os = "nto")]
    fn send_pulse(&self) -> Result<(), std::io::Error> {
        extern "C" {
            fn MsgSendPulse(
                coid: libc::c_int,
                priority: libc::c_int,
                code: libc::c_int,
                value: libc::c_int,
            ) -> libc::c_int;
        }
        let ret = unsafe { MsgSendPulse(self.coid, -1, self.pulse_code as i32, 0) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(not(target_os = "nto"))]
    fn send_pulse(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Doorbell for QnxPulseDoorbell {
    fn notify(&self) -> Result<(), TransportError> {
        self.send_pulse().map_err(TransportError::Io)
    }

    fn wait(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn try_wait(&self) -> Result<bool, TransportError> {
        Ok(false)
    }
}

/// No-op doorbell for cases where pulse notification is not needed.
pub struct NullDoorbell;

impl Doorbell for NullDoorbell {
    fn notify(&self) -> Result<(), TransportError> { Ok(()) }
    fn wait(&self) -> Result<(), TransportError> { Ok(()) }
    fn try_wait(&self) -> Result<bool, TransportError> { Ok(false) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shm_create_read_write() {
        let name = "/vm-devices-qnx-test";
        let shm = PosixSharedMemory::create(name, 4096).unwrap();
        shm.write_u32(0, 0xDEADBEEF);
        assert_eq!(shm.read_u32(0), 0xDEADBEEF);
        shm.write_u64(8, 0x1234567890ABCDEF);
        assert_eq!(shm.read_u64(8), 0x1234567890ABCDEF);
        drop(shm);
        let c_name = std::ffi::CString::new(name).unwrap();
        unsafe { libc::shm_unlink(c_name.as_ptr()) };
    }

    #[test]
    fn null_doorbell_is_noop() {
        let db = NullDoorbell;
        assert!(db.notify().is_ok());
        assert!(db.wait().is_ok());
        assert_eq!(db.try_wait().unwrap(), false);
    }
}
