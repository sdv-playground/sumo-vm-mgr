//! In-memory shared memory backend for tests.

use std::sync::atomic::{AtomicU8, Ordering};

use super::{Doorbell, SharedMemory, TransportError};

/// Heap-backed shared memory for unit tests.
pub struct MemSharedMemory {
    data: Vec<AtomicU8>,
}

impl MemSharedMemory {
    pub fn new(size: usize) -> Self {
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            data.push(AtomicU8::new(0));
        }
        Self { data }
    }
}

impl SharedMemory for MemSharedMemory {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn read_u16(&self, offset: usize) -> u16 {
        let b0 = self.data[offset].load(Ordering::Relaxed);
        let b1 = self.data[offset + 1].load(Ordering::Relaxed);
        u16::from_le_bytes([b0, b1])
    }

    fn write_u16(&self, offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        self.data[offset].store(bytes[0], Ordering::Relaxed);
        self.data[offset + 1].store(bytes[1], Ordering::Relaxed);
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut buf = [0u8; 4];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[offset + i].load(Ordering::Relaxed);
        }
        u32::from_le_bytes(buf)
    }

    fn write_u32(&self, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            self.data[offset + i].store(*b, Ordering::Relaxed);
        }
    }

    fn read_u64(&self, offset: usize) -> u64 {
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[offset + i].load(Ordering::Relaxed);
        }
        u64::from_le_bytes(buf)
    }

    fn write_u64(&self, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            self.data[offset + i].store(*b, Ordering::Relaxed);
        }
    }

    fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[offset + i].load(Ordering::Relaxed);
        }
    }

    fn write_bytes(&self, offset: usize, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.data[offset + i].store(*b, Ordering::Relaxed);
        }
    }

    fn fence(&self, ordering: Ordering) {
        std::sync::atomic::fence(ordering);
    }
}

/// No-op doorbell for tests.
pub struct MemDoorbell;

impl Doorbell for MemDoorbell {
    fn notify(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn wait(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn try_wait(&self) -> Result<bool, TransportError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_matches_constructor_size() {
        let shm = MemSharedMemory::new(128);
        assert_eq!(shm.len(), 128);
    }

    #[test]
    fn u16_roundtrip_little_endian() {
        let shm = MemSharedMemory::new(16);
        shm.write_u16(0, 0xABCD);
        assert_eq!(shm.read_u16(0), 0xABCD);
        // Low byte first (LE)
        let mut raw = [0u8; 2];
        shm.read_bytes(0, &mut raw);
        assert_eq!(raw, [0xCD, 0xAB]);
    }

    #[test]
    fn u32_roundtrip_little_endian() {
        let shm = MemSharedMemory::new(16);
        shm.write_u32(4, 0xDEAD_BEEF);
        assert_eq!(shm.read_u32(4), 0xDEAD_BEEF);
        let mut raw = [0u8; 4];
        shm.read_bytes(4, &mut raw);
        assert_eq!(raw, [0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn u64_roundtrip_little_endian() {
        let shm = MemSharedMemory::new(16);
        shm.write_u64(0, 0x0123_4567_89AB_CDEF);
        assert_eq!(shm.read_u64(0), 0x0123_4567_89AB_CDEF);
        let mut raw = [0u8; 8];
        shm.read_bytes(0, &mut raw);
        assert_eq!(raw, [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]);
    }

    #[test]
    fn i64_roundtrip_preserves_sign() {
        let shm = MemSharedMemory::new(16);
        shm.write_i64(0, -42);
        assert_eq!(shm.read_i64(0), -42);
        shm.write_i64(0, i64::MIN);
        assert_eq!(shm.read_i64(0), i64::MIN);
    }

    #[test]
    fn read_bytes_write_bytes_roundtrip() {
        let shm = MemSharedMemory::new(32);
        let payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
        shm.write_bytes(8, &payload);
        let mut out = [0u8; 8];
        shm.read_bytes(8, &mut out);
        assert_eq!(out, payload);
    }

    #[test]
    fn adjacent_writes_do_not_overlap() {
        let shm = MemSharedMemory::new(16);
        shm.write_u32(0, 0x1111_1111);
        shm.write_u32(4, 0x2222_2222);
        assert_eq!(shm.read_u32(0), 0x1111_1111);
        assert_eq!(shm.read_u32(4), 0x2222_2222);
    }

    #[test]
    fn new_memory_starts_zeroed() {
        let shm = MemSharedMemory::new(32);
        for i in 0..32 {
            let mut b = [0xFFu8; 1];
            shm.read_bytes(i, &mut b);
            assert_eq!(b[0], 0, "byte {i} not zero-initialized");
        }
    }

    #[test]
    fn doorbell_notify_wait_are_noops() {
        let db = MemDoorbell;
        // Notify and try_wait never block or error in the test impl.
        db.notify().unwrap();
        assert!(!db.try_wait().unwrap());
    }
}
