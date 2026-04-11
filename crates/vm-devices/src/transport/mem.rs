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
