use crate::error::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait representing a buffer holding sensitive secrets in memory.
pub trait LockedBuffer: Zeroize {
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn wipe(&mut self) {
        self.zeroize();
    }
}

/// Buffer with OS-level memory locking (`mlock`) and exclusion from core dumps (`MADV_DONTDUMP`).
#[derive(Debug)]
pub struct MemLockedBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl MemLockedBuffer {
    /// Creates a new locked buffer from a byte slice.
    pub fn new(source: &[u8]) -> Result<Self, CryptoError> {
        let mut data = source.to_vec();
        let len = data.len();

        if len == 0 {
            return Ok(Self {
                data,
                locked: false,
            });
        }

        // Lock memory pages and mark DONTDUMP
        let ptr = data.as_mut_ptr() as *mut core::ffi::c_void;
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let _ = rustix::mm::mlock(ptr, len);
                let _ = rustix::mm::madvise(ptr, len, rustix::mm::Advice::LinuxDontDump);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            unsafe {
                let _ = rustix::mm::mlock(ptr, len);
            }
        }

        Ok(Self { data, locked: true })
    }

    /// Creates an empty buffer with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Result<Self, CryptoError> {
        let data = vec![0u8; capacity];
        Self::new(&data)
    }
}

impl LockedBuffer for MemLockedBuffer {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn wipe(&mut self) {
        self.data.as_mut_slice().zeroize();
    }
}

impl Zeroize for MemLockedBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for MemLockedBuffer {
    fn drop(&mut self) {
        if self.locked && !self.data.is_empty() {
            let ptr = self.data.as_mut_ptr() as *mut core::ffi::c_void;
            unsafe {
                let _ = rustix::mm::munlock(ptr, self.data.len());
            }
        }
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for MemLockedBuffer {}

/// Regular memory buffer with secure wipe on drop (parity with `useMemguard=false`).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MemoryBuffer {
    data: Vec<u8>,
}

impl MemoryBuffer {
    pub fn new(source: &[u8]) -> Self {
        Self {
            data: source.to_vec(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
        }
    }
}

impl LockedBuffer for MemoryBuffer {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn wipe(&mut self) {
        self.data.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_buffer_wipe() {
        let secret = b"super_secret_master_password";
        let mut buf = MemoryBuffer::new(secret);
        assert_eq!(buf.as_slice(), secret);
        assert_eq!(buf.len(), secret.len());
        assert!(!buf.is_empty());

        buf.wipe();
        assert_eq!(buf.as_slice(), vec![0u8; secret.len()].as_slice());
    }

    #[test]
    fn test_mem_locked_buffer_lifecycle() {
        let secret = b"another_sensitive_pin_123456";
        let mut locked = MemLockedBuffer::new(secret).expect("Failed to create locked buffer");
        assert_eq!(locked.as_slice(), secret);
        assert_eq!(locked.len(), secret.len());

        locked.wipe();
        assert_eq!(locked.as_slice(), vec![0u8; secret.len()].as_slice());
    }

    #[test]
    fn test_empty_buffers() {
        let mut empty = MemLockedBuffer::new(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        empty.wipe();
    }
}
