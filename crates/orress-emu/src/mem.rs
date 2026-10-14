//! Sparse paged guest memory. Pages are allocated only by the *loader* paths
//! ([`Memory::write_bytes`] / [`Memory::map_zeroed`]); guest reads and writes
//! ([`Memory::read`] / [`Memory::write`] / [`Memory::write_u8`] / [`Memory::write_slice`]) are
//! little-endian, may cross page boundaries, and fault on an unmapped page — so a null or wild
//! pointer write is caught instead of silently allocating (a striding write loop could otherwise
//! allocate gigabytes of host memory).

use std::collections::HashMap;

use crate::EmuError;

const PAGE_BITS: u64 = 12;
const PAGE_SIZE: usize = 1 << PAGE_BITS;
const PAGE_MASK: u64 = (PAGE_SIZE as u64) - 1;

/// Sparse guest address space, one 4 KiB page at a time.
#[derive(Default, Clone)]
pub struct Memory {
    pages: HashMap<u64, Box<[u8; PAGE_SIZE]>>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    fn page_mut(&mut self, page: u64) -> &mut [u8; PAGE_SIZE] {
        self.pages
            .entry(page)
            .or_insert_with(|| Box::new([0u8; PAGE_SIZE]))
    }

    /// Maps `bytes` at `addr`, allocating pages as needed (used to load code/data/stack).
    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let a = addr.wrapping_add(i as u64);
            self.page_mut(a >> PAGE_BITS)[(a & PAGE_MASK) as usize] = b;
        }
    }

    /// Reserves a zero-filled region (e.g. a stack), so reads there don't fault.
    pub fn map_zeroed(&mut self, addr: u64, len: u64) {
        let first = addr >> PAGE_BITS;
        let last = (addr.wrapping_add(len.saturating_sub(1))) >> PAGE_BITS;
        for page in first..=last {
            self.page_mut(page);
        }
    }

    /// Whether `addr` is in an allocated page.
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.pages.contains_key(&(addr >> PAGE_BITS))
    }

    pub fn read_u8(&self, addr: u64) -> Result<u8, EmuError> {
        self.pages
            .get(&(addr >> PAGE_BITS))
            .map(|p| p[(addr & PAGE_MASK) as usize])
            .ok_or(EmuError::Fault(addr))
    }

    /// Guest write of one byte; faults on an unmapped page (it never allocates).
    pub fn write_u8(&mut self, addr: u64, val: u8) -> Result<(), EmuError> {
        let page = self
            .pages
            .get_mut(&(addr >> PAGE_BITS))
            .ok_or(EmuError::Fault(addr))?;
        page[(addr & PAGE_MASK) as usize] = val;
        Ok(())
    }

    /// Guest write of a byte slice (e.g. a `memcpy` stub). All-or-nothing: if any byte falls on
    /// an unmapped page it faults at the first such address and writes nothing.
    pub fn write_slice(&mut self, addr: u64, bytes: &[u8]) -> Result<(), EmuError> {
        if let Some(bad) = (0..bytes.len() as u64)
            .map(|i| addr.wrapping_add(i))
            .find(|&a| !self.is_mapped(a))
        {
            return Err(EmuError::Fault(bad));
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u64), b)?;
        }
        Ok(())
    }

    /// Reads a little-endian value of `size` (1/2/4/8) bytes.
    pub fn read(&self, addr: u64, size: usize) -> Result<u64, EmuError> {
        let mut val: u64 = 0;
        for i in 0..size as u64 {
            val |= u64::from(self.read_u8(addr.wrapping_add(i))?) << (8 * i);
        }
        Ok(val)
    }

    /// Writes the low `size` (1/2/4/8) bytes of `val`, little-endian.
    /// Faults (writing nothing) if any byte is unmapped.
    pub fn write(&mut self, addr: u64, val: u64, size: usize) -> Result<(), EmuError> {
        if let Some(bad) = (0..size as u64)
            .map(|i| addr.wrapping_add(i))
            .find(|&a| !self.is_mapped(a))
        {
            return Err(EmuError::Fault(bad));
        }
        for i in 0..size as u64 {
            self.write_u8(addr.wrapping_add(i), (val >> (8 * i)) as u8)?;
        }
        Ok(())
    }

    /// Reads `len` bytes into a `Vec` (for pulling a result buffer back out after a run).
    pub fn read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmuError> {
        (0..len as u64)
            .map(|i| self.read_u8(addr.wrapping_add(i)))
            .collect()
    }
}
