//! The program's memory image as far as the file defines it: which addresses map to
//! which bytes, and which of them are code.

use std::sync::Arc;

use orress_loaders::{BinaryInfo, Format};

#[derive(Clone, Debug)]
pub struct Region {
    pub start: u64,
    pub file_offset: u64,
    pub len: u64,
    pub executable: bool,
    pub name: String,
}

#[derive(Clone)]
pub struct Memory {
    data: Arc<Vec<u8>>,
    /// Sorted by start address.
    pub regions: Vec<Region>,
    pub is_elf: bool,
}

impl Memory {
    pub fn new(info: &BinaryInfo, data: Arc<Vec<u8>>) -> Self {
        let mut regions: Vec<Region> = info
            .sections
            .iter()
            .filter(|s| s.file_size > 0 && s.address != 0)
            .map(|s| Region {
                start: s.address,
                file_offset: s.offset,
                // Raw data past the virtual size (PE file-alignment padding) is not mapped; a zero
                // virtual size means "unknown", so the file size stands.
                len: if s.virtual_size > 0 {
                    s.file_size.min(s.virtual_size)
                } else {
                    s.file_size
                },
                executable: s.perms.execute,
                name: s.name.clone(),
            })
            .collect();
        // ELF files without section headers: fall back to the loadable segments.
        if regions.is_empty() {
            regions = info
                .segments
                .iter()
                .filter(|s| s.file_size > 0)
                .map(|s| Region {
                    start: s.address,
                    file_offset: s.offset,
                    len: s.file_size,
                    executable: s.perms.execute,
                    name: s
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("segment_{:x}", s.address)),
                })
                .collect();
        }
        let size = data.len() as u64;
        // Drop regions whose file range runs past the data, or whose address range wraps past the
        // top of the address space (a malformed header), so `start + len` never overflows later.
        regions.retain(|r| {
            r.file_offset
                .checked_add(r.len)
                .is_some_and(|end| end <= size)
                && r.start.checked_add(r.len).is_some()
        });
        regions.sort_by_key(|r| r.start);
        Self {
            data,
            regions,
            is_elf: info.format == Format::Elf,
        }
    }

    pub fn region(&self, addr: u64) -> Option<&Region> {
        let i = self.regions.partition_point(|r| r.start <= addr);
        let r = self.regions.get(i.checked_sub(1)?)?;
        (addr - r.start < r.len).then_some(r)
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.region(addr).is_some()
    }

    pub fn is_code(&self, addr: u64) -> bool {
        self.region(addr).is_some_and(|r| r.executable)
    }

    /// Up to `len` bytes at `addr`, stopping at the end of the region.
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let r = self.region(addr)?;
        let skip = addr - r.start;
        let available = (r.len - skip) as usize;
        let start = (r.file_offset + skip) as usize;
        self.data.get(start..start + len.min(available))
    }

    pub fn offset_of(&self, addr: u64) -> Option<u64> {
        let r = self.region(addr)?;
        Some(r.file_offset + (addr - r.start))
    }

    pub fn address_of(&self, offset: u64) -> Option<u64> {
        self.regions
            .iter()
            .find(|r| offset >= r.file_offset && offset - r.file_offset < r.len)
            .map(|r| r.start + (offset - r.file_offset))
    }
}
