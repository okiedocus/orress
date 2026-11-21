//! The program's memory image as far as the file defines it: which addresses map to
//! which bytes, and which of them are code.

use std::sync::Arc;

use orress_loaders::{BinaryInfo, Format};

/// Page granularity of a mapped image. A loader maps whole pages, so a section's last page is
/// live memory past the section's own end.
const PAGE: u64 = 0x1000;

#[derive(Clone, Debug)]
pub struct Region {
    pub start: u64,
    pub file_offset: u64,
    /// How much of the address space this region covers — page-granular, so it includes the tail of
    /// the section's last page. In the real process that tail is readable, and a hand-crafted or
    /// packed binary can put code, even its entry point, there.
    pub len: u64,
    /// How much of `len` is backed by bytes in the file. The rest reads as zero in the process, and
    /// [`Memory::read`] stops there rather than handing back a neighbouring section's bytes.
    pub file_len: u64,
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
                // The section covers its own span rounded up to a page, because the loader maps
                // whole pages: the file-alignment padding past `virtual_size` and any zero tail are
                // live memory. Clamping this to `virtual_size` made an entry point sitting in that
                // tail read as "not code", which stopped function discovery before it began and
                // left the binary with ZERO functions — nothing downstream could analyse it at all.
                // Overlap with the next section is trimmed below.
                len: if s.virtual_size > 0 {
                    s.virtual_size.max(s.file_size).next_multiple_of(PAGE)
                } else {
                    s.file_size.next_multiple_of(PAGE)
                },
                // Raw data, rounded up with the page below: the mapping is page-granular over
                // the FILE as well, so a section's last file page is readable past its declared
                // raw size — which is where a packer's entry point often sits. Clamped to the
                // file's real length below.
                file_len: s.file_size,
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
                    file_len: s.file_size,
                    executable: s.perms.execute,
                    name: s
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("segment_{:x}", s.address)),
                })
                .collect();
        }
        let size = data.len() as u64;
        // Extend each region's file-backed part to its page, then clamp it to the bytes the file
        // actually has. A declared raw size is often unaligned (packers especially), yet the loader
        // maps whole pages of the file, so those extra bytes are real memory — and clamping here
        // rather than dropping the region keeps a section with a short or overlong header usable.
        for r in &mut regions {
            let available = size.saturating_sub(r.file_offset);
            r.file_len = r.file_len.next_multiple_of(PAGE).min(r.len).min(available);
        }
        // Drop regions whose file offset is outside the data, or whose address range wraps past the
        // top of the address space (a malformed header), so `start + len` never overflows later.
        regions.retain(|r| {
            r.file_offset < size && r.file_len > 0 && r.start.checked_add(r.len).is_some()
        });
        regions.sort_by_key(|r| r.start);
        // Trim any region that would now run into the next one: raw data is file-aligned and can be
        // longer than the gap between two sections' virtual addresses, and overlapping regions
        // would make an address resolve to the wrong bytes.
        for i in 0..regions.len().saturating_sub(1) {
            let next_start = regions[i + 1].start;
            let end = regions[i].start.saturating_add(regions[i].len);
            if end > next_start {
                regions[i].len = next_start.saturating_sub(regions[i].start);
                regions[i].file_len = regions[i].file_len.min(regions[i].len);
            }
        }
        regions.retain(|r| r.len > 0);
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

    /// Up to `len` bytes at `addr`, stopping at the end of the region's **file-backed** part.
    /// `None` past it: those addresses are mapped but hold zeros in the real process, and handing
    /// back what follows in the file would be a neighbouring section's data.
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let r = self.region(addr)?;
        let skip = addr - r.start;
        let available = r.file_len.checked_sub(skip)? as usize;
        if available == 0 {
            return None;
        }
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
