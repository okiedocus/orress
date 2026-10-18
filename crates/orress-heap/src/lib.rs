//! A glibc (ptmalloc) heap parser for 64-bit targets. Given a memory snapshot — the `[heap]`
//! region's bytes, and optionally the `main_arena` bytes — it walks the malloc chunks and the
//! free lists (tcache, fastbins, unsorted/small/large bins). Pure logic: no process and no OS, so
//! it is fully unit-testable; the live Heap view reads the bytes from the debugger and calls in.
//!
//! Assumptions (the common modern case, matching nightmare's challenges): little-endian x86-64,
//! glibc >= 2.30 for the tcache layout (`uint16_t counts[64]`), and glibc >= 2.27 for the
//! `malloc_state` layout (a `have_fastchunks` word before `fastbinsY`). `mangled` selects
//! safe-linking (glibc >= 2.32), which XORs free-list `fd` pointers with `pos >> 12`.

use std::collections::HashSet;

/// Chunk header flag bits (the low 3 bits of the `size` field).
const PREV_INUSE: u64 = 1;
const IS_MMAPPED: u64 = 2;
const NON_MAIN_ARENA: u64 = 4;
/// Smallest real chunk; anything below this ends the walk.
const MIN_CHUNK: u64 = 0x20;
/// Number of tcache / fastbin bins.
const TCACHE_BINS: usize = 64;
const FASTBINS: usize = 10;
/// `malloc_state` field offsets (glibc >= 2.27, x86-64): fastbinsY, then bins.
const FASTBINSY_OFF: usize = 0x10;
const BINS_OFF: usize = 0x70;
/// Guard against runaway walks / cyclic free lists.
const MAX_CHUNKS: usize = 200_000;
const MAX_LIST: usize = 4000;

/// A single malloc chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub addr: u64,
    /// Total chunk size in bytes (flag bits masked off).
    pub size: u64,
    pub prev_inuse: bool,
    pub is_mmapped: bool,
    pub non_main_arena: bool,
    /// Whether the chunk is allocated (the next chunk's PREV_INUSE bit is set).
    pub in_use: bool,
    /// For a free chunk, its `fd`/`bk` (0 for an allocated chunk).
    pub fd: u64,
    pub bk: u64,
}

/// Which free list a [`Bin`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinKind {
    Tcache,
    Fastbin,
    Unsorted,
    Small,
    Large,
}

impl BinKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcache => "tcache",
            Self::Fastbin => "fastbin",
            Self::Unsorted => "unsorted",
            Self::Small => "small",
            Self::Large => "large",
        }
    }
}

/// One free list: its kind, index, the chunk size it holds (when fixed), and the chunk addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bin {
    pub kind: BinKind,
    pub index: usize,
    pub size: Option<u64>,
    /// Chunk header addresses on the list, in list order.
    pub entries: Vec<u64>,
}

/// A parsed heap.
#[derive(Clone, Debug, Default)]
pub struct Heap {
    pub chunks: Vec<Chunk>,
    pub bins: Vec<Bin>,
    pub notes: Vec<String>,
}

fn rd_u64(bytes: &[u8], off: usize) -> u64 {
    bytes
        .get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Reads a u64 at an absolute address from a region starting at `base`, if in range.
fn read_at(bytes: &[u8], base: u64, addr: u64) -> Option<u64> {
    let off = addr.checked_sub(base)? as usize;
    bytes
        .get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// Walks the chunks of a heap region linearly from `heap_base`.
pub fn walk_chunks(heap: &[u8], heap_base: u64) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 16 <= heap.len() && out.len() < MAX_CHUNKS {
        let raw_size = rd_u64(heap, off + 8);
        let size = raw_size & !0x7;
        if size < MIN_CHUNK {
            break;
        }
        let next_off = off + size as usize;
        let in_use = if next_off + 16 <= heap.len() {
            rd_u64(heap, next_off + 8) & PREV_INUSE != 0
        } else {
            true // the top chunk (last) is treated as in use
        };
        let (fd, bk) = (rd_u64(heap, off + 16), rd_u64(heap, off + 24));
        out.push(Chunk {
            addr: heap_base + off as u64,
            size,
            prev_inuse: raw_size & PREV_INUSE != 0,
            is_mmapped: raw_size & IS_MMAPPED != 0,
            non_main_arena: raw_size & NON_MAIN_ARENA != 0,
            in_use,
            fd: if in_use { 0 } else { fd },
            bk: if in_use { 0 } else { bk },
        });
        if next_off <= off {
            break;
        }
        off = next_off;
    }
    out
}

/// Follows a singly-linked free list (tcache / fastbin) from `head`, reading the next pointer at
/// each node's `fd` and de-mangling under safe-linking. `user_offset` is where the `fd` lives
/// relative to the node value (0 for tcache entries, which point at user data; 16 for fastbins,
/// which point at the chunk header). Returns chunk header addresses.
fn follow_singly(
    heap: &[u8],
    heap_base: u64,
    head: u64,
    chunk_from_node: u64,
    fd_offset: u64,
    mangled: bool,
) -> Vec<u64> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut node = head;
    while node != 0 && entries.len() < MAX_LIST && seen.insert(node) {
        entries.push(node.wrapping_sub(chunk_from_node));
        let fd_addr = node + fd_offset;
        let Some(raw) = read_at(heap, heap_base, fd_addr) else {
            break;
        };
        node = if mangled { raw ^ (fd_addr >> 12) } else { raw };
    }
    entries
}

/// Parses the tcache bins from the tcache_perthread_struct (the first chunk of the heap).
pub fn parse_tcache(heap: &[u8], heap_base: u64, mangled: bool) -> Vec<Bin> {
    let counts_off = 16usize; // user data of the first chunk
    let entries_off = counts_off + TCACHE_BINS * 2; // uint16_t counts[64] (glibc >= 2.30)
    let mut bins = Vec::new();
    for i in 0..TCACHE_BINS {
        let head = rd_u64(heap, entries_off + i * 8);
        if head == 0 {
            continue;
        }
        // tcache entries point at user data; the chunk header is 16 bytes earlier.
        let entries = follow_singly(heap, heap_base, head, 16, 0, mangled);
        if entries.is_empty() {
            continue;
        }
        bins.push(Bin {
            kind: BinKind::Tcache,
            index: i,
            size: Some(0x20 + i as u64 * 0x10),
            entries,
        });
    }
    bins
}

/// Parses the fastbins from `main_arena`.
pub fn parse_fastbins(arena: &[u8], heap: &[u8], heap_base: u64, mangled: bool) -> Vec<Bin> {
    let mut bins = Vec::new();
    for i in 0..FASTBINS {
        let head = rd_u64(arena, FASTBINSY_OFF + i * 8);
        if head == 0 {
            continue;
        }
        // fastbin pointers reference the chunk header; the `fd` is at chunk+16.
        let entries = follow_singly(heap, heap_base, head, 0, 16, mangled);
        if entries.is_empty() {
            continue;
        }
        bins.push(Bin {
            kind: BinKind::Fastbin,
            index: i,
            size: Some(0x20 + i as u64 * 0x10),
            entries,
        });
    }
    bins
}

/// Parses the unsorted/small/large bins from `main_arena` (circular doubly-linked lists whose
/// heads live in the arena; chunks link via `fd`).
pub fn parse_arena_bins(arena: &[u8], arena_addr: u64, heap: &[u8], heap_base: u64) -> Vec<Bin> {
    let mut out = Vec::new();
    for k in 1..=127usize {
        let fd_off = BINS_OFF + (2 * k - 2) * 8;
        let head_fd = rd_u64(arena, fd_off);
        // A bin's head acts as a fake chunk whose fd/bk are at +16/+24.
        let bin_chunk = arena_addr + fd_off as u64 - 16;
        if head_fd == 0 || head_fd == bin_chunk {
            continue; // empty bin points to itself
        }
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let mut node = head_fd;
        while node != 0 && node != bin_chunk && entries.len() < MAX_LIST && seen.insert(node) {
            entries.push(node);
            match read_at(heap, heap_base, node + 16) {
                Some(next) => node = next,
                None => break,
            }
        }
        if entries.is_empty() {
            continue;
        }
        let kind = match k {
            1 => BinKind::Unsorted,
            2..=63 => BinKind::Small,
            _ => BinKind::Large,
        };
        out.push(Bin {
            kind,
            index: k,
            size: None,
            entries,
        });
    }
    out
}

/// Parses a whole heap: chunks + tcache, plus the arena bins when the arena snapshot is given.
pub fn parse(heap: &[u8], heap_base: u64, arena: Option<(&[u8], u64)>, mangled: bool) -> Heap {
    let chunks = walk_chunks(heap, heap_base);
    let mut bins = parse_tcache(heap, heap_base, mangled);
    let mut notes = Vec::new();
    match arena {
        Some((abytes, aaddr)) => {
            bins.extend(parse_fastbins(abytes, heap, heap_base, mangled));
            bins.extend(parse_arena_bins(abytes, aaddr, heap, heap_base));
        }
        None => notes.push(
            "main_arena not located — fastbins and unsorted/small/large bins are not shown \
             (chunks and tcache only)."
                .into(),
        ),
    }
    Heap {
        chunks,
        bins,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little builder for a synthetic heap region.
    struct Builder {
        base: u64,
        bytes: Vec<u8>,
    }
    impl Builder {
        fn new(base: u64) -> Self {
            Self {
                base,
                bytes: Vec::new(),
            }
        }
        fn put_u64(&mut self, off: usize, v: u64) {
            if self.bytes.len() < off + 8 {
                self.bytes.resize(off + 8, 0);
            }
            self.bytes[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        fn put_u16(&mut self, off: usize, v: u16) {
            if self.bytes.len() < off + 2 {
                self.bytes.resize(off + 2, 0);
            }
            self.bytes[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
    }

    #[test]
    fn walks_allocated_and_free_chunks() {
        // Three 0x20 chunks, the middle one free (its next chunk clears PREV_INUSE).
        let mut b = Builder::new(0x5000);
        // chunk0 @ off 0, size 0x20, prev_inuse set
        b.put_u64(8, 0x20 | PREV_INUSE);
        // chunk1 @ 0x20, size 0x20, prev_inuse set
        b.put_u64(0x20 + 8, 0x20 | PREV_INUSE);
        // chunk2 @ 0x40, size 0x20, PREV_INUSE cleared -> chunk1 is free
        b.put_u64(0x40 + 8, 0x20);
        // top @ 0x60
        b.put_u64(0x60 + 8, 0x20 | PREV_INUSE);
        b.put_u64(0x80 + 8, 0); // terminate

        let chunks = walk_chunks(&b.bytes, b.base);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].addr, 0x5000);
        assert_eq!(chunks[0].size, 0x20);
        assert!(chunks[0].in_use);
        assert!(!chunks[1].in_use, "middle chunk is free");
    }

    #[test]
    fn tcache_list_unmangled_and_mangled() {
        // Two chunks past the tcache struct; tcache bin 0 links them (user data = chunk+16).
        let base = 0x5000u64;
        let (c0, c1) = (0x5300u64, 0x5380u64);
        let (u0, u1) = (c0 + 16, c1 + 16);
        let mut b = Builder::new(base);
        // tcache struct: counts[64] u16 at off16, entries[64] at off 16+128.
        let entries_off = 16 + 64 * 2;
        b.put_u16(16, 2); // counts[0] = 2 (cosmetic)
        b.put_u64(entries_off, u0); // entries[0] -> first user data
        b.put_u64((u0 - base) as usize, u1); // first.fd -> second
        b.put_u64((u1 - base) as usize, 0); // second.fd -> NULL
        let bins = parse_tcache(&b.bytes, base, false);
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].entries, vec![c0, c1]);

        // Mangled (safe-linking): store fd ^ (fd_addr >> 12).
        let mut m = Builder::new(base);
        m.put_u64(entries_off, u0);
        m.put_u64((u0 - base) as usize, u1 ^ (u0 >> 12));
        m.put_u64((u1 - base) as usize, 0 ^ (u1 >> 12));
        let bins = parse_tcache(&m.bytes, base, true);
        assert_eq!(bins[0].entries, vec![c0, c1]);
    }

    #[test]
    fn fastbin_list_from_arena() {
        let base = 0x5000u64;
        let arena_addr = 0x7f0000u64;
        let (c0, c1) = (0x5100u64, 0x5200u64);
        let mut heap = Builder::new(base);
        heap.put_u64((c0 - base) as usize + 16, c1); // c0.fd -> c1
        heap.put_u64((c1 - base) as usize + 16, 0); // c1.fd -> NULL
        let mut arena = Builder::new(arena_addr);
        arena.put_u64(FASTBINSY_OFF, c0); // fastbinsY[0] -> c0
        let bins = parse_fastbins(&arena.bytes, &heap.bytes, base, false);
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].entries, vec![c0, c1]);
    }

    #[test]
    fn unsorted_bin_circular_walk() {
        let base = 0x5000u64;
        let arena_addr = 0x7f0000u64;
        let c0 = 0x5100u64;
        let fd_off = BINS_OFF; // bin 1 (unsorted) fd
        let bin_chunk = arena_addr + fd_off as u64 - 16;
        let mut arena = Builder::new(arena_addr);
        arena.put_u64(fd_off, c0); // unsorted.fd -> c0
        let mut heap = Builder::new(base);
        heap.put_u64((c0 - base) as usize + 16, bin_chunk); // c0.fd -> back to bin head
        let bins = parse_arena_bins(&arena.bytes, arena_addr, &heap.bytes, base);
        let unsorted: Vec<_> = bins.iter().filter(|b| b.kind == BinKind::Unsorted).collect();
        assert_eq!(unsorted.len(), 1);
        assert_eq!(unsorted[0].entries, vec![c0]);
    }

    #[test]
    fn cycle_guard_terminates() {
        // A self-referential tcache entry must not loop forever.
        let base = 0x5000u64;
        let c0 = 0x5300u64;
        let u0 = c0 + 16;
        let entries_off = 16 + 64 * 2;
        let mut b = Builder::new(base);
        b.put_u64(entries_off, u0);
        b.put_u64((u0 - base) as usize, u0); // points to itself
        let bins = parse_tcache(&b.bytes, base, false);
        assert_eq!(bins[0].entries, vec![c0]); // visited once, then stops
    }
}
