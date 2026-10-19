//! The linear disassembly listing: every byte of the mapped image, in address order, as
//! function headers, labels, instructions, strings or raw data. Executable regions decode to
//! instructions; non-executable regions (`.rodata`, `.data`, …) show detected strings and
//! `db` data, so the listing covers the whole binary like IDA/Binary Ninja, not just code.

use orress_loaders::BinaryInfo;

use crate::Program;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// Start of a mapped region (section).
    Region,
    /// Blank separator plus the function name.
    Function,
    /// `loc_401020:` jump target inside a function.
    Label,
    Insn,
    /// Bytes that are not decoded code (`db` line), with their count.
    Data(u8),
    /// A detected, NUL-terminated ASCII string in a data region, with its byte length
    /// (including the terminator), capped at [`u16::MAX`].
    Str(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub addr: u64,
    pub kind: LineKind,
}

const DATA_PER_LINE: u64 = 8;
/// Shortest printable run (plus a NUL) shown as a string rather than `db` bytes.
const MIN_STRING: usize = 4;
/// Longest string scanned, so a pathological run cannot be unbounded.
const MAX_STRING: usize = 4096;

pub fn build(p: &Program, _info: &BinaryInfo) -> Vec<Line> {
    let mut lines = Vec::new();
    for region in &p.memory.regions {
        lines.push(Line {
            addr: region.start,
            kind: LineKind::Region,
        });
        let end = region.start.saturating_add(region.len);
        if region.executable {
            build_code(p, region.start, end, &mut lines);
        } else {
            build_data(p, region.start, end, &mut lines);
        }
    }
    lines
}

/// Walks an executable region, emitting function/label headers, instructions, and `db` runs
/// for undecoded bytes.
fn build_code(p: &Program, start: u64, end: u64, lines: &mut Vec<Line>) {
    let mut addr = start;
    while addr < end {
        if p.functions.contains_key(&addr) {
            lines.push(Line {
                addr,
                kind: LineKind::Function,
            });
        } else if p.labels.contains(&addr) {
            lines.push(Line {
                addr,
                kind: LineKind::Label,
            });
        }
        if let Some(&len) = p.insns.get(&addr) {
            lines.push(Line {
                addr,
                kind: LineKind::Insn,
            });
            addr += u64::from(len.max(1));
            continue;
        }
        // Data up to the next instruction or line boundary.
        let next_code = p.insns.range(addr + 1..).next().map_or(end, |(&a, _)| a);
        let aligned = (addr / DATA_PER_LINE + 1) * DATA_PER_LINE;
        let stop = next_code.min(aligned).min(end);
        lines.push(Line {
            addr,
            kind: LineKind::Data((stop - addr) as u8),
        });
        addr = stop;
    }
}

/// Walks a non-executable (data) region, emitting a string line for each detected
/// NUL-terminated ASCII run and `db` lines (bounded at a line boundary, and never crossing
/// into a string) for everything else.
fn build_data(p: &Program, start: u64, end: u64, lines: &mut Vec<Line>) {
    let mut addr = start;
    while addr < end {
        if let Some(len) = string_at(p, addr, end) {
            lines.push(Line {
                addr,
                kind: LineKind::Str(len),
            });
            addr += u64::from(len);
            continue;
        }
        // A `db` run up to the next line boundary, stopping early if a string begins within it
        // so the string renders on its own line.
        let mut stop = ((addr / DATA_PER_LINE + 1) * DATA_PER_LINE).min(end);
        let mut scan = addr + 1;
        while scan < stop {
            if string_at(p, scan, end).is_some() {
                stop = scan;
                break;
            }
            scan += 1;
        }
        lines.push(Line {
            addr,
            kind: LineKind::Data((stop - addr) as u8),
        });
        addr = stop;
    }
}

/// If a printable, NUL-terminated ASCII string of at least [`MIN_STRING`] characters starts at
/// `addr` (within `end`), returns its byte length including the terminator (capped at
/// [`u16::MAX`]). Otherwise `None`.
fn string_at(p: &Program, addr: u64, end: u64) -> Option<u16> {
    let max = ((end - addr) as usize).min(MAX_STRING);
    let bytes = p.memory.read(addr, max)?;
    let printable = bytes.iter().take_while(|&&b| is_text(b)).count();
    if printable >= MIN_STRING && bytes.get(printable) == Some(&0) {
        return Some(u16::try_from(printable + 1).unwrap_or(u16::MAX));
    }
    None
}

/// A byte shown as part of a string: printable ASCII, tab, newline or carriage return.
fn is_text(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r')
}

/// Index of the line showing `addr`: the last line starting at or before it. Header and
/// label lines come before the instruction at the same address, so this is the
/// instruction (or data) line.
pub fn find(lines: &[Line], addr: u64) -> Option<usize> {
    lines.partition_point(|l| l.addr <= addr).checked_sub(1)
}
