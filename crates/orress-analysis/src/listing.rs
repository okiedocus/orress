//! The linear disassembly listing: every byte of the executable regions, in address
//! order, as function headers, labels, instructions or raw data.

use orress_loaders::BinaryInfo;

use crate::Program;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// Start of an executable region.
    Region,
    /// Blank separator plus the function name.
    Function,
    /// `loc_401020:` jump target inside a function.
    Label,
    Insn,
    /// Bytes that are not decoded code (`db` line), with their count.
    Data(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub addr: u64,
    pub kind: LineKind,
}

const DATA_PER_LINE: u64 = 8;

pub fn build(p: &Program, _info: &BinaryInfo) -> Vec<Line> {
    let mut lines = Vec::new();
    for region in p.memory.regions.iter().filter(|r| r.executable) {
        lines.push(Line {
            addr: region.start,
            kind: LineKind::Region,
        });
        let end = region.start.saturating_add(region.len);
        let mut addr = region.start;
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
    lines
}

/// Index of the line showing `addr`: the last line starting at or before it. Header and
/// label lines come before the instruction at the same address, so this is the
/// instruction (or data) line.
pub fn find(lines: &[Line], addr: u64) -> Option<usize> {
    lines.partition_point(|l| l.addr <= addr).checked_sub(1)
}
