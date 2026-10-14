//! Register dataflow queries over a function's instructions, built on orress-arch's per-instruction
//! register effects ([`orress_arch::reg_info`]).
//!
//! The current analysis is single-static-definition: if a register is defined exactly once in a
//! function, that definition reaches every use, so a loop-invariant pointer (such as a hoisted
//! `lea` of a jump-table or bytecode base) resolves soundly to the constant it holds. This is the
//! foundation a fuller reaching-definitions analysis would extend.

use std::collections::{HashMap, HashSet};

use orress_arch::{Flow, MemRef, Reg, RegInfo};

use crate::{Function, Program};

/// Registers a call may clobber: the union of the SysV (rax, rcx, rdx, rsi, rdi, r8-r11) and
/// Win64 (rax, rcx, rdx, r8-r11) caller-saved sets, so the analysis stays sound under either ABI.
const CALL_CLOBBERED: [Reg; 9] = [0, 1, 2, 6, 7, 8, 9, 10, 11];

impl Program {
    /// Structured register effects of the instruction at `addr`.
    pub fn reg_info(&self, addr: u64) -> Option<RegInfo> {
        let bytes = self.memory.read(addr, self.isa.max_len())?;
        orress_arch::reg_info(self.isa, bytes, addr)
    }

    /// [`Self::reg_info`] for dataflow: a call also defines every caller-saved register (the
    /// decoder only reports the registers the `call` instruction itself touches).
    fn dataflow_info(&self, addr: u64) -> Option<RegInfo> {
        let mut info = self.reg_info(addr)?;
        let is_call = self
            .memory
            .read(addr, self.isa.max_len())
            .and_then(|bytes| orress_arch::decode(self.isa, bytes, addr))
            .is_some_and(|i| matches!(i.flow, Flow::Call(_) | Flow::IndirectCall { .. }));
        if is_call {
            for r in CALL_CLOBBERED {
                if !info.defs.contains(&r) {
                    info.defs.push(r);
                }
            }
        }
        Some(info)
    }

    /// The memory operand at `addr`, if the instruction has one.
    pub fn mem_ref(&self, addr: u64) -> Option<MemRef> {
        self.reg_info(addr)?.mem
    }

    /// If register `reg` has exactly one definition in `func` and that definition is
    /// `lea reg, [rip+X]`, returns `X`. A single static definition reaches every use, so this
    /// soundly resolves a loop-invariant base register (a hoisted table or bytecode pointer) to
    /// its constant address; a register written more than once (e.g. a loop counter) returns `None`.
    pub fn register_const(&self, func: &Function, reg: u8) -> Option<u64> {
        let mut defs = 0usize;
        let mut addr = None;
        for block in &func.blocks {
            for &a in &block.insns {
                let Some(info) = self.dataflow_info(a) else {
                    continue;
                };
                if info.defs.contains(&reg) {
                    defs += 1;
                    addr = info.lea_const.and_then(|(d, x)| (d == reg).then_some(x));
                }
            }
        }
        (defs == 1).then_some(addr).flatten()
    }

    /// The smallest address referenced as data anywhere in the program that is strictly greater
    /// than `after` — i.e. where the datum starting at `after` ends, bounded by the next referenced
    /// one. Used to size a blob (a jump table, a bytecode array) without a length in the code.
    pub fn next_data_ref(&self, after: u64) -> Option<u64> {
        self.data_refs
            .range(after.checked_add(1)?..)
            .next()
            .copied()
    }

    /// Reaching-definition variant of [`Self::register_const`]: if every definition of `reg` that
    /// can reach the instruction at `use_addr` is the same `lea reg, [rip+X]`, returns `X`.
    ///
    /// Unlike the whole-function version this ignores definitions that cannot reach the use — e.g.
    /// a base register reloaded with junk only on error/panic paths that lead to `exit`, never back
    /// to the use. A definition reaches the use if its block can reach the use's block in the CFG.
    pub fn register_const_at(&self, func: &Function, use_addr: u64, reg: u8) -> Option<u64> {
        let use_block = func
            .blocks
            .iter()
            .find(|b| b.insns.contains(&use_addr))?
            .start;
        let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
        for b in &func.blocks {
            for e in &b.succs {
                preds.entry(e.target).or_default().push(b.start);
            }
        }
        // Blocks that can reach the use (its predecessors, transitively) plus the use's own block.
        let mut reachers = HashSet::from([use_block]);
        let mut stack = vec![use_block];
        while let Some(n) = stack.pop() {
            for &p in preds.get(&n).into_iter().flatten() {
                if reachers.insert(p) {
                    stack.push(p);
                }
            }
        }
        let mut addr = None;
        let mut defs = 0usize;
        for block in func.blocks.iter().filter(|b| reachers.contains(&b.start)) {
            for &a in &block.insns {
                let Some(info) = self.dataflow_info(a) else {
                    continue;
                };
                if info.defs.contains(&reg) {
                    let this = info.lea_const.and_then(|(d, x)| (d == reg).then_some(x));
                    if defs == 0 {
                        addr = this;
                    } else if addr != this {
                        addr = None;
                    }
                    defs += 1;
                }
            }
        }
        (defs >= 1).then_some(addr).flatten()
    }
}
