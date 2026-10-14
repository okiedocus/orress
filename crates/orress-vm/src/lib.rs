//! VM-obfuscation detection (M14): find the **dispatch loop** of a bytecode interpreter.
//!
//! VM-based protections (VMProtect, Themida, and homegrown CTF VMs) replace a function's code with
//! bytecode for a custom virtual machine, plus an interpreter that fetches an opcode and jumps to a
//! handler for it. In the CFG this interpreter has a very recognizable shape: one **dispatcher**
//! block that many handler blocks branch back to (so it has a high fan-in), inside a loop. This is
//! the entry point of any devirtualization effort — you first have to find the VM.
//!
//! This is a deterministic, CFG-only heuristic (no execution): it flags functions whose structure
//! matches an interpreter, ranked by confidence. It does not yet *lift* the bytecode.
//!
//! Precision note: a high fan-in block alone is *not* enough, and neither is a high fan-out one.
//! Ordinary loops in library code (error-handling latches in a statically-linked runtime) have a
//! high-fan-in block; an ordinary `switch` has a high-fan-out block. On their own either produces a
//! flood of false positives. The distinguishing mark of an interpreter is a **dispatch loop**: a
//! block that branches *out* to many handlers, most of which *loop back* to it to fetch the next
//! opcode. So we look for a high-fan-out block whose successors can reach it again, and count those
//! looping handlers. A one-shot `switch` fails this (its cases fall through, they don't return to
//! the switch) and so does a plain loop latch (low fan-out), while a real interpreter scores high.
//! `scan` additionally drops low-confidence matches and keeps only the strongest few.

use std::collections::{HashMap, HashSet};

use orress_analysis::{Block, Function, Program};

/// Functions below this many basic blocks are never interpreters (handlers make them large).
const MIN_BLOCKS: usize = 12;
/// A dispatcher must branch out to at least this many handlers that loop back to it.
const MIN_HANDLERS: usize = 6;
/// `scan` reports only matches at least this confident, so weak shapes don't flood the results.
const CONFIDENCE_FLOOR: f32 = 0.6;
/// `scan` returns at most this many candidates (the highest-confidence ones).
const MAX_REPORTS: usize = 8;

/// A function that looks like a VM interpreter.
#[derive(Debug, Clone, PartialEq)]
pub struct VmReport {
    /// The function's entry address.
    pub entry: u64,
    /// The dispatcher block: the one most handlers branch back to.
    pub dispatcher: u64,
    /// Total basic blocks (roughly: handlers + glue).
    pub blocks: usize,
    /// Handlers: blocks the dispatcher branches to that also branch back to it (≈ the opcode count).
    pub handlers: usize,
    /// In-degree of the dispatcher (how many blocks target it).
    pub max_fan_in: usize,
    /// 0.0–1.0 — how strongly the shape matches an interpreter.
    pub confidence: f32,
}

/// Tests one function for the interpreter shape.
pub fn detect(func: &Function) -> Option<VmReport> {
    let blocks = func.blocks.len();
    if blocks < MIN_BLOCKS {
        return None;
    }

    // Predecessors of every block, and the in-degree (for the report).
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut in_degree: HashMap<u64, usize> = HashMap::new();
    for block in &func.blocks {
        for edge in &block.succs {
            preds.entry(edge.target).or_default().push(block.start);
            *in_degree.entry(edge.target).or_default() += 1;
        }
    }

    // The dispatcher is the high-fan-out block with the most *looping* handlers: successors that can
    // reach the block again (so the loop fetches the next opcode through it). A one-shot switch has
    // high fan-out but no looping successors; a plain loop latch has looping edges but low fan-out.
    let mut best: Option<(&orress_analysis::Block, usize)> = None;
    for block in &func.blocks {
        if block.succs.len() < MIN_HANDLERS {
            continue;
        }
        let back = reach_to(&preds, block.start);
        let handlers = block
            .succs
            .iter()
            .filter(|e| back.contains(&e.target))
            .count();
        if handlers >= MIN_HANDLERS && best.is_none_or(|(_, h)| handlers > h) {
            best = Some((block, handlers));
        }
    }

    let (dispatcher, handlers) = best?;
    let fan_out = dispatcher.succs.len();
    let max_fan_in = in_degree.get(&dispatcher.start).copied().unwrap_or(0);

    Some(VmReport {
        entry: func.entry,
        dispatcher: dispatcher.start,
        blocks,
        handlers,
        max_fan_in,
        confidence: confidence(handlers, fan_out),
    })
}

/// One recovered VM opcode: the dispatch case index, the handler it runs, and a first look at what
/// that handler does. This is the opcode table — the skeleton a full devirtualization is built on.
#[derive(Debug, Clone, PartialEq)]
pub struct VmHandler {
    /// The opcode value (the dispatch index that selects this handler).
    pub opcode: usize,
    /// The handler block's address.
    pub address: u64,
    /// Instructions in the handler's entry block.
    pub insns: usize,
    /// The distinctive data operations the handler performs (e.g. `xor, add`), as a first hint of
    /// the virtual instruction's meaning. Empty when the handler is only glue/control flow.
    pub ops: Vec<String>,
    /// Net change the handler makes to the operand-stack pointer: `+1` pushes a value, `-1` is a
    /// binary operation (pop two, push one), `-2` consumes two (a comparison), `0` is unary/none.
    pub stack_delta: i64,
}

/// A best-effort name for the virtual operation a handler implements, inferred from the distinctive
/// data operations in its (dominator-isolated) body. Reliable for the arithmetic/logic opcodes — VM
/// bookkeeping only uses `add`/`inc`/`cmp`, so `xor`/`sub`/`rol`/shift/`mul` single out the real op.
/// Handlers that only move/compare (push, pop, dup, equality, length) can't be told apart from
/// bookkeeping at this level, so they are reported as `stack/control` rather than guessed.
pub fn operation(h: &VmHandler) -> &'static str {
    let has = |m: &str| h.ops.iter().any(|o| o == m);
    if has("rol") || has("ror") {
        "rotate"
    } else if has("shl") || has("shr") || has("sar") {
        "shift"
    } else if has("imul") || has("mul") {
        "multiply"
    } else if has("xor") {
        "xor"
    } else if has("sub") || has("sbb") {
        "subtract"
    } else if has("and") || has("or") || has("not") || has("neg") {
        "bitwise"
    } else if h.stack_delta >= 1 {
        // A net increase of the stack pointer means the handler pushes a value (push-immediate,
        // push-input, dup). A net decrease is NOT reliably a comparison vs a binary op here — the
        // pushed result of a binary op is often written without a tracked `sp` increment — so those
        // stay `stack/control` rather than risk a wrong label.
        "push"
    } else if h.insns <= 3 {
        "halt/return"
    } else {
        "stack/control"
    }
}

/// One decoded virtual instruction of the bytecode: its offset in the blob, the opcode byte, the
/// recovered operation name, and the operand bytes that follow it.
#[derive(Debug, Clone, PartialEq)]
pub struct VmInsn {
    pub offset: usize,
    pub opcode: u8,
    pub op: &'static str,
    pub operands: Vec<u8>,
}

/// Disassembles the VM's bytecode into virtual instructions. For each opcode it recovers the
/// operand size from how far the handler advances the virtual program counter (an `add vpc, k`
/// consumes `k - 1` operand bytes after the opcode byte), names the operation, and walks the blob
/// instruction by instruction until a halt handler or the end. Turns the extracted bytecode into a
/// readable program in the recovered instruction set. `None` if the bytecode can't be located.
pub fn disassemble(program: &Program, report: &VmReport) -> Option<Vec<VmInsn>> {
    let bc = bytecode(program, report)?;
    // `Memory::read` returns *up to* the requested length (it stops at the region end), so the
    // walk must be bounded by what was actually read, not by the recovered length.
    let blob = program.memory.read(bc.base, bc.len? as usize)?.to_vec();
    let func = program.functions.get(&report.entry)?;

    // Identify the virtual program counter: the opcode fetch's address register that is not the
    // (constant) bytecode base.
    let mem = program.mem_ref(bc.fetch)?;
    let regs: Vec<u8> = [mem.base, mem.index].into_iter().flatten().collect();
    let base_reg = regs
        .iter()
        .copied()
        .find(|&r| program.register_const_at(func, bc.fetch, r) == Some(bc.base))?;
    let vpc = regs.iter().copied().find(|&r| r != base_reg)?;

    let table = handlers(program, report);
    let idom = idoms(func);
    // How far the vpc advances per instruction = the shared advance in the fetch/dispatch blocks
    // (blocks not owned by any handler — covers a uniform fixed-size encoding) plus the handler's
    // own advance (covers per-opcode operand reads). Operand bytes = total advance minus the opcode
    // byte. `vpc_advance(pred)` sums the positive constant deltas to the vpc over matching blocks.
    let handler_entries: Vec<u64> = table.iter().map(|h| h.address).collect();
    let vpc_advance = |owned: &dyn Fn(u64) -> bool| -> i64 {
        func.blocks
            .iter()
            .filter(|b| owned(b.start))
            .flat_map(|b| &b.insns)
            .filter_map(|&a| program.reg_info(a).and_then(|i| i.delta))
            .filter(|&(r, k)| r == vpc && k > 0)
            .map(|(_, k)| k)
            .max()
            .unwrap_or(0)
    };
    let in_a_handler = |blk: u64| handler_entries.iter().any(|&h| dominates(&idom, h, blk));
    let shared_advance = vpc_advance(&|blk| !in_a_handler(blk));
    let operand_size = |opcode: u8| -> usize {
        let Some(h) = table.iter().find(|h| h.opcode == opcode as usize) else {
            return 0;
        };
        let handler_advance = vpc_advance(&|blk| dominates(&idom, h.address, blk));
        let total = (shared_advance + handler_advance).max(1);
        (total as usize).saturating_sub(1)
    };
    let name = |opcode: u8| -> &'static str {
        table
            .iter()
            .find(|h| h.opcode == opcode as usize)
            .map_or("unknown", operation)
    };

    Some(walk_bytecode(&blob, operand_size, name))
}

/// Walks a bytecode blob instruction by instruction: each opcode byte, its operand bytes (clipped
/// to what is left of the blob), until a halt handler or the end. Bounded by `blob.len()` alone,
/// so a blob shorter than the recovered extent can't index out of bounds.
fn walk_bytecode(
    blob: &[u8],
    operand_size: impl Fn(u8) -> usize,
    name: impl Fn(u8) -> &'static str,
) -> Vec<VmInsn> {
    let len = blob.len();
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < len {
        let opcode = blob[pc];
        let op = name(opcode);
        let size = operand_size(opcode).min(len - pc - 1);
        let operands = blob[pc + 1..pc + 1 + size].to_vec();
        out.push(VmInsn {
            offset: pc,
            opcode,
            op,
            operands,
        });
        pc += 1 + size;
        if op == "halt/return" {
            break;
        }
    }
    out
}

/// The recovered location of a VM's bytecode blob: the base address the interpreter reads opcodes
/// from, and the fetch instruction that reads it. The first concrete artifact for reading the
/// virtual program itself (the next step after the opcode table).
#[derive(Debug, Clone, PartialEq)]
pub struct VmBytecode {
    /// Base address of the bytecode blob in the binary.
    pub base: u64,
    /// The opcode-fetch instruction that reads the blob.
    pub fetch: u64,
    /// Length of the blob in bytes, when the interpreter's bound (`cmp vpc, len`) is recovered.
    pub len: Option<u64>,
}

/// Locates the VM's bytecode blob. The opcode fetch is a byte-sized load `[base + index]` in the
/// dispatcher's fetch region (the dispatcher block or a direct predecessor, run before each
/// dispatch); one of its address registers is a loop-invariant pointer to a data blob — the
/// bytecode — which register dataflow resolves to a constant address. `None` if it can't be found.
pub fn bytecode(program: &Program, report: &VmReport) -> Option<VmBytecode> {
    let func = program.functions.get(&report.entry)?;
    let fetch_region: Vec<&Block> = func
        .blocks
        .iter()
        .filter(|b| {
            b.start == report.dispatcher || b.succs.iter().any(|e| e.target == report.dispatcher)
        })
        .collect();
    for block in fetch_region {
        for &a in &block.insns {
            let Some(mem) = program.mem_ref(a) else {
                continue;
            };
            if !mem.is_load || mem.size != 1 {
                continue; // the opcode fetch reads a single byte
            }
            for reg in [mem.base, mem.index].into_iter().flatten() {
                let Some(base) = program.register_const_at(func, a, reg) else {
                    continue;
                };
                if program.memory.is_code(base) {
                    continue;
                }
                // The blob runs from its base until the next referenced datum (e.g. the jump
                // table) — a reliable extent even when the interpreter has no `cmp vpc, len` bound
                // (it may just run until a HALT opcode). Capped so a missing next-ref stays sane.
                const MAX_BLOB: u64 = 4096;
                let len = program
                    .next_data_ref(base)
                    .map(|n| (n - base).min(MAX_BLOB));
                return Some(VmBytecode {
                    base,
                    fetch: a,
                    len,
                });
            }
        }
    }
    None
}

/// Mnemonics that characterise what a handler *computes* (not glue like mov/jmp/push/lea).
const SIGNAL_OPS: &[&str] = &[
    "xor", "add", "sub", "adc", "sbb", "and", "or", "not", "neg", "inc", "dec", "imul", "mul",
    "idiv", "div", "shl", "shr", "sar", "rol", "ror", "cmp", "test",
];

/// Recovers the VM's **opcode table**: for each dispatch case, the handler it runs and a summary of
/// the operations that handler performs. The first step of devirtualization — turning the detected
/// interpreter into a described instruction set. Returns empty if the dispatcher's jump table was
/// not recovered (e.g. a compare-chain dispatch with no table).
pub fn handlers(program: &Program, report: &VmReport) -> Vec<VmHandler> {
    let Some(func) = program.functions.get(&report.entry) else {
        return Vec::new();
    };
    let Some(block) = func.blocks.iter().find(|b| b.start == report.dispatcher) else {
        return Vec::new();
    };
    // The dispatcher block ends in the indirect jump; its recovered jump table is the opcode table.
    let Some(&jmp) = block.insns.last() else {
        return Vec::new();
    };
    let Some(cases) = program.switch_tables.get(&jmp) else {
        return Vec::new();
    };
    let idom = idoms(func);
    let sp = find_sp(program, func);
    cases
        .iter()
        .enumerate()
        .map(|(opcode, &address)| {
            // The handler's region is the blocks it dominates — its own body, not the shared fetch
            // and dispatch blocks every handler returns to. Collect the operations it performs there
            // and its net effect on the operand-stack pointer.
            let mut ops: Vec<String> = Vec::new();
            let mut insns = 0;
            let mut stack_delta = 0i64;
            for hb in func
                .blocks
                .iter()
                .filter(|b| dominates(&idom, address, b.start))
            {
                insns += hb.insns.len();
                for &a in &hb.insns {
                    let Some(info) = program.reg_info(a) else {
                        continue;
                    };
                    if let Some(insn) = program.decode(a)
                        && SIGNAL_OPS.contains(&insn.mnemonic.as_str())
                        && !ops.iter().any(|o| o == &insn.mnemonic)
                    {
                        ops.push(insn.mnemonic.clone());
                    }
                    if let (Some(sp), Some((r, k))) = (sp, info.delta)
                        && r == sp
                    {
                        stack_delta += k;
                    }
                }
            }
            VmHandler {
                opcode,
                address,
                insns,
                ops,
                stack_delta,
            }
        })
        .collect()
}

/// Identifies the operand-stack pointer: the register most often used to index a stack-slot buffer
/// (`[rsp|rbp + sp + disp]`) across the interpreter — every handler touches the operand stack.
fn find_sp(program: &Program, func: &Function) -> Option<u8> {
    let mut counts = [0usize; 16];
    for block in &func.blocks {
        for &a in &block.insns {
            if let Some(info) = program.reg_info(a)
                && let Some(mem) = info.mem
                && matches!(mem.base, Some(4) | Some(5)) // rsp / rbp
                && let Some(idx) = mem.index
            {
                counts[idx as usize] += 1;
            }
        }
    }
    counts
        .iter()
        .enumerate()
        .filter(|&(_, &c)| c > 0)
        .max_by_key(|&(_, &c)| c)
        .map(|(i, _)| i as u8)
}

/// Immediate-dominator map for a function's CFG (Cooper–Harvey–Kennedy). A block's handler region
/// is the set of blocks it dominates — the code reached *only* through it, i.e. its own body,
/// excluding the shared dispatcher and fetch blocks that every handler returns to.
fn idoms(func: &Function) -> HashMap<u64, u64> {
    // Reverse post-order from the entry.
    let succ: HashMap<u64, Vec<u64>> = func
        .blocks
        .iter()
        .map(|b| (b.start, b.succs.iter().map(|e| e.target).collect()))
        .collect();
    let mut post = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![(func.entry, 0usize)];
    while let Some((n, i)) = stack.pop() {
        if i == 0 && !seen.insert(n) {
            continue;
        }
        match succ.get(&n).and_then(|s| s.get(i)) {
            Some(&next) => {
                stack.push((n, i + 1));
                if !seen.contains(&next) {
                    stack.push((next, 0));
                }
            }
            None => post.push(n),
        }
    }
    let rpo: Vec<u64> = post.iter().rev().copied().collect();
    let order: HashMap<u64, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    for b in &func.blocks {
        for e in &b.succs {
            preds.entry(e.target).or_default().push(b.start);
        }
    }
    let mut idom: HashMap<u64, u64> = HashMap::from([(func.entry, func.entry)]);
    let intersect = |idom: &HashMap<u64, u64>, mut a: u64, mut b: u64| {
        while a != b {
            while order.get(&a).copied().unwrap_or(usize::MAX)
                > order.get(&b).copied().unwrap_or(usize::MAX)
            {
                a = idom[&a];
            }
            while order.get(&b).copied().unwrap_or(usize::MAX)
                > order.get(&a).copied().unwrap_or(usize::MAX)
            {
                b = idom[&b];
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let mut new = None;
            for &p in preds.get(&b).into_iter().flatten() {
                if idom.contains_key(&p) {
                    new = Some(match new {
                        None => p,
                        Some(n) => intersect(&idom, p, n),
                    });
                }
            }
            if let Some(new) = new
                && idom.get(&b) != Some(&new)
            {
                idom.insert(b, new);
                changed = true;
            }
        }
    }
    idom
}

/// Whether `h` dominates `b` (so `b` is part of `h`'s handler region).
fn dominates(idom: &HashMap<u64, u64>, h: u64, b: u64) -> bool {
    let mut cur = b;
    loop {
        if cur == h {
            return true;
        }
        match idom.get(&cur) {
            Some(&p) if p != cur => cur = p,
            _ => return false,
        }
    }
}

/// Every block that can reach `target` (reverse reachability over the predecessor edges).
fn reach_to(preds: &HashMap<u64, Vec<u64>>, target: u64) -> HashSet<u64> {
    let mut seen = HashSet::new();
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if let Some(ps) = preds.get(&node) {
            for &p in ps {
                if seen.insert(p) {
                    stack.push(p);
                }
            }
        }
    }
    seen
}

/// Scans every function in a program for interpreters, highest-confidence first. Only matches at
/// or above `CONFIDENCE_FLOOR` are returned, capped at `MAX_REPORTS`, so the result is a short
/// list of strong candidates rather than every loop in the binary.
pub fn scan(program: &Program) -> Vec<VmReport> {
    let mut out: Vec<VmReport> = program
        .functions
        .values()
        .filter_map(detect)
        .filter(|r| r.confidence >= CONFIDENCE_FLOOR)
        .collect();
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.truncate(MAX_REPORTS);
    out
}

/// Weighs how many handlers the dispatcher has against the share of its out-edges that are
/// handlers (a pure dispatcher sends almost every branch to a handler that returns).
fn confidence(handlers: usize, fan_out: usize) -> f32 {
    let count = (handlers as f32 / 16.0).min(1.0);
    let purity = if fan_out == 0 {
        0.0
    } else {
        (handlers as f32 / fan_out as f32).min(1.0)
    };
    (0.6 * count + 0.4 * purity).clamp(0.0, 1.0)
}

mod lift;
pub use lift::{VmSolution, emu_image, import_hooks, solve, try_solve};

#[cfg(test)]
mod tests;
