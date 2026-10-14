//! Concolic lifting of a detected VM: recover the input (key) that drives the interpreter to its
//! success return. The insight (see PLAN.md M14.53/.55) is that a VM's control flow is driven by
//! the *concrete* bytecode while the program input is symbolic, so symbolically executing the whole
//! interpreter unrolls the dispatch loop and yields the real per-byte check constraints; solving
//! them gives a valid key that passes the real binary (self-verifying).
//!
//! This module derives the symbolic-execution parameters purely from the CFG — the success/fail
//! verdict blocks and the "doomed" blocks to steer away from — then runs [`orress_sym::solve_check`]
//! over the emulator's image of the program. No per-opcode semantics are guessed; correctness comes
//! from execution.

use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use orress_analysis::{Block, Function, Isa, NameKind, Program};
use orress_sym::{Abi, SymError};

use crate::VmReport;

/// The outcome of concolically lifting a VM: the recovered key and the constraints behind it.
#[derive(Debug, Clone)]
pub struct VmSolution {
    /// The interpreter function that was solved.
    pub func: u64,
    /// The input length the solve succeeded at.
    pub input_len: u32,
    /// The recovered input bytes (the key).
    pub key: Vec<u8>,
    /// Whether every captured constraint was satisfied (a self-verifying key).
    pub complete: bool,
    /// How many path constraints the symbolic run captured.
    pub constraints: usize,
    /// The lifted per-byte checks, rendered readably (e.g. `rol(in[0] ^ 0x3b, 1) == 0x9a`) — the
    /// logic the virtualized check performs, recovered by execution rather than pattern-matching.
    pub checks: Vec<String>,
    /// The constraints as SMT-LIB2, for an external solver.
    pub smt2: String,
}

/// Input lengths to try (the VM's length check rejects wrong lengths concretely and fast).
const MAX_LEN: u32 = 48;

/// Concolically solve a detected VM, recovering the key. Returns `None` if the interpreter's
/// verdict blocks can't be identified or no length yields a solution; [`try_solve`] says why.
pub fn solve(program: &Program, report: &VmReport) -> Option<VmSolution> {
    try_solve(program, report).ok()
}

/// How informative a failed attempt's error is: a real modelling gap (unsupported instruction,
/// symbolic address, fault) explains a failure better than a budget overrun, which in turn says
/// more than "this length hit an avoided block" (the expected outcome for every wrong length).
fn error_rank(e: &SymError) -> u8 {
    match e {
        SymError::HitAvoid(_) => 0,
        SymError::BudgetExhausted => 1,
        SymError::Unsupported { .. } | SymError::SymbolicAddress(_) | SymError::Fault(_) => 2,
    }
}

/// [`solve`], but on failure returns the most relevant reason: the highest-ranked symbolic
/// execution error seen across the tried input lengths (see `error_rank`), or an
/// [`SymError::Unsupported`] naming the precondition that failed (non-x86-64 program, no
/// enclosing function, no recognisable success/fail verdict, no constraints captured).
pub fn try_solve(program: &Program, report: &VmReport) -> Result<VmSolution, SymError> {
    let unsupported = |what: &str| SymError::Unsupported {
        addr: report.entry,
        what: what.to_string(),
    };
    // The symbolic executor and `decode_block` are x86-64 only.
    if program.isa != Isa::X64 {
        return Err(unsupported(&format!(
            "VM lifting for {:?} (x86-64 only)",
            program.isa
        )));
    }
    let func = program
        .function_containing(report.entry)
        .ok_or_else(|| unsupported("VM entry outside any function"))?;
    let abi = if program.memory.is_elf {
        Abi::SysV
    } else {
        Abi::Win64
    };

    let (target, avoid) = verdict_blocks(program, func)
        .ok_or_else(|| unsupported("interpreter without a recognisable success verdict"))?;

    // Place the symbolic input above every mapped region (clear of the program, its `.bss`
    // slack, and the stack `run_check` maps near 0x7fff_0000).
    let max_end = program
        .memory
        .regions
        .iter()
        .map(|r| r.start.saturating_add(r.len))
        .max()
        .unwrap_or(0);
    let mut input_base = max_end.saturating_add(0x1_0000) & !0xfff;
    // Keep clear of the scratch stack `run_check` maps just below 0x7fff_0000.
    if (0x7fe0_0000..0x8010_0000).contains(&input_base) {
        input_base = 0x8010_0000;
    }

    let hooks = import_hooks(program);
    let base_mem = emu_image(program);

    let mut best: Option<VmSolution> = None;
    let mut worst_err: Option<SymError> = None;
    for input_len in 1..=MAX_LEN {
        let mut mem = base_mem.clone();
        mem.map_zeroed(input_base, u64::from(input_len) + 16);
        let args = [input_base, u64::from(input_len)];
        let found = match orress_sym::solve_check(
            mem,
            func.entry,
            &args,
            input_base,
            input_len,
            target,
            avoid.clone(),
            hooks.clone(),
            abi,
        ) {
            Ok(f) => f,
            // Usually: this length drove execution into a doomed/avoided block — the wrong
            // length. Remember the most telling error in case no length works.
            Err(e) => {
                if worst_err
                    .as_ref()
                    .is_none_or(|w| error_rank(&e) > error_rank(w))
                {
                    worst_err = Some(e);
                }
                continue;
            }
        };
        let sol = VmSolution {
            func: func.entry,
            input_len,
            key: found.result.input,
            complete: found.result.complete,
            constraints: found.constraints,
            checks: found.checks,
            smt2: found.smt2,
        };
        // A complete solve with real constraints is the answer; otherwise keep the richest attempt.
        if sol.complete && sol.constraints > 0 {
            return Ok(sol);
        }
        if best
            .as_ref()
            .is_none_or(|b| sol.constraints > b.constraints)
        {
            best = Some(sol);
        }
    }
    match best.filter(|b| b.constraints > 0) {
        Some(b) => Ok(b),
        None => Err(worst_err
            .unwrap_or_else(|| unsupported("VM run that captured no input-dependent constraints"))),
    }
}

/// The success block to steer toward and the set of blocks to avoid. Success = the verdict block
/// that sets the return register to a non-zero constant and flows straight to `ret`; the avoid set
/// is every block from which that success block is unreachable (the "doomed" set), so steering an
/// input-dependent branch away from `avoid` keeps execution on the passing path even when the fail
/// edge reaches the failure return only through intermediate blocks.
fn verdict_blocks(program: &Program, func: &Function) -> Option<(u64, Vec<u64>)> {
    let target = func
        .blocks
        .iter()
        .filter(|b| reaches_ret_cleanly(program, func, b.start))
        .find(|b| matches!(verdict_const(program, b), Some(k) if k != 0))
        .map(|b| b.start)?;

    // Each block's successors, augmented with its recovered switch-table targets: a dispatcher's
    // register-indirect jump has its cases in `switch_tables`, and the analysis CFG may not carry
    // every one as a `succs` edge, so reachability has to consult the table directly.
    let succs_of = |b: &Block| -> Vec<u64> {
        let mut s: Vec<u64> = b.succs.iter().map(|e| e.target).collect();
        if let Some(cases) = b.insns.last().and_then(|a| program.switch_tables.get(a)) {
            s.extend(cases.iter().copied());
        }
        s
    };

    // Reverse reachability: the blocks from which `target` is reachable over successor edges.
    let mut can_reach: HashSet<u64> = HashSet::from([target]);
    let mut changed = true;
    while changed {
        changed = false;
        for b in &func.blocks {
            if !can_reach.contains(&b.start) && succs_of(b).iter().any(|t| can_reach.contains(t)) {
                can_reach.insert(b.start);
                changed = true;
            }
        }
    }
    let avoid = func
        .blocks
        .iter()
        .map(|b| b.start)
        .filter(|a| !can_reach.contains(a))
        .collect();
    Some((target, avoid))
}

/// The constant this block leaves in the return register (rax/eax/al), if its net effect is a
/// constant — `mov eax, k` or `xor eax, eax`. Used to classify success (non-zero) vs fail (zero).
fn verdict_const(program: &Program, b: &Block) -> Option<u64> {
    let mut k = None;
    for ins in decode_block(program, b) {
        let is_ret_reg = |r: Register| r.full_register() == Register::RAX;
        match ins.mnemonic() {
            Mnemonic::Mov if is_ret_reg(ins.op0_register()) => {
                k = matches!(
                    ins.op1_kind(),
                    OpKind::Immediate8
                        | OpKind::Immediate32
                        | OpKind::Immediate32to64
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                )
                .then(|| ins.immediate(1));
            }
            Mnemonic::Xor
                if is_ret_reg(ins.op0_register()) && ins.op0_register() == ins.op1_register() =>
            {
                k = Some(0);
            }
            _ => {}
        }
    }
    k
}

/// Whether `start` flows straight to a `ret` along single-successor edges without any further
/// write to the return register (so the constant a verdict block set still holds at the return).
fn reaches_ret_cleanly(program: &Program, func: &Function, start: u64) -> bool {
    let mut cur = start;
    for _ in 0..6 {
        let Some(b) = func.blocks.iter().find(|b| b.start == cur) else {
            return false;
        };
        if decode_block(program, b)
            .last()
            .is_some_and(|i| i.mnemonic() == Mnemonic::Ret)
        {
            return true;
        }
        if b.succs.len() != 1 {
            return false;
        }
        let next = b.succs[0].target;
        if let Some(nb) = func.blocks.iter().find(|b| b.start == next)
            && verdict_const(program, nb).is_none()
            && writes_ret_reg(program, nb)
        {
            return false; // an intervening block clobbers the return register
        }
        cur = next;
    }
    false
}

/// Whether the block writes the return register (rax/eax/al) at all.
fn writes_ret_reg(program: &Program, b: &Block) -> bool {
    decode_block(program, b).iter().any(|ins| {
        matches!(
            ins.mnemonic(),
            Mnemonic::Mov | Mnemonic::Xor | Mnemonic::Movzx | Mnemonic::Add | Mnemonic::Sub
        ) && ins.op0_register().full_register() == Register::RAX
    })
}

/// Decodes all instructions in a block from the program image.
fn decode_block(program: &Program, b: &Block) -> Vec<iced_x86::Instruction> {
    let Some(bytes) = program.memory.read(b.start, (b.end - b.start) as usize) else {
        return Vec::new();
    };
    let mut dec = Decoder::with_ip(64, bytes, b.start, DecoderOptions::NONE);
    let mut out = Vec::new();
    while dec.can_decode() {
        out.push(dec.decode());
    }
    out
}

/// Zero-filled slack mapped after every file-backed region. The analysis image only carries a
/// section's file bytes, so a zero-initialised tail (`.bss`, a `.data` section's virtual
/// overhang) would otherwise be unmapped — and guest writes to unmapped memory fault.
const BSS_SLACK: u64 = 0x8000;

/// Builds an emulator memory image from the program's mapped regions (each followed by
/// `BSS_SLACK` zeroed bytes where nothing else is mapped). The shared seeding step for every
/// front end that runs a loaded program in `orress-emu` / `orress-sym`.
pub fn emu_image(program: &Program) -> orress_emu::Memory {
    let mut mem = orress_emu::Memory::new();
    for r in &program.memory.regions {
        if let Some(bytes) = program.memory.read(r.start, r.len as usize) {
            mem.write_bytes(r.start, bytes);
        }
    }
    // After all file bytes are in: `map_zeroed` only adds missing pages, never clears data.
    for r in &program.memory.regions {
        mem.map_zeroed(r.start.saturating_add(r.len), BSS_SLACK);
    }
    mem
}

/// Import stubs keyed by import address (both the IAT/GOT slot and any thunk named after the
/// import), so library calls return something sensible instead of faulting. The emulator and
/// the symbolic executor match a hooked slot on `call [slot]` / `jmp [slot]` as well as a direct
/// call to a hooked address. The name → stub mapping is [`orress_emu::stub_for`].
pub fn import_hooks(program: &Program) -> std::collections::HashMap<u64, orress_emu::Stub> {
    program
        .names
        .iter()
        .filter(|(_, n)| n.kind == NameKind::Import)
        .map(|(&addr, n)| (addr, orress_emu::stub_for(&n.text)))
        .collect()
}
