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

/// The calling convention for `program`'s architecture, or `None` if the symbolic executor can't
/// handle it. x86-64 uses the platform ABI (SysV for ELF, Win64 otherwise); x86-32 uses cdecl.
fn abi_for(program: &Program) -> Option<Abi> {
    match program.isa {
        Isa::X64 => Some(if program.memory.is_elf {
            Abi::SysV
        } else {
            Abi::Win64
        }),
        Isa::X86 => Some(Abi::Cdecl),
        _ => None,
    }
}

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
    // The symbolic executor handles x86-64 and x86-32.
    let abi = abi_for(program)
        .ok_or_else(|| unsupported(&format!("VM lifting for {:?} (x86 only)", program.isa)))?;
    let func = program
        .function_containing(report.entry)
        .ok_or_else(|| unsupported("VM entry outside any function"))?;

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

/// Place the symbolic input above every mapped region (clear of the program and of the scratch
/// stack `run_check` maps near `0x7fff_0000`).
fn input_placement(program: &Program) -> u64 {
    let max_end = program
        .memory
        .regions
        .iter()
        .map(|r| r.start.saturating_add(r.len))
        .max()
        .unwrap_or(0);
    let mut base = max_end.saturating_add(0x1_0000) & !0xfff;
    if (0x7fe0_0000..0x8010_0000).contains(&base) {
        base = 0x8010_0000;
    }
    base
}

/// Solve an arbitrary `check(input) -> bool` function (not only a VM interpreter): recover an input
/// the function *accepts*. It steers away from the function's `return false` verdict blocks, runs to
/// the return, and requires the return value be non-zero — so a branchless final comparison
/// (`return a[i] == c`) is captured as a constraint, which steering to a success *block* cannot do.
///
/// `func_entry` is the check function's entry (e.g. from [`crate::scan`]-adjacent analysis or a
/// caller's own function selection). Returns the recovered input and the lifted per-byte checks, or
/// `None` if the program is not x86-64, the function is unknown, or no input length solves.
pub fn solve_function(program: &Program, func_entry: u64, abi: Abi) -> Option<VmSolution> {
    abi_for(program)?;
    let func = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))?;

    // The failure path: blocks that leave 0 in the return register and flow to `ret` (`return
    // false`). Steering away from these keeps execution on the accepting path.
    let avoid: Vec<u64> = func
        .blocks
        .iter()
        .filter(|b| verdict_const(program, b) == Some(0) && reaches_ret_cleanly(program, func, b.start))
        .map(|b| b.start)
        .collect();

    let input_base = input_placement(program);
    let base_mem = emu_image(program);
    let hooks = import_hooks(program);

    let mut best: Option<VmSolution> = None;
    for input_len in 1..=MAX_LEN {
        let mut mem = base_mem.clone();
        mem.map_zeroed(input_base, u64::from(input_len) + 16);
        let args = [input_base, u64::from(input_len)];
        let Ok(found) = orress_sym::solve_check_return(
            mem,
            func.entry,
            &args,
            input_base,
            input_len,
            avoid.clone(),
            hooks.clone(),
            abi,
        ) else {
            continue;
        };
        if found.result.complete && found.constraints > 0 {
            let sol = VmSolution {
                func: func.entry,
                input_len,
                key: found.result.input,
                complete: true,
                constraints: found.constraints,
                checks: found.checks,
                smt2: found.smt2,
            };
            // Keep the richest solve (the length/path that constrained the most bytes).
            if best.as_ref().is_none_or(|b| sol.constraints > b.constraints) {
                best = Some(sol);
            }
        }
    }
    best
}

/// Path-exploring return-model solve of `func_entry` — the expensive counterpart to
/// [`solve_function`]. It forks symbolic branches, so it can crack a check whose accepting path
/// must loop N times on a symbolic condition (an input-length scan, a validation loop) or that
/// reads its input internally (gets/scanf) — which the greedy single-path [`solve_function`]
/// cannot. Kept separate (not a fallback inside `solve_function`) because exploration is ~an order
/// of magnitude slower; a bulk static pass uses `solve_function`, and only a deep/targeted pass
/// opts into this.
pub fn solve_function_explore(program: &Program, func_entry: u64, abi: Abi) -> Option<VmSolution> {
    abi_for(program)?;
    let func = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))?;
    let avoid: Vec<u64> = func
        .blocks
        .iter()
        .filter(|b| verdict_const(program, b) == Some(0) && reaches_ret_cleanly(program, func, b.start))
        .map(|b| b.start)
        .collect();
    let input_base = input_placement(program);
    let base_mem = emu_image(program);
    let hooks = import_hooks(program);

    for input_len in 1..=MAX_LEN {
        let mut mem = base_mem.clone();
        mem.map_zeroed(input_base, u64::from(input_len) + 16);
        let args = [input_base, u64::from(input_len)];
        let Some(found) = orress_sym::solve_check_return_explore(
            mem,
            func.entry,
            &args,
            input_base,
            input_len,
            avoid.clone(),
            hooks.clone(),
            abi,
            EXPLORE_MAX_STATES,
            EXPLORE_MAX_STEPS,
        ) else {
            continue;
        };
        if found.result.complete && found.constraints > 0 {
            return Some(VmSolution {
                func: func.entry,
                input_len,
                key: found.result.input,
                complete: true,
                constraints: found.constraints,
                checks: found.checks,
                smt2: found.smt2,
            });
        }
    }
    None
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
    Some((target, avoid_set_for_target(program, func, target)))
}

/// Blocks of `func` from which `target` is NOT reachable over successor edges (augmented with
/// recovered switch-table targets — a dispatcher's register-indirect `jmp` keeps its cases in
/// `switch_tables`, and the CFG may not carry every one as a `succs` edge). Steering an
/// input-dependent branch away from these keeps execution on a path that can still reach `target`.
fn avoid_set_for_target(program: &Program, func: &Function, target: u64) -> Vec<u64> {
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
    func.blocks
        .iter()
        .map(|b| b.start)
        .filter(|a| !can_reach.contains(a))
        .collect()
}

/// Solve a function that reads its input *internally* (via `gets`/`scanf`/`fgets`/`read`/…) and
/// signals acceptance by reaching a block that prints a success string ("Correct", "You win!", …),
/// rather than by returning a bool. The input-reading hooks ([`orress_emu::stub_for`]) make the
/// read buffer the symbolic input; execution is then steered to the success block. This is the
/// common real-world shape that [`solve_function`] (input == argument, verdict == return) misses:
/// the input arrives from libc into a stack buffer, not as a function argument.
///
/// Returns the recovered accepting input, or `None` if the program is not x86-64, the function is
/// unknown, has no identifiable success block, or no input length solves.
pub fn solve_stdin_function(program: &Program, func_entry: u64, abi: Abi) -> Option<VmSolution> {
    abi_for(program)?;
    let func = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))?;
    // Only the target (success block) matters here; the path explorer prunes dead paths by the
    // return sentinel, so it doesn't need — and isn't misled by — a reverse-reachability avoid set.
    let (target, _avoid) = success_block(program, func)?;

    let input_base = input_placement(program);
    let base_mem = emu_image(program);
    let hooks = import_hooks(program);

    // Reaching the verdict means looping N times on a symbolic condition (the input-length scan,
    // the per-char validation), so this uses the path-exploring solver, not the single-path steerer.
    for input_len in 1..=MAX_LEN {
        let mut mem = base_mem.clone();
        mem.map_zeroed(input_base, u64::from(input_len) + 16);
        let Some(found) = orress_sym::solve_check_explore(
            mem,
            func.entry,
            &[],
            input_base,
            input_len,
            target,
            Vec::new(),
            hooks.clone(),
            abi,
            EXPLORE_MAX_STATES,
            EXPLORE_MAX_STEPS,
        ) else {
            continue;
        };
        if found.result.complete && found.constraints > 0 {
            // First accepting path wins: a shorter length is the natural key length, and the
            // explorer already proved this input drives execution to the success block.
            return Some(VmSolution {
                func: func.entry,
                input_len,
                key: found.result.input,
                complete: true,
                constraints: found.constraints,
                checks: found.checks,
                smt2: found.smt2,
            });
        }
    }
    None
}

/// Frontier and total-step caps for [`solve_stdin_function`]'s path exploration, bounding path
/// explosion and unbounded loops.
const EXPLORE_MAX_STATES: usize = 4000;
const EXPLORE_MAX_STEPS: u64 = 1_000_000;

/// The success block to steer toward (and the blocks to avoid): a block of `func` whose code
/// references a success-indicator string. `None` if the function references no such string.
fn success_block(program: &Program, func: &Function) -> Option<(u64, Vec<u64>)> {
    // Instruction addresses that reference a success string anywhere in the program.
    let mut refs: HashSet<u64> = HashSet::new();
    for (&addr, text) in &program.string_refs {
        if is_success_text(text) {
            for x in program.xrefs(addr) {
                refs.insert(x.from);
            }
        }
    }
    if refs.is_empty() {
        return None;
    }
    // This function's block that contains one of those references.
    let target = func
        .blocks
        .iter()
        .find(|b| b.insns.iter().any(|a| refs.contains(a)))?
        .start;
    Some((target, avoid_set_for_target(program, func, target)))
}

/// Whether a referenced string reads like an acceptance verdict. Deliberately strict: a wrong
/// target would steer the solver at the wrong block, so a failure marker (even one that contains a
/// success word, like "**in**correct") vetoes the match first.
fn is_success_text(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    const FAIL: &[&str] = &[
        "incorrect", "wrong", "invalid", "denied", "fail", "unsuccessful", "try again", "sorry",
        "error", "not correct", "no match",
    ];
    if FAIL.iter().any(|m| t.contains(m)) {
        return false;
    }
    const WIN: &[&str] = &[
        "correct", "congrat", "you win", "access granted", "well done", "good job", "accepted",
        "unlocked", "right password", "right key", "right serial", "winner", "you did it",
        "you got it", "flag{",
    ];
    WIN.iter().any(|m| t.contains(m))
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

/// What the **compare-hook** recovered from one emulated run: the input we seeded and the values the
/// check compared that input against. See [`recover_by_compare`].
#[derive(Debug, Clone)]
pub struct CompareRecovery {
    /// The concrete input seeded into every read (the "name" for a keygen; the probe for a password
    /// check). All reads get the same bytes, so a keygen's serial = f(seed) is computed concretely.
    pub seed: Vec<u8>,
    /// Printable values the check compared the input against — the recovered key/serial candidates
    /// (deduped, excluding the seed itself). For a password check this is the password; for a keygen
    /// it is `f(seed)`, to be paired with `name = seed`.
    pub keys: Vec<Vec<u8>>,
}

/// Seeds used by [`recover_by_compare`], a few lengths so a length-gate before the compare doesn't
/// hide the oracle. Printable so a recovered-vs-seed comparison stays meaningful.
const COMPARE_SEEDS: [&[u8]; 3] = [b"AAAAAAAAAAAAAAAA", b"AAAAAAAA", b"AAAA"];
/// Step budget per compare-hook run — keygen check routines are small; this bounds runaway loops.
const COMPARE_BUDGET: u64 = 2_000_000;

/// Recover a key/serial by the **compare-hook**: seed a known input, emulate `func_entry` forward
/// with [`orress_emu`], and read back the value(s) the code compared the input against via
/// `strcmp`/`strncmp`/`memcmp`. This cracks the shapes symbolic solving struggles with — keygens
/// (`serial = f(name)`, then `strcmp(entered, serial)`) and hardcoded-string password checks —
/// because the expected value is *computed then compared* rather than branched on per byte.
///
/// Returns one [`CompareRecovery`] per seed length that produced at least one printable candidate
/// (best/longest seed first). The keys are leads to be verified by running the binary, not
/// self-verifying solves. Empty if the function reads/compares nothing we can observe.
pub fn recover_by_compare(program: &Program, func_entry: u64, abi: Abi) -> Vec<CompareRecovery> {
    let mut out = Vec::new();
    // Start from the fixed seed lengths. A length gate observed mid-run (`strlen(input) == 19`, which
    // the three fixed lengths fail so the byte loop behind it never runs) appends a seed of exactly
    // that length, so a later pass clears the gate and the inline compares become observable.
    let mut seeds: Vec<Vec<u8>> = COMPARE_SEEDS.iter().map(|s| s.to_vec()).collect();
    let mut i = 0;
    while i < seeds.len() {
        let seed = seeds[i].clone();
        i += 1;
        let (keys, wanted) = run_seed(program, func_entry, abi, &seed);
        for n in wanted {
            let n = n as usize;
            if (1..=MAX_LEN as usize).contains(&n) && !seeds.iter().any(|s| s.len() == n) {
                seeds.push(vec![b'A'; n]);
            }
        }
        if !keys.is_empty() {
            out.push(CompareRecovery { seed, keys });
        }
    }
    out
}

/// One compare-hook fixpoint for a single seed. A single run only reaches the first mismatching byte
/// of a per-byte check (it then branches to failure), so we iterate: learn the bytes the run
/// compared, feed them back into the input, and re-run so the next byte is reached. This recovers the
/// whole inline key (`cmp input[0],'W'` → seed[0]='W' → next run reaches `cmp input[1],'X'` → …).
///
/// Returns the recovered key/serial candidates and any length-gate constants the run observed (a
/// value equal to the seed length compared against a different small constant — see
/// [`orress_emu::Emulator::wanted_lens`]).
fn run_seed(
    program: &Program,
    func_entry: u64,
    abi: Abi,
    seed: &[u8],
) -> (Vec<Vec<u8>>, Vec<u64>) {
    let mut cur = seed.to_vec();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut wanted: Vec<u64> = Vec::new();
    for _ in 0..MAX_LEN {
        let mut emu = orress_emu::Emulator::new();
        emu.mem = emu_image(program);
        emu.hooks = import_hooks(program);
        emu.budget = COMPARE_BUDGET;
        emu.seed_input(cur.clone());
        emu.record_compares(true);
        let _ = emu.call(func_entry, &[], abi);

        // Length gates seen this run — surfaced to the caller to try that exact length.
        for &n in emu.wanted_lens() {
            if !wanted.contains(&n) {
                wanted.push(n);
            }
        }
        // Collect library-compare operands (keygen serials / hardcoded strings).
        for (a, b) in emu.compares() {
            for operand in [a, b] {
                if operand.as_slice() != cur.as_slice()
                    && is_printable_key(operand)
                    && !keys.contains(operand)
                {
                    keys.push(operand.clone());
                }
            }
        }
        // Feed inline per-byte findings back into the working input.
        let Some(k) = emu.inline_key() else { break };
        let mut next = cur.clone();
        for (j, &b) in k.iter().enumerate() {
            if j < next.len() {
                next[j] = b;
            }
        }
        if next == cur {
            // Fixpoint: the input now satisfies every byte the check looks at.
            let recovered = k[..k.len().min(cur.len())].to_vec();
            if is_printable_key(&recovered) && !keys.contains(&recovered) {
                keys.insert(0, recovered); // strongest signal first
            }
            break;
        }
        cur = next;
    }
    (keys, wanted)
}

/// Whether recovered bytes look like a real key: non-empty and all printable ASCII (a computed
/// serial or hardcoded password), not binary filler a `memcmp` happened to see.
fn is_printable_key(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

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
///
/// Also hooks **statically-linked** compare-hook oracles by name (readers, comparators, `strlen`;
/// see [`orress_emu::is_oracle_name`]). MinGW/MSVC binaries routinely compile `scanf`/`strcmp`/
/// `strlen` straight in, so an import-only table would leave the compare-hook with no seeded input
/// and no observable comparison on exactly the common console-crackme shape.
pub fn import_hooks(program: &Program) -> std::collections::HashMap<u64, orress_emu::Stub> {
    program
        .names
        .iter()
        .filter(|(_, n)| n.kind == NameKind::Import || orress_emu::is_oracle_name(&n.text))
        .map(|(&addr, n)| (addr, orress_emu::stub_for(&n.text)))
        .collect()
}
