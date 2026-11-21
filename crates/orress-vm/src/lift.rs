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
        SymError::BudgetExhausted | SymError::Deadline => 1,
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

/// **Oracle-free confirmation via the check's own comparison.** Seed a concrete `candidate` as the
/// input, emulate `func_entry` with the compare-hook on, and report whether the check's comparison
/// *passed*: every inline per-byte comparison matched (the reconstructed inline key equals the
/// candidate), a library `strcmp`/`memcmp` saw its two operands equal with the input among them,
/// or — for an "enter the number" crackme — a whole-value comparison against the *parsed* numeric
/// input (`scanf("%d")`/`atoi`) was an equality.
/// That is exactly the condition the check tests, so it confirms a password/serial without needing a
/// success string and even if unrelated code faults later (the comparison runs first). `None` when
/// the architecture is unsupported or the function is unknown; `Some(false)` when nothing matched.
///
/// A `name\nserial` candidate is fed one line per read, so a keygen that reads a name and then its
/// serial can be confirmed as a pair: the comparison may equal either line (the serial, usually) or
/// the whole candidate.
///
/// Use differentially (same-shaped wrong inputs must NOT satisfy it) to rule out a check that
/// compares the input against itself (an echo) rather than against a stored key.
pub fn compare_satisfied(
    program: &Program,
    func_entry: u64,
    candidate: &[u8],
    abi: Abi,
) -> Option<bool> {
    match compare_pass(program, func_entry, candidate, abi) {
        ComparePassOutcome::Unsupported => None,
        ComparePassOutcome::No => Some(false),
        ComparePassOutcome::Passed(_) => Some(true),
    }
}

/// Which kind of comparison accepted a candidate — the two carry very different weight as evidence,
/// so a caller confirming a key has to be able to tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparePass {
    /// The candidate's **bytes** were matched: an inline per-byte loop whose expected byte at every
    /// compared offset equalled the candidate, or a library `strcmp`/`memcmp` whose two operands
    /// were equal with the input among them.
    ///
    /// Strong evidence on its own. The comparison did not merely return "equal" — it spelled out a
    /// whole byte sequence that agreed with the candidate at every position, which a wrong input
    /// cannot do by coincidence.
    Bytes,
    /// A **whole-value numeric** comparison was an equality (`cmp eax, 1234h` on the parsed input).
    ///
    /// Weak evidence on its own, and must not be treated as proof. The passing constant is a single
    /// small integer, and when the candidate was itself read out of that same comparison by the
    /// decompiler, re-running it is circular: it can only pass, no wrong twin can ever make it
    /// fail, and the differential test is therefore vacuous. Three unrelated MSVC GUI crackmes
    /// "confirmed" the key `252` this way. A caller must corroborate it — see CRACKEN's
    /// `emulate_confirm`, which requires the pass to also change where execution goes.
    Number,
}

/// [`compare_pass`]'s result: unsupported, nothing passed, or which comparison passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparePassOutcome {
    /// The architecture is unsupported or the function is unknown — nothing was tried.
    Unsupported,
    /// Nothing passed.
    No,
    /// This kind of comparison accepted the candidate.
    Passed(ComparePass),
}

/// As [`compare_satisfied`], but reporting **which** comparison passed, so the caller can weigh it.
pub fn compare_pass(
    program: &Program,
    func_entry: u64,
    candidate: &[u8],
    abi: Abi,
) -> ComparePassOutcome {
    if abi_for(program).is_none() {
        return ComparePassOutcome::Unsupported;
    }
    let Some(entry) = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))
        .map(|f| f.entry)
    else {
        return ComparePassOutcome::Unsupported;
    };

    // A check gets its input in several ways, and which one this function uses is not known up
    // front — so try each shape and accept if any of them satisfies the comparison. A `Bytes` pass
    // outranks a `Number` one, so keep looking if only the weak signal has fired.
    let mut best: Option<ComparePass> = None;
    let mut shapes = vec![Shape::Pointer];
    // `check(int n)`: the caller already parsed the number, so there is no reader to seed and no
    // buffer to point at — the value arrives in a register.
    if numeric_candidate(candidate).is_some() {
        shapes.push(Shape::Number);
    }
    // A dialog handler: enter at the block that reads the edit box, not at the message dispatch.
    shapes.extend(
        gui_reader_blocks(program, entry)
            .into_iter()
            .map(Shape::GuiBlock),
    );
    for shape in shapes {
        match compare_run(program, entry, candidate, abi, shape).pass {
            Some(ComparePass::Bytes) => return ComparePassOutcome::Passed(ComparePass::Bytes),
            Some(ComparePass::Number) => best = Some(ComparePass::Number),
            None => {}
        }
    }
    match best {
        Some(k) => ComparePassOutcome::Passed(k),
        None => ComparePassOutcome::No,
    }
}

/// How a check is entered and handed its input. Which one applies is not knowable up front, so
/// [`compare_satisfied`] tries them in turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Called with `(ptr, len)`, and any hooked reader seeded — the common console shape.
    Pointer,
    /// Called with the parsed number as argument 0 (`check(int n)`).
    Number,
    /// Entered mid-function at a block that reads a GUI edit box, with a synthetic frame.
    GuiBlock(u64),
}

/// Names of the GUI edit-box readers whose call site marks where a dialog crackme's check starts.
const GUI_READERS: [&str; 3] = ["GetDlgItemTextA", "GetWindowTextA", "GetDlgItemInt"];

/// Imports that read user input, in any flavour the emulator can seed. Broader than
/// [`GUI_READERS`], which stays the dialog-specific list because a dialog needs a different calling
/// shape, not just a different name.
const INPUT_READERS: [&str; 30] = [
    "gets",
    "gets_s",
    "fgets",
    "scanf",
    "scanf_s",
    "fscanf",
    "sscanf",
    "__isoc99_scanf",
    "__isoc99_sscanf",
    "getchar",
    "getch",
    "getche",
    "fgetc",
    "getline",
    "ReadFile",
    "ReadConsoleA",
    "ReadConsoleW",
    "GetDlgItemTextA",
    "GetDlgItemTextW",
    "GetWindowTextA",
    "GetWindowTextW",
    "GetDlgItemInt",
    // C++ `cin >> n`, by its Itanium-ABI mangling (one symbol per integer type). The `cin` object
    // appears in 12% of corpus binaries, the largest family that had no reader hook, and a check
    // whose read is unhooked is invisible to extraction, confirmation and search alike.
    "_ZNSirsERi",
    "_ZNSirsERj",
    "_ZNSirsERs",
    "_ZNSirsERt",
    "_ZNSirsERl",
    "_ZNSirsERm",
    "_ZNSirsERx",
    "_ZNSirsERy",
];

/// Imports that compare a string or buffer — where a key check lands when it is not written inline.
const COMPARERS: [&str; 14] = [
    "strcmp",
    "strncmp",
    "stricmp",
    "strcmpi",
    "strcasecmp",
    "strncasecmp",
    "memcmp",
    "bcmp",
    "lstrcmpA",
    "lstrcmpW",
    "lstrcmpiA",
    "wcscmp",
    "mbscmp",
    "CompareStringA",
];

/// An import's name with the decoration a linker adds stripped, so one spelling matches them all:
/// `_strcmp`, `__imp__strcmp`, `strcmp@8`.
fn plain_import_name(text: &str) -> &str {
    let t = text.trim_start_matches('_');
    let t = t.strip_prefix("imp_").unwrap_or(t).trim_start_matches('_');
    t.split('@').next().unwrap_or(t)
}

/// Functions that **handle the input**: they call something that reads it, or something that
/// compares it. Best first — a function that does both is the check itself far more often than one
/// that only does one.
///
/// This selects by what a function *does*, which is why it is worth having alongside the
/// size/call-graph heuristics: those rank by shape and position, and on a corpus where `main` is
/// usually unidentifiable they fall back to address order. A function with no reader and no
/// comparer in it cannot produce an observable comparison against the input at all, so spending a
/// budget slot on it is wasted either way.
pub fn input_check_functions(program: &Program) -> Vec<u64> {
    let mut reads: Vec<u64> = Vec::new();
    let mut cmps: Vec<u64> = Vec::new();
    for (&addr, n) in &program.names {
        let name = plain_import_name(&n.text);
        let bucket = if INPUT_READERS.contains(&name) {
            &mut reads
        } else if COMPARERS.contains(&name) {
            &mut cmps
        } else {
            continue;
        };
        for x in program.xrefs(addr) {
            // A thunk (`jmp [slot]`) is not the caller; follow through to whoever called it.
            let callers: Vec<u64> = if program
                .functions
                .get(&x.from)
                .is_some_and(|f| f.kind == orress_analysis::FunctionKind::Thunk)
            {
                program.xrefs(x.from).iter().map(|t| t.from).collect()
            } else {
                vec![x.from]
            };
            for from in callers {
                if let Some(f) = program.function_containing(from)
                    && !bucket.contains(&f.entry)
                {
                    bucket.push(f.entry);
                }
            }
        }
    }
    let mut out: Vec<u64> = reads.iter().copied().filter(|a| cmps.contains(a)).collect();
    for a in reads.into_iter().chain(cmps) {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Functions that read a GUI edit box — a dialog crackme's check, wherever it lives.
///
/// Worth naming explicitly because a dialog procedure is never *called* by the program: its address
/// is handed to `DialogBoxParam` as a callback, so it has no call edge for a call-graph heuristic to
/// rank and can be missed entirely. Following the reader's own cross-references finds it regardless.
pub fn gui_check_functions(program: &Program) -> Vec<u64> {
    let mut out = Vec::new();
    for (&addr, n) in &program.names {
        if !GUI_READERS.contains(&n.text.trim_start_matches('_')) {
            continue;
        }
        for x in program.xrefs(addr) {
            if let Some(f) = program.function_containing(x.from)
                && !out.contains(&f.entry)
            {
                out.push(f.entry);
            }
        }
    }
    out
}

/// Block starts inside `func` that call a **GUI edit-box reader** (`GetDlgItemTextA` /
/// `GetWindowTextA` / `GetDlgItemInt`) — where a dialog crackme's check actually begins.
///
/// A dialog procedure only reaches that code for one message and one control id, so entering at
/// the function start falls straight through its `switch` and returns having read nothing. The
/// reader's own basic block is the honest entry point, and it needs no guessing.
fn gui_reader_blocks(program: &Program, func_entry: u64) -> Vec<u64> {
    let Some(func) = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (&addr, n) in &program.names {
        if !GUI_READERS.contains(&n.text.trim_start_matches('_')) {
            continue;
        }
        for x in program.xrefs(addr) {
            if let Some(b) = func.block_at(x.from)
                && !out.contains(&b.start)
            {
                out.push(b.start);
            }
        }
    }
    out.truncate(2); // the budget is shared with every other shape
    if std::env::var("ORRESS_DEBUG_GUI").is_ok() {
        let names: Vec<String> = program.names.values().map(|n| n.text.clone()).collect();
        eprintln!("[gui] func={func_entry:#x} blocks={out:?} names={names:?}");
    }
    out
}

/// The candidate as a plain decimal integer, if that is what it is — the only shape worth trying as
/// a numeric *argument* (a hex/octal reading is a property of the check's own format string, which
/// the reader stub applies; an argument has already been converted).
fn numeric_candidate(candidate: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(candidate).ok()?.trim();
    if s.is_empty() || s.len() > 20 {
        return None;
    }
    s.parse::<i64>().ok()
}

/// Whether a recovered number is really an **address** in the program's own image rather than a
/// key someone would type. The numeric taint follows values through registers and stack slots, and
/// a pointer that ends up compared against itself is indistinguishable, by value alone, from a
/// passing numeric check — so a "key" that is a live address in this binary is rejected. The three
/// false confirmations that motivated this were all addresses of the input buffer in `.data`.
///
/// Small values are kept: a plausible key like `252` can also be a valid file offset, and the
/// region test is about *mapped* addresses, which start well above any number a person would type.
fn looks_like_address(program: &Program, value: u64) -> bool {
    value >= 0x1000 && program.memory.contains(value)
}

/// How the candidate text could have been converted to a number by the check: as a decimal, and as
/// hex, since a `%x` crackme's key is typed in hex. Used to verify that a passing numeric
/// comparison really matched *this* candidate rather than some unrelated pair of equal values.
fn candidate_numbers(candidate: &[u8]) -> Vec<u64> {
    let Ok(s) = std::str::from_utf8(candidate) else {
        return Vec::new();
    };
    let s = s.trim();
    if s.is_empty() || s.len() > 20 {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Ok(v) = s.parse::<i64>() {
        out.push(v as u64);
        out.push(v as u32 as u64);
    }
    if let Ok(v) = u64::from_str_radix(s.trim_start_matches("0x"), 16) {
        out.push(v);
    }
    out.dedup();
    out
}

/// What one compare-hook run saw.
#[derive(Debug, Clone, Copy, Default)]
struct RunOutcome {
    /// Which of the check's comparisons passed for this candidate, if any. `None` = none passed.
    pass: Option<ComparePass>,
    /// How many comparisons against the seeded input were observed at all, passing or not. Zero
    /// means the run never reached a check that looked at the input — which is the precondition
    /// every oracle here depends on, so it is worth reporting separately from a plain failure.
    observed: usize,
}

/// One compare-hook run on `candidate`. See [`Shape`] for what the calling conventions mean.
fn compare_run(
    program: &Program,
    entry: u64,
    candidate: &[u8],
    abi: Abi,
    shape: Shape,
) -> RunOutcome {
    let mut emu = orress_emu::Emulator::new();
    emu.mem = emu_image(program);
    emu.hooks = import_hooks(program);
    emu.budget = COMPARE_BUDGET;
    emu.seed_input(candidate.to_vec());
    emu.record_compares(true);

    let args: Vec<u64> = match shape {
        Shape::Number => {
            emu.seed_num_arg(0);
            let Some(v) = numeric_candidate(candidate) else {
                return RunOutcome::default();
            };
            vec![v as u64]
        }
        _ => {
            // Place the candidate in memory and pass `(ptr, len)`, so a check that is *handed* its
            // input is seeded too — most of the corpus links its reader statically and unnamed, so
            // there is no `gets`/`scanf` stub to inject through.
            let base = input_placement(program);
            emu.mem.map_zeroed(base, candidate.len() as u64 + 16);
            emu.mem.write_bytes(base, candidate);
            emu.mark_input_region(base, base + candidate.len() as u64);
            vec![base, candidate.len() as u64]
        }
    };
    // A later fault is fine — the comparison that decides the verdict has already happened.
    match shape {
        Shape::GuiBlock(block) => {
            let _ = emu.run_block(block, abi);
        }
        _ => {
            let _ = emu.call(entry, &args, abi);
        }
    }

    let observed =
        emu.compares().len() + emu.int_compares().len() + usize::from(emu.inline_key().is_some());

    // What the check may legitimately have compared: the candidate, and — for a keygen pair fed
    // as `name\nserial`, where each read takes one line — either line on its own.
    let expected: Vec<&[u8]> = std::iter::once(candidate)
        .chain(
            candidate
                .split(|&b| b == b'\n')
                .filter(|l| !l.is_empty() && l.len() != candidate.len()),
        )
        .collect();

    // Inline per-byte check: `inline_key` is the expected byte at every compared offset, with gaps
    // filled by the seed. Seeded with the candidate, it equals the candidate exactly iff every
    // compared byte matched it — i.e. the candidate is the accepted input.
    if let Some(k) = emu.inline_key()
        && !k.is_empty()
        && expected
            .iter()
            .any(|e| k.len() <= e.len() && k.as_slice() == &e[..k.len()])
    {
        return RunOutcome {
            pass: Some(ComparePass::Bytes),
            observed,
        };
    }
    // Library compare: the input operand equals the value it was compared against.
    if emu
        .compares()
        .iter()
        .any(|(a, b)| a == b && expected.contains(&a.as_slice()))
    {
        return RunOutcome {
            pass: Some(ComparePass::Bytes),
            observed,
        };
    }
    // Numeric check: the parsed input was compared whole against a number and matched. Three
    // guards, each of which a real false positive walked through:
    //   * zero is excluded — an unconverted or uninitialised value is also 0, so `cmp eax, 0`
    //     would confirm anything;
    //   * the matching value must be a reading of *this candidate* rather than merely some equal
    //     pair the run happened to produce. "The input side is the candidate by construction" only
    //     holds while the taint is right, and that is exactly what fails here; and
    //   * an address in the program's image is not a key (see `looks_like_address`).
    let want = candidate_numbers(candidate);
    let hit = emu
        .int_compares()
        .iter()
        .any(|&(x, y)| x == y && x != 0 && want.contains(&x) && !looks_like_address(program, x));
    RunOutcome {
        pass: hit.then_some(ComparePass::Number),
        observed,
    }
}

/// **Precondition diagnostic.** How many comparisons against a seeded probe input a run of this
/// function observes, taking the best of the calling shapes. Zero means the compare-hook never
/// reached a check that looked at the input, so neither extraction nor confirmation can work there
/// — which is a different, and far more actionable, failure than "the candidate was wrong".
pub fn compare_observations(program: &Program, func_entry: u64, probe: &[u8], abi: Abi) -> usize {
    if abi_for(program).is_none() {
        return 0;
    }
    let Some(entry) = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))
        .map(|f| f.entry)
    else {
        return 0;
    };
    let mut shapes = vec![Shape::Pointer, Shape::Number];
    shapes.extend(
        gui_reader_blocks(program, entry)
            .into_iter()
            .map(Shape::GuiBlock),
    );
    shapes
        .into_iter()
        .map(|s| compare_run(program, entry, probe, abi, s).observed)
        .max()
        .unwrap_or(0)
}

/// Every basic-block start in the program — what a reachability run watches. Program-wide rather
/// than one function's, because a check usually prints its verdict in its *caller*.
fn block_sites(program: &Program) -> HashSet<u64> {
    program
        .functions
        .values()
        .flat_map(|f| f.blocks.iter().map(|b| b.start))
        .collect()
}

/// **Oracle-free confirmation, third signal: differential reachability.** Emulate `func_entry` on
/// `candidate` and report which of the program's basic blocks the run *reached*.
///
/// The two other signals both need something recognisable — an observable comparison
/// ([`compare_satisfied`]) or a success *string* ([`emulate_outcome`]). Many checks have neither: a
/// hash/checksum check compares a computed value the taint can't follow, an SSE `pcmpeqb` compare
/// is invisible to the per-byte oracle, and most binaries carry no "Correct" text at all. What such
/// a check still does is **branch** — so the accepting input is the one that reaches code no wrong
/// input reaches, which needs no names, no strings and no model of the comparison.
///
/// This returns the raw evidence for one input; the caller forms the differential by comparing the
/// candidate's blocks against those of several same-shaped wrong twins (a block only the candidate
/// reaches, *and* a block every twin reaches but it does not). `None` when the architecture is
/// unsupported, the function is unknown, or the program has no block structure to watch.
pub fn reached_blocks(
    program: &Program,
    func_entry: u64,
    candidate: &[u8],
    abi: Abi,
) -> Option<Vec<u64>> {
    abi_for(program)?;
    let entry = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))?
        .entry;
    let sites = block_sites(program);
    if sites.len() < 2 {
        return None; // nothing to tell two paths apart with
    }

    let mut emu = orress_emu::Emulator::new();
    emu.mem = emu_image(program);
    emu.hooks = import_hooks(program);
    emu.budget = COMPARE_BUDGET;
    emu.seed_input(candidate.to_vec());
    // Seed both shapes at once: a hooked reader picks the seed up by itself, and a check that is
    // handed its input gets `(ptr, len)`. No compare recording — only the path matters here.
    let base = input_placement(program);
    emu.mem.map_zeroed(base, candidate.len() as u64 + 16);
    emu.mem.write_bytes(base, candidate);
    emu.trace_sites(sites);
    let _ = emu.call(entry, &[base, candidate.len() as u64], abi);
    Some(emu.sites_hit().to_vec())
}

/// The outcome of emulating a check on a concrete candidate: which verdict block execution reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Execution reached a block that prints/references a success string ("Correct", "Access granted").
    Accept,
    /// Execution reached a failure-string block ("Wrong", "Incorrect") first.
    Reject,
    /// Neither verdict block was reached (ran to return, faulted, or the program has no such strings).
    Unknown,
}

/// Instruction addresses (anywhere in the program) that reference a success- or a failure-indicator
/// string — the two verdict sites a console crackme prints its result from.
fn verdict_sites(program: &Program) -> (HashSet<u64>, HashSet<u64>) {
    let (mut win, mut lose) = (HashSet::new(), HashSet::new());
    for (&addr, text) in &program.string_refs {
        let set = if is_success_text(text) {
            Some(&mut win)
        } else if is_fail_text(text) {
            Some(&mut lose)
        } else {
            None
        };
        if let Some(set) = set {
            for x in program.xrefs(addr) {
                set.insert(x.from);
            }
        }
    }
    (win, lose)
}

/// Functions that reference a verdict string ("Correct" / "Wrong") — in a console crackme that is
/// the check itself, or `main` inlining it. Success-referencing functions come first, then
/// failure-referencing ones; each entry appears once.
///
/// This is a *targeting* signal: a caller that can only afford to emulate a handful of functions
/// per binary (see CRACKEN's confirm budget) should spend them here rather than on whatever the
/// generic size/call-graph heuristics rank first.
pub fn verdict_functions(program: &Program) -> Vec<u64> {
    let (win, lose) = verdict_sites(program);
    let mut out: Vec<u64> = Vec::new();
    for set in [&win, &lose] {
        let mut entries: Vec<u64> = set
            .iter()
            .filter_map(|&site| program.function_containing(site).map(|f| f.entry))
            .collect();
        entries.sort_unstable();
        entries.dedup();
        for e in entries {
            if !out.contains(&e) {
                out.push(e);
            }
        }
    }
    out
}

/// Whether a referenced string reads like a *rejection* verdict (the inverse of [`is_success_text`]).
fn is_fail_text(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    const FAIL: &[&str] = &[
        "incorrect",
        "wrong",
        "invalid",
        "denied",
        "fail",
        "unsuccessful",
        "try again",
        "sorry",
        "not correct",
        "no match",
        "nope",
        "bad ",
    ];
    FAIL.iter().any(|m| t.contains(m))
}

/// **Oracle-free confirmation.** Concretely emulate `func_entry` on a known `candidate` and report
/// which verdict block it reaches — WITHOUT running the real binary, so a candidate key can be
/// confirmed even for a sample that can't be run here (it segfaults on this host, is a GUI app, or
/// reads input through an API the sandbox can't drive) as long as its check emulates cleanly.
///
/// The verdict is *where execution goes*, not the return register: a crackme reports accept/reject
/// by branching to a "Correct"/"Wrong" print site, and typically returns the same value either way.
/// We breakpoint every success- and failure-string reference in the program and report whichever is
/// reached first. The candidate is placed both at the pointer passed as the first argument *and*
/// into the seeded `ReadInput` stub, so the check sees it whether it takes `(ptr, len)` arguments or
/// reads its input internally (`gets`/`scanf`/`fgets`).
///
/// Use differentially: a candidate is the key when it reaches `Accept` while same-shaped wrong
/// inputs reach `Reject`. `Unknown` for an unsupported architecture, an unknown function, or a
/// program with no recognisable verdict strings.
pub fn emulate_outcome(program: &Program, func_entry: u64, candidate: &[u8], abi: Abi) -> Verdict {
    if abi_for(program).is_none() {
        return Verdict::Unknown;
    }
    let Some(func) = program
        .functions
        .get(&func_entry)
        .or_else(|| program.function_containing(func_entry))
    else {
        return Verdict::Unknown;
    };
    let (win, lose) = verdict_sites(program);
    let dbg = std::env::var("CRACKEN_DEBUG_CONFIRM").is_ok();
    if win.is_empty() {
        if dbg {
            eprintln!(
                "[outcome] no success-string sites (win=0 lose={})",
                lose.len()
            );
        }
        return Verdict::Unknown; // nothing to steer toward — the return-value check can't help here
    }

    let input_base = input_placement(program);
    let mut mem = emu_image(program);
    mem.map_zeroed(input_base, candidate.len() as u64 + 16);
    mem.write_bytes(input_base, candidate);

    let mut emu = orress_emu::Emulator::new();
    emu.mem = mem;
    emu.hooks = import_hooks(program);
    emu.budget = COMPARE_BUDGET;
    emu.seed_input(candidate.to_vec());
    emu.breakpoints = win.iter().chain(lose.iter()).copied().collect();

    let args = [input_base, candidate.len() as u64];
    let stop = emu.call_watch(func.entry, &args, abi);
    let verdict = match stop {
        Ok(orress_emu::Stop::Breakpoint(ip)) if win.contains(&ip) => Verdict::Accept,
        Ok(orress_emu::Stop::Breakpoint(ip)) if lose.contains(&ip) => Verdict::Reject,
        _ => Verdict::Unknown,
    };
    if dbg {
        eprintln!(
            "[outcome] func={func_entry:#x} win={} lose={} cand={:?} stop={stop:?} -> {verdict:?}",
            win.len(),
            lose.len(),
            String::from_utf8_lossy(candidate)
        );
    }
    verdict
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
        .filter(|b| {
            verdict_const(program, b) == Some(0) && reaches_ret_cleanly(program, func, b.start)
        })
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
            if best
                .as_ref()
                .is_none_or(|b| sol.constraints > b.constraints)
            {
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
        .filter(|b| {
            verdict_const(program, b) == Some(0) && reaches_ret_cleanly(program, func, b.start)
        })
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
        "incorrect",
        "wrong",
        "invalid",
        "denied",
        "fail",
        "unsuccessful",
        "try again",
        "sorry",
        "error",
        "not correct",
        "no match",
    ];
    if FAIL.iter().any(|m| t.contains(m)) {
        return false;
    }
    const WIN: &[&str] = &[
        "correct",
        "congrat",
        "you win",
        "access granted",
        "well done",
        "good job",
        "accepted",
        "unlocked",
        "right password",
        "right key",
        "right serial",
        "winner",
        "you did it",
        "you got it",
        "flag{",
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
///
/// The last one is **numeric**: an `scanf("%d")`/`atoi` reader converts its input, and `"AAAA"`
/// converts to nothing — the destination stays zero and the check's comparison is never observed.
/// A digit seed makes the whole-value comparison of an "enter the number" crackme visible, which is
/// what turns it into a recovered key (see [`CompareRecovery::keys`]).
const COMPARE_SEEDS: [&[u8]; 4] = [b"AAAAAAAAAAAAAAAA", b"AAAAAAAA", b"AAAA", b"12345"];
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
fn run_seed(program: &Program, func_entry: u64, abi: Abi, seed: &[u8]) -> (Vec<Vec<u8>>, Vec<u64>) {
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
        // Also place the seed in memory and pass `(ptr, len)`: a check that is *handed* its input
        // has no reader to inject through, and most of the corpus links its reader statically and
        // unnamed. A function that does read internally overrides this region from its stub.
        let base = input_placement(program);
        emu.mem.map_zeroed(base, cur.len() as u64 + 16);
        emu.mem.write_bytes(base, &cur);
        emu.mark_input_region(base, base + cur.len() as u64);
        let _ = emu.call(func_entry, &[base, cur.len() as u64], abi);

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
        // Collect NUMERIC leads: the value a parsed numeric input was compared against, as the
        // decimal text a user would type. Only equality comparisons are recorded (see
        // `orress_emu`'s equality gate), and the seeded side is excluded, so what is left is the
        // number the check wants. This is the dynamic counterpart of scraping `cmp eax, imm`
        // immediates statically: it sees through a value the program *computed* and it cannot
        // mistake an unrelated constant for a key, because the input had to reach the comparison.
        for &(mine, expected) in emu.int_compares() {
            if mine == expected || expected == 0 {
                continue; // an echo, or an uninitialised zero
            }
            if looks_like_address(program, expected) {
                continue; // a pointer the taint followed, not a number anyone would type
            }
            for text in numeric_lead_texts(expected) {
                if text.as_slice() != cur.as_slice() && !keys.contains(&text) {
                    keys.push(text);
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
/// How a compared-against number would have been typed: as a decimal, and — when the value is
/// small enough to be plausible either way — as its signed reading too, since a 32-bit compare of a
/// negative constant shows up here as a large unsigned value.
fn numeric_lead_texts(value: u64) -> Vec<Vec<u8>> {
    let mut out = vec![value.to_string().into_bytes()];
    let signed = value as i64;
    if signed < 0 {
        out.push(signed.to_string().into_bytes());
    }
    // A 32-bit `cmp eax, -5` arrives as 0xffff_fffb; offer the small negative reading as well.
    if value > u64::from(u32::MAX) / 2 && value <= u64::from(u32::MAX) {
        let as_i32 = value as u32 as i32;
        out.push(as_i32.to_string().into_bytes());
    }
    out.retain(|t| t.len() <= 20);
    out.dedup();
    out
}

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
