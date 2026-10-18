//! The ORRESS decompiler: turns x86 / x86-64 and ARM64 (AArch64) functions into Rust-syntax
//! pseudocode (or, in port mode, a compilable Rust scaffold).
//!
//! Pipeline (modelled on decy's C-to-Rust translation, but starting from machine code):
//!
//! 1. [`lift`]: instructions -> a small IR of assignments, loads, stores and calls.
//! 2. [`simplify`]: forward substitution, constant folding and dead-code removal
//!    turn register shuffling into expressions; argument registers become parameters.
//! 3. [`structure`]: jumps become `if` / `else`, `while`, `loop`, `break`, `continue`.
//! 4. [`types`]: decy-style type recovery from how values are used (`&[u8]`, `&mut T`,
//!    `bool`, signedness).
//! 5. [`print`](mod@print): Rust syntax, as tokens tagged with their source address.
//!
//! The output is pseudocode for reading, not code that compiles: memory the decompiler
//! cannot type is shown as `read::<u32>(addr)` / `write::<u32>(addr, value)`.

pub mod arm64;
#[cfg(feature = "compile-check")]
pub mod compile;
pub mod deobfuscate;
pub mod ir;
pub mod lift;
pub mod print;
pub mod simplify;
pub mod ssa;
pub mod structure;
pub mod types;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use orress_analysis::{FunctionKind, Isa, Program};
use orress_loaders::Format;

pub use lift::Convention;
pub use print::{Line, Span, TokKind};

/// A decompiled function.
#[derive(Clone, Debug)]
pub struct Output {
    pub entry: u64,
    pub name: String,
    pub lines: Vec<Line>,
}

impl Output {
    pub fn text(&self) -> String {
        let mut s = String::new();
        for l in &self.lines {
            s.push_str(&l.text());
            s.push('\n');
        }
        s
    }

    /// The output line for a machine address (the last line at or before it).
    pub fn line_for(&self, addr: u64) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (i, l) in self.lines.iter().enumerate() {
            if let Some(a) = l.addr
                && a <= addr
                && best.is_none_or(|(_, b)| a > b)
            {
                best = Some((i, a));
            }
        }
        best.map(|(i, _)| i)
    }
}

/// Why a function cannot be decompiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    NoFunction(u64),
    /// An instruction set the decompiler has no front end for. (x86, x86-64 and ARM64 are all
    /// supported today; this is the boundary a new ISA's `Isa` variant meets first.)
    Unsupported(Isa),
    /// The function is too big to decompile in reasonable time and memory (a mis-detected function
    /// spanning a huge region, or generated/obfuscated code).
    TooLarge {
        insns: usize,
        blocks: usize,
    },
}

/// Functions with more instructions than this are refused with [`Error::TooLarge`].
pub const MAX_INSNS: usize = 20_000;
/// Functions with more basic blocks than this are refused with [`Error::TooLarge`].
pub const MAX_BLOCKS: usize = 5_000;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFunction(a) => write!(f, "no function at {a:#x}"),
            Self::Unsupported(isa) => write!(
                f,
                "the decompiler supports x86, x86-64 and ARM64, not {isa:?} (yet)"
            ),
            Self::TooLarge { insns, blocks } => write!(
                f,
                "function too large to decompile ({insns} instructions, {blocks} blocks; the \
                 limit is {MAX_INSNS} instructions or {MAX_BLOCKS} blocks)"
            ),
        }
    }
}

/// The calling convention binaries of this format use.
pub fn convention(format: Format) -> Convention {
    match format {
        Format::Pe | Format::Coff => Convention::Win64,
        _ => Convention::SysV,
    }
}

fn lifter<'a>(
    program: &'a Program,
    conv: Convention,
    counts: &'a HashMap<u64, usize>,
) -> lift::Lifter<'a> {
    lift::Lifter {
        program,
        conv,
        param_counts: counts,
    }
}

/// Lifts one function to IR with the right architecture front end.
fn lift_function(
    program: &Program,
    f: &orress_analysis::Function,
    conv: Convention,
    counts: &HashMap<u64, usize>,
) -> Vec<ir::Block> {
    if program.isa == Isa::Arm64 {
        arm64::Arm64Lifter {
            program,
            param_counts: counts,
        }
        .lift(f)
    } else {
        lifter(program, conv, counts).lift(f)
    }
}

/// The shared result of the lift → simplify → structure → types pipeline, before printing.
struct Decompiled {
    entry: u64,
    name: String,
    sig: types::Signature,
    locals: std::collections::BTreeMap<ir::Var, (ir::Width, bool)>,
    float_locals: std::collections::BTreeSet<ir::Var>,
    vec_locals: std::collections::BTreeMap<ir::Var, (u8, ir::Lane)>,
    usize_locals: std::collections::BTreeSet<ir::Var>,
    returns: bool,
    body: Vec<structure::Node>,
    /// Deobfuscation passes that fired on this function (for a header note), e.g. "control-flow
    /// flattening".
    deobfuscated: Vec<&'static str>,
}

/// Runs the decompilation pipeline for the function containing `addr`, up to (but not including)
/// printing — so the result can be rendered as readable pseudocode or as a Rust port.
fn run(program: &Program, addr: u64, conv: Convention) -> Result<Decompiled, Error> {
    if !matches!(program.isa, Isa::X86 | Isa::X64 | Isa::Arm64) {
        return Err(Error::Unsupported(program.isa));
    }
    // ARM64 uses its own calling convention regardless of the caller's x86 choice.
    let conv = if program.isa == Isa::Arm64 {
        Convention::Aarch64
    } else {
        conv
    };
    let f = program
        .functions
        .get(&addr)
        .or_else(|| program.function_containing(addr))
        .ok_or(Error::NoFunction(addr))?;
    let (insns, n_blocks) = (f.insn_count(), f.blocks.len());
    if insns > MAX_INSNS || n_blocks > MAX_BLOCKS {
        return Err(Error::TooLarge {
            insns,
            blocks: n_blocks,
        });
    }

    // Parameter counts of the callees, so calls get the right arguments.
    let empty = HashMap::new();
    let mut counts = HashMap::new();
    for &c in &f.calls {
        if let Some(callee) = program.functions.get(&c)
            && callee.kind != FunctionKind::Thunk
        {
            let blocks = lift_function(program, callee, conv, &empty);
            counts.insert(c, simplify::param_count(&blocks, c, conv));
        }
    }

    let mut blocks = lift_function(program, f, conv, &counts);
    let n_int = simplify::param_count(&blocks, f.entry, conv);
    let n_float = simplify::float_param_count(&blocks, f.entry, conv);
    // Integer parameters bind first (GPR order), then floating-point parameters (XMM order);
    // the ABI loses the original interleaving, so register order is the honest presentation.
    let mut arg_map: Vec<(ir::Var, usize)> = conv.arg_regs()[..n_int]
        .iter()
        .enumerate()
        .map(|(i, &r)| (ir::Var::Reg(r), i))
        .collect();
    arg_map.extend(
        simplify::float_arg_regs(conv)[..n_float]
            .iter()
            .enumerate()
            .map(|(j, &x)| (ir::Var::Xmm(x), n_int + j)),
    );
    // Retarget a floating-point return (xmm0) before binding, so the return expression's
    // register references bind to parameters on paths where xmm0 still holds an argument. Run it
    // before register splitting so xmm0's return-reaching web keeps the plain name.
    let float_ret = simplify::retarget_float_return(&mut blocks);
    // Preserve the upper bits of 8/16-bit register writes where a reaching definition (a prior
    // wider write, or a parameter register) makes them live. Runs before register splitting so the
    // inserted `old` reference binds to the reaching definition's live range.
    lift::restore_partial_writes(&mut blocks, f.entry, &conv.arg_regs()[..n_int]);
    // Split reused registers (GP and XMM) into per-live-range variables before binding, so each
    // use types independently and a reused accumulator/scratch register is disambiguated.
    ssa::split_registers(&mut blocks, f.entry, conv.arg_regs());
    simplify::bind_params(&mut blocks, f.entry, &arg_map);
    // Undo control-flow flattening before simplifying, so a flattened function's dispatcher is
    // bypassed and the normal dead-code/merge passes then remove it.
    let mut deobfuscated = Vec::new();
    if deobfuscate::unflatten(&mut blocks) {
        deobfuscated.push("control-flow flattening");
    }
    simplify::simplify(&mut blocks, f.entry);
    let params = n_int + n_float;
    let returns = simplify::returns_value(&blocks) || float_ret.is_some();
    if !returns {
        simplify::drop_void_return(&mut blocks);
    }
    let mut sig = types::infer(&blocks, params, returns, n_int, float_ret);
    let locals = types::locals(&blocks);
    let float_locals = types::float_locals(&blocks);
    let vec_locals = types::vec_locals(&blocks);
    let usize_locals = types::usize_locals(&blocks, &sig);
    let mut body = structure::structure(blocks, f.entry);
    structure::normalize_do_while(&mut body);
    // Pointer-walk loops become element iteration first (which may retype a parameter to a
    // slice), then the index-based and reduction passes run over the resulting `for`.
    structure::recover_pointer_loops(&mut body, &mut sig, conv.arg_regs());
    structure::recover_for_loops(&mut body);
    structure::recover_iterators(&mut body, &sig);
    structure::recover_zip_map(&mut body, &sig);
    structure::recover_sum(&mut body);
    structure::recover_search(&mut body);
    structure::recover_fill(&mut body);
    structure::recover_reduction(&mut body, &sig);
    let name = program
        .name(f.entry)
        .map_or_else(|| format!("sub_{:x}", f.entry), |n| n.text.clone());

    Ok(Decompiled {
        entry: f.entry,
        name,
        sig,
        locals,
        float_locals,
        vec_locals,
        usize_locals,
        returns,
        body,
        deobfuscated,
    })
}

/// Decompiles the function containing `addr` into readable Rust-syntax pseudocode.
pub fn decompile(program: &Program, addr: u64, conv: Convention) -> Result<Output, Error> {
    decompile_with(program, addr, conv, &types::TypeHints::default())
}

/// Like [`decompile`], but applies user type hints: names recovered struct parameters and
/// their fields from the user's catalog, and overlays any function prototype.
pub fn decompile_with(
    program: &Program,
    addr: u64,
    conv: Convention,
    hints: &types::TypeHints,
) -> Result<Output, Error> {
    let mut d = run(program, addr, conv)?;
    types::apply_hints(&mut d.sig, d.entry, hints);
    let mut lines = print::Printer::new(
        program,
        &d.sig,
        &d.locals,
        &d.float_locals,
        &d.vec_locals,
        &d.usize_locals,
        d.returns,
    )
    .function(d.entry, &d.name, &d.body);
    // A header note when deobfuscation reshaped the function, so the reader knows the recovered
    // control flow differs from the raw bytes (and why it reads cleanly).
    if !d.deobfuscated.is_empty() {
        let note = format!(
            "// deobfuscated by ORRESS: {} undone",
            d.deobfuscated.join(", ")
        );
        lines.insert(
            0,
            print::Line {
                addr: None,
                indent: 0,
                spans: vec![print::Span {
                    text: note,
                    kind: print::TokKind::Comment,
                    target: None,
                }],
            },
        );
    }
    Ok(Output {
        entry: d.entry,
        name: d.name,
        lines,
    })
}

/// The compilable-scaffold prelude: helpers the port output references.
pub const PORT_PRELUDE: &str = "// Best-effort Rust port generated by ORRESS — review before use.\n\
    // Un-lifted instructions are kept as inline `asm!`; untyped memory uses the raw\n\
    // read/write helpers below. External `sub_*`/imports and globals are stubbed at the\n\
    // end for you to fill in.\n\
    #![allow(unused, non_snake_case, non_upper_case_globals, clippy::all)]\n\
    \n\
    mod orress_rt {\n\
    \x20   /// Raw read of `T` from an absolute address ORRESS could not type.\n\
    \x20   pub fn read<T: Copy>(addr: u64) -> T {\n\
    \x20       unsafe { core::ptr::read((addr as usize) as *const T) }\n\
    \x20   }\n\
    \x20   /// Raw write of `T` to an absolute address.\n\
    \x20   pub fn write<T>(addr: u64, value: T) {\n\
    \x20       unsafe { core::ptr::write((addr as usize) as *mut T, value) }\n\
    \x20   }\n\
    \x20   /// A value ORRESS could not recover; replace it as you port.\n\
    \x20   pub fn unknown<T>(what: &str) -> T {\n\
    \x20       panic!(\"ORRESS: unrecovered value: {what}\")\n\
    \x20   }\n\
    \x20   // Packed-vector (SIMD) helpers: vectors are modelled as `[T; N]` lane arrays.\n\
    \x20   pub fn vload<T: Copy, const N: usize>(addr: u64) -> [T; N] {\n\
    \x20       unsafe { core::ptr::read((addr as usize) as *const [T; N]) }\n\
    \x20   }\n\
    \x20   pub fn vstore<T, const N: usize>(addr: u64, v: [T; N]) {\n\
    \x20       unsafe { core::ptr::write((addr as usize) as *mut [T; N], v) }\n\
    \x20   }\n\
    \x20   pub fn vadd<T: core::ops::Add<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] + b[i]; } r\n\
    \x20   }\n\
    \x20   pub fn vsub<T: core::ops::Sub<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] - b[i]; } r\n\
    \x20   }\n\
    \x20   pub fn vmul<T: core::ops::Mul<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] * b[i]; } r\n\
    \x20   }\n\
    \x20   pub fn vdiv<T: core::ops::Div<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] / b[i]; } r\n\
    \x20   }\n\
    \x20   pub fn vand<T: core::ops::BitAnd<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] & b[i]; } r\n\
    \x20   }\n\
    \x20   pub fn vor<T: core::ops::BitOr<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] | b[i]; } r\n\
    \x20   }\n\
    \x20   pub fn vxor<T: core::ops::BitXor<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { r[i] = a[i] ^ b[i]; } r\n\
    \x20   }\n\
    \x20   /// Load/store `N` lanes starting at element `i` of a slice (a vector access whose base\n\
    \x20   /// is a `&[T]` parameter, so the slice type serves both the vector and element uses).\n\
    \x20   pub fn vload_slice<T: Copy, const N: usize>(s: &[T], i: usize) -> [T; N] {\n\
    \x20       let mut r = [s[i]; N]; for k in 0..N { r[k] = s[i + k]; } r\n\
    \x20   }\n\
    \x20   pub fn vstore_slice<T: Copy, const N: usize>(s: &mut [T], i: usize, v: [T; N]) {\n\
    \x20       for k in 0..N { s[i + k] = v[k]; }\n\
    \x20   }\n\
    \x20   // `PartialOrd` (not `Ord`) so these serve both integer and floating-point lanes.\n\
    \x20   pub fn vmax<T: PartialOrd + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { if b[i] > a[i] { r[i] = b[i]; } } r\n\
    \x20   }\n\
    \x20   pub fn vmin<T: PartialOrd + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = a; for i in 0..N { if b[i] < a[i] { r[i] = b[i]; } } r\n\
    \x20   }\n\
    \x20   pub fn vandn<T: core::ops::BitAnd<Output = T> + core::ops::Not<Output = T> + Copy, const N: usize>(a: [T; N], b: [T; N]) -> [T; N] {\n\
    \x20       let mut r = b; for i in 0..N { r[i] = !a[i] & b[i]; } r\n\
    \x20   }\n\
    \x20   /// `pshufd`-style dword permute: lane i takes source lane `(imm >> 2i) & 3`.\n\
    \x20   pub fn vshuffle<T: Copy>(a: [T; 4], imm: u8) -> [T; 4] {\n\
    \x20       [a[(imm & 3) as usize], a[((imm >> 2) & 3) as usize],\n\
    \x20        a[((imm >> 4) & 3) as usize], a[((imm >> 6) & 3) as usize]]\n\
    \x20   }\n\
    }\n\n";

/// Transpiles the function containing `addr` into a compilable Rust scaffold (port mode): the
/// prelude, then the function with un-lifted instructions kept as inline `asm!`.
pub fn port(program: &Program, addr: u64, conv: Convention) -> Result<String, Error> {
    let d = run(program, addr, conv)?;
    let lines = print::Printer::new(
        program,
        &d.sig,
        &d.locals,
        &d.float_locals,
        &d.vec_locals,
        &d.usize_locals,
        d.returns,
    )
    .port_mode()
    .function(d.entry, &d.name, &d.body);
    let mut s = String::from(PORT_PRELUDE);
    for l in &lines {
        s.push_str(&l.text());
        s.push('\n');
    }
    s.push_str(&print::stub_decls(program, d.entry, &d.body));
    Ok(s)
}
