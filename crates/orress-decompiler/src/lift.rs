//! Lifting x86 / x86-64 machine code into the IR.

use std::collections::{HashMap, VecDeque};

use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};
use orress_analysis::{EdgeKind, Function, Program};

use crate::ir::*;

/// Which registers carry arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Convention {
    /// Windows x64: rcx, rdx, r8, r9.
    Win64,
    /// Linux/macOS x64 (System V): rdi, rsi, rdx, rcx, r8, r9.
    SysV,
    /// ARM64 (AAPCS64): x0–x7, result in x0 (which the IR models as register 0, like rax).
    Aarch64,
    /// RISC-V: a0–a7, result in a0 (the IR models a0 as register 0). See riscv.rs for the
    /// x-register -> IR register numbering.
    Riscv,
    /// MIPS o32: a0–a3, result in v0 (the IR models v0 as register 0). See mips.rs for the
    /// register numbering.
    Mips,
    /// MIPS n64 (the MIPS64 ABI): a0–a7 for integer arguments and $f12–$f19 for floats, result
    /// in v0. Uses the same IR register numbering as [`Convention::Mips`].
    Mips64,
    /// PowerPC (SysV / PowerOpen): r3–r10 for integer arguments, f1–f13 for floats, result in r3
    /// (the IR models r3 as register 0, like RISC-V's a0). See ppc.rs for the numbering.
    Ppc,
}

impl Convention {
    pub fn arg_regs(self) -> &'static [u8] {
        match self {
            Self::Win64 => &[RCX, RDX, R8, R9],
            Self::SysV => &[RDI, RSI, RDX, RCX, R8, R9],
            Self::Aarch64 => &[0, 1, 2, 3, 4, 5, 6, 7],
            // a0..a7 map to IR registers 0..7 (see riscv.rs).
            Self::Riscv => &[0, 1, 2, 3, 4, 5, 6, 7],
            // a0..a3 map to IR registers 1..4 (v0 is register 0, the result).
            Self::Mips => &[1, 2, 3, 4],
            // n64 adds a4..a7 ($8..$11), which map to IR registers 6..9 (see mips.rs reg_num).
            Self::Mips64 => &[1, 2, 3, 4, 6, 7, 8, 9],
            // r3..r10 map to IR registers 0..7 (r3 is register 0, the result).
            Self::Ppc => &[0, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    /// Registers a call may change (besides the result register).
    pub fn clobbered(self) -> &'static [u8] {
        match self {
            Self::Win64 => &[RCX, RDX, R8, R9, 10, 11],
            Self::SysV => &[RCX, RDX, RSI, RDI, R8, R9, 10, 11],
            // The AAPCS64 caller-saved set x1–x18 (x0 is the result, handled separately).
            Self::Aarch64 => &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            ],
            // RISC-V caller-saved: ra (8) and t0..t6 (9..15) in riscv.rs numbering.
            Self::Riscv => &[8, 9, 10, 11, 12, 13, 14, 15],
            // MIPS caller-saved in mips.rs numbering: v1(5), t0..t9(6..13,22,23), ra(24).
            Self::Mips => &[5, 6, 7, 8, 9, 10, 11, 12, 13, 22, 23, 24],
            // n64: a4..a7 ($8..$11, IR 6..9) are argument registers, so like a0..a3 they are not
            // in the clobbered set; the temporaries are t4..t7 ($12..$15, IR 10..13) and
            // t8/t9 (22/23), plus v1(5) and ra(24).
            Self::Mips64 => &[5, 10, 11, 12, 13, 22, 23, 24],
            // PowerPC volatile registers besides the arguments r3..r10: r0 (IR 8), r11 (11),
            // r12 (12). See ppc.rs for the numbering.
            Self::Ppc => &[8, 11, 12],
        }
    }
}

/// What the last flag-setting instruction computed.
#[derive(Clone, Debug)]
enum Flags {
    /// `cmp a, b` or `sub a, b`.
    Sub(Expr, Expr),
    /// `test a, b`.
    Test(Expr, Expr),
    /// Any other arithmetic or logic result.
    Result(Expr),
    /// `bt x, n` and friends: the carry flag is bit `n` of `x`.
    Bit(Expr, Expr),
    /// `comiss`/`comisd`: a floating-point compare. The jumps that read it (`ja`/`jb`/… — SSE
    /// sets the flags unsigned-style) become floating-point comparisons.
    FSub(Expr, Expr),
}

/// Number of parameters of well-known imported functions.
pub fn import_params(name: &str) -> Option<usize> {
    let n = name.trim_start_matches('_');
    Some(match n {
        "exit" | "free" | "puts" | "strlen" | "malloc" | "Sleep" | "ExitProcess"
        | "GetModuleHandleA" | "GetModuleHandleW" | "LoadLibraryA" | "LoadLibraryW"
        | "CloseHandle" | "abort" | "atoi" => 1,
        "strcmp" | "strcpy" | "strcat" | "strstr" | "fopen" | "GetProcAddress" | "calloc"
        | "realloc" | "strchr" => 2,
        "memcmp" | "memcpy" | "memset" | "memmove" | "strncmp" | "strncpy" | "fgets" | "read"
        | "write" => 3,
        "VirtualProtect" | "WriteFile" | "ReadFile" => 4,
        "IsDebuggerPresent" | "GetTickCount" | "GetLastError" | "getchar" | "rand" => 0,
        _ => return None,
    })
}

/// Imports that never return.
pub fn import_noreturn(name: &str) -> bool {
    matches!(
        name.trim_start_matches('_'),
        "exit"
            | "abort"
            | "ExitProcess"
            | "o_exit"
            | "o__exit"
            | "Exit"
            | "assert_fail"
            | "stack_chk_fail"
    )
}

/// The XMM-register number of a register, if it is one (`xmm0` → 0 … `xmm15` → 15).
fn xmm(r: Register) -> Option<u8> {
    r.is_xmm()
        .then(|| (r as u32).wrapping_sub(Register::XMM0 as u32) as u8)
        .filter(|&n| n < 16)
}

fn reg(r: Register) -> Option<(u8, Width)> {
    if !r.is_gpr() {
        return None;
    }
    // ah/bh/ch/dh are not modeled.
    if matches!(r, Register::AH | Register::BH | Register::CH | Register::DH) {
        return None;
    }
    Some((r.full_register().number() as u8, Width(r.size() as u8)))
}

pub struct Lifter<'a> {
    pub program: &'a Program,
    pub conv: Convention,
    /// Parameter counts of other functions, for call arguments.
    pub param_counts: &'a HashMap<u64, usize>,
}

struct State {
    rsp: i64,
    /// rbp = entry rsp + offset, when rbp is a frame pointer.
    rbp: Option<i64>,
    flags: Option<Flags>,
    /// Argument registers written since the last call (for argument counting).
    written: Vec<u8>,
    /// Still in the function prologue, where pushes only save registers.
    prologue: bool,
}

impl Lifter<'_> {
    fn decode(&self, addr: u64) -> Option<Instruction> {
        let bytes = self.program.memory.read(addr, 15)?;
        let bitness = if self.program.isa == orress_analysis::Isa::X86 {
            32
        } else {
            64
        };
        let mut d = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
        let i = d.decode();
        (!i.is_invalid()).then_some(i)
    }

    /// Reads a dense jump table's case targets (slot order), stopping at the first entry that
    /// is not a valid code address.
    fn jump_table(&self, base: u64, entry: u8) -> Option<Vec<u64>> {
        let mut cases = Vec::new();
        let mut slot = base;
        for _ in 0..1024 {
            let bytes = self.program.memory.read(slot, entry as usize)?;
            let target = match entry {
                8 => u64::from_le_bytes(bytes.try_into().ok()?),
                4 => u64::from(u32::from_le_bytes(bytes.try_into().ok()?)),
                _ => break,
            };
            if !self.program.memory.is_code(target) {
                break;
            }
            cases.push(target);
            slot += u64::from(entry);
        }
        (!cases.is_empty()).then_some(cases)
    }

    /// Lifts every block of `f`.
    pub fn lift(&self, f: &Function) -> Vec<Block> {
        let by_addr: HashMap<u64, usize> = f
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start, i))
            .collect();
        let mut entry_state: HashMap<u64, (i64, Option<i64>)> = HashMap::new();
        entry_state.insert(f.entry, (0, None));
        let mut queue: VecDeque<u64> = VecDeque::from([f.entry]);
        let mut out: HashMap<u64, Block> = HashMap::new();
        while let Some(addr) = queue.pop_front() {
            if out.contains_key(&addr) {
                continue;
            }
            let Some(&index) = by_addr.get(&addr) else {
                continue;
            };
            let (rsp, rbp) = entry_state[&addr];
            let (block, end) = self.lift_block(
                f,
                index,
                State {
                    rsp,
                    rbp,
                    flags: None,
                    written: Vec::new(),
                    prologue: addr == f.entry,
                },
            );
            for e in &f.blocks[index].succs {
                entry_state.entry(e.target).or_insert((end.rsp, end.rbp));
                queue.push_back(e.target);
            }
            out.insert(addr, block);
        }
        // Blocks not reachable by the walk above (rare) still get lifted.
        for (i, b) in f.blocks.iter().enumerate() {
            out.entry(b.start).or_insert_with(|| {
                let (block, _) = self.lift_block(
                    f,
                    i,
                    State {
                        rsp: 0,
                        rbp: None,
                        flags: None,
                        written: Vec::new(),
                        prologue: false,
                    },
                );
                block
            });
        }
        let mut blocks: Vec<Block> = out.into_values().collect();
        blocks.sort_by_key(|b| b.addr);
        blocks
    }

    fn lift_block(&self, f: &Function, index: usize, mut st: State) -> (Block, State) {
        let fb = &f.blocks[index];
        let mut stmts = Vec::new();
        let mut term = None;
        let mut term_addr = fb.start;
        for &addr in &fb.insns {
            let Some(ins) = self.decode(addr) else {
                stmts.push((addr, Stmt::Asm("(undecodable)".into(), Vec::new())));
                continue;
            };
            term_addr = addr;
            if let Some(t) = self.lift_insn(&ins, &mut st, &mut stmts) {
                term = Some(t);
            }
        }
        // A register-indirect `jmp` through a recovered offset jump table (a modern position-
        // independent `switch`): the analyzer resolved its ordered case targets, so structure it as
        // a multi-way Switch instead of the indirect tail call `lift_insn` produced. The absolute
        // table form is already lifted to a Switch directly, so skip it here.
        if !matches!(term, Some(Term::Switch(..)))
            && let Some(cases) = self.program.switch_tables.get(&term_addr)
            && cases.len() >= 2
        {
            // An index register we could not identify is shown as unknown, not guessed as rax.
            let scrut = self
                .switch_scrutinee(fb, &mut stmts)
                .unwrap_or_else(|| Expr::Unknown("switch index".into()));
            term = Some(Term::Switch(scrut, cases.clone()));
        }

        let term = term.unwrap_or_else(|| {
            // Fall-through into the next block.
            match fb
                .succs
                .iter()
                .find(|e| matches!(e.kind, EdgeKind::FallThrough | EdgeKind::Jump))
            {
                Some(e) => Term::Jump(e.target),
                None => Term::Stop,
            }
        });
        (
            Block {
                addr: fb.start,
                stmts,
                term,
                term_addr,
            },
            st,
        )
    }

    /// Scrutinee for an offset-table `switch`: the index into the table — i.e. the opcode/selector.
    /// The index register is read by the table load `mov reg, [base + idx*scale]` and then (in the
    /// offset form) clobbered by that same load, so by the terminator it no longer holds the index.
    /// We capture it in a synthetic `sel` variable assigned right before the load, where SSA still
    /// resolves it to the index value; copy-propagation then inlines `sel` to the opcode expression.
    fn switch_scrutinee(
        &self,
        fb: &orress_analysis::Block,
        stmts: &mut Vec<(u64, Stmt)>,
    ) -> Option<Expr> {
        for &addr in &fb.insns {
            let Some(ins) = self.decode(addr) else {
                continue;
            };
            if ins.memory_base() != Register::None
                && ins.memory_index() != Register::None
                && matches!(ins.memory_index_scale(), 4 | 8)
                && let Some((idx, _)) = reg(ins.memory_index())
            {
                let sel = Expr::Var(Var::Named("sel"), Width::B64);
                let at = stmts
                    .iter()
                    .position(|(a, _)| *a == addr)
                    .unwrap_or(stmts.len());
                stmts.insert(
                    at,
                    (
                        addr,
                        Stmt::Assign(Var::Named("sel"), Expr::Var(Var::Reg(idx), Width::B64)),
                    ),
                );
                return Some(sel);
            }
        }
        None
    }

    fn mem_addr(&self, ins: &Instruction, st: &State) -> Result<Expr, (Var, Width)> {
        let width = Width(ins.memory_size().size().clamp(1, 8) as u8);
        if ins.is_ip_rel_memory_operand() {
            return Ok(Expr::Addr(ins.ip_rel_memory_address()));
        }
        let base = ins.memory_base();
        let index = ins.memory_index();
        let disp = ins.memory_displacement64() as i64;
        if index == Register::None {
            match base.full_register() {
                Register::RSP | Register::ESP => return Err((Var::Stack(st.rsp + disp), width)),
                Register::RBP | Register::EBP if st.rbp.is_some() => {
                    return Err((Var::Stack(st.rbp.unwrap_or(0) + disp), width));
                }
                _ => {}
            }
        }
        let mut e: Option<Expr> = None;
        if base != Register::None {
            e = Some(match reg(base) {
                Some((r, _)) => Expr::Var(Var::Reg(r), Width::B64),
                None => Expr::Unknown(format!("{base:?}").to_lowercase()),
            });
        }
        if index != Register::None {
            let idx = match reg(index) {
                Some((r, _)) => Expr::Var(Var::Reg(r), Width::B64),
                None => Expr::Unknown(format!("{index:?}").to_lowercase()),
            };
            let scale = u64::from(ins.memory_index_scale());
            let scaled = if scale > 1 {
                Expr::bin(BinOp::Mul, idx, Expr::konst(scale, Width::B64), Width::B64)
            } else {
                idx
            };
            e = Some(match e {
                Some(b) => Expr::bin(BinOp::Add, b, scaled, Width::B64),
                None => scaled,
            });
        }
        let e = match (e, disp) {
            (None, d) => Expr::Addr(d as u64),
            (Some(b), 0) => b,
            (Some(b), d) if d < 0 => Expr::bin(
                BinOp::Sub,
                b,
                Expr::konst(d.unsigned_abs(), Width::B64),
                Width::B64,
            ),
            (Some(b), d) => Expr::bin(BinOp::Add, b, Expr::konst(d as u64, Width::B64), Width::B64),
        };
        Ok(e)
    }

    fn read(&self, ins: &Instruction, op: u32, st: &State) -> Expr {
        match ins.op_kind(op) {
            OpKind::Register => match reg(ins.op_register(op)) {
                Some((r, _)) if r == RSP => Expr::StackAddr(st.rsp),
                Some((r, w)) => Expr::Var(Var::Reg(r), w),
                None => Expr::Unknown(format!("{:?}", ins.op_register(op)).to_lowercase()),
            },
            OpKind::Memory => {
                let w = Width(ins.memory_size().size().clamp(1, 8) as u8);
                match self.mem_addr(ins, st) {
                    Ok(addr) => Expr::Load(Box::new(addr), w),
                    Err((var, w)) => Expr::Var(var, w),
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                let w = self.op_width(ins, 0, st);
                Expr::konst(ins.immediate(op), w)
            }
            _ => Expr::Unknown(String::from("?")),
        }
    }

    fn op_width(&self, ins: &Instruction, op: u32, _st: &State) -> Width {
        match ins.op_kind(op) {
            OpKind::Register => reg(ins.op_register(op)).map_or(Width::B64, |(_, w)| w),
            OpKind::Memory => Width(ins.memory_size().size().clamp(1, 8) as u8),
            _ => Width::B32,
        }
    }

    /// Writes `value` to operand `op`.
    fn write(
        &self,
        ins: &Instruction,
        op: u32,
        value: Expr,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let addr = ins.ip();
        match ins.op_kind(op) {
            OpKind::Register => {
                if let Some((r, w)) = reg(ins.op_register(op)) {
                    if (0..=9).contains(&r) {
                        st.written.push(r);
                    }
                    // 32-bit writes zero the upper half; 8/16-bit writes are treated as
                    // replacing the register (a simplification that reads naturally).
                    let value = if value.width() > w {
                        Expr::Cast(Box::new(value), w, false)
                    } else {
                        value
                    };
                    out.push((addr, Stmt::Assign(Var::Reg(r), value)));
                } else {
                    // A high-byte sub-register we don't model (ah/bh/ch/dh): keep the write
                    // visible as asm rather than silently dropping it.
                    out.push((addr, Stmt::Asm(format!("{ins}"), Vec::new())));
                }
            }
            OpKind::Memory => {
                let w = Width(ins.memory_size().size().clamp(1, 8) as u8);
                match self.mem_addr(ins, st) {
                    Ok(a) => out.push((addr, Stmt::Store(a, value, w))),
                    Err((var, _)) => out.push((addr, Stmt::Assign(var, value))),
                }
            }
            _ => out.push((addr, Stmt::Asm(format!("{ins}"), Vec::new()))),
        }
    }

    fn condition(&self, cc: ConditionCode, st: &State) -> Expr {
        use CmpOp::*;
        let unknown = || Expr::Unknown(format!("flags_{cc:?}"));
        match &st.flags {
            Some(Flags::Sub(a, b)) => {
                let (a, b) = (a.clone(), b.clone());
                match cc {
                    ConditionCode::e => Expr::cmp(Eq, a, b, false),
                    ConditionCode::ne => Expr::cmp(Ne, a, b, false),
                    ConditionCode::l => Expr::cmp(Lt, a, b, true),
                    ConditionCode::le => Expr::cmp(Le, a, b, true),
                    ConditionCode::g => Expr::cmp(Gt, a, b, true),
                    ConditionCode::ge => Expr::cmp(Ge, a, b, true),
                    ConditionCode::b => Expr::cmp(Lt, a, b, false),
                    ConditionCode::be => Expr::cmp(Le, a, b, false),
                    ConditionCode::a => Expr::cmp(Gt, a, b, false),
                    ConditionCode::ae => Expr::cmp(Ge, a, b, false),
                    ConditionCode::s => {
                        let w = a.width();
                        Expr::cmp(Lt, Expr::bin(BinOp::Sub, a, b, w), Expr::konst(0, w), true)
                    }
                    ConditionCode::ns => {
                        let w = a.width();
                        Expr::cmp(Ge, Expr::bin(BinOp::Sub, a, b, w), Expr::konst(0, w), true)
                    }
                    _ => unknown(),
                }
            }
            Some(Flags::Test(a, b)) => {
                let w = a.width();
                let x = if a == b {
                    a.clone()
                } else {
                    Expr::bin(BinOp::And, a.clone(), b.clone(), w)
                };
                let zero = Expr::konst(0, w);
                match cc {
                    ConditionCode::e | ConditionCode::be => Expr::cmp(Eq, x, zero, false),
                    ConditionCode::ne | ConditionCode::a => Expr::cmp(Ne, x, zero, false),
                    ConditionCode::s | ConditionCode::l => Expr::cmp(Lt, x, zero, true),
                    ConditionCode::ns | ConditionCode::ge => Expr::cmp(Ge, x, zero, true),
                    ConditionCode::le => Expr::cmp(Le, x, zero, true),
                    ConditionCode::g => Expr::cmp(Gt, x, zero, true),
                    _ => unknown(),
                }
            }
            Some(Flags::Result(r)) => {
                let w = r.width();
                let zero = Expr::konst(0, w);
                match cc {
                    ConditionCode::e => Expr::cmp(Eq, r.clone(), zero, false),
                    ConditionCode::ne => Expr::cmp(Ne, r.clone(), zero, false),
                    ConditionCode::s => Expr::cmp(Lt, r.clone(), zero, true),
                    ConditionCode::ns => Expr::cmp(Ge, r.clone(), zero, true),
                    ConditionCode::le => Expr::cmp(Le, r.clone(), zero, true),
                    ConditionCode::g => Expr::cmp(Gt, r.clone(), zero, true),
                    _ => unknown(),
                }
            }
            Some(Flags::Bit(x, n)) => {
                // Carry is bit `n` of `x`, so `jc`/`setc` ↔ `(x >> n) & 1 != 0`.
                let w = x.width();
                let bit = Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Shr, x.clone(), n.clone(), w),
                    Expr::konst(1, w),
                    w,
                );
                let zero = Expr::konst(0, w);
                match cc {
                    ConditionCode::b => Expr::cmp(Ne, bit, zero, false), // CF == 1
                    ConditionCode::ae => Expr::cmp(Eq, bit, zero, false), // CF == 0
                    _ => unknown(),
                }
            }
            Some(Flags::FSub(a, b)) => {
                let (a, b) = (a.clone(), b.clone());
                match cc {
                    ConditionCode::e => Expr::fcmp(Eq, a, b),
                    ConditionCode::ne => Expr::fcmp(Ne, a, b),
                    // SSE compares set CF/ZF as for an unsigned compare, so float `<`/`>` use
                    // the `b`/`a` (below/above) jumps.
                    ConditionCode::a => Expr::fcmp(Gt, a, b),
                    ConditionCode::ae => Expr::fcmp(Ge, a, b),
                    ConditionCode::b => Expr::fcmp(Lt, a, b),
                    ConditionCode::be => Expr::fcmp(Le, a, b),
                    _ => unknown(),
                }
            }
            None => unknown(),
        }
    }

    fn call_target(&self, ins: &Instruction, st: &State) -> CallTarget {
        if matches!(
            ins.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            // Thunks to imports are named after the import, so a direct call reads well.
            return CallTarget::Direct(ins.near_branch_target());
        }
        if ins.op0_kind() == OpKind::Memory
            && let Ok(Expr::Addr(slot)) = self.mem_addr(ins, st)
        {
            return CallTarget::Import(slot);
        }
        CallTarget::Indirect(Box::new(self.read(ins, 0, st)))
    }

    fn target_name(&self, t: &CallTarget) -> Option<String> {
        match t {
            CallTarget::Direct(a) | CallTarget::Import(a) => {
                self.program.name(*a).map(|n| n.text.clone())
            }
            CallTarget::Indirect(_) | CallTarget::Builtin(_) => None,
        }
    }

    fn lift_call(
        &self,
        ins: &Instruction,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let target = self.call_target(ins, st);
        let name = self.target_name(&target);
        let regs = self.conv.arg_regs();
        let count = match &target {
            CallTarget::Direct(a) => self
                .param_counts
                .get(a)
                .copied()
                .or_else(|| name.as_deref().and_then(import_params)),
            CallTarget::Import(_) => name.as_deref().and_then(import_params),
            CallTarget::Indirect(_) | CallTarget::Builtin(_) => None,
        }
        .unwrap_or_else(|| {
            // Unknown callee: the argument registers written just before the call.
            regs.iter().take_while(|r| st.written.contains(r)).count()
        });
        let args: Vec<Expr> = regs
            .iter()
            .take(count)
            .map(|&r| Expr::Var(Var::Reg(r), Width::B64))
            .collect();
        out.push((
            ins.ip(),
            Stmt::Assign(Var::Reg(RAX), Expr::Call(target, args)),
        ));
        for &r in self.conv.clobbered() {
            out.push((
                ins.ip(),
                Stmt::Assign(Var::Reg(r), Expr::Unknown("clobbered".into())),
            ));
        }
        st.written.clear();
        st.flags = None;
        if name.as_deref().is_some_and(import_noreturn) {
            return Some(Term::Stop);
        }
        None
    }

    /// Lifts one instruction. Returns a terminator if it ends the block.
    fn lift_insn(
        &self,
        ins: &Instruction,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        use Mnemonic as M;
        let addr = ins.ip();
        let next = ins.next_ip();
        let w0 = self.op_width(ins, 0, st);
        let is_rsp = |i: &Instruction, op: u32| {
            i.op_kind(op) == OpKind::Register && i.op_register(op).full_register() == Register::RSP
        };
        // The prologue is pushes plus frame setup (`mov rbp, rsp`, `sub rsp, n`).
        let frame_setup = ins.op_count() > 0
            && ins.op_kind(0) == OpKind::Register
            && matches!(
                ins.op_register(0).full_register(),
                Register::RSP | Register::RBP
            );
        if ins.mnemonic() != M::Push && !frame_setup {
            st.prologue = false;
        }
        let is_rbp = |i: &Instruction, op: u32| {
            i.op_kind(op) == OpKind::Register && i.op_register(op).full_register() == Register::RBP
        };
        if self.lift_float(ins, st, out) {
            return None;
        }
        if self.lift_simd(ins, st, out) {
            return None;
        }
        match ins.mnemonic() {
            M::Nop | M::Endbr64 | M::Endbr32 | M::Pause | M::Prefetchnta | M::Prefetcht0 => {}
            // The direction flag; the string lifts already assume forward (`cld`), so both are
            // bookkeeping with no effect on the recovered logic.
            M::Cld | M::Std => {}
            M::Mov if is_rbp(ins, 0) && is_rsp(ins, 1) => st.rbp = Some(st.rsp),
            M::Mov if is_rsp(ins, 0) && is_rbp(ins, 1) => {
                if let Some(b) = st.rbp {
                    st.rsp = b;
                }
            }
            M::Mov => {
                let v = self.read(ins, 1, st);
                self.write(ins, 0, v, st, out);
            }
            M::Movzx => {
                let v = self.read(ins, 1, st);
                self.write(ins, 0, Expr::Cast(Box::new(v), w0, false), st, out);
            }
            M::Movsx | M::Movsxd => {
                let v = self.read(ins, 1, st);
                self.write(ins, 0, Expr::Cast(Box::new(v), w0, true), st, out);
            }
            M::Lea => {
                if is_rbp(ins, 0) && ins.memory_base().full_register() == Register::RSP {
                    st.rbp = Some(st.rsp + ins.memory_displacement64() as i64);
                } else {
                    let v = match self.mem_addr(ins, st) {
                        Ok(a) => a,
                        Err((Var::Stack(off), _)) => Expr::StackAddr(off),
                        Err((v, w)) => Expr::Var(v, w),
                    };
                    self.write(ins, 0, v, st, out);
                }
            }
            M::Sub | M::Add
                if is_rsp(ins, 0)
                    && matches!(
                        ins.op_kind(1),
                        OpKind::Immediate8to64
                            | OpKind::Immediate32to64
                            | OpKind::Immediate32
                            | OpKind::Immediate8to32
                    ) =>
            {
                let n = ins.immediate(1) as i64;
                st.rsp += if ins.mnemonic() == M::Sub { -n } else { n };
            }
            M::Xor
                if ins.op_kind(0) == OpKind::Register
                    && ins.op_kind(1) == OpKind::Register
                    && ins.op_register(0) == ins.op_register(1) =>
            {
                self.write(ins, 0, Expr::konst(0, w0), st, out);
                st.flags = Some(Flags::Result(Expr::konst(0, w0)));
            }
            // `or reg, -1` is a constant load (all ones), not a read of the old value —
            // this is the `rcx = -1` seed of the inline `strlen` idiom.
            M::Or
                if matches!(
                    ins.op_kind(1),
                    OpKind::Immediate8
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32to64
                ) && ins.immediate(1) == w0.mask() =>
            {
                let v = Expr::konst(w0.mask(), w0);
                self.write(ins, 0, v.clone(), st, out);
                st.flags = Some(Flags::Result(v));
            }
            M::Add | M::Sub | M::And | M::Or | M::Xor | M::Shl | M::Shr | M::Sar | M::Sal => {
                let a = self.read(ins, 0, st);
                let b = self.read(ins, 1, st);
                let op = match ins.mnemonic() {
                    M::Add => BinOp::Add,
                    M::Sub => BinOp::Sub,
                    M::And => BinOp::And,
                    M::Or => BinOp::Or,
                    M::Xor => BinOp::Xor,
                    M::Shl | M::Sal => BinOp::Shl,
                    M::Shr => BinOp::Shr,
                    _ => BinOp::Sar,
                };
                // x86 masks a shift count to the operand width (5 bits for <=32-bit operands,
                // 6 bits for 64-bit). Emit the mask so the Rust port matches hardware and never
                // shifts by >= the bit-width (which panics in Rust). Non-shifts use `b` as-is.
                let rhs = if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                    let m = if w0.0 >= 8 { 0x3f } else { 0x1f };
                    Expr::bin(BinOp::And, b.clone(), Expr::konst(m, Width::B8), Width::B8)
                } else {
                    b.clone()
                };
                let r = Expr::bin(op, a, rhs, w0);
                self.write(ins, 0, r, st, out);
                // Flags describe the result, which now lives in the destination. For `sub`
                // the original left operand is `result + b` (when b does not read it).
                let new = self.read(ins, 0, st);
                let dest_vars = new.vars();
                st.flags = Some(
                    if op == BinOp::Sub && !dest_vars.iter().any(|v| b.reads(*v)) && !b.has_load() {
                        Flags::Sub(Expr::bin(BinOp::Add, new, b.clone(), w0), b)
                    } else {
                        Flags::Result(new)
                    },
                );
            }
            M::Adc | M::Sbb => {
                let carry = self.condition(ConditionCode::b, st);
                if matches!(carry, Expr::Unknown(_)) {
                    return self.unmodeled(ins, st, out);
                }
                let a = self.read(ins, 0, st);
                let b = self.read(ins, 1, st);
                let op = if ins.mnemonic() == M::Adc {
                    BinOp::Add
                } else {
                    BinOp::Sub
                };
                let c = Expr::Cast(Box::new(carry), w0, false);
                let r = Expr::bin(op, Expr::bin(op, a, b, w0), c, w0);
                self.write(ins, 0, r, st, out);
                st.flags = None;
            }
            M::Imul if ins.op_count() >= 2 => {
                let (a, b) = if ins.op_count() == 3 {
                    (self.read(ins, 1, st), self.read(ins, 2, st))
                } else {
                    (self.read(ins, 0, st), self.read(ins, 1, st))
                };
                let r = Expr::bin(BinOp::Mul, a, b, w0);
                self.write(ins, 0, r, st, out);
                st.flags = None;
            }
            M::Mul | M::Imul | M::Div | M::Idiv => {
                // One-operand forms work on rax (and rdx).
                let w = w0;
                let mut a = Expr::Var(Var::Reg(RAX), w);
                let mut b = self.read(ins, 0, st);
                match ins.mnemonic() {
                    M::Div | M::Idiv => {
                        // Signed division: reinterpret both operands as signed so `/` and `%`
                        // mean signed division (the Ghidra-style `(int)a / (int)b`).
                        if ins.mnemonic() == M::Idiv {
                            a = Expr::Cast(Box::new(a), w, true);
                            b = Expr::Cast(Box::new(b), w, true);
                        }
                        out.push((
                            addr,
                            Stmt::Assign(
                                Var::Reg(RDX),
                                Expr::bin(BinOp::Rem, a.clone(), b.clone(), w),
                            ),
                        ));
                        out.push((
                            addr,
                            Stmt::Assign(Var::Reg(RAX), Expr::bin(BinOp::Div, a, b, w)),
                        ));
                    }
                    _ => {
                        // Emit the HIGH half (rdx) first: both halves read the original rax, so
                        // the rdx expression must be built before the rax assignment clobbers it.
                        // rdx = top `w` bits of the double-width product,
                        // `((a as wide) * (b as wide) >> bits) as w` (signed for imul).
                        if w.0 >= 2 {
                            let signed = ins.mnemonic() == M::Imul;
                            let wide = Width(w.0 * 2);
                            let widen = |e: Expr| {
                                if signed {
                                    Expr::Cast(
                                        Box::new(Expr::Cast(Box::new(e), w, true)),
                                        wide,
                                        true,
                                    )
                                } else {
                                    Expr::Cast(Box::new(e), wide, false)
                                }
                            };
                            let hi = Expr::Cast(
                                Box::new(Expr::bin(
                                    BinOp::Shr,
                                    Expr::bin(BinOp::Mul, widen(a.clone()), widen(b.clone()), wide),
                                    Expr::konst(u64::from(w.bits()), Width::B8),
                                    wide,
                                )),
                                w,
                                false,
                            );
                            out.push((addr, Stmt::Assign(Var::Reg(RDX), hi)));
                        }
                        // Low half -> rax (= rdx:rax mod 2^w).
                        out.push((
                            addr,
                            Stmt::Assign(Var::Reg(RAX), Expr::bin(BinOp::Mul, a, b, w)),
                        ));
                    }
                }
                st.flags = None;
            }
            M::Inc | M::Dec => {
                let a = self.read(ins, 0, st);
                let op = if ins.mnemonic() == M::Inc {
                    BinOp::Add
                } else {
                    BinOp::Sub
                };
                let r = Expr::bin(op, a, Expr::konst(1, w0), w0);
                self.write(ins, 0, r, st, out);
                st.flags = Some(Flags::Result(self.read(ins, 0, st)));
            }
            M::Neg => {
                let a = self.read(ins, 0, st);
                let r = Expr::Neg(Box::new(a), w0);
                self.write(ins, 0, r, st, out);
                st.flags = Some(Flags::Result(self.read(ins, 0, st)));
            }
            M::Not => {
                let a = self.read(ins, 0, st);
                self.write(ins, 0, Expr::Not(Box::new(a), w0), st, out);
            }
            // Rotates → Rust `rotate_left` / `rotate_right` (the shift count is a `u32`).
            M::Rol | M::Ror => {
                let a = self.read(ins, 0, st);
                let n = Expr::Cast(Box::new(self.read(ins, 1, st)), Width::B32, false);
                let name = if ins.mnemonic() == M::Rol {
                    "rotate_left"
                } else {
                    "rotate_right"
                };
                self.write(ins, 0, Expr::method(a, name, vec![n], w0), st, out);
                st.flags = None;
            }
            // Byte swap → `swap_bytes`.
            M::Bswap => {
                let a = self.read(ins, 0, st);
                self.write(
                    ins,
                    0,
                    Expr::method(a, "swap_bytes", Vec::new(), w0),
                    st,
                    out,
                );
            }
            // Bit counts → the matching integer method (result is a `u32`, cast to the dest width).
            M::Popcnt | M::Lzcnt | M::Tzcnt => {
                let src = self.read(ins, 1, st);
                let name = match ins.mnemonic() {
                    M::Popcnt => "count_ones",
                    M::Lzcnt => "leading_zeros",
                    _ => "trailing_zeros",
                };
                let m = Expr::method(src, name, Vec::new(), Width::B32);
                self.write(ins, 0, Expr::Cast(Box::new(m), w0, false), st, out);
                st.flags = Some(Flags::Result(self.read(ins, 0, st)));
            }
            // Bit scan: the index of the lowest (`bsf`) or highest (`bsr`) set bit. The zero
            // flag records whether the source was zero.
            M::Bsf | M::Bsr => {
                let src = self.read(ins, 1, st);
                let r = if ins.mnemonic() == M::Bsf {
                    let m = Expr::method(src.clone(), "trailing_zeros", Vec::new(), Width::B32);
                    Expr::Cast(Box::new(m), w0, false)
                } else {
                    // The top set bit's index is `bits - 1 - leading_zeros`.
                    let lz = Expr::method(src.clone(), "leading_zeros", Vec::new(), Width::B32);
                    let lz = Expr::Cast(Box::new(lz), w0, false);
                    Expr::bin(
                        BinOp::Sub,
                        Expr::konst(u64::from(w0.bits()) - 1, w0),
                        lz,
                        w0,
                    )
                };
                self.write(ins, 0, r, st, out);
                st.flags = Some(Flags::Sub(src, Expr::konst(0, w0)));
            }
            // BMI: lowest-set-bit tricks. blsi = `x & -x` (isolate), blsr = `x & (x - 1)`
            // (clear), blsmsk = `x ^ (x - 1)` (mask up to it).
            M::Blsi | M::Blsr | M::Blsmsk => {
                let src = self.read(ins, 1, st);
                let one = || Expr::konst(1, w0);
                let r = match ins.mnemonic() {
                    M::Blsi => Expr::bin(
                        BinOp::And,
                        src.clone(),
                        Expr::method(src, "wrapping_neg", Vec::new(), w0),
                        w0,
                    ),
                    M::Blsr => Expr::bin(
                        BinOp::And,
                        src.clone(),
                        Expr::bin(BinOp::Sub, src, one(), w0),
                        w0,
                    ),
                    _ => Expr::bin(
                        BinOp::Xor,
                        src.clone(),
                        Expr::bin(BinOp::Sub, src, one(), w0),
                        w0,
                    ),
                };
                self.write(ins, 0, r, st, out);
                st.flags = Some(Flags::Result(self.read(ins, 0, st)));
            }
            // Move big-endian: a byte-swapped load or store.
            M::Movbe => {
                let v = self.read(ins, 1, st);
                self.write(
                    ins,
                    0,
                    Expr::method(v, "swap_bytes", Vec::new(), w0),
                    st,
                    out,
                );
            }
            // BMI: `andn dst, a, b` is `!a & b`.
            M::Andn => {
                let a = self.read(ins, 1, st);
                let b = self.read(ins, 2, st);
                let r = Expr::bin(BinOp::And, Expr::Not(Box::new(a), w0), b, w0);
                self.write(ins, 0, r, st, out);
                st.flags = None;
            }
            // BMI2: flag-free shifts `dst, src, count`.
            M::Shlx | M::Shrx | M::Sarx => {
                let src = self.read(ins, 1, st);
                let count = self.read(ins, 2, st);
                let op = match ins.mnemonic() {
                    M::Shlx => BinOp::Shl,
                    M::Shrx => BinOp::Shr,
                    _ => BinOp::Sar,
                };
                self.write(ins, 0, Expr::bin(op, src, count, w0), st, out);
            }
            // BMI2: `rorx dst, src, imm` → `rotate_right`.
            M::Rorx => {
                let src = self.read(ins, 1, st);
                let n = Expr::Cast(Box::new(self.read(ins, 2, st)), Width::B32, false);
                self.write(
                    ins,
                    0,
                    Expr::method(src, "rotate_right", vec![n], w0),
                    st,
                    out,
                );
            }
            // Sign-extend the accumulator's low half (al→ax, ax→eax; `cdqe` does eax→rax).
            M::Cbw => out.push((
                addr,
                Stmt::Assign(
                    Var::Reg(RAX),
                    Expr::Cast(
                        Box::new(Expr::Var(Var::Reg(RAX), Width::B8)),
                        Width::B16,
                        true,
                    ),
                ),
            )),
            M::Cwde => out.push((
                addr,
                Stmt::Assign(
                    Var::Reg(RAX),
                    Expr::Cast(
                        Box::new(Expr::Var(Var::Reg(RAX), Width::B16)),
                        Width::B32,
                        true,
                    ),
                ),
            )),
            // Double-precision shifts expand to a shift/or expression.
            M::Shld | M::Shrd => {
                let dst = self.read(ins, 0, st);
                let src = self.read(ins, 1, st);
                let n = self.read(ins, 2, st);
                let bits = Expr::konst(u64::from(w0.bits()), w0);
                let inv = Expr::bin(BinOp::Sub, bits, n.clone(), w0);
                let (main, fill) = if ins.mnemonic() == M::Shld {
                    (
                        Expr::bin(BinOp::Shl, dst, n, w0),
                        Expr::bin(BinOp::Shr, src, inv, w0),
                    )
                } else {
                    (
                        Expr::bin(BinOp::Shr, dst, n, w0),
                        Expr::bin(BinOp::Shl, src, inv, w0),
                    )
                };
                self.write(ins, 0, Expr::bin(BinOp::Or, main, fill, w0), st, out);
                st.flags = None;
            }
            // Exchange: swap the two operands' values (read both first, then write).
            M::Xchg => {
                let a = self.read(ins, 0, st);
                let b = self.read(ins, 1, st);
                self.write(ins, 0, b, st, out);
                self.write(ins, 1, a, st, out);
            }
            // Exchange-and-add: dst gets dst+src, src gets the old dst.
            M::Xadd => {
                let a = self.read(ins, 0, st);
                let b = self.read(ins, 1, st);
                self.write(ins, 1, a.clone(), st, out);
                self.write(ins, 0, Expr::bin(BinOp::Add, a, b, w0), st, out);
                st.flags = None;
            }
            // Bit test (+ set/reset/complement): CF = bit `n` of the operand before any change.
            M::Bt | M::Bts | M::Btr | M::Btc => {
                let x = self.read(ins, 0, st);
                let n = self.read(ins, 1, st);
                st.flags = Some(Flags::Bit(x.clone(), n.clone()));
                let bit = || Expr::bin(BinOp::Shl, Expr::konst(1, w0), n.clone(), w0);
                match ins.mnemonic() {
                    M::Bts => {
                        self.write(ins, 0, Expr::bin(BinOp::Or, x, bit(), w0), st, out);
                    }
                    M::Btr => {
                        let mask = Expr::Not(Box::new(bit()), w0);
                        self.write(ins, 0, Expr::bin(BinOp::And, x, mask, w0), st, out);
                    }
                    M::Btc => {
                        self.write(ins, 0, Expr::bin(BinOp::Xor, x, bit(), w0), st, out);
                    }
                    _ => {} // Bt only tests.
                }
            }
            // Repeated string moves / stores → C `memcpy` / `memset` over `rcx` elements
            // (forward direction, the usual `cld` case). `rsi`/`rdi` advance past the block
            // and `rcx` is consumed, so later reads of them stay sound.
            M::Movsb
            | M::Movsw
            | M::Movsd
            | M::Movsq
            | M::Stosb
            | M::Stosw
            | M::Stosd
            | M::Stosq
                if ins.has_rep_prefix() || ins.has_repe_prefix() =>
            {
                let ew: u64 = match ins.mnemonic() {
                    M::Movsb | M::Stosb => 1,
                    M::Movsw | M::Stosw => 2,
                    M::Movsd | M::Stosd => 4,
                    _ => 8, // movsq / stosq
                };
                let rcx = Expr::Var(Var::Reg(RCX), Width::B64);
                let bytes = if ew == 1 {
                    rcx
                } else {
                    Expr::bin(BinOp::Mul, rcx, Expr::konst(ew, Width::B64), Width::B64)
                };
                let dst = Expr::Var(Var::Reg(RDI), Width::B64);
                let is_move = matches!(ins.mnemonic(), M::Movsb | M::Movsw | M::Movsd | M::Movsq);
                if is_move {
                    let src = Expr::Var(Var::Reg(RSI), Width::B64);
                    out.push((
                        addr,
                        Stmt::Eval(Expr::Call(
                            CallTarget::Builtin("memcpy"),
                            vec![dst.clone(), src.clone(), bytes.clone()],
                        )),
                    ));
                    out.push((
                        addr,
                        Stmt::Assign(
                            Var::Reg(RSI),
                            Expr::bin(BinOp::Add, src, bytes.clone(), Width::B64),
                        ),
                    ));
                } else {
                    let val = Expr::Var(Var::Reg(RAX), Width(ew as u8));
                    out.push((
                        addr,
                        Stmt::Eval(Expr::Call(
                            CallTarget::Builtin("memset"),
                            vec![dst.clone(), val, bytes.clone()],
                        )),
                    ));
                }
                out.push((
                    addr,
                    Stmt::Assign(Var::Reg(RDI), Expr::bin(BinOp::Add, dst, bytes, Width::B64)),
                ));
                out.push((
                    addr,
                    Stmt::Assign(Var::Reg(RCX), Expr::konst(0, Width::B64)),
                ));
                st.flags = None;
            }
            // Repeated compare → C `memcmp`: the flags become `memcmp(rsi, rdi, n) <=> 0`, so a
            // following `je`/`jne`/`jl`/… reads as `memcmp(..) == 0` and friends.
            M::Cmpsb | M::Cmpsw | M::Cmpsd | M::Cmpsq
                if ins.has_rep_prefix() || ins.has_repe_prefix() || ins.has_repne_prefix() =>
            {
                let ew: u64 = match ins.mnemonic() {
                    M::Cmpsb => 1,
                    M::Cmpsw => 2,
                    M::Cmpsd => 4,
                    _ => 8,
                };
                let rcx = Expr::Var(Var::Reg(RCX), Width::B64);
                let bytes = if ew == 1 {
                    rcx
                } else {
                    Expr::bin(BinOp::Mul, rcx, Expr::konst(ew, Width::B64), Width::B64)
                };
                let memcmp = Expr::Call(
                    CallTarget::Builtin("memcmp"),
                    vec![
                        Expr::Var(Var::Reg(RSI), Width::B64),
                        Expr::Var(Var::Reg(RDI), Width::B64),
                        bytes,
                    ],
                );
                st.flags = Some(Flags::Sub(memcmp, Expr::konst(0, Width::B32)));
            }
            // Repeated scan for a byte. Modelled as `__scasb(ptr, value)` = the number of
            // bytes examined up to and including the match, decrementing `rcx` by it — so the
            // classic `or rcx,-1; xor al,al; repne scasb; not rcx; dec rcx` idiom folds to
            // `strlen(ptr)` (see `simplify::fold`).
            M::Scasb | M::Scasw | M::Scasd | M::Scasq
                if ins.has_rep_prefix() || ins.has_repe_prefix() || ins.has_repne_prefix() =>
            {
                let ew: u64 = match ins.mnemonic() {
                    M::Scasb => 1,
                    M::Scasw => 2,
                    M::Scasd => 4,
                    _ => 8,
                };
                let scan = Expr::Call(
                    CallTarget::Builtin("__scasb"),
                    vec![
                        Expr::Var(Var::Reg(RDI), Width::B64),
                        Expr::Var(Var::Reg(RAX), Width(ew as u8)),
                    ],
                );
                out.push((
                    addr,
                    Stmt::Assign(
                        Var::Reg(RCX),
                        Expr::bin(
                            BinOp::Sub,
                            Expr::Var(Var::Reg(RCX), Width::B64),
                            scan,
                            Width::B64,
                        ),
                    ),
                ));
                st.flags = None;
            }
            M::Cmp => st.flags = Some(Flags::Sub(self.read(ins, 0, st), self.read(ins, 1, st))),
            M::Test => st.flags = Some(Flags::Test(self.read(ins, 0, st), self.read(ins, 1, st))),
            M::Push => {
                let v = self.read(ins, 0, st);
                st.rsp -= 8;
                // Saving a register in the prologue is bookkeeping, not program logic.
                if !(st.prologue && ins.op_kind(0) == OpKind::Register) {
                    out.push((addr, Stmt::Assign(Var::Stack(st.rsp), v)));
                }
            }
            M::Pop => {
                let v = Expr::Var(Var::Stack(st.rsp), Width::B64);
                st.rsp += 8;
                if is_rbp(ins, 0) {
                    st.rbp = None;
                }
                self.write(ins, 0, v, st, out);
            }
            M::Leave => {
                if let Some(b) = st.rbp {
                    st.rsp = b + 8;
                }
                st.rbp = None;
            }
            M::Cdqe => out.push((
                addr,
                Stmt::Assign(
                    Var::Reg(RAX),
                    Expr::Cast(
                        Box::new(Expr::Var(Var::Reg(RAX), Width::B32)),
                        Width::B64,
                        true,
                    ),
                ),
            )),
            M::Cdq | M::Cqo | M::Cwd => {} // sign bits for a division; the division reads rax
            M::Call => return self.lift_call(ins, st, out),
            M::Ret | M::Retf => {
                return Some(Term::Return(Some(Expr::Var(Var::Reg(RAX), Width::B64))));
            }
            M::Jmp => {
                // A `switch` jump table `jmp [base + index*entry]` → a multi-way `Switch`.
                if ins.op0_kind() == OpKind::Memory
                    && ins.memory_base() == Register::None
                    && ins.memory_index() != Register::None
                    && matches!(ins.memory_index_scale(), 4 | 8)
                    && let Some((idx, _)) = reg(ins.memory_index())
                    && let Some(cases) =
                        self.jump_table(ins.memory_displacement64(), ins.memory_index_scale() as u8)
                {
                    return Some(Term::Switch(Expr::Var(Var::Reg(idx), Width::B64), cases));
                }
                return Some(match ins.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let t = ins.near_branch_target();
                        if self.program.functions.contains_key(&t) {
                            Term::TailCall(Expr::Call(CallTarget::Direct(t), Vec::new()))
                        } else {
                            Term::Jump(t)
                        }
                    }
                    _ => Term::TailCall(Expr::Call(self.call_target(ins, st), Vec::new())),
                });
            }
            M::Int3 | M::Ud2 | M::Hlt => return Some(Term::Stop),
            // `jcxz`/`jecxz`/`jrcxz`: branch if the count register is zero. These have
            // condition_code() == None, so they'd otherwise fall through to `unmodeled` and lose
            // the conditional edge entirely.
            M::Jcxz | M::Jecxz | M::Jrcxz => {
                let w = match ins.mnemonic() {
                    M::Jrcxz => Width::B64,
                    M::Jcxz => Width::B16,
                    _ => Width::B32,
                };
                let c = Expr::cmp(
                    CmpOp::Eq,
                    Expr::Var(Var::Reg(RCX), w),
                    Expr::konst(0, w),
                    false,
                );
                return Some(Term::Branch(c, ins.near_branch_target(), next));
            }
            // `loop`/`loope`/`loopne`: `--rcx; branch if rcx != 0` (and ZF for loope / !ZF for
            // loopne). The decrement does not touch flags, so the ZF test reads the loop body's
            // last flag-setting instruction.
            M::Loop | M::Loope | M::Loopne => {
                out.push((
                    addr,
                    Stmt::Assign(
                        Var::Reg(RCX),
                        Expr::bin(
                            BinOp::Sub,
                            Expr::Var(Var::Reg(RCX), Width::B64),
                            Expr::konst(1, Width::B64),
                            Width::B64,
                        ),
                    ),
                ));
                let nz = Expr::cmp(
                    CmpOp::Ne,
                    Expr::Var(Var::Reg(RCX), Width::B64),
                    Expr::konst(0, Width::B64),
                    false,
                );
                let cond = match ins.mnemonic() {
                    M::Loope => {
                        Expr::LAnd(Box::new(nz), Box::new(self.condition(ConditionCode::e, st)))
                    }
                    M::Loopne => Expr::LAnd(
                        Box::new(nz),
                        Box::new(self.condition(ConditionCode::ne, st)),
                    ),
                    _ => nz,
                };
                return Some(Term::Branch(cond, ins.near_branch_target(), next));
            }
            m if ins.condition_code() != ConditionCode::None
                && ins.flow_control() == iced_x86::FlowControl::ConditionalBranch =>
            {
                let _ = m;
                let cond = self.condition(ins.condition_code(), st);
                return Some(Term::Branch(cond, ins.near_branch_target(), next));
            }
            m if ins.condition_code() != ConditionCode::None
                && format!("{m:?}").starts_with("Set") =>
            {
                let cond = self.condition(ins.condition_code(), st);
                self.write(ins, 0, cond, st, out);
            }
            m if ins.condition_code() != ConditionCode::None
                && format!("{m:?}").starts_with("Cmov") =>
            {
                let cond = self.condition(ins.condition_code(), st);
                let old = self.read(ins, 0, st);
                let new = self.read(ins, 1, st);
                self.write(
                    ins,
                    0,
                    Expr::Select(Box::new(cond), Box::new(new), Box::new(old), w0),
                    st,
                    out,
                );
            }
            _ => return self.unmodeled(ins, st, out),
        }
        None
    }

    /// Reads a floating-point source operand of `w` bytes: an XMM register as the scalar value,
    /// a general-purpose register as its integer (for `cvtsi2*`), or a memory load.
    fn fread(&self, ins: &Instruction, op: u32, st: &State, w: Width) -> Expr {
        match ins.op_kind(op) {
            OpKind::Register => {
                let r = ins.op_register(op);
                if let Some(x) = xmm(r) {
                    Expr::Var(Var::Xmm(x), w)
                } else if let Some((g, gw)) = reg(r) {
                    Expr::Var(Var::Reg(g), gw)
                } else {
                    Expr::Unknown(format!("{r:?}").to_lowercase())
                }
            }
            OpKind::Memory => {
                // A compiler keeps float literals in a read-only constant pool, loaded
                // rip-relative. Recover the actual value so it reads `x * 2.5` not a raw read.
                if ins.is_ip_rel_memory_operand()
                    && let Some(v) = self.float_const(ins.ip_rel_memory_address(), w)
                {
                    return Expr::FConst(v, w);
                }
                match self.mem_addr(ins, st) {
                    Ok(a) => Expr::Load(Box::new(a), w),
                    Err((v, vw)) => Expr::Var(v, vw),
                }
            }
            _ => Expr::Unknown(String::from("?")),
        }
    }

    /// Reads a `w`-byte float literal from a read-only constant pool, as raw bits.
    fn float_const(&self, addr: u64, w: Width) -> Option<u64> {
        let r = self.program.memory.region(addr)?;
        let n = r.name.to_ascii_lowercase();
        if !(n.contains("rodata")
            || n.contains("rdata")
            || n.contains("text")
            || n.contains("const"))
        {
            return None;
        }
        let bytes = self.program.memory.read(addr, usize::from(w.0))?;
        if bytes.len() < usize::from(w.0) {
            return None;
        }
        let mut v = 0u64;
        for (i, &b) in bytes.iter().enumerate() {
            v |= u64::from(b) << (8 * i);
        }
        Some(v & w.mask())
    }

    /// Writes a floating-point `value` to operand `op` (an XMM register, a general register for
    /// a float→int conversion, or memory).
    fn fwrite(
        &self,
        ins: &Instruction,
        op: u32,
        value: Expr,
        st: &State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let addr = ins.ip();
        match ins.op_kind(op) {
            OpKind::Register => {
                let r = ins.op_register(op);
                if let Some(x) = xmm(r) {
                    out.push((addr, Stmt::Assign(Var::Xmm(x), value)));
                } else if let Some((g, _)) = reg(r) {
                    out.push((addr, Stmt::Assign(Var::Reg(g), value)));
                }
            }
            OpKind::Memory => {
                let w = value.width();
                match self.mem_addr(ins, st) {
                    Ok(a) => out.push((addr, Stmt::Store(a, value, w))),
                    Err((v, _)) => out.push((addr, Stmt::Assign(v, value))),
                }
            }
            _ => {}
        }
    }

    /// Lifts the scalar SSE/SSE2 floating-point instructions (`addsd`, `mulss`, `cvtsi2sd`,
    /// `comisd`, `sqrtsd`, …) into float IR nodes. Returns `true` if it handled the instruction.
    fn lift_float(&self, ins: &Instruction, st: &mut State, out: &mut Vec<(u64, Stmt)>) -> bool {
        use Mnemonic as M;
        let m = ins.mnemonic();
        // `movsd` is also a string instruction; the SSE form always has an XMM operand.
        let has_xmm = (0..ins.op_count())
            .any(|op| ins.op_kind(op) == OpKind::Register && xmm(ins.op_register(op)).is_some());
        // Arithmetic `dst = dst OP src`.
        let arith = |op: BinOp, w: Width, s: &Self, out: &mut Vec<(u64, Stmt)>| {
            let a = s.fread(ins, 0, st, w);
            let b = s.fread(ins, 1, st, w);
            s.fwrite(ins, 0, Expr::fbin(op, a, b, w), st, out);
        };
        match m {
            M::Addss => arith(BinOp::Add, Width::B32, self, out),
            M::Addsd => arith(BinOp::Add, Width::B64, self, out),
            M::Subss => arith(BinOp::Sub, Width::B32, self, out),
            M::Subsd => arith(BinOp::Sub, Width::B64, self, out),
            M::Mulss => arith(BinOp::Mul, Width::B32, self, out),
            M::Mulsd => arith(BinOp::Mul, Width::B64, self, out),
            M::Divss => arith(BinOp::Div, Width::B32, self, out),
            M::Divsd => arith(BinOp::Div, Width::B64, self, out),
            M::Sqrtss | M::Sqrtsd => {
                let w = if m == M::Sqrtss {
                    Width::B32
                } else {
                    Width::B64
                };
                let src = self.fread(ins, 1, st, w);
                self.fwrite(ins, 0, Expr::FUn(FUnOp::Sqrt, Box::new(src), w), st, out);
            }
            M::Minss | M::Minsd | M::Maxss | M::Maxsd => {
                let w = if matches!(m, M::Minss | M::Maxss) {
                    Width::B32
                } else {
                    Width::B64
                };
                let name = if matches!(m, M::Minss | M::Minsd) {
                    "min"
                } else {
                    "max"
                };
                let a = self.fread(ins, 0, st, w);
                let b = self.fread(ins, 1, st, w);
                self.fwrite(ins, 0, Expr::method(a, name, vec![b], w), st, out);
            }
            // Compare → floating-point flags for the following `ja`/`jb`/`je`/….
            M::Comiss | M::Ucomiss | M::Comisd | M::Ucomisd => {
                let w = if matches!(m, M::Comiss | M::Ucomiss) {
                    Width::B32
                } else {
                    Width::B64
                };
                st.flags = Some(Flags::FSub(
                    self.fread(ins, 0, st, w),
                    self.fread(ins, 1, st, w),
                ));
            }
            // Integer → float.
            M::Cvtsi2ss | M::Cvtsi2sd => {
                let w = if m == M::Cvtsi2ss {
                    Width::B32
                } else {
                    Width::B64
                };
                let src = self.fread(ins, 1, st, self.op_width(ins, 1, st));
                self.fwrite(
                    ins,
                    0,
                    Expr::FCast(Box::new(src), w, FCast::SIntToFloat),
                    st,
                    out,
                );
            }
            // Float → integer (truncating).
            M::Cvttss2si | M::Cvttsd2si | M::Cvtss2si | M::Cvtsd2si => {
                let sw = if matches!(m, M::Cvttss2si | M::Cvtss2si) {
                    Width::B32
                } else {
                    Width::B64
                };
                let dw = self.op_width(ins, 0, st);
                let src = self.fread(ins, 1, st, sw);
                self.fwrite(
                    ins,
                    0,
                    Expr::FCast(Box::new(src), dw, FCast::FloatToSInt),
                    st,
                    out,
                );
            }
            // Float → float.
            M::Cvtss2sd => {
                let src = self.fread(ins, 1, st, Width::B32);
                self.fwrite(
                    ins,
                    0,
                    Expr::FCast(Box::new(src), Width::B64, FCast::FloatToFloat),
                    st,
                    out,
                );
            }
            M::Cvtsd2ss => {
                let src = self.fread(ins, 1, st, Width::B64);
                self.fwrite(
                    ins,
                    0,
                    Expr::FCast(Box::new(src), Width::B32, FCast::FloatToFloat),
                    st,
                    out,
                );
            }
            // Scalar float moves. `movss`/`movsd` are always scalar; the packed moves
            // (`movaps`/`movups`/…) are scalar only as a register↔register copy — with a memory
            // operand they move a full 128-bit vector, so they fall through to `lift_simd`.
            M::Movss if has_xmm => {
                let v = self.fread(ins, 1, st, Width::B32);
                self.fwrite(ins, 0, v, st, out);
            }
            M::Movsd if has_xmm => {
                let v = self.fread(ins, 1, st, Width::B64);
                self.fwrite(ins, 0, v, st, out);
            }
            M::Movaps | M::Movups
                if has_xmm
                    && ins.op_kind(0) == OpKind::Register
                    && ins.op_kind(1) == OpKind::Register =>
            {
                let v = self.fread(ins, 1, st, Width::B32);
                self.fwrite(ins, 0, v, st, out);
            }
            M::Movapd | M::Movupd
                if has_xmm
                    && ins.op_kind(0) == OpKind::Register
                    && ins.op_kind(1) == OpKind::Register =>
            {
                let v = self.fread(ins, 1, st, Width::B64);
                self.fwrite(ins, 0, v, st, out);
            }
            // `xorps`/`xorpd xmm, xmm` with the same register is the zero-a-float idiom. (`pxor`
            // is the integer form and is handled by `lift_simd` as a zero vector.)
            M::Xorps | M::Xorpd
                if has_xmm
                    && ins.op_kind(0) == OpKind::Register
                    && ins.op_kind(1) == OpKind::Register
                    && ins.op_register(0) == ins.op_register(1) =>
            {
                let w = if m == M::Xorps {
                    Width::B32
                } else {
                    Width::B64
                };
                self.fwrite(ins, 0, Expr::FConst(0, w), st, out);
            }
            // `movd`/`movq` between a GPR and an XMM register reinterpret the bits as a float
            // (`f64::from_bits` / `.to_bits()`), e.g. returning a float computed in a GPR.
            M::Movd | M::Movq
                if ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register =>
            {
                let w = if m == M::Movq { Width::B64 } else { Width::B32 };
                let (r0, r1) = (ins.op_register(0), ins.op_register(1));
                match (xmm(r0), reg(r1), reg(r0), xmm(r1)) {
                    // GPR -> XMM: xmm = fN::from_bits(gpr).
                    (Some(_), Some((g, _)), _, _) => {
                        let name = if w == Width::B64 {
                            "f64::from_bits"
                        } else {
                            "f32::from_bits"
                        };
                        let bits = Expr::Var(Var::Reg(g), w);
                        self.fwrite(
                            ins,
                            0,
                            Expr::Call(CallTarget::Builtin(name), vec![bits]),
                            st,
                            out,
                        );
                    }
                    // XMM -> GPR: gpr = xmm.to_bits().
                    (_, _, Some((g, _)), Some(x)) => {
                        let fv = Expr::Var(Var::Xmm(x), w);
                        out.push((
                            ins.ip(),
                            Stmt::Assign(Var::Reg(g), Expr::method(fv, "to_bits", Vec::new(), w)),
                        ));
                    }
                    _ => return false,
                }
            }
            _ => return false,
        }
        true
    }

    /// Reads a packed-vector source operand: an XMM register (as the whole vector) or a memory
    /// load of `lanes`×`lane`.
    fn vread(&self, ins: &Instruction, op: u32, lanes: u8, lane: Lane, st: &State) -> Expr {
        match ins.op_kind(op) {
            OpKind::Register => match xmm(ins.op_register(op)) {
                Some(x) => Expr::Var(Var::Xmm(x), Width::B64),
                None => Expr::Unknown(String::from("vec")),
            },
            OpKind::Memory => match self.mem_addr(ins, st) {
                Ok(a) => Expr::VecLoad(Box::new(a), lanes, lane),
                Err((v, _)) => Expr::Var(v, Width::B64),
            },
            _ => Expr::Unknown(String::from("?")),
        }
    }

    /// Writes a packed-vector `value` to operand `op` (an XMM register or memory).
    fn vwrite(
        &self,
        ins: &Instruction,
        op: u32,
        value: Expr,
        st: &State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let addr = ins.ip();
        match ins.op_kind(op) {
            OpKind::Register => {
                if let Some(x) = xmm(ins.op_register(op)) {
                    out.push((addr, Stmt::Assign(Var::Xmm(x), value)));
                }
            }
            OpKind::Memory => match self.mem_addr(ins, st) {
                Ok(a) => out.push((addr, Stmt::Store(a, value, Width::B64))),
                Err((v, _)) => out.push((addr, Stmt::Assign(v, value))),
            },
            _ => {}
        }
    }

    /// Lifts the common packed-integer SSE2 instructions (`paddd`, `pxor`, `movdqu`, `pshufd`, …)
    /// into packed-vector IR. Returns `true` if it handled the instruction. This is the vector-IR
    /// groundwork; a later pass folds a vectorised reduction into `s.iter().sum()`.
    fn lift_simd(&self, ins: &Instruction, st: &State, out: &mut Vec<(u64, Stmt)>) -> bool {
        use Mnemonic as M;
        let i32 = Lane::int(Width::B32);
        let (lanes, lane, op) = match ins.mnemonic() {
            // Packed integer arithmetic / logic.
            M::Paddb => (16u8, Lane::int(Width::B8), Some(BinOp::Add)),
            M::Psubb => (16, Lane::int(Width::B8), Some(BinOp::Sub)),
            M::Paddw => (8, Lane::int(Width::B16), Some(BinOp::Add)),
            M::Psubw => (8, Lane::int(Width::B16), Some(BinOp::Sub)),
            M::Pmullw => (8, Lane::int(Width::B16), Some(BinOp::Mul)),
            M::Paddd => (4, i32, Some(BinOp::Add)),
            M::Psubd => (4, i32, Some(BinOp::Sub)),
            M::Pmulld => (4, i32, Some(BinOp::Mul)),
            M::Paddq => (2, Lane::int(Width::B64), Some(BinOp::Add)),
            M::Psubq => (2, Lane::int(Width::B64), Some(BinOp::Sub)),
            M::Pand => (4, i32, Some(BinOp::And)),
            M::Por => (4, i32, Some(BinOp::Or)),
            M::Pxor => (4, i32, Some(BinOp::Xor)),
            // Packed single/double floating-point arithmetic (addps/mulps/divps …): same shape as
            // the integer ops but float lanes, so they render as `[f32; 4]` / `[f64; 2]`.
            M::Addps => (4, Lane::float(Width::B32), Some(BinOp::Add)),
            M::Subps => (4, Lane::float(Width::B32), Some(BinOp::Sub)),
            M::Mulps => (4, Lane::float(Width::B32), Some(BinOp::Mul)),
            M::Divps => (4, Lane::float(Width::B32), Some(BinOp::Div)),
            M::Addpd => (2, Lane::float(Width::B64), Some(BinOp::Add)),
            M::Subpd => (2, Lane::float(Width::B64), Some(BinOp::Sub)),
            M::Mulpd => (2, Lane::float(Width::B64), Some(BinOp::Mul)),
            M::Divpd => (2, Lane::float(Width::B64), Some(BinOp::Div)),
            // 128-bit moves. Integer domain (movdqa/movdqu) → int lanes; the float domain
            // (movaps/movups, movapd/movupd) → float lanes.
            M::Movdqu | M::Movdqa => {
                let v = self.vread(ins, 1, 4, i32, st);
                self.vwrite(ins, 0, v, st, out);
                return true;
            }
            M::Movups | M::Movaps => {
                let v = self.vread(ins, 1, 4, Lane::float(Width::B32), st);
                self.vwrite(ins, 0, v, st, out);
                return true;
            }
            M::Movupd | M::Movapd => {
                let v = self.vread(ins, 1, 2, Lane::float(Width::B64), st);
                self.vwrite(ins, 0, v, st, out);
                return true;
            }
            M::Pshufd => {
                let src = self.vread(ins, 1, 4, i32, st);
                self.vwrite(
                    ins,
                    0,
                    Expr::VecShuffle(Box::new(src), ins.immediate8(), 4, i32),
                    st,
                    out,
                );
                return true;
            }
            // Packed float max/min (`maxps`/`minps`, `maxpd`/`minpd`) — a direct lane-wise max/min.
            M::Maxps | M::Minps | M::Maxpd | M::Minpd => {
                let (n, l) = if matches!(ins.mnemonic(), M::Maxpd | M::Minpd) {
                    (2, Lane::float(Width::B64))
                } else {
                    (4, Lane::float(Width::B32))
                };
                let a = self.vread(ins, 0, n, l, st);
                let b = self.vread(ins, 1, n, l, st);
                let v = if matches!(ins.mnemonic(), M::Maxps | M::Maxpd) {
                    Expr::VecMax(Box::new(a), Box::new(b), n, l)
                } else {
                    Expr::VecMin(Box::new(a), Box::new(b), n, l)
                };
                self.vwrite(ins, 0, v, st, out);
                return true;
            }
            // `pcmpgtd dst, src` → a lane-wise greater-than mask; `pandn dst, src` → `!dst & src`.
            // These feed the compare-and-blend that `simplify::fold` recovers as `VecMax`/`VecMin`.
            M::Pcmpgtd | M::Pandn => {
                let a = self.vread(ins, 0, 4, i32, st);
                let b = self.vread(ins, 1, 4, i32, st);
                let v = if ins.mnemonic() == M::Pcmpgtd {
                    Expr::VecGt(Box::new(a), Box::new(b), 4, i32)
                } else {
                    Expr::VecAndn(Box::new(a), Box::new(b), 4, i32)
                };
                self.vwrite(ins, 0, v, st, out);
                return true;
            }
            _ => return false,
        };
        let Some(op) = op else {
            return false;
        };
        // `pxor xmm, xmm` with the same register zeroes it.
        if op == BinOp::Xor
            && ins.op_kind(0) == OpKind::Register
            && ins.op_kind(1) == OpKind::Register
            && ins.op_register(0) == ins.op_register(1)
        {
            self.vwrite(ins, 0, Expr::VecImm(0, lanes, lane), st, out);
            return true;
        }
        let a = self.vread(ins, 0, lanes, lane, st);
        let b = self.vread(ins, 1, lanes, lane, st);
        self.vwrite(
            ins,
            0,
            Expr::VecBin(op, Box::new(a), Box::new(b), lanes, lane),
            st,
            out,
        );
        true
    }

    /// An instruction the IR has no model for is kept as `asm!`.
    fn unmodeled(
        &self,
        ins: &Instruction,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let addr = ins.ip();
        // The general-purpose registers the instruction reads and writes (including implicit
        // ones, e.g. `cpuid` reads eax and writes eax/ebx/ecx/edx with no explicit operands).
        let mut info = InstructionInfoFactory::new();
        let mut reads: std::collections::BTreeSet<u8> = Default::default();
        let mut writes: std::collections::BTreeSet<u8> = Default::default();
        for u in info.info(ins).used_registers() {
            let Some((r, _)) = reg(u.register().full_register()) else {
                continue;
            };
            if r == RSP || (r as usize) >= REG_NAMES.len() {
                continue;
            }
            match u.access() {
                OpAccess::Read | OpAccess::CondRead => {
                    reads.insert(r);
                }
                OpAccess::Write | OpAccess::CondWrite => {
                    writes.insert(r);
                }
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    reads.insert(r);
                    writes.insert(r);
                }
                _ => {}
            }
        }
        // rbx and rbp cannot be `asm!` operands (LLVM reserves them), so they get no operand and
        // their writes stay modelled as `reg = unknown(...)` afterwards.
        const RBX: u8 = 3;
        let can_bind = |r: u8| r != RBX && r != RBP;
        let mut ops = Vec::new();
        let all: std::collections::BTreeSet<u8> = reads.union(&writes).copied().collect();
        for &r in &all {
            if !can_bind(r) {
                continue;
            }
            let name = REG_NAMES[r as usize];
            let input = Expr::Var(Var::Reg(r), Width::B64);
            let output = Var::Reg(r);
            ops.push(match (reads.contains(&r), writes.contains(&r)) {
                (true, true) => AsmOp::InOut(name, input, output),
                (false, true) => AsmOp::Out(name, output),
                (true, false) => AsmOp::In(name, input),
                (false, false) => unreachable!(),
            });
        }
        out.push((addr, Stmt::Asm(format!("{ins}"), ops)));
        // Writes to registers that cannot be `asm!` operands are still unknown afterwards.
        let what = format!("{:?}", ins.mnemonic()).to_lowercase();
        for r in writes {
            if !can_bind(r) {
                out.push((addr, Stmt::Assign(Var::Reg(r), Expr::Unknown(what.clone()))));
            }
        }
        st.flags = None;
        None
    }
}

/// Partial-register fix. An x86 8/16-bit register write PRESERVES the upper bits (unlike a 32-bit
/// write, which zeroes them). The lifter models a narrow write as a plain replace, which is only
/// correct when those upper bits do not carry a meaningful live value. This pass rewrites a narrow
/// write to `(old & !mask) | (val & mask)` exactly when the register's upper bits are:
///   * DEFINED by a reaching write (a prior >=16-bit write, or a parameter at entry) — forward
///     max-merge dataflow; and
///   * LIVE — read later at a width > w before being fully redefined — backward liveness; and
///   * NOT known-zero — the reaching value is not a `xor r,r` / `mov r,0` zeroing — forward
///     and-merge dataflow (a zeroed register's upper bits are 0, so the clean replace is already
///     right, which also keeps bool/byte returns clean).
///
/// So `mov al,X; ret` (undefined), `setb al; movzx eax,al` (dead) and `xor eax,eax; setz al; ret`
/// (zeroed) all stay clean; only a genuine `mov eax,V; mov al,Y; <use eax>` gets the RMW.
pub fn restore_partial_writes(blocks: &mut [Block], entry: u64, params: &[u8]) {
    use std::collections::HashMap;
    // Register file size: x86-64 uses 0..16, ARM64 `x0`..`x30` plus 31 (sp/zr).
    const NREG: usize = 32;
    type State = [u8; NREG];
    type Flags = [bool; NREG];

    fn gen_reads(live: &mut State, e: &Expr) {
        e.walk(&mut |x| {
            if let Expr::Var(Var::Reg(r), w) = x {
                live[*r as usize] = live[*r as usize].max(w.0);
            }
        });
    }
    fn term_reads(live: &mut State, t: &Term) {
        match t {
            // NB: Return is deliberately excluded. The IR models a return as reading rax at 64
            // bits, but the real return width is the (not-yet-inferred) return type; counting it
            // would mark the upper bits of a bool/byte return live and wrap it in a spurious RMW.
            // A genuine wide use of a partially-written register is a computation, caught below.
            Term::Branch(e, ..) | Term::TailCall(e) | Term::Switch(e, _) => gen_reads(live, e),
            _ => {}
        }
    }
    fn kill(live: &mut State, s: &Stmt) {
        match s {
            Stmt::Assign(Var::Reg(r), v) if v.width().0 >= 4 => live[*r as usize] = 0,
            Stmt::Assign(Var::Reg(_), _) => {}
            _ => {
                for d in s.defs() {
                    if let Var::Reg(r) = d {
                        live[r as usize] = 0;
                    }
                }
            }
        }
    }
    fn def_step(st: &mut State, s: &Stmt) {
        if let Stmt::Assign(Var::Reg(r), v) = s {
            let wv = v.width().0;
            st[*r as usize] = st[*r as usize].max(if wv >= 4 { 8 } else { wv });
        } else {
            for d in s.defs() {
                if let Var::Reg(r) = d {
                    st[r as usize] = 8;
                }
            }
        }
    }
    // A write that leaves the register all-zero: `mov r,0`, `xor r,r`, `sub r,r`.
    fn is_zero_write(v: &Expr) -> bool {
        match v {
            Expr::Const(0, _) => true,
            Expr::Bin(BinOp::Xor | BinOp::Sub, a, b, _) => a == b,
            _ => false,
        }
    }
    fn zero_step(z: &mut Flags, s: &Stmt) {
        if let Stmt::Assign(Var::Reg(r), v) = s {
            z[*r as usize] = is_zero_write(v);
        } else {
            for d in s.defs() {
                if let Var::Reg(r) = d {
                    z[r as usize] = false;
                }
            }
        }
    }

    let idx: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, i))
        .collect();
    let n = blocks.len();
    let (mut preds, mut succs): (Vec<Vec<usize>>, Vec<Vec<usize>>) =
        (vec![Vec::new(); n], vec![Vec::new(); n]);
    for (i, b) in blocks.iter().enumerate() {
        for s in crate::simplify::successors(&b.term) {
            if let Some(&j) = idx.get(&s) {
                preds[j].push(i);
                succs[i].push(j);
            }
        }
    }
    let mut entry_def: State = [0; NREG];
    for &p in params {
        entry_def[p as usize] = 8;
    }

    let mut def_in = vec![[0u8; NREG]; n];
    let mut def_out = vec![[0u8; NREG]; n];
    let mut zero_in = vec![[false; NREG]; n];
    let mut zero_out = vec![[false; NREG]; n];
    let mut live_in = vec![[0u8; NREG]; n];
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            let mut d = if blocks[i].addr == entry {
                entry_def
            } else {
                [0u8; NREG]
            };
            for &p in &preds[i] {
                for r in 0..16 {
                    d[r] = d[r].max(def_out[p][r]);
                }
            }
            let mut z = if blocks[i].addr == entry || preds[i].is_empty() {
                [false; NREG]
            } else {
                [true; NREG]
            };
            for &p in &preds[i] {
                for r in 0..16 {
                    z[r] &= zero_out[p][r];
                }
            }
            if d != def_in[i] || z != zero_in[i] {
                def_in[i] = d;
                zero_in[i] = z;
                changed = true;
            }
            let (mut od, mut oz) = (def_in[i], zero_in[i]);
            for (_, s) in &blocks[i].stmts {
                def_step(&mut od, s);
                zero_step(&mut oz, s);
            }
            if od != def_out[i] || oz != zero_out[i] {
                def_out[i] = od;
                zero_out[i] = oz;
                changed = true;
            }
            let mut live = [0u8; NREG];
            for &j in &succs[i] {
                for r in 0..16 {
                    live[r] = live[r].max(live_in[j][r]);
                }
            }
            term_reads(&mut live, &blocks[i].term);
            for (_, s) in blocks[i].stmts.iter().rev() {
                kill(&mut live, s);
                for e in s.exprs() {
                    gen_reads(&mut live, e);
                }
            }
            if live != live_in[i] {
                live_in[i] = live;
                changed = true;
            }
        }
    }

    for i in 0..n {
        let mut live_out = [0u8; NREG];
        for &j in &succs[i] {
            for r in 0..16 {
                live_out[r] = live_out[r].max(live_in[j][r]);
            }
        }
        let mut live_after = vec![[0u8; NREG]; blocks[i].stmts.len()];
        {
            let mut live = live_out;
            term_reads(&mut live, &blocks[i].term);
            for k in (0..blocks[i].stmts.len()).rev() {
                live_after[k] = live;
                kill(&mut live, &blocks[i].stmts[k].1);
                for e in blocks[i].stmts[k].1.exprs() {
                    gen_reads(&mut live, e);
                }
            }
        }
        let (mut st, mut z) = (def_in[i], zero_in[i]);
        for (k, (_, s)) in blocks[i].stmts.iter_mut().enumerate() {
            if let Stmt::Assign(Var::Reg(r), v) = s {
                let w = v.width().0;
                if (w == 1 || w == 2)
                    && st[*r as usize] > w
                    && live_after[k][*r as usize] > w
                    && !z[*r as usize]
                {
                    let mask = Width(w).mask();
                    let old = Expr::Var(Var::Reg(*r), Width::B64);
                    let val = std::mem::replace(v, Expr::Unknown(String::new()));
                    *v = Expr::bin(
                        BinOp::Or,
                        Expr::bin(BinOp::And, old, Expr::konst(!mask, Width::B64), Width::B64),
                        Expr::bin(
                            BinOp::And,
                            Expr::Cast(Box::new(val), Width::B64, false),
                            Expr::konst(mask, Width::B64),
                            Width::B64,
                        ),
                        Width::B64,
                    );
                }
            }
            def_step(&mut st, s);
            zero_step(&mut z, s);
        }
    }
}
