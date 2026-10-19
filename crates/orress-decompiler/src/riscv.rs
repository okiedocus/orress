//! Lifting RISC-V (RV64I + M) machine code into the shared decompiler IR, so the simplify →
//! structure → types → print pipeline produces Rust-style pseudocode for RISC-V too.
//!
//! Registers map to `Var::Reg(n)` with a numbering chosen so the ABI argument/return registers
//! land where the pipeline expects them: `a0`..`a7` (x10..x17) become IR registers 0..7 (so
//! `a0` is register 0, the result register, like x86's `rax`), and [`Convention::Riscv`] uses
//! `[0..7]` as its argument registers. `x0` (the zero register) becomes a constant `0`; `sp`
//! -relative loads/stores become `Var::Stack` slots.
//!
//! Covered: RV64I + the M extension, plus the common compressed (`C`) forms expanded to the same
//! IR. Floating-point, CSR/system and uncommon compressed instructions are kept as `asm!`.

use std::collections::{HashMap, VecDeque};

use orress_analysis::{EdgeKind, Function, Program};

use crate::ir::*;
use crate::lift::{Convention, import_noreturn, import_params};

pub struct RiscvLifter<'a> {
    pub program: &'a Program,
    pub param_counts: &'a HashMap<u64, usize>,
}

struct State {
    /// Argument registers (0..8) written since the last call, to count a call's arguments.
    written: Vec<u8>,
}

/// Maps an x-register number to the IR register numbering (see the module docs). `x0` is never
/// mapped — it is the zero register and becomes a constant.
fn reg_num(x: u32) -> u8 {
    match x {
        10..=17 => (x - 10) as u8, // a0..a7 -> 0..7
        1 => 8,                    // ra -> 8
        5..=7 => (x + 4) as u8,    // t0..t2 -> 9..11
        28..=31 => (x - 16) as u8, // t3..t6 -> 12..15
        8 | 9 => (x + 8) as u8,    // s0,s1 -> 16,17
        18..=27 => x as u8,        // s2..s11 -> 18..27
        2 => 28,                   // sp
        3 => 29,                   // gp
        4 => 30,                   // tp
        _ => (x & 0x1f) as u8,
    }
}

/// A source x-register as an expression: `x0` is the constant 0.
fn src(x: u32, w: Width) -> Expr {
    if x == 0 {
        Expr::konst(0, w)
    } else {
        Expr::Var(Var::Reg(reg_num(x)), w)
    }
}

/// The destination of a write to x-register `x`, or `None` when it is `x0` (writes discarded).
fn dest(x: u32) -> Option<Var> {
    (x != 0).then(|| Var::Reg(reg_num(x)))
}

/// Maps an f-register to the IR float-register numbering (reusing `Var::Xmm`), chosen so the
/// floating-point argument/return registers `fa0..fa7` are 0..7 — matching `float_arg_regs` and
/// `retarget_float_return` in `simplify`, exactly as the integer [`reg_num`] does for `a0..a7`.
fn freg_num(f: u32) -> u8 {
    match f {
        10..=17 => (f - 10) as u8, // fa0..fa7 -> 0..7
        0..=9 => (f + 8) as u8,    // ft0..ft7 -> 8..15, fs0,fs1 -> 16,17
        _ => f as u8,              // fs2..fs11 (18..27), ft8..ft11 (28..31)
    }
}

/// A source f-register as a float-valued expression.
fn fsrc(f: u32, w: Width) -> Expr {
    Expr::Var(Var::Xmm(freg_num(f)), w)
}

/// The destination f-register (float writes are never discarded — there is no float zero register).
fn fdest(f: u32) -> Var {
    Var::Xmm(freg_num(f))
}

fn sext(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((value << shift) as i32 >> shift) as i64
}

impl RiscvLifter<'_> {
    pub fn lift(&self, f: &Function) -> Vec<Block> {
        let mut out: HashMap<u64, Block> = HashMap::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, b) in f.blocks.iter().enumerate() {
            if b.start == f.entry {
                queue.push_back(i);
                break;
            }
        }
        let mut seen = vec![false; f.blocks.len()];
        while let Some(index) = queue.pop_front() {
            if seen[index] {
                continue;
            }
            seen[index] = true;
            let block = self.lift_block(f, index);
            for e in &f.blocks[index].succs {
                if let Some(j) = f.blocks.iter().position(|b| b.start == e.target) {
                    queue.push_back(j);
                }
            }
            out.insert(f.blocks[index].start, block);
        }
        for (i, b) in f.blocks.iter().enumerate() {
            out.entry(b.start).or_insert_with(|| self.lift_block(f, i));
        }
        let mut blocks: Vec<Block> = out.into_values().collect();
        blocks.sort_by_key(|b| b.addr);
        blocks
    }

    fn lift_block(&self, f: &Function, index: usize) -> Block {
        let fb = &f.blocks[index];
        let mut st = State {
            written: Vec::new(),
        };
        let mut stmts = Vec::new();
        let mut term = None;
        let mut term_addr = fb.start;
        for &addr in &fb.insns {
            let Some(word) = self.read(addr) else {
                stmts.push((addr, Stmt::Asm("(undecodable)".into(), Vec::new())));
                continue;
            };
            term_addr = addr;
            if let Some(t) = self.lift_word(word, addr, &mut st, &mut stmts) {
                term = Some(t);
            }
        }
        let term = term.unwrap_or_else(|| {
            match fb
                .succs
                .iter()
                .find(|e| matches!(e.kind, EdgeKind::FallThrough | EdgeKind::Jump))
            {
                Some(e) => Term::Jump(e.target),
                None => Term::Stop,
            }
        });
        Block {
            addr: fb.start,
            stmts,
            term,
            term_addr,
        }
    }

    /// Reads the 32 bits at `addr` (RISC-V is little-endian).
    fn read(&self, addr: u64) -> Option<u32> {
        let bytes = self.program.memory.read(addr, 4)?;
        Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
    }

    /// Records a write to an argument register (0..8) for counting an unknown call's arguments.
    fn note_write(st: &mut State, v: &Var) {
        if let Var::Reg(r) = v
            && *r < 8
        {
            st.written.push(*r);
        }
    }

    fn assign(out: &mut Vec<(u64, Stmt)>, addr: u64, st: &mut State, v: Var, e: Expr) {
        Self::note_write(st, &v);
        out.push((addr, Stmt::Assign(v, e)));
    }

    fn lift_word(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        // Compressed instructions expand to a base word (or an asm fallback) with length 2.
        if w as u16 & 0b11 != 0b11 {
            return self.lift_compressed(w as u16, addr, st, out);
        }
        self.lift_base(w, addr, 4, st, out)
    }

    #[allow(clippy::too_many_arguments)]
    fn lift_base(
        &self,
        w: u32,
        addr: u64,
        len: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let opcode = w & 0x7f;
        let rd = (w >> 7) & 0x1f;
        let rs1 = (w >> 15) & 0x1f;
        let rs2 = (w >> 20) & 0x1f;
        let f3 = (w >> 12) & 0x7;
        let f7 = (w >> 25) & 0x7f;
        let i_imm = sext(w >> 20, 12);
        let s_imm = sext(((w >> 25) << 5) | ((w >> 7) & 0x1f), 12);
        let b_imm = sext(
            ((w >> 31) << 12)
                | (((w >> 7) & 1) << 11)
                | (((w >> 25) & 0x3f) << 5)
                | (((w >> 8) & 0xf) << 1),
            13,
        );
        let u_imm = (w & 0xffff_f000) as i32 as i64;
        let j_imm = sext(
            ((w >> 31) << 20)
                | (((w >> 12) & 0xff) << 12)
                | (((w >> 20) & 1) << 11)
                | (((w >> 21) & 0x3ff) << 1),
            21,
        );
        let next = addr + len;
        let b64 = Width::B64;

        match opcode {
            0x37 => {
                // lui
                if let Some(d) = dest(rd) {
                    Self::assign(
                        out,
                        addr,
                        st,
                        d,
                        Expr::konst((u_imm as u64) & 0xffff_ffff, b64),
                    );
                }
            }
            0x17 => {
                // auipc: pc-relative base.
                if let Some(d) = dest(rd) {
                    let v = addr.wrapping_add_signed(u_imm);
                    Self::assign(out, addr, st, d, Expr::Addr(v));
                }
            }
            0x6f => {
                // jal: call (rd == ra) or jump.
                let target = addr.wrapping_add_signed(j_imm);
                if rd == 1 {
                    return self.call(addr, CallTarget::Direct(target), st, out);
                }
                return Some(if self.program.functions.contains_key(&target) && rd != 0 {
                    Term::TailCall(Expr::Call(CallTarget::Direct(target), Vec::new()))
                } else {
                    Term::Jump(target)
                });
            }
            0x67 => {
                // jalr: ret / indirect call / indirect jump.
                if rd == 0 && rs1 == 1 && i_imm == 0 {
                    return Some(Term::Return(Some(Expr::Var(Var::Reg(0), b64))));
                }
                let target = Expr::bin(
                    BinOp::Add,
                    src(rs1, b64),
                    Expr::konst(i_imm as u64, b64),
                    b64,
                );
                if rd == 1 {
                    return self.call(addr, CallTarget::Indirect(Box::new(target)), st, out);
                }
                return Some(Term::TailCall(Expr::Call(
                    CallTarget::Indirect(Box::new(target)),
                    Vec::new(),
                )));
            }
            0x63 => {
                // Conditional branches.
                let target = addr.wrapping_add_signed(b_imm);
                let (op, signed) = match f3 {
                    0 => (CmpOp::Eq, false),
                    1 => (CmpOp::Ne, false),
                    4 => (CmpOp::Lt, true),
                    5 => (CmpOp::Ge, true),
                    6 => (CmpOp::Lt, false),
                    7 => (CmpOp::Ge, false),
                    _ => return self.asm(w, addr, out),
                };
                let cond = Expr::cmp(op, src(rs1, b64), src(rs2, b64), signed);
                return Some(Term::Branch(cond, target, next));
            }
            0x03 => {
                // Loads.
                let (width, signed) = match f3 {
                    0 => (Width::B8, true),
                    1 => (Width::B16, true),
                    2 => (Width::B32, true),
                    3 => (b64, false),
                    4 => (Width::B8, false),
                    5 => (Width::B16, false),
                    6 => (Width::B32, false),
                    _ => return self.asm(w, addr, out),
                };
                if let Some(d) = dest(rd) {
                    let mut value = self.load(rs1, i_imm, width);
                    if signed && width != b64 {
                        value = Expr::Cast(Box::new(value), b64, true);
                    }
                    Self::assign(out, addr, st, d, value);
                }
            }
            0x23 => {
                // Stores.
                let width = match f3 {
                    0 => Width::B8,
                    1 => Width::B16,
                    2 => Width::B32,
                    3 => b64,
                    _ => return self.asm(w, addr, out),
                };
                self.store(rs1, s_imm, src(rs2, width), width, addr, out);
            }
            0x13 | 0x1b => {
                self.op_imm(w, addr, opcode == 0x1b, rd, rs1, f3, i_imm, st, out);
            }
            0x33 | 0x3b => {
                return self.op_reg(w, addr, opcode == 0x3b, rd, rs1, rs2, f3, f7, st, out);
            }
            0x73 => {
                if w == 0x0010_0073 {
                    return Some(Term::Stop); // ebreak
                }
                return self.asm(w, addr, out); // ecall / CSR
            }
            // Floating-point loads/stores (f3 2 = single, 3 = double).
            0x07 if f3 == 2 || f3 == 3 => {
                let fw = if f3 == 3 { b64 } else { Width::B32 };
                let v = self.load(rs1, i_imm, fw);
                Self::assign(out, addr, st, fdest(rd), v);
            }
            0x27 if f3 == 2 || f3 == 3 => {
                let fw = if f3 == 3 { b64 } else { Width::B32 };
                self.store(rs1, s_imm, fsrc(rs2, fw), fw, addr, out);
            }
            // OP-FP and fused multiply-add.
            0x53 => return self.lift_fp(w, addr, rd, rs1, rs2, f3, f7, st, out),
            0x43 | 0x47 | 0x4b | 0x4f => self.lift_fma(w, addr, opcode, rd, rs1, rs2, st, out),
            0x0f => {} // fence: no effect on the recovered logic.
            _ => return self.asm(w, addr, out),
        }
        None
    }

    /// OP-FP (opcode 0x53): the single/double arithmetic, min/max, compares (integer result),
    /// conversions and reinterpreting moves. The general `fsgnj` and `fclass` have no direct IR
    /// and stay as `asm!`.
    #[allow(clippy::too_many_arguments)]
    fn lift_fp(
        &self,
        w: u32,
        addr: u64,
        rd: u32,
        rs1: u32,
        rs2: u32,
        f3: u32,
        f7: u32,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let fw = if f7 & 1 == 0 { Width::B32 } else { Width::B64 };
        let b64 = Width::B64;
        let fab = |op| Expr::fbin(op, fsrc(rs1, fw), fsrc(rs2, fw), fw);
        match f7 >> 1 {
            0x00 => Self::assign(out, addr, st, fdest(rd), fab(BinOp::Add)),
            0x02 => Self::assign(out, addr, st, fdest(rd), fab(BinOp::Sub)),
            0x04 => Self::assign(out, addr, st, fdest(rd), fab(BinOp::Mul)),
            0x06 => Self::assign(out, addr, st, fdest(rd), fab(BinOp::Div)),
            0x16 => {
                let v = Expr::FUn(FUnOp::Sqrt, Box::new(fsrc(rs1, fw)), fw);
                Self::assign(out, addr, st, fdest(rd), v);
            }
            // fsgnj group — the fmv/fneg/fabs pseudo-ops (when the two sources are the same reg).
            0x08 if rs1 == rs2 => {
                let v = match f3 {
                    0 => fsrc(rs1, fw),
                    1 => Expr::FUn(FUnOp::Neg, Box::new(fsrc(rs1, fw)), fw),
                    2 => Expr::FUn(FUnOp::Abs, Box::new(fsrc(rs1, fw)), fw),
                    _ => return self.asm(w, addr, out),
                };
                Self::assign(out, addr, st, fdest(rd), v);
            }
            // fmin / fmax.
            0x0a => {
                let name = if f3 == 0 { "min" } else { "max" };
                let v = Expr::method(fsrc(rs1, fw), name, vec![fsrc(rs2, fw)], fw);
                Self::assign(out, addr, st, fdest(rd), v);
            }
            // feq / flt / fle -> a bool in an integer register.
            0x28 => {
                let op = match f3 {
                    0 => CmpOp::Le,
                    1 => CmpOp::Lt,
                    2 => CmpOp::Eq,
                    _ => return self.asm(w, addr, out),
                };
                if let Some(d) = dest(rd) {
                    let cond = Expr::fcmp(op, fsrc(rs1, fw), fsrc(rs2, fw));
                    Self::assign(out, addr, st, d, Expr::Cast(Box::new(cond), b64, false));
                }
            }
            // fcvt.s.d / fcvt.d.s.
            0x10 => {
                let (dstw, srcw) = if f7 & 1 == 0 {
                    (Width::B32, b64)
                } else {
                    (b64, Width::B32)
                };
                let v = Expr::FCast(Box::new(fsrc(rs1, srcw)), dstw, FCast::FloatToFloat);
                Self::assign(out, addr, st, fdest(rd), v);
            }
            // Float -> integer (fcvt.w/wu/l/lu).
            0x30 => {
                if let Some(d) = dest(rd) {
                    let v = Expr::FCast(Box::new(fsrc(rs1, fw)), b64, FCast::FloatToSInt);
                    Self::assign(out, addr, st, d, v);
                }
            }
            // Integer -> float (fcvt.{s,d}.w/...).
            0x34 => {
                let v = Expr::FCast(Box::new(src(rs1, b64)), fw, FCast::SIntToFloat);
                Self::assign(out, addr, st, fdest(rd), v);
            }
            // fmv.x.w: reinterpret the float's bits as an integer.
            0x38 if f3 == 0 => {
                if let Some(d) = dest(rd) {
                    Self::assign(out, addr, st, d, fsrc(rs1, fw));
                }
            }
            // fmv.w.x: reinterpret an integer's bits as a float.
            0x3c => Self::assign(out, addr, st, fdest(rd), src(rs1, fw)),
            _ => return self.asm(w, addr, out),
        }
        None
    }

    /// Fused multiply-add (opcodes 0x43/0x47/0x4b/0x4f): `±(rs1 * rs2) ± rs3`.
    #[allow(clippy::too_many_arguments)]
    fn lift_fma(
        &self,
        w: u32,
        addr: u64,
        opcode: u32,
        rd: u32,
        rs1: u32,
        rs2: u32,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let fw = if (w >> 25) & 1 == 0 {
            Width::B32
        } else {
            Width::B64
        };
        let rs3 = (w >> 27) & 0x1f;
        let mul = Expr::fbin(BinOp::Mul, fsrc(rs1, fw), fsrc(rs2, fw), fw);
        let c = fsrc(rs3, fw);
        let v = match opcode {
            0x43 => Expr::fbin(BinOp::Add, mul, c, fw), // fmadd: a*b + c
            0x47 => Expr::fbin(BinOp::Sub, mul, c, fw), // fmsub: a*b - c
            0x4b => Expr::fbin(BinOp::Sub, c, mul, fw), // fnmsub: c - a*b
            _ => Expr::FUn(FUnOp::Neg, Box::new(Expr::fbin(BinOp::Add, mul, c, fw)), fw), // fnmadd
        };
        Self::assign(out, addr, st, fdest(rd), v);
    }

    #[allow(clippy::too_many_arguments)]
    fn op_imm(
        &self,
        w: u32,
        addr: u64,
        word32: bool,
        rd: u32,
        rs1: u32,
        f3: u32,
        i_imm: i64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let b64 = Width::B64;
        let Some(d) = dest(rd) else { return };
        // addi rd, rs1, 0 is a move; addi rd, x0, imm is a load-immediate.
        if !word32 && f3 == 0 {
            if rs1 == 0 {
                Self::assign(out, addr, st, d, Expr::konst(i_imm as u64, b64));
                return;
            }
            if i_imm == 0 {
                Self::assign(out, addr, st, d, src(rs1, b64));
                return;
            }
        }
        let shamt = (i_imm as u64) & if word32 { 0x1f } else { 0x3f };
        let (op, rhs) = match f3 {
            0 => (BinOp::Add, Expr::konst(i_imm as u64, b64)),
            1 => (BinOp::Shl, Expr::konst(shamt, b64)),
            4 => (BinOp::Xor, Expr::konst(i_imm as u64, b64)),
            5 if (w >> 30) & 1 == 1 => (BinOp::Sar, Expr::konst(shamt, b64)),
            5 => (BinOp::Shr, Expr::konst(shamt, b64)),
            6 => (BinOp::Or, Expr::konst(i_imm as u64, b64)),
            7 => (BinOp::And, Expr::konst(i_imm as u64, b64)),
            // slti / sltiu: a comparison producing 0/1.
            2 | 3 => {
                let cond = Expr::cmp(
                    CmpOp::Lt,
                    src(rs1, b64),
                    Expr::konst(i_imm as u64, b64),
                    f3 == 2,
                );
                Self::assign(out, addr, st, d, Expr::Cast(Box::new(cond), b64, false));
                return;
            }
            _ => unreachable!(),
        };
        let value = self.widen(Expr::bin(op, src(rs1, b64), rhs, b64), word32);
        Self::assign(out, addr, st, d, value);
    }

    #[allow(clippy::too_many_arguments)]
    fn op_reg(
        &self,
        w: u32,
        addr: u64,
        word32: bool,
        rd: u32,
        rs1: u32,
        rs2: u32,
        f3: u32,
        f7: u32,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let b64 = Width::B64;
        let d = dest(rd)?;
        let a = src(rs1, b64);
        let b = src(rs2, b64);
        let value = if f7 == 0x01 {
            // M extension.
            match f3 {
                0 => Expr::bin(BinOp::Mul, a, b, b64),
                4 => Expr::bin(BinOp::Div, Self::signed(a), Self::signed(b), b64),
                5 => Expr::bin(BinOp::Div, a, b, b64),
                6 => Expr::bin(BinOp::Rem, Self::signed(a), Self::signed(b), b64),
                7 => Expr::bin(BinOp::Rem, a, b, b64),
                _ => return self.asm(w, addr, out),
            }
        } else {
            match (f3, f7) {
                (0, 0x00) => Expr::bin(BinOp::Add, a, b, b64),
                (0, 0x20) => Expr::bin(BinOp::Sub, a, b, b64),
                (1, 0x00) => Expr::bin(BinOp::Shl, a, b, b64),
                (4, 0x00) => Expr::bin(BinOp::Xor, a, b, b64),
                (5, 0x00) => Expr::bin(BinOp::Shr, a, b, b64),
                (5, 0x20) => Expr::bin(BinOp::Sar, a, b, b64),
                (6, 0x00) => Expr::bin(BinOp::Or, a, b, b64),
                (7, 0x00) => Expr::bin(BinOp::And, a, b, b64),
                (2, 0x00) => Expr::Cast(
                    Box::new(Expr::cmp(CmpOp::Lt, Self::signed(a), Self::signed(b), true)),
                    b64,
                    false,
                ),
                (3, 0x00) => Expr::Cast(Box::new(Expr::cmp(CmpOp::Lt, a, b, false)), b64, false),
                _ => return self.asm(w, addr, out),
            }
        };
        let value = self.widen(value, word32);
        Self::assign(out, addr, st, d, value);
        None
    }

    /// For a word-size (`.w`) op, the 64-bit result is the 32-bit value sign-extended.
    fn widen(&self, e: Expr, word32: bool) -> Expr {
        if word32 {
            Expr::Cast(
                Box::new(Expr::Cast(Box::new(e), Width::B32, false)),
                Width::B64,
                true,
            )
        } else {
            e
        }
    }

    fn signed(e: Expr) -> Expr {
        Expr::Cast(Box::new(e), Width::B64, true)
    }

    /// A load of `width` from `off(rs1)`: a stack slot when through `sp`, else a memory read.
    fn load(&self, rs1: u32, off: i64, width: Width) -> Expr {
        if rs1 == 2 {
            Expr::Var(Var::Stack(off), width)
        } else {
            let addr = Expr::bin(
                BinOp::Add,
                src(rs1, Width::B64),
                Expr::konst(off as u64, Width::B64),
                Width::B64,
            );
            Expr::Load(Box::new(addr), width)
        }
    }

    fn store(
        &self,
        rs1: u32,
        off: i64,
        value: Expr,
        width: Width,
        addr: u64,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        if rs1 == 2 {
            out.push((addr, Stmt::Assign(Var::Stack(off), value)));
        } else {
            let a = Expr::bin(
                BinOp::Add,
                src(rs1, Width::B64),
                Expr::konst(off as u64, Width::B64),
                Width::B64,
            );
            out.push((addr, Stmt::Store(a, value, width)));
        }
    }

    /// Emits a call: arguments from `a0..` up to the callee's parameter count, result in `a0`
    /// (IR register 0), caller-saved registers clobbered.
    fn call(
        &self,
        addr: u64,
        target: CallTarget,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let name = match &target {
            CallTarget::Direct(a) => self.program.name(*a).map(|n| n.text.clone()),
            _ => None,
        };
        let regs = Convention::Riscv.arg_regs();
        let count = match &target {
            CallTarget::Direct(a) => self
                .param_counts
                .get(a)
                .copied()
                .or_else(|| name.as_deref().and_then(import_params)),
            _ => None,
        }
        .unwrap_or_else(|| regs.iter().take_while(|r| st.written.contains(r)).count());
        let args = regs
            .iter()
            .take(count)
            .map(|&r| Expr::Var(Var::Reg(r), Width::B64))
            .collect();
        out.push((addr, Stmt::Assign(Var::Reg(0), Expr::Call(target, args))));
        for &r in Convention::Riscv.clobbered() {
            out.push((
                addr,
                Stmt::Assign(Var::Reg(r), Expr::Unknown("clobbered".into())),
            ));
        }
        st.written.clear();
        if name.as_deref().is_some_and(import_noreturn) {
            return Some(Term::Stop);
        }
        None
    }

    fn asm(&self, w: u32, addr: u64, out: &mut Vec<(u64, Stmt)>) -> Option<Term> {
        // Keep the original mnemonic (from the disassembler) for the un-lifted instruction.
        let text = self.program.decode(addr).map_or_else(
            || format!(".word 0x{w:08x}"),
            |insn| {
                let ops: String = insn.operands.iter().map(|t| t.text.as_str()).collect();
                if ops.is_empty() {
                    insn.mnemonic
                } else {
                    format!("{} {ops}", insn.mnemonic)
                }
            },
        );
        out.push((addr, Stmt::Asm(text, Vec::new())));
        None
    }

    /// Compressed instructions: the common forms expand to the same IR; the rest are kept as asm
    /// (length 2 so the block stays aligned).
    fn lift_compressed(
        &self,
        h: u16,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let w = u32::from(h);
        let op = w & 0b11;
        let f3 = (w >> 13) & 0b111;
        let b64 = Width::B64;
        match (op, f3) {
            // C.J
            (0b01, 0b101) => {
                let off = cj_imm(w);
                return Some(Term::Jump(addr.wrapping_add_signed(off)));
            }
            // C.BEQZ / C.BNEZ (register x8..x15).
            (0b01, 0b110) | (0b01, 0b111) => {
                let rs1 = 8 + ((w >> 7) & 7);
                let target = addr.wrapping_add_signed(cb_imm(w));
                let op = if f3 == 0b110 { CmpOp::Eq } else { CmpOp::Ne };
                let cond = Expr::cmp(op, src(rs1, b64), Expr::konst(0, b64), false);
                return Some(Term::Branch(cond, target, addr + 2));
            }
            // C.JR / C.MV / C.JALR / C.ADD / C.EBREAK (quadrant 2, funct3=100).
            (0b10, 0b100) => {
                let rs1 = (w >> 7) & 0x1f;
                let rs2 = (w >> 2) & 0x1f;
                let bit12 = (w >> 12) & 1;
                match (bit12, rs1, rs2) {
                    (0, 1, 0) => return Some(Term::Return(Some(Expr::Var(Var::Reg(0), b64)))), // c.jr ra
                    (0, r, 0) if r != 0 => {
                        return Some(Term::TailCall(Expr::Call(
                            CallTarget::Indirect(Box::new(src(r, b64))),
                            Vec::new(),
                        )));
                    }
                    (0, r, s) if s != 0 => {
                        if let Some(d) = dest(r) {
                            Self::assign(out, addr, st, d, src(s, b64));
                        }
                    }
                    (1, 0, 0) => return Some(Term::Stop), // c.ebreak
                    (1, r, 0) if r != 0 => {
                        return self.call(
                            addr,
                            CallTarget::Indirect(Box::new(src(r, b64))),
                            st,
                            out,
                        );
                    }
                    (1, r, s) if s != 0 => {
                        if let Some(d) = dest(r) {
                            Self::assign(
                                out,
                                addr,
                                st,
                                d,
                                Expr::bin(BinOp::Add, src(r, b64), src(s, b64), b64),
                            );
                        }
                    }
                    _ => return self.asm(w, addr, out),
                }
            }
            // C.NOP / C.ADDI.
            (0b01, 0b000) => {
                let rd = (w >> 7) & 0x1f;
                if let Some(d) = dest(rd) {
                    Self::assign(
                        out,
                        addr,
                        st,
                        d,
                        Expr::bin(
                            BinOp::Add,
                            src(rd, b64),
                            Expr::konst(ci_imm(w) as u64, b64),
                            b64,
                        ),
                    );
                }
            }
            // C.LI.
            (0b01, 0b010) => {
                let rd = (w >> 7) & 0x1f;
                if let Some(d) = dest(rd) {
                    Self::assign(out, addr, st, d, Expr::konst(ci_imm(w) as u64, b64));
                }
            }
            // ---- Quadrant 0: frame and reg+offset loads/stores (`rs1'`/`rd'` are x8..x15) ----
            // C.ADDI4SPN: addi rd', sp, nzuimm. An all-zero immediate is reserved.
            (0b00, 0b000) => {
                let nz = ciw_imm(w);
                if nz == 0 {
                    return self.asm(w, addr, out);
                }
                if let Some(d) = dest(8 + ((w >> 2) & 7)) {
                    let v = Expr::bin(BinOp::Add, src(2, b64), Expr::konst(nz as u64, b64), b64);
                    Self::assign(out, addr, st, d, v);
                }
            }
            // C.LW / C.LD.
            (0b00, 0b010) | (0b00, 0b011) => {
                let (width, off) = if f3 == 0b010 {
                    (Width::B32, clw_imm(w))
                } else {
                    (b64, cld_imm(w))
                };
                if let Some(d) = dest(8 + ((w >> 2) & 7)) {
                    let mut value = self.load(8 + ((w >> 7) & 7), off, width);
                    // `c.lw` sign-extends its 32-bit result to the 64-bit register.
                    if width != b64 {
                        value = Expr::Cast(Box::new(value), b64, true);
                    }
                    Self::assign(out, addr, st, d, value);
                }
            }
            // C.SW / C.SD.
            (0b00, 0b110) | (0b00, 0b111) => {
                let (width, off) = if f3 == 0b110 {
                    (Width::B32, clw_imm(w))
                } else {
                    (b64, cld_imm(w))
                };
                self.store(
                    8 + ((w >> 7) & 7),
                    off,
                    src(8 + ((w >> 2) & 7), width),
                    width,
                    addr,
                    out,
                );
            }
            // ---- Quadrant 1 ----
            // C.ADDIW (RV64): addiw rd, rd, imm.
            (0b01, 0b001) => {
                let rd = (w >> 7) & 0x1f;
                if let Some(d) = dest(rd) {
                    let v = self.widen(
                        Expr::bin(
                            BinOp::Add,
                            src(rd, b64),
                            Expr::konst(ci_imm(w) as u64, b64),
                            b64,
                        ),
                        true,
                    );
                    Self::assign(out, addr, st, d, v);
                }
            }
            // C.LUI (rd != 0, 2) / C.ADDI16SP (rd == 2).
            (0b01, 0b011) => {
                let rd = (w >> 7) & 0x1f;
                if rd == 2 {
                    if let Some(d) = dest(2) {
                        let v = Expr::bin(
                            BinOp::Add,
                            src(2, b64),
                            Expr::konst(addi16sp_imm(w) as u64, b64),
                            b64,
                        );
                        Self::assign(out, addr, st, d, v);
                    }
                } else if let Some(d) = dest(rd) {
                    Self::assign(
                        out,
                        addr,
                        st,
                        d,
                        Expr::konst((clui_imm(w) as u64) & 0xffff_ffff, b64),
                    );
                }
            }
            // C.SRLI / C.SRAI / C.ANDI / C.SUB / C.XOR / C.OR / C.AND / C.SUBW / C.ADDW.
            (0b01, 0b100) => {
                let rd = 8 + ((w >> 7) & 7);
                let d = dest(rd)?;
                let value = match (w >> 10) & 0b11 {
                    0b00 => Expr::bin(BinOp::Shr, src(rd, b64), Expr::konst(cshamt(w), b64), b64),
                    0b01 => Expr::bin(BinOp::Sar, src(rd, b64), Expr::konst(cshamt(w), b64), b64),
                    0b10 => Expr::bin(
                        BinOp::And,
                        src(rd, b64),
                        Expr::konst(ci_imm(w) as u64, b64),
                        b64,
                    ),
                    _ => {
                        let rs2 = src(8 + ((w >> 2) & 7), b64);
                        match ((w >> 12) & 1, (w >> 5) & 0b11) {
                            (0, 0b00) => Expr::bin(BinOp::Sub, src(rd, b64), rs2, b64),
                            (0, 0b01) => Expr::bin(BinOp::Xor, src(rd, b64), rs2, b64),
                            (0, 0b10) => Expr::bin(BinOp::Or, src(rd, b64), rs2, b64),
                            (0, 0b11) => Expr::bin(BinOp::And, src(rd, b64), rs2, b64),
                            (1, 0b00) => {
                                self.widen(Expr::bin(BinOp::Sub, src(rd, b64), rs2, b64), true)
                            }
                            (1, 0b01) => {
                                self.widen(Expr::bin(BinOp::Add, src(rd, b64), rs2, b64), true)
                            }
                            _ => return self.asm(w, addr, out),
                        }
                    }
                };
                Self::assign(out, addr, st, d, value);
            }
            // ---- Quadrant 2 ----
            // C.SLLI.
            (0b10, 0b000) => {
                let rd = (w >> 7) & 0x1f;
                if let Some(d) = dest(rd) {
                    let v = Expr::bin(BinOp::Shl, src(rd, b64), Expr::konst(cshamt(w), b64), b64);
                    Self::assign(out, addr, st, d, v);
                }
            }
            // C.LWSP / C.LDSP (base is sp = x2).
            (0b10, 0b010) | (0b10, 0b011) => {
                let (width, off) = if f3 == 0b010 {
                    (Width::B32, lwsp_imm(w))
                } else {
                    (b64, ldsp_imm(w))
                };
                if let Some(d) = dest((w >> 7) & 0x1f) {
                    let mut value = self.load(2, off, width);
                    if width != b64 {
                        value = Expr::Cast(Box::new(value), b64, true);
                    }
                    Self::assign(out, addr, st, d, value);
                }
            }
            // C.SWSP / C.SDSP (base is sp = x2).
            (0b10, 0b110) | (0b10, 0b111) => {
                let (width, off) = if f3 == 0b110 {
                    (Width::B32, swsp_imm(w))
                } else {
                    (b64, sdsp_imm(w))
                };
                self.store(2, off, src((w >> 2) & 0x1f, width), width, addr, out);
            }
            // Compressed double-precision float loads/stores (RV64).
            (0b00, 0b001) => {
                let v = self.load(8 + ((w >> 7) & 7), cld_imm(w), b64);
                Self::assign(out, addr, st, fdest(8 + ((w >> 2) & 7)), v);
            }
            (0b00, 0b101) => {
                self.store(
                    8 + ((w >> 7) & 7),
                    cld_imm(w),
                    fsrc(8 + ((w >> 2) & 7), b64),
                    b64,
                    addr,
                    out,
                );
            }
            (0b10, 0b001) => {
                let v = self.load(2, ldsp_imm(w), b64);
                Self::assign(out, addr, st, fdest((w >> 7) & 0x1f), v);
            }
            (0b10, 0b101) => {
                self.store(2, sdsp_imm(w), fsrc((w >> 2) & 0x1f, b64), b64, addr, out);
            }
            _ => return self.asm(w, addr, out),
        }
        None
    }
}

fn ci_imm(w: u32) -> i64 {
    sext(((w >> 12) & 1) << 5 | ((w >> 2) & 0x1f), 6)
}

fn cj_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 11)
        | (((w >> 11) & 1) << 4)
        | (((w >> 9) & 3) << 8)
        | (((w >> 8) & 1) << 10)
        | (((w >> 7) & 1) << 6)
        | (((w >> 6) & 1) << 7)
        | (((w >> 3) & 7) << 1)
        | (((w >> 2) & 1) << 5);
    sext(v, 12)
}

fn cb_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 8)
        | (((w >> 10) & 3) << 3)
        | (((w >> 5) & 3) << 6)
        | (((w >> 3) & 3) << 1)
        | (((w >> 2) & 1) << 5);
    sext(v, 9)
}

// Compressed immediate decoders, matching the disassembler in `orress-arch`.

/// CIW `nzuimm` (`c.addi4spn`): zero-extended, 4-scaled.
fn ciw_imm(w: u32) -> i64 {
    i64::from(
        (((w >> 11) & 0b11) << 4)
            | (((w >> 7) & 0b1111) << 6)
            | (((w >> 6) & 1) << 2)
            | (((w >> 5) & 1) << 3),
    )
}

/// CL/CS word offset (`c.lw`/`c.sw`): zero-extended, 4-scaled.
fn clw_imm(w: u32) -> i64 {
    i64::from((((w >> 10) & 0b111) << 3) | (((w >> 6) & 1) << 2) | (((w >> 5) & 1) << 6))
}

/// CL/CS double offset (`c.ld`/`c.sd`): zero-extended, 8-scaled.
fn cld_imm(w: u32) -> i64 {
    i64::from((((w >> 10) & 0b111) << 3) | (((w >> 5) & 0b11) << 6))
}

/// C.LWSP offset: zero-extended, 4-scaled.
fn lwsp_imm(w: u32) -> i64 {
    i64::from((((w >> 12) & 1) << 5) | (((w >> 4) & 0b111) << 2) | (((w >> 2) & 0b11) << 6))
}

/// C.LDSP offset: zero-extended, 8-scaled.
fn ldsp_imm(w: u32) -> i64 {
    i64::from((((w >> 12) & 1) << 5) | (((w >> 5) & 0b11) << 3) | (((w >> 2) & 0b111) << 6))
}

/// C.SWSP offset: zero-extended, 4-scaled.
fn swsp_imm(w: u32) -> i64 {
    i64::from((((w >> 9) & 0b1111) << 2) | (((w >> 7) & 0b11) << 6))
}

/// C.SDSP offset: zero-extended, 8-scaled.
fn sdsp_imm(w: u32) -> i64 {
    i64::from((((w >> 10) & 0b111) << 3) | (((w >> 7) & 0b111) << 6))
}

/// A 6-bit shift amount (`c.slli`/`c.srli`/`c.srai`).
fn cshamt(w: u32) -> u64 {
    u64::from((((w >> 12) & 1) << 5) | ((w >> 2) & 0x1f))
}

/// C.ADDI16SP `nzimm`: sign-extended, 16-scaled.
fn addi16sp_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 9)
        | (((w >> 6) & 1) << 4)
        | (((w >> 5) & 1) << 6)
        | (((w >> 3) & 0b11) << 7)
        | (((w >> 2) & 1) << 5);
    sext(v, 10)
}

/// C.LUI immediate (the value loaded, i.e. `nzimm << 12`), sign-extended.
fn clui_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 17) | (((w >> 2) & 0x1f) << 12);
    sext(v, 18)
}
