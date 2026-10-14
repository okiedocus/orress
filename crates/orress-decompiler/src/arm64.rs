//! Lifting ARM64 (AArch64) machine code into the shared decompiler IR.
//!
//! The x86 and ARM64 front ends produce the same [`Block`]/[`Stmt`]/[`Expr`] IR, so the
//! simplify → structure → types → print pipeline is entirely shared. Registers map to
//! `Var::Reg(n)`: `x0`..`x30` are 0..30, and `x0` (register 0) is the result register, which the
//! pipeline already treats as the return value (like x86's `rax`). The zero register `xzr`/`wzr`
//! becomes a constant `0`; the stack pointer and `[sp, #off]` slots become `Var::Stack`.

use std::collections::{HashMap, VecDeque};

use orress_analysis::{EdgeKind, Function, Program};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    InstDecoder, Instruction, Opcode, Operand, SIMDSizeCode, ShiftStyle, SizeCode,
};

use crate::ir::*;
use crate::lift::{Convention, import_noreturn, import_params};

/// What the last flag-setting instruction (`cmp`/`subs`/`adds`/`ands`/`tst`) computed.
#[derive(Clone)]
enum Flags {
    /// `cmp`/`subs`: the comparison `a` vs `b`.
    Sub(Expr, Expr),
    /// `tst`/`ands` with a discarded result: the bitwise `a & b`.
    Test(Expr, Expr),
    /// Any other result whose sign/zero a condition may read.
    Result(Expr),
    /// `fcmp`: a floating-point comparison `a` vs `b`.
    FSub(Expr, Expr),
}

struct State {
    flags: Option<Flags>,
    /// Argument registers written since the last call (to count a call's arguments).
    written: Vec<u8>,
}

pub struct Arm64Lifter<'a> {
    pub program: &'a Program,
    pub param_counts: &'a HashMap<u64, usize>,
}

fn wsz(sz: SizeCode) -> Width {
    match sz {
        SizeCode::X => Width::B64,
        SizeCode::W => Width::B32,
    }
}

impl Arm64Lifter<'_> {
    fn decode(&self, addr: u64) -> Option<Instruction> {
        let bytes = self.program.memory.read(addr, 4)?;
        let mut reader = U8Reader::new(bytes.get(..4)?);
        InstDecoder::default().decode(&mut reader).ok()
    }

    /// Lifts every block of `f`.
    pub fn lift(&self, f: &Function) -> Vec<Block> {
        let mut out: HashMap<u64, Block> = HashMap::new();
        let mut queue: VecDeque<usize> = VecDeque::from([0]);
        let mut seen = vec![false; f.blocks.len()];
        // Walk in reachable order so an argument-written set carries across fall-through.
        for (i, b) in f.blocks.iter().enumerate() {
            if b.start == f.entry {
                queue.clear();
                queue.push_back(i);
                break;
            }
        }
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
            flags: None,
            written: Vec::new(),
        };
        let mut stmts = Vec::new();
        let mut term = None;
        let mut term_addr = fb.start;
        for &addr in &fb.insns {
            let Some(ins) = self.decode(addr) else {
                stmts.push((addr, Stmt::Asm("(undecodable)".into(), Vec::new())));
                continue;
            };
            term_addr = addr;
            if let Some(t) = self.lift_insn(&ins, addr, &mut st, &mut stmts) {
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

    /// A source operand as an expression.
    fn val(&self, op: &Operand) -> Expr {
        match op {
            Operand::Register(sz, 31) => Expr::konst(0, wsz(*sz)),
            Operand::Register(sz, n) => Expr::Var(Var::Reg(*n as u8), wsz(*sz)),
            Operand::RegisterOrSP(_, 31) => Expr::StackAddr(0),
            Operand::RegisterOrSP(sz, n) => Expr::Var(Var::Reg(*n as u8), wsz(*sz)),
            Operand::Immediate(i) => Expr::konst(u64::from(*i), Width::B64),
            Operand::Imm64(i) => Expr::konst(*i, Width::B64),
            Operand::Imm16(i) => Expr::konst(u64::from(*i), Width::B64),
            Operand::ImmShift(base, sh) => Expr::konst(u64::from(*base) << sh, Width::B64),
            Operand::RegShift(style, amt, sz, n) => {
                let r = if *n == 31 {
                    Expr::konst(0, wsz(*sz))
                } else {
                    Expr::Var(Var::Reg(*n as u8), wsz(*sz))
                };
                shift_expr(*style, u32::from(*amt), r, wsz(*sz))
            }
            _ => Expr::Unknown("op".into()),
        }
    }

    /// The destination register of operand 0, unless it is the zero register (then the result is
    /// discarded, which for the `*s` forms means a flag-only compare).
    fn dest(op: &Operand) -> Option<(Var, Width)> {
        match op {
            Operand::Register(sz, n) | Operand::RegisterOrSP(sz, n) if *n != 31 => {
                Some((Var::Reg(*n as u8), wsz(*sz)))
            }
            _ => None,
        }
    }

    /// Writes `value` to a destination register (a 32-bit `w` write narrows, matching the
    /// zero-extend-to-64 hardware semantics the rest of the IR already assumes).
    fn write(dst: (Var, Width), value: Expr, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        let (v, w) = dst;
        let value = if value.width() > w {
            Expr::Cast(Box::new(value), w, false)
        } else {
            value
        };
        out.push((addr, Stmt::Assign(v, value)));
    }

    /// A data-processing `Rd = Rn OP op2` (operands Rd, Rn, op2).
    fn dp(&self, ins: &Instruction, op: BinOp, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        let Some(dst) = Self::dest(&ins.operands[0]) else {
            return;
        };
        let w = dst.1;
        let a = self.val(&ins.operands[1]);
        let b = self.val(&ins.operands[2]);
        Self::write(dst, Expr::bin(op, a, b, w), addr, out);
    }

    /// A bitwise op whose second source is complemented (`bic`/`orn`/`eon`): `Rd = Rn OP !op2`.
    fn dp_not(&self, ins: &Instruction, op: BinOp, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        let Some(dst) = Self::dest(&ins.operands[0]) else {
            return;
        };
        let w = dst.1;
        let a = self.val(&ins.operands[1]);
        let b = Expr::Not(Box::new(self.val(&ins.operands[2])), w);
        Self::write(dst, Expr::bin(op, a, b, w), addr, out);
    }

    /// A flag-setting data-processing op (`adds`/`subs`/`ands`). With a `zr` destination it is a
    /// `cmp`/`cmn`/`tst` that only sets the flags.
    fn dp_flags(
        &self,
        ins: &Instruction,
        op: BinOp,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let a = self.val(&ins.operands[1]);
        let b = self.val(&ins.operands[2]);
        match Self::dest(&ins.operands[0]) {
            Some(dst) => {
                let w = dst.1;
                Self::write(dst, Expr::bin(op, a, b, w), addr, out);
                // The flags reflect the stored result, so a following `b.ne` reads `dst != 0`
                // (this is what a `subs`/`b.ne` loop counter decrements to zero).
                st.flags = Some(Flags::Result(Expr::Var(dst.0, w)));
            }
            None => {
                st.flags = Some(match op {
                    BinOp::Sub => Flags::Sub(a, b),
                    BinOp::And => Flags::Test(a, b),
                    _ => Flags::Result(Expr::bin(op, a, b, Width::B64)),
                });
            }
        }
    }

    fn lift_insn(
        &self,
        ins: &Instruction,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        use Opcode as O;
        // Record a write to an argument register, for counting an unknown call's arguments.
        if let Some((Var::Reg(r), _)) = Self::dest(&ins.operands[0])
            && r < 8
        {
            st.written.push(r);
        }
        if self.lift_fp(ins, addr, st, out) {
            return None;
        }
        match ins.opcode {
            // Pointer-authentication and branch-target hints: no effect on the recovered logic.
            O::HINT
            | O::PACIASP
            | O::PACIBSP
            | O::AUTIASP
            | O::AUTIBSP
            | O::PACIAZ
            | O::PACIBZ
            | O::AUTIAZ
            | O::AUTIBZ
            | O::PACIA
            | O::PACIB
            | O::AUTIA
            | O::AUTIB
            | O::PACM
            | O::XPACLRI => {}
            O::ADD => self.dp(ins, BinOp::Add, addr, out),
            O::SUB => self.dp(ins, BinOp::Sub, addr, out),
            O::AND => self.dp(ins, BinOp::And, addr, out),
            O::ORR => self.dp(ins, BinOp::Or, addr, out),
            O::EOR => self.dp(ins, BinOp::Xor, addr, out),
            O::BIC => self.dp_not(ins, BinOp::And, addr, out),
            O::ORN => self.dp_not(ins, BinOp::Or, addr, out),
            O::EON => self.dp_not(ins, BinOp::Xor, addr, out),
            O::ADDS => self.dp_flags(ins, BinOp::Add, addr, st, out),
            O::SUBS => self.dp_flags(ins, BinOp::Sub, addr, st, out),
            O::ANDS => self.dp_flags(ins, BinOp::And, addr, st, out),
            O::BICS => {
                // `Rd = Rn & !op2`, setting flags.
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    let a = self.val(&ins.operands[1]);
                    let b = Expr::Not(Box::new(self.val(&ins.operands[2])), w);
                    Self::write(dst, Expr::bin(BinOp::And, a, b, w), addr, out);
                }
                st.flags = None;
            }
            O::NEG => {
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    Self::write(
                        dst,
                        Expr::Neg(Box::new(self.val(&ins.operands[1])), w),
                        addr,
                        out,
                    );
                }
            }
            O::MUL => self.dp(ins, BinOp::Mul, addr, out),
            O::MADD | O::MSUB => {
                // Rd = Ra ± (Rn * Rm); `mul` is `madd` with a zero addend.
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    let n = self.val(&ins.operands[1]);
                    let m = self.val(&ins.operands[2]);
                    let prod = Expr::bin(BinOp::Mul, n, m, w);
                    let value = if matches!(ins.operands[3], Operand::Register(_, 31)) {
                        prod
                    } else {
                        let a = self.val(&ins.operands[3]);
                        let op = if ins.opcode == O::MADD {
                            BinOp::Add
                        } else {
                            BinOp::Sub
                        };
                        Expr::bin(op, a, prod, w)
                    };
                    Self::write(dst, value, addr, out);
                }
            }
            O::SDIV | O::UDIV => {
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    let (mut a, mut b) = (self.val(&ins.operands[1]), self.val(&ins.operands[2]));
                    if ins.opcode == O::SDIV {
                        a = Expr::Cast(Box::new(a), w, true);
                        b = Expr::Cast(Box::new(b), w, true);
                    }
                    Self::write(dst, Expr::bin(BinOp::Div, a, b, w), addr, out);
                }
            }
            O::LSLV | O::LSRV | O::ASRV => {
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    let op = match ins.opcode {
                        O::LSLV => BinOp::Shl,
                        O::LSRV => BinOp::Shr,
                        _ => BinOp::Sar,
                    };
                    let a = self.val(&ins.operands[1]);
                    let b = self.val(&ins.operands[2]);
                    Self::write(dst, Expr::bin(op, a, b, w), addr, out);
                }
            }
            O::RORV => {
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    let a = self.val(&ins.operands[1]);
                    let b = self.val(&ins.operands[2]);
                    Self::write(dst, Expr::method(a, "rotate_right", vec![b], w), addr, out);
                }
            }
            O::UBFM | O::SBFM => return self.bitfield(ins, addr, out),
            O::MOVZ => {
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    Self::write(dst, self.val(&ins.operands[1]), addr, out);
                    let _ = w;
                }
            }
            O::MOVN => {
                if let Some(dst) = Self::dest(&ins.operands[0]) {
                    let w = dst.1;
                    Self::write(
                        dst,
                        Expr::Not(Box::new(self.val(&ins.operands[1])), w),
                        addr,
                        out,
                    );
                }
            }
            O::MOVK => {
                // Insert a 16-bit field, keeping the rest: `Rd = (Rd & !mask) | (imm << s)`.
                if let (Some(dst), Operand::ImmShift(base, sh)) =
                    (Self::dest(&ins.operands[0]), &ins.operands[1])
                {
                    let w = dst.1;
                    let mask = !(0xffffu64 << sh);
                    let kept = Expr::bin(BinOp::And, Expr::Var(dst.0, w), Expr::konst(mask, w), w);
                    let ins_val = Expr::konst(u64::from(*base) << sh, w);
                    Self::write(dst, Expr::bin(BinOp::Or, kept, ins_val, w), addr, out);
                }
            }
            O::CSEL | O::CSINC | O::CSINV | O::CSNEG => return self.csel(ins, addr, out, st),
            O::LDR | O::LDRB | O::LDRH | O::LDRSW | O::LDRSB | O::LDRSH => {
                self.load(ins, addr, out)
            }
            O::STR | O::STRB | O::STRH => self.store(ins, addr, out),
            O::STP | O::LDP => self.pair(ins, addr, out),
            O::ADRP => {
                if let (Some(dst), Some(t)) =
                    (Self::dest(&ins.operands[0]), self.pc_target(ins, addr))
                {
                    out.push((addr, Stmt::Assign(dst.0, Expr::Addr(t & !0xfff))));
                }
            }
            O::ADR => {
                if let (Some(dst), Some(t)) =
                    (Self::dest(&ins.operands[0]), self.pc_target(ins, addr))
                {
                    out.push((addr, Stmt::Assign(dst.0, Expr::Addr(t))));
                }
            }
            O::B => {
                return Some(match self.pc_target(ins, addr) {
                    Some(t) if self.program.functions.contains_key(&t) => {
                        Term::TailCall(Expr::Call(CallTarget::Direct(t), Vec::new()))
                    }
                    Some(t) => Term::Jump(t),
                    None => Term::Stop,
                });
            }
            O::Bcc(c) => {
                let next = addr + 4;
                let t = self.pc_target(ins, addr).unwrap_or(next);
                return Some(Term::Branch(self.condition(c, st), t, next));
            }
            O::CBZ | O::CBNZ => {
                let next = addr + 4;
                let t = self.pc_target(ins, addr).unwrap_or(next);
                let v = self.val(&ins.operands[0]);
                let op = if ins.opcode == O::CBZ {
                    CmpOp::Eq
                } else {
                    CmpOp::Ne
                };
                return Some(Term::Branch(
                    Expr::cmp(op, v, Expr::konst(0, Width::B64), false),
                    t,
                    next,
                ));
            }
            O::TBZ | O::TBNZ => {
                let next = addr + 4;
                let t = self.pc_target(ins, addr).unwrap_or(next);
                let v = self.val(&ins.operands[0]);
                let bit = self.val(&ins.operands[1]);
                let w = v.width();
                let test = Expr::bin(
                    BinOp::And,
                    Expr::bin(BinOp::Shr, v, bit, w),
                    Expr::konst(1, w),
                    w,
                );
                let op = if ins.opcode == O::TBZ {
                    CmpOp::Eq
                } else {
                    CmpOp::Ne
                };
                return Some(Term::Branch(
                    Expr::cmp(op, test, Expr::konst(0, w), false),
                    t,
                    next,
                ));
            }
            O::BL => {
                return self.call(
                    ins,
                    addr,
                    self.pc_target(ins, addr).map(CallTarget::Direct),
                    st,
                    out,
                );
            }
            // PAC (pointer-authenticated) forms behave like their plain counterparts.
            O::BLR | O::BLRAA | O::BLRAAZ | O::BLRAB | O::BLRABZ => {
                let t = CallTarget::Indirect(Box::new(self.val(&ins.operands[0])));
                return self.call(ins, addr, Some(t), st, out);
            }
            O::RET
            | O::RETAA
            | O::RETAB
            | O::RETAASPPC
            | O::RETABSPPC
            | O::RETAASPPCR
            | O::RETABSPPCR
            | O::ERET
            | O::ERETAA
            | O::ERETAB => {
                return Some(Term::Return(Some(Expr::Var(Var::Reg(0), Width::B64))));
            }
            O::BR | O::BRAA | O::BRAAZ | O::BRAB | O::BRABZ => {
                return Some(Term::TailCall(Expr::Call(
                    CallTarget::Indirect(Box::new(self.val(&ins.operands[0]))),
                    Vec::new(),
                )));
            }
            O::BRK | O::HLT | O::UDF => return Some(Term::Stop),
            _ => {
                out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
                st.flags = None;
            }
        }
        None
    }

    /// `UBFM`/`SBFM` cover the shift/extend aliases. The common `lsl`/`lsr`/`asr` immediates and
    /// `uxt*`/`sxt*` extends are recovered; a general bitfield move stays `asm!`.
    fn bitfield(&self, ins: &Instruction, addr: u64, out: &mut Vec<(u64, Stmt)>) -> Option<Term> {
        let dst = Self::dest(&ins.operands[0])?;
        let w = dst.1;
        let bits = u32::from(w.0) * 8;
        let rn = self.val(&ins.operands[1]);
        let imm = |o: &Operand| match o {
            Operand::Immediate(i) => Some(*i),
            Operand::Imm16(i) => Some(u32::from(*i)),
            _ => None,
        };
        let (Some(immr), Some(imms)) = (imm(&ins.operands[2]), imm(&ins.operands[3])) else {
            out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            return None;
        };
        let signed = ins.opcode == Opcode::SBFM;
        let value = if imms >= immr {
            if signed && immr == 0 && matches!(imms, 7 | 15 | 31) {
                // sxtb / sxth / sxtw: sign-extend the low (imms+1) bits.
                let small = Width(((imms + 1) / 8) as u8);
                Expr::Cast(
                    Box::new(Expr::Cast(Box::new(rn), small, true)),
                    Width::B64,
                    true,
                )
            } else if signed && imms == bits - 1 {
                // asr #immr.
                Expr::bin(BinOp::Sar, rn, Expr::konst(u64::from(immr), w), w)
            } else if !signed && immr == 0 && matches!(imms, 7 | 15) {
                // uxtb / uxth.
                Expr::Cast(Box::new(rn), Width(((imms + 1) / 8) as u8), false)
            } else if !signed {
                // lsr / ubfx: (Rn >> immr) & mask(imms-immr+1).
                let width = imms - immr + 1;
                let shifted = if immr > 0 {
                    Expr::bin(BinOp::Shr, rn, Expr::konst(u64::from(immr), w), w)
                } else {
                    rn
                };
                if width < bits {
                    Expr::bin(BinOp::And, shifted, Expr::konst((1u64 << width) - 1, w), w)
                } else {
                    shifted
                }
            } else {
                out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
                return None;
            }
        } else {
            // lsl #(bits - immr).
            Expr::bin(BinOp::Shl, rn, Expr::konst(u64::from(bits - immr), w), w)
        };
        Self::write(dst, value, addr, out);
        None
    }

    /// `csel`/`cset`/`csinc`/`csinv`/`csneg`: `Rd = cond ? Rn : else(Rm)`.
    fn csel(
        &self,
        ins: &Instruction,
        addr: u64,
        out: &mut Vec<(u64, Stmt)>,
        st: &State,
    ) -> Option<Term> {
        let dst = Self::dest(&ins.operands[0])?;
        let w = dst.1;
        let n = self.val(&ins.operands[1]);
        let m = self.val(&ins.operands[2]);
        let cond = ins.operands.iter().find_map(|o| match o {
            Operand::ConditionCode(c) => Some(self.condition(*c, st)),
            _ => None,
        });
        let cond = cond?;
        let other = match ins.opcode {
            Opcode::CSINC => Expr::bin(BinOp::Add, m, Expr::konst(1, w), w),
            Opcode::CSINV => Expr::Not(Box::new(m), w),
            Opcode::CSNEG => Expr::Neg(Box::new(m), w),
            _ => m,
        };
        Self::write(
            dst,
            Expr::Select(Box::new(cond), Box::new(n), Box::new(other), w),
            addr,
            out,
        );
        None
    }

    fn load(&self, ins: &Instruction, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        // A floating-point load (`ldr d0, [x0]`) targets a NEON register.
        if let Some(fd) = Self::fdest(&ins.operands[0])
            && ins.opcode == Opcode::LDR
        {
            if let Some(mem) = self.mem(&ins.operands[1]) {
                let value = match mem {
                    Mem::Stack(slot) => Expr::Var(Var::Stack(slot), fd.1),
                    Mem::Addr(a) => Expr::Load(Box::new(a), fd.1),
                };
                out.push((addr, Stmt::Assign(fd.0, value)));
                Self::writeback(&ins.operands[1], addr, out);
            } else {
                out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            }
            return;
        }
        let Some(dst) = Self::dest(&ins.operands[0]) else {
            return;
        };
        let rt_w = dst.1;
        let (w, signed) = match ins.opcode {
            Opcode::LDRB => (Width::B8, false),
            Opcode::LDRH => (Width::B16, false),
            Opcode::LDRSB => (Width::B8, true),
            Opcode::LDRSH => (Width::B16, true),
            Opcode::LDRSW => (Width::B32, true),
            _ => (rt_w, false),
        };
        let Some(mem) = self.mem(&ins.operands[1]) else {
            out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            return;
        };
        let mut value = match mem {
            Mem::Stack(slot) => Expr::Var(Var::Stack(slot), w),
            Mem::Addr(a) => Expr::Load(Box::new(a), w),
        };
        if signed {
            // Sign-extend to the DESTINATION width (B32 for a W-form load, B64 for X), then let
            // `write` apply register-write semantics (a W write zeros the upper 32 bits).
            // Previously this always extended to B64, so `ldrsb w0,..` wrongly filled x0's top half.
            value = Expr::Cast(Box::new(value), rt_w, true);
        }
        Self::write(dst, value, addr, out);
        Self::writeback(&ins.operands[1], addr, out);
    }

    /// A pre-/post-indexed addressing mode writes the adjusted address back to the base register
    /// (`x8 += 4` after `ldr w0, [x8], #4`), which is what advances a pointer-walking loop.
    fn writeback(op: &Operand, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        let (base, delta) = match op {
            Operand::RegPreIndex(base, off, true) => (*base, i64::from(*off)),
            Operand::RegPostIndex(base, off) => (*base, i64::from(*off)),
            _ => return,
        };
        if base == 31 || delta == 0 {
            return;
        }
        let v = Var::Reg(base as u8);
        out.push((
            addr,
            Stmt::Assign(v, add_off(Expr::Var(v, Width::B64), delta)),
        ));
    }

    fn store(&self, ins: &Instruction, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        // A floating-point store (`str d0, [x0]`) from a NEON register.
        if let Some(fd) = Self::fdest(&ins.operands[0])
            && ins.opcode == Opcode::STR
        {
            let v = Expr::Var(fd.0, fd.1);
            if let Some(mem) = self.mem(&ins.operands[1]) {
                match mem {
                    Mem::Stack(slot) => out.push((addr, Stmt::Assign(Var::Stack(slot), v))),
                    Mem::Addr(a) => out.push((addr, Stmt::Store(a, v, fd.1))),
                }
                Self::writeback(&ins.operands[1], addr, out);
            } else {
                out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            }
            return;
        }
        let w = match ins.opcode {
            Opcode::STRB => Width::B8,
            Opcode::STRH => Width::B16,
            _ => match &ins.operands[0] {
                Operand::Register(sz, _) => wsz(*sz),
                _ => Width::B64,
            },
        };
        let v = self.val(&ins.operands[0]);
        let v = if v.width() > w {
            Expr::Cast(Box::new(v), w, false)
        } else {
            v
        };
        let Some(mem) = self.mem(&ins.operands[1]) else {
            out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            return;
        };
        match mem {
            Mem::Stack(slot) => out.push((addr, Stmt::Assign(Var::Stack(slot), v))),
            Mem::Addr(a) => out.push((addr, Stmt::Store(a, v, w))),
        }
        Self::writeback(&ins.operands[1], addr, out);
    }

    /// `ldp`/`stp`. A save/restore of the frame pair (`x29`/`x30`) around `sp` is prologue
    /// bookkeeping; otherwise the pair becomes two loads/stores at consecutive slots.
    fn pair(&self, ins: &Instruction, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        let regs: Vec<&Operand> = ins.operands[..2].iter().collect();
        if regs
            .iter()
            .all(|o| matches!(o, Operand::Register(_, 29 | 30)))
        {
            return;
        }
        let is_load = ins.opcode == Opcode::LDP;
        let Some(mem) = self.mem(&ins.operands[2]) else {
            out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            return;
        };
        let (base_slot, base_addr) = match mem {
            Mem::Stack(slot) => (Some(slot), None),
            Mem::Addr(a) => (None, Some(a)),
        };
        for (k, op) in ins.operands[..2].iter().enumerate() {
            let w = match op {
                Operand::Register(sz, _) => wsz(*sz),
                _ => Width::B64,
            };
            let off = (k as i64) * i64::from(w.0);
            if is_load {
                let Some((v, _)) = Self::dest(op) else {
                    continue;
                };
                let value = match (&base_slot, &base_addr) {
                    (Some(slot), _) => Expr::Var(Var::Stack(slot + off), w),
                    (_, Some(a)) => Expr::Load(Box::new(add_off(a.clone(), off)), w),
                    _ => continue,
                };
                out.push((addr, Stmt::Assign(v, value)));
            } else {
                let v = self.val(op);
                match (&base_slot, &base_addr) {
                    (Some(slot), _) => out.push((addr, Stmt::Assign(Var::Stack(slot + off), v))),
                    (_, Some(a)) => out.push((addr, Stmt::Store(add_off(a.clone(), off), v, w))),
                    _ => {}
                }
            }
        }
    }

    /// A memory operand as either a stack slot or an address expression.
    fn mem(&self, op: &Operand) -> Option<Mem> {
        match op {
            Operand::RegPreIndex(31, off, _) => Some(Mem::Stack(i64::from(*off))),
            Operand::RegPreIndex(base, off, _) => Some(Mem::Addr(add_off(
                Expr::Var(Var::Reg(*base as u8), Width::B64),
                i64::from(*off),
            ))),
            Operand::RegPostIndex(31, _) => Some(Mem::Stack(0)),
            Operand::RegPostIndex(base, _) => {
                Some(Mem::Addr(Expr::Var(Var::Reg(*base as u8), Width::B64)))
            }
            Operand::RegRegOffset(base, idx, sz, style, amt) => {
                let b = Expr::Var(Var::Reg(*base as u8), Width::B64);
                let i = shift_expr(
                    *style,
                    u32::from(*amt),
                    Expr::Var(Var::Reg(*idx as u8), wsz(*sz)),
                    Width::B64,
                );
                Some(Mem::Addr(Expr::bin(BinOp::Add, b, i, Width::B64)))
            }
            _ => None,
        }
    }

    fn pc_target(&self, ins: &Instruction, addr: u64) -> Option<u64> {
        ins.operands.iter().find_map(|op| match op {
            Operand::PCOffset(off) => Some(addr.wrapping_add_signed(*off)),
            _ => None,
        })
    }

    fn call(
        &self,
        ins: &Instruction,
        addr: u64,
        target: Option<CallTarget>,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let _ = ins;
        let Some(target) = target else {
            out.push((addr, Stmt::Asm("blr".into(), Vec::new())));
            return None;
        };
        let name = match &target {
            CallTarget::Direct(a) => self.program.name(*a).map(|n| n.text.clone()),
            _ => None,
        };
        let regs = Convention::Aarch64.arg_regs();
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
        for &r in Convention::Aarch64.clobbered() {
            out.push((
                addr,
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

    /// A scalar floating-point (NEON) register's width, if operand `op` is one (`s`→f32, `d`→f64).
    fn fdest(op: &Operand) -> Option<(Var, Width)> {
        match op {
            Operand::SIMDRegister(SIMDSizeCode::S, n) => Some((Var::Xmm(*n as u8), Width::B32)),
            Operand::SIMDRegister(SIMDSizeCode::D, n) => Some((Var::Xmm(*n as u8), Width::B64)),
            _ => None,
        }
    }

    /// A floating-point source operand (SIMD register, GPR for a conversion, or an immediate at
    /// the given width).
    fn fval(&self, op: &Operand, w: Width) -> Expr {
        match op {
            Operand::SIMDRegister(SIMDSizeCode::S, n) => Expr::Var(Var::Xmm(*n as u8), Width::B32),
            Operand::SIMDRegister(SIMDSizeCode::D, n) => Expr::Var(Var::Xmm(*n as u8), Width::B64),
            Operand::Register(sz, 31) => Expr::konst(0, wsz(*sz)),
            Operand::Register(sz, n) => Expr::Var(Var::Reg(*n as u8), wsz(*sz)),
            Operand::ImmediateDouble(d) => {
                let bits = if w.0 == 4 {
                    u64::from((*d as f32).to_bits())
                } else {
                    d.to_bits()
                };
                Expr::FConst(bits, w)
            }
            _ => Expr::Unknown("fop".into()),
        }
    }

    /// Lifts the scalar NEON floating-point instructions (`fadd`, `fmul`, `fcvt*`, `fcmp`,
    /// `fcsel`, …) into float IR. Returns `true` if it handled the instruction.
    fn lift_fp(
        &self,
        ins: &Instruction,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> bool {
        use Opcode as O;
        let fwrite = |d: (Var, Width), value: Expr, out: &mut Vec<(u64, Stmt)>| {
            out.push((addr, Stmt::Assign(d.0, value)));
        };
        let bin = |op: BinOp, s: &Self, out: &mut Vec<(u64, Stmt)>| {
            if let Some(d) = Self::fdest(&ins.operands[0]) {
                let (a, b) = (s.fval(&ins.operands[1], d.1), s.fval(&ins.operands[2], d.1));
                fwrite(d, Expr::fbin(op, a, b, d.1), out);
            }
        };
        let unary = |op: FUnOp, s: &Self, out: &mut Vec<(u64, Stmt)>| {
            if let Some(d) = Self::fdest(&ins.operands[0]) {
                let a = s.fval(&ins.operands[1], d.1);
                fwrite(d, Expr::FUn(op, Box::new(a), d.1), out);
            }
        };
        match ins.opcode {
            O::FADD => bin(BinOp::Add, self, out),
            O::FSUB => bin(BinOp::Sub, self, out),
            O::FMUL => bin(BinOp::Mul, self, out),
            O::FDIV => bin(BinOp::Div, self, out),
            O::FSQRT => unary(FUnOp::Sqrt, self, out),
            O::FABS => unary(FUnOp::Abs, self, out),
            O::FNEG => unary(FUnOp::Neg, self, out),
            O::FMAX | O::FMAXNM | O::FMIN | O::FMINNM => {
                if let Some(d) = Self::fdest(&ins.operands[0]) {
                    let name = if matches!(ins.opcode, O::FMAX | O::FMAXNM) {
                        "max"
                    } else {
                        "min"
                    };
                    let (a, b) = (
                        self.fval(&ins.operands[1], d.1),
                        self.fval(&ins.operands[2], d.1),
                    );
                    fwrite(d, Expr::method(a, name, vec![b], d.1), out);
                }
            }
            O::FMADD | O::FMSUB | O::FNMADD => {
                if let Some(d) = Self::fdest(&ins.operands[0]) {
                    let w = d.1;
                    let n = self.fval(&ins.operands[1], w);
                    let m = self.fval(&ins.operands[2], w);
                    let a = self.fval(&ins.operands[3], w);
                    let prod = Expr::fbin(BinOp::Mul, n, m, w);
                    let value = match ins.opcode {
                        O::FMADD => Expr::fbin(BinOp::Add, a, prod, w),
                        O::FMSUB => Expr::fbin(BinOp::Sub, a, prod, w),
                        _ => Expr::FUn(FUnOp::Neg, Box::new(Expr::fbin(BinOp::Add, a, prod, w)), w),
                    };
                    fwrite(d, value, out);
                }
            }
            O::FMOV => {
                // reg<-imm, reg<-reg, or a GPR<->FP bit reinterpret.
                if let Some(d) = Self::fdest(&ins.operands[0]) {
                    match &ins.operands[1] {
                        Operand::Register(_, n) if *n != 31 => {
                            // GPR -> FP: bit reinterpret as a float.
                            let name = if d.1.0 == 4 {
                                "f32::from_bits"
                            } else {
                                "f64::from_bits"
                            };
                            let g = Expr::Var(Var::Reg(*n as u8), d.1);
                            fwrite(d, Expr::Call(CallTarget::Builtin(name), vec![g]), out);
                        }
                        other => fwrite(d, self.fval(other, d.1), out),
                    }
                } else if let Some((g, gw)) = Self::dest(&ins.operands[0]) {
                    // FP -> GPR: `x.to_bits()`.
                    let fv = self.fval(&ins.operands[1], gw);
                    fwrite((g, gw), Expr::method(fv, "to_bits", Vec::new(), gw), out);
                }
            }
            O::FCMP | O::FCMPE => {
                let w = Self::fdest(&ins.operands[0]).map_or(Width::B64, |d| d.1);
                let a = self.fval(&ins.operands[0], w);
                let b = self.fval(&ins.operands[1], w);
                st.flags = Some(Flags::FSub(a, b));
            }
            O::FCSEL => {
                if let Some(d) = Self::fdest(&ins.operands[0]) {
                    let cond = ins.operands.iter().find_map(|o| match o {
                        Operand::ConditionCode(c) => Some(self.condition(*c, st)),
                        _ => None,
                    });
                    if let Some(cond) = cond {
                        let (a, b) = (
                            self.fval(&ins.operands[1], d.1),
                            self.fval(&ins.operands[2], d.1),
                        );
                        fwrite(
                            d,
                            Expr::Select(Box::new(cond), Box::new(a), Box::new(b), d.1),
                            out,
                        );
                    }
                }
            }
            O::SCVTF | O::UCVTF => {
                // Integer -> float (dest is the FP register).
                if let Some(d) = Self::fdest(&ins.operands[0]) {
                    let src = self.fval(&ins.operands[1], d.1);
                    fwrite(d, Expr::FCast(Box::new(src), d.1, FCast::SIntToFloat), out);
                }
            }
            O::FCVTZS | O::FCVTZU => {
                // Float -> integer, truncating (dest is a GPR).
                if let Some((g, gw)) = Self::dest(&ins.operands[0]) {
                    let sw = Self::fdest(&ins.operands[1]).map_or(Width::B64, |d| d.1);
                    let src = self.fval(&ins.operands[1], sw);
                    fwrite(
                        (g, gw),
                        Expr::FCast(Box::new(src), gw, FCast::FloatToSInt),
                        out,
                    );
                }
            }
            O::FCVT => {
                // Float -> float of a different width.
                if let Some(d) = Self::fdest(&ins.operands[0]) {
                    let sw = Self::fdest(&ins.operands[1]).map_or(Width::B64, |x| x.1);
                    let src = self.fval(&ins.operands[1], sw);
                    fwrite(d, Expr::FCast(Box::new(src), d.1, FCast::FloatToFloat), out);
                }
            }
            _ => return false,
        }
        true
    }

    /// An ARM condition code as an IR condition, read from the pending flags.
    fn condition(&self, cc: u8, st: &State) -> Expr {
        use CmpOp::*;
        let unknown = || Expr::Unknown(format!("cond_{cc}"));
        match &st.flags {
            Some(Flags::Sub(a, b)) => {
                let (a, b) = (a.clone(), b.clone());
                match cc {
                    0 => Expr::cmp(Eq, a, b, false),
                    1 => Expr::cmp(Ne, a, b, false),
                    2 => Expr::cmp(Ge, a, b, false), // hs / cs
                    3 => Expr::cmp(Lt, a, b, false), // lo / cc
                    8 => Expr::cmp(Gt, a, b, false), // hi
                    9 => Expr::cmp(Le, a, b, false), // ls
                    10 => Expr::cmp(Ge, a, b, true), // ge
                    11 => Expr::cmp(Lt, a, b, true), // lt
                    12 => Expr::cmp(Gt, a, b, true), // gt
                    13 => Expr::cmp(Le, a, b, true), // le
                    4 => {
                        let w = a.width();
                        Expr::cmp(Lt, Expr::bin(BinOp::Sub, a, b, w), Expr::konst(0, w), true)
                    }
                    5 => {
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
                    0 => Expr::cmp(Eq, x, zero, false),
                    1 => Expr::cmp(Ne, x, zero, false),
                    4 => Expr::cmp(Lt, x, zero, true),
                    5 => Expr::cmp(Ge, x, zero, true),
                    _ => unknown(),
                }
            }
            Some(Flags::Result(r)) => {
                let w = r.width();
                let (r, zero) = (r.clone(), Expr::konst(0, w));
                match cc {
                    0 => Expr::cmp(Eq, r, zero, false),
                    1 => Expr::cmp(Ne, r, zero, false),
                    4 | 11 => Expr::cmp(Lt, r, zero, true),
                    5 | 10 => Expr::cmp(Ge, r, zero, true),
                    12 => Expr::cmp(Gt, r, zero, true),
                    13 => Expr::cmp(Le, r, zero, true),
                    _ => unknown(),
                }
            }
            Some(Flags::FSub(a, b)) => {
                use CmpOp::*;
                let (a, b) = (a.clone(), b.clone());
                match cc {
                    0 => Expr::fcmp(Eq, a, b),
                    1 => Expr::fcmp(Ne, a, b),
                    8 | 12 => Expr::fcmp(Gt, a, b), // hi / gt
                    2 | 10 => Expr::fcmp(Ge, a, b), // hs / ge
                    3 | 11 => Expr::fcmp(Lt, a, b), // lo / lt
                    9 | 13 => Expr::fcmp(Le, a, b), // ls / le
                    _ => Expr::Unknown(format!("fcond_{cc}")), // mi/pl/vs/vc (NaN handling)
                }
            }
            None => unknown(),
        }
    }
}

enum Mem {
    Stack(i64),
    Addr(Expr),
}

fn add_off(base: Expr, off: i64) -> Expr {
    match off.cmp(&0) {
        std::cmp::Ordering::Equal => base,
        std::cmp::Ordering::Greater => Expr::bin(
            BinOp::Add,
            base,
            Expr::konst(off as u64, Width::B64),
            Width::B64,
        ),
        std::cmp::Ordering::Less => Expr::bin(
            BinOp::Sub,
            base,
            Expr::konst(off.unsigned_abs(), Width::B64),
            Width::B64,
        ),
    }
}

fn shift_expr(style: ShiftStyle, amt: u32, r: Expr, w: Width) -> Expr {
    match style {
        ShiftStyle::LSL => Expr::bin(BinOp::Shl, r, Expr::konst(u64::from(amt), w), w),
        ShiftStyle::LSR => Expr::bin(BinOp::Shr, r, Expr::konst(u64::from(amt), w), w),
        ShiftStyle::ASR => Expr::bin(BinOp::Sar, r, Expr::konst(u64::from(amt), w), w),
        ShiftStyle::ROR => Expr::method(r, "rotate_right", vec![Expr::konst(u64::from(amt), w)], w),
        ShiftStyle::UXTB => Expr::Cast(Box::new(r), Width::B8, false),
        ShiftStyle::UXTH => Expr::Cast(Box::new(r), Width::B16, false),
        ShiftStyle::UXTW => Expr::Cast(Box::new(r), Width::B32, false),
        ShiftStyle::SXTB => Expr::Cast(
            Box::new(Expr::Cast(Box::new(r), Width::B8, true)),
            Width::B64,
            true,
        ),
        ShiftStyle::SXTH => Expr::Cast(
            Box::new(Expr::Cast(Box::new(r), Width::B16, true)),
            Width::B64,
            true,
        ),
        ShiftStyle::SXTW => Expr::Cast(
            Box::new(Expr::Cast(Box::new(r), Width::B32, true)),
            Width::B64,
            true,
        ),
        ShiftStyle::UXTX | ShiftStyle::SXTX => r,
    }
}
