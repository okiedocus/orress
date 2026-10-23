//! ARM 32-bit (AArch32) / Thumb front end: lifts the common integer subset of `armv7`
//! instructions to the shared IR. One lifter serves both states — yaxpeax decodes ARM and Thumb
//! into the same `Instruction`, and [`Program::isa_at`] picks the state per address.
//!
//! The IR models `r0`–`r12` and `lr` as `Var::Reg(n)` at 32 bits; `r0` is the result register.
//! `sp` (`r13`) and `[sp, #off]` become the stack (`StackAddr`/`Var::Stack`), `pc` (`r15`) reads
//! as the constant pipeline value so PC-relative literal loads fold to the datum they load.
//! Conditional execution (a non-`AL` condition) becomes a predicated `Select`; `cmp`/`cmn`/`tst`/
//! `teq` set a flag state that the conditional branches read back as structured comparisons, the
//! same technique the x86/ARM64/PowerPC lifters use. VFP/NEON and coprocessor ops stay `asm!`.

use std::collections::{HashMap, VecDeque};

use orress_analysis::{EdgeKind, Function, Isa, Program};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{
    ConditionCode, InstDecoder, Instruction, Opcode, Operand, Reg, RegShift, RegShiftStyle,
    ShiftStyle,
};

use crate::ir::{BinOp, Block, CallTarget, CmpOp, Expr, Stmt, Term, Var, Width};
use crate::lift::{Convention, import_noreturn, import_params};

/// Every ARM32 value is 32 bits wide.
const W: Width = Width::B32;

pub struct Arm32Lifter<'a> {
    pub program: &'a Program,
    pub param_counts: &'a HashMap<u64, usize>,
}

/// What the last flag-setting instruction (`cmp`/`cmn`/`tst`/`teq`/`*s`) computed.
#[derive(Clone)]
enum Flags {
    /// `cmp`/`subs`: the comparison `a` vs `b`.
    Sub(Expr, Expr),
    /// `tst`/`ands`: the bitwise `a & b`.
    Test(Expr, Expr),
    /// Any other result whose sign/zero a condition reads.
    Result(Expr),
}

struct State {
    flags: Option<Flags>,
    /// Argument registers (`r0`–`r3`) written since the last call, to count its arguments.
    written: Vec<u8>,
    /// Pending Thumb-2 IT-block conditions, one per upcoming instruction (front = next). yaxpeax
    /// decodes each instruction independently, so the lifter carries the IT state itself.
    it: VecDeque<u8>,
}

/// The value `pc` reads as inside an instruction: `address + 8` in ARM state, `(address + 4)`
/// word-aligned in Thumb state.
fn pc_value(address: u64, thumb: bool) -> u64 {
    if thumb {
        (address + 4) & !3
    } else {
        address + 8
    }
}

fn shift(style: ShiftStyle, amount: Expr, r: Expr) -> Expr {
    match style {
        ShiftStyle::LSL => Expr::bin(BinOp::Shl, r, amount, W),
        ShiftStyle::LSR => Expr::bin(BinOp::Shr, r, amount, W),
        ShiftStyle::ASR => Expr::bin(BinOp::Sar, r, amount, W),
        ShiftStyle::ROR => Expr::method(r, "rotate_right", vec![amount], W),
        ShiftStyle::RRX => Expr::Unknown("rrx".into()),
    }
}

impl Arm32Lifter<'_> {
    fn decode(&self, addr: u64) -> Option<(Instruction, bool)> {
        let thumb = self.program.isa_at(addr) == Isa::Thumb;
        let bytes = self.program.memory.read(addr, 4)?;
        let mut reader = U8Reader::new(bytes);
        let ins = InstDecoder::default()
            .with_thumb_mode(thumb)
            .decode(&mut reader)
            .ok()?;
        Some((ins, thumb))
    }

    pub fn lift(&self, f: &Function) -> Vec<Block> {
        let mut out: HashMap<u64, Block> = HashMap::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, b) in f.blocks.iter().enumerate() {
            if b.start == f.entry {
                queue.push_back(i);
                break;
            }
        }
        if queue.is_empty() {
            queue.push_back(0);
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
            flags: None,
            written: Vec::new(),
            it: VecDeque::new(),
        };
        let mut stmts = Vec::new();
        let mut term = None;
        let mut term_addr = fb.start;
        for &addr in &fb.insns {
            let Some((ins, thumb)) = self.decode(addr) else {
                stmts.push((addr, Stmt::Asm("(undecodable)".into(), Vec::new())));
                continue;
            };
            term_addr = addr;
            if let Some(t) = self.lift_insn(&ins, addr, thumb, &mut st, &mut stmts) {
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

    /// A source operand as a 32-bit expression.
    fn val(&self, op: &Operand, addr: u64, thumb: bool) -> Expr {
        match op {
            Operand::Reg(r) => self.reg(*r, addr, thumb),
            Operand::Imm12(i) => Expr::konst(u64::from(*i), W),
            Operand::Imm32(i) => Expr::konst(u64::from(*i), W),
            Operand::RegShift(rs) => self.shifted(rs, addr, thumb),
            _ => Expr::Unknown("op".into()),
        }
    }

    /// A barrel-shifted register operand (`r1, lsl #2` / `r1, asr r2`) as an expression.
    fn shifted(&self, rs: &RegShift, addr: u64, thumb: bool) -> Expr {
        match rs.into_shift() {
            RegShiftStyle::RegImm(ri) => {
                let base = self.reg(ri.shiftee(), addr, thumb);
                if ri.stype() == ShiftStyle::LSL && ri.imm() == 0 {
                    base
                } else {
                    shift(ri.stype(), Expr::konst(u64::from(ri.imm()), W), base)
                }
            }
            RegShiftStyle::RegReg(rr) => {
                let base = self.reg(rr.shiftee(), addr, thumb);
                let amount = self.reg(rr.shifter(), addr, thumb);
                shift(rr.stype(), amount, base)
            }
        }
    }

    /// A register as an expression: `pc` is the constant pipeline value, `sp` the stack base, the
    /// rest their IR variable.
    fn reg(&self, r: Reg, addr: u64, thumb: bool) -> Expr {
        match r.number() {
            15 => Expr::konst(pc_value(addr, thumb), W),
            13 => Expr::StackAddr(0),
            n => Expr::Var(Var::Reg(n), W),
        }
    }

    /// The destination register of operand 0 — `None` for `pc`/`sp` writes (a branch, or stack
    /// bookkeeping the stack model already captures).
    fn dest(op: &Operand) -> Option<Var> {
        match op {
            Operand::Reg(r) | Operand::RegWBack(r, _) if !matches!(r.number(), 13 | 15) => {
                Some(Var::Reg(r.number()))
            }
            _ => None,
        }
    }

    /// Writes `value` to `dst`, guarded by `pred` when the instruction is conditional.
    fn write(dst: Var, value: Expr, pred: &Option<Expr>, addr: u64, out: &mut Vec<(u64, Stmt)>) {
        let value = match pred {
            Some(c) => Expr::Select(
                Box::new(c.clone()),
                Box::new(value),
                Box::new(Expr::Var(dst, W)),
                W,
            ),
            None => value,
        };
        out.push((addr, Stmt::Assign(dst, value)));
    }

    fn lift_insn(
        &self,
        ins: &Instruction,
        addr: u64,
        thumb: bool,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        use Opcode as O;
        // IT only arms the predicate for the following instructions; it has no effect of its own.
        if ins.opcode == O::IT {
            if let (Operand::Imm32(firstcond), Operand::Imm32(mask)) =
                (&ins.operands[0], &ins.operands[1])
            {
                st.it = it_conditions(*firstcond as u8, *mask as u8);
            }
            return None;
        }
        // The effective condition is the IT-block slot for this instruction, else its own.
        let cc = st
            .it
            .pop_front()
            .unwrap_or_else(|| cond_index(ins.condition));

        // Track writes to r0–r3, to count an unknown call's arguments.
        if let Some(Var::Reg(r)) = Self::dest(&ins.operands[0])
            && r < 4
        {
            st.written.push(r);
        }

        // Predicate for conditionally-executed instructions (anything but a plain branch).
        let pred = (cc != 14 && !matches!(ins.opcode, O::B | O::BL | O::BLX | O::BX))
            .then(|| self.condition(cc, st));
        let v = |i: usize| self.val(&ins.operands[i], addr, thumb);

        // The two sources of a data-processing op. The 3-operand form is `Rd, Rn, op2`; the 2-
        // operand Thumb form (`add r0, r5`) leaves operand 2 empty and reuses `Rd` as `Rn`.
        let srcs = || {
            if matches!(ins.operands[2], Operand::Nothing) {
                (v(0), v(1))
            } else {
                (v(1), v(2))
            }
        };
        // Data-processing: Rd = a OP b.
        let dp = |op: BinOp, out: &mut Vec<(u64, Stmt)>| {
            if let Some(d) = Self::dest(&ins.operands[0]) {
                let (a, b) = srcs();
                Self::write(d, Expr::bin(op, a, b, W), &pred, addr, out);
            }
        };

        match ins.opcode {
            O::ADD => dp(BinOp::Add, out),
            O::SUB => dp(BinOp::Sub, out),
            O::AND => dp(BinOp::And, out),
            O::ORR => dp(BinOp::Or, out),
            O::EOR => dp(BinOp::Xor, out),
            O::MUL => dp(BinOp::Mul, out),
            O::RSB => {
                // Reverse subtract: Rd = op2 - Rn.
                if let Some(d) = Self::dest(&ins.operands[0]) {
                    let (a, b) = srcs();
                    Self::write(d, Expr::bin(BinOp::Sub, b, a, W), &pred, addr, out);
                }
            }
            O::BIC => {
                // Rd = Rn & !op2.
                if let Some(d) = Self::dest(&ins.operands[0]) {
                    let (a, b) = srcs();
                    let b = Expr::Not(Box::new(b), W);
                    Self::write(d, Expr::bin(BinOp::And, a, b, W), &pred, addr, out);
                }
            }
            O::MOV => {
                if let Some(d) = Self::dest(&ins.operands[0]) {
                    Self::write(d, v(1), &pred, addr, out);
                }
            }
            O::MVN => {
                if let Some(d) = Self::dest(&ins.operands[0]) {
                    Self::write(d, Expr::Not(Box::new(v(1)), W), &pred, addr, out);
                }
            }
            O::LSL | O::LSR | O::ASR | O::ROR => {
                if let Some(d) = Self::dest(&ins.operands[0]) {
                    let style = match ins.opcode {
                        O::LSL => ShiftStyle::LSL,
                        O::LSR => ShiftStyle::LSR,
                        O::ASR => ShiftStyle::ASR,
                        _ => ShiftStyle::ROR,
                    };
                    Self::write(d, shift(style, v(2), v(1)), &pred, addr, out);
                }
            }
            O::CMP => st.flags = Some(Flags::Sub(v(0), v(1))),
            O::CMN => st.flags = Some(Flags::Result(Expr::bin(BinOp::Add, v(0), v(1), W))),
            O::TST => st.flags = Some(Flags::Test(v(0), v(1))),
            O::TEQ => st.flags = Some(Flags::Result(Expr::bin(BinOp::Xor, v(0), v(1), W))),
            O::LDR | O::LDRB | O::LDRH | O::LDRSB | O::LDRSH => {
                self.load(ins, addr, thumb, &pred, out)
            }
            O::STR | O::STRB | O::STRH => self.store(ins, addr, thumb, out),
            // push/pop/ldm/stm of callee-saved registers and lr/pc are prologue/epilogue
            // bookkeeping; a `pop`/`ldm` that restores pc returns (unconditionally).
            O::POP | O::LDM(..) if restores_pc(ins) && cc == 14 => {
                return Some(self.ret());
            }
            O::PUSH | O::POP | O::LDM(..) | O::STM(..) if cc != 14 && restores_pc(ins) => {
                // A conditional `pop {…, pc}` is an early-return guard; keep it visible.
                out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            }
            O::PUSH | O::POP | O::LDM(..) | O::STM(..) => {}
            O::B => {
                return Some(match self.target(ins, addr, thumb) {
                    Some(t) if self.program.functions.contains_key(&t) => {
                        Term::TailCall(Expr::Call(CallTarget::Direct(t), Vec::new()))
                    }
                    Some(t) if cc == 14 => Term::Jump(t),
                    Some(t) => {
                        let next = addr + if thumb && !ins.wide { 2 } else { 4 };
                        Term::Branch(self.condition(cc, st), t, next)
                    }
                    None => Term::Stop,
                });
            }
            O::BL | O::BLX if self.target(ins, addr, thumb).is_some() => {
                let t = self.target(ins, addr, thumb).map(CallTarget::Direct);
                return self.call(t, st, out, addr);
            }
            O::BLX => {
                // Register form: indirect call through the operand.
                let t = CallTarget::Indirect(Box::new(v(0)));
                return self.call(Some(t), st, out, addr);
            }
            O::BX => {
                let is_ret = matches!(ins.operands[0], Operand::Reg(r) if r.number() == 14);
                if cc != 14 {
                    // Conditional `bx` (e.g. a `bxlt lr` early-return guard): keep it visible and
                    // fall through, matching the disassembler's fall-through flow.
                    out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
                } else if is_ret {
                    return Some(self.ret());
                } else {
                    return Some(Term::TailCall(Expr::Call(
                        CallTarget::Indirect(Box::new(v(0))),
                        Vec::new(),
                    )));
                }
            }
            O::BKPT | O::UDF => return Some(Term::Stop),
            O::NOP => {}
            _ => {
                out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
                st.flags = None;
            }
        }

        // A flag-setting arithmetic/logic form (`subs`/`adds`/…) leaves the result's sign and zero
        // for a following conditional branch to read (`subs r0,#1; bne`).
        if ins.s
            && matches!(
                ins.opcode,
                O::ADD
                    | O::SUB
                    | O::RSB
                    | O::AND
                    | O::ORR
                    | O::EOR
                    | O::BIC
                    | O::MOV
                    | O::MVN
                    | O::LSL
                    | O::LSR
                    | O::ASR
                    | O::ROR
                    | O::MUL
            )
            && let Some(Var::Reg(r)) = Self::dest(&ins.operands[0])
        {
            st.flags = Some(Flags::Result(Expr::Var(Var::Reg(r), W)));
        }
        None
    }

    fn ret(&self) -> Term {
        Term::Return(Some(Expr::Var(Var::Reg(0), W)))
    }

    /// The branch target of a `B`/`BL`/`BLX(imm)`, decoded from the bytes (matching the
    /// disassembler), or `None` for the register forms.
    fn target(&self, _ins: &Instruction, addr: u64, _thumb: bool) -> Option<u64> {
        self.program.decode(addr).and_then(|i| i.branch_target())
    }

    fn call(
        &self,
        target: Option<CallTarget>,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
    ) -> Option<Term> {
        let Some(target) = target else {
            out.push((addr, Stmt::Asm("blx".into(), Vec::new())));
            return None;
        };
        let name = match &target {
            CallTarget::Direct(a) => self.program.name(*a).map(|n| n.text.clone()),
            _ => None,
        };
        let regs = Convention::Arm.arg_regs();
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
            .map(|&r| Expr::Var(Var::Reg(r), W))
            .collect();
        out.push((addr, Stmt::Assign(Var::Reg(0), Expr::Call(target, args))));
        for &r in Convention::Arm.clobbered() {
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

    fn load(
        &self,
        ins: &Instruction,
        addr: u64,
        thumb: bool,
        pred: &Option<Expr>,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let Some(dst) = Self::dest(&ins.operands[0]) else {
            out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            return;
        };
        let (w, signed) = match ins.opcode {
            Opcode::LDRB => (Width::B8, false),
            Opcode::LDRH => (Width::B16, false),
            Opcode::LDRSB => (Width::B8, true),
            Opcode::LDRSH => (Width::B16, true),
            _ => (W, false),
        };
        // `ldr rX, [pc, #imm]` loads from a literal pool; fold to the constant it reads.
        if ins.opcode == Opcode::LDR
            && let Some(pool) = self
                .program
                .decode(addr)
                .and_then(|i| i.data_refs.first().copied())
            && let Some(bytes) = self.program.memory.read(pool, 4)
            && let Some(word) = bytes.get(..4)
        {
            let word = u32::from_le_bytes(word.try_into().unwrap());
            Self::write(dst, Expr::konst(u64::from(word), W), pred, addr, out);
            return;
        }
        let Some(address) = self.mem(ins, addr, thumb) else {
            out.push((addr, Stmt::Asm(ins.to_string(), Vec::new())));
            return;
        };
        let mut value = match address {
            Mem::Stack(slot) => Expr::Var(Var::Stack(slot), w),
            Mem::Addr(a) => Expr::Load(Box::new(a), w),
        };
        if signed {
            value = Expr::Cast(Box::new(value), W, true);
        }
        Self::write(dst, value, pred, addr, out);
    }

    fn store(&self, ins: &Instruction, addr: u64, thumb: bool, out: &mut Vec<(u64, Stmt)>) {
        let w = match ins.opcode {
            Opcode::STRB => Width::B8,
            Opcode::STRH => Width::B16,
            _ => W,
        };
        let value = self.val(&ins.operands[0], addr, thumb);
        let value = if w.0 < W.0 {
            Expr::Cast(Box::new(value), w, false)
        } else {
            value
        };
        match self.mem(ins, addr, thumb) {
            Some(Mem::Stack(slot)) => out.push((addr, Stmt::Assign(Var::Stack(slot), value))),
            Some(Mem::Addr(a)) => out.push((addr, Stmt::Store(a, value, w))),
            None => out.push((addr, Stmt::Asm(ins.to_string(), Vec::new()))),
        }
    }

    /// The memory operand of a load/store (operand 1), as a stack slot or an address expression.
    fn mem(&self, ins: &Instruction, addr: u64, thumb: bool) -> Option<Mem> {
        let base_off = |r: Reg, off: i64| -> Mem {
            if r.number() == 13 {
                Mem::Stack(off)
            } else {
                Mem::Addr(add_off(self.reg(r, addr, thumb), off))
            }
        };
        match &ins.operands[1] {
            Operand::RegDeref(r) => Some(base_off(*r, 0)),
            Operand::RegDerefPreindexOffset(r, off, add, _)
            | Operand::RegDerefPostindexOffset(r, off, add, _) => {
                let off = if *add {
                    i64::from(*off)
                } else {
                    -i64::from(*off)
                };
                Some(base_off(*r, off))
            }
            Operand::RegDerefPreindexReg(r, idx, add, _)
            | Operand::RegDerefPostindexReg(r, idx, add, _) => {
                let i = self.reg(*idx, addr, thumb);
                let base = self.reg(*r, addr, thumb);
                let op = if *add { BinOp::Add } else { BinOp::Sub };
                Some(Mem::Addr(Expr::bin(op, base, i, W)))
            }
            // Indexed with a shifted register, e.g. `[a, i, lsl #2]` for `a[i]`.
            Operand::RegDerefPreindexRegShift(r, rs, add, _)
            | Operand::RegDerefPostindexRegShift(r, rs, add, _) => {
                let base = self.reg(*r, addr, thumb);
                let i = self.shifted(rs, addr, thumb);
                let op = if *add { BinOp::Add } else { BinOp::Sub };
                Some(Mem::Addr(Expr::bin(op, base, i, W)))
            }
            _ => None,
        }
    }

    /// Reconstructs the comparison a condition code reads from the pending flag state.
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
                    _ => unknown(),
                }
            }
            Some(Flags::Test(a, b)) => {
                let w = W;
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
                let (r, zero) = (r.clone(), Expr::konst(0, W));
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
        std::cmp::Ordering::Greater => Expr::bin(BinOp::Add, base, Expr::konst(off as u64, W), W),
        std::cmp::Ordering::Less => {
            Expr::bin(BinOp::Sub, base, Expr::konst(off.unsigned_abs(), W), W)
        }
    }
}

/// Whether a `pop`/`ldm` restores `pc` (bit 15 of its register list) — a function return.
fn restores_pc(ins: &Instruction) -> bool {
    ins.operands
        .iter()
        .any(|op| matches!(op, Operand::RegList(list) if list & (1 << 15) != 0))
}

/// The per-instruction conditions of a Thumb-2 IT block, from the `firstcond` and `mask` fields.
/// The block runs from the lowest set bit of the mask; the first instruction uses `firstcond`, and
/// each later one is `firstcond` (then) or its inverse (else) per the corresponding mask bit. The
/// raw 4-bit condition is already the index [`Arm32Lifter::condition`] uses (EQ=0 … AL=14).
fn it_conditions(firstcond: u8, mask: u8) -> VecDeque<u8> {
    let mask = mask & 0xf;
    let len = 4usize.saturating_sub(mask.trailing_zeros() as usize);
    (0..len)
        .map(|i| {
            if i == 0 {
                firstcond & 0xf
            } else {
                let bit = (mask >> (4 - i)) & 1;
                if bit == (firstcond & 1) {
                    firstcond & 0xf
                } else {
                    (firstcond ^ 1) & 0xf
                }
            }
        })
        .collect()
}

/// The 0..14 index of a condition code, matching the numbering [`Arm32Lifter::condition`] uses
/// (EQ=0, NE=1, HS=2, LO=3, MI=4, PL=5, VS=6, VC=7, HI=8, LS=9, GE=10, LT=11, GT=12, LE=13).
fn cond_index(c: ConditionCode) -> u8 {
    use ConditionCode as C;
    match c {
        C::EQ => 0,
        C::NE => 1,
        C::HS => 2,
        C::LO => 3,
        C::MI => 4,
        C::PL => 5,
        C::VS => 6,
        C::VC => 7,
        C::HI => 8,
        C::LS => 9,
        C::GE => 10,
        C::LT => 11,
        C::GT => 12,
        C::LE => 13,
        C::AL => 14,
    }
}
