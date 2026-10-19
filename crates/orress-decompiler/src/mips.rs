//! Lifting MIPS32 machine code into the shared decompiler IR. Like the RISC-V and ARM64 front
//! ends, it feeds the common simplify → structure → types → print pipeline.
//!
//! Registers map to `Var::Reg(n)` so the o32 ABI argument/return registers land where the
//! pipeline expects: `v0` becomes IR register 0 (the result, like x86's `rax`) and `a0`..`a3`
//! become registers 1..4 ([`Convention::Mips`] uses `[1, 2, 3, 4]`). `$zero` is a constant `0`;
//! `sp`-relative loads/stores become `Var::Stack`. `mult`/`div` write the `Named("hi")`/
//! `Named("lo")` pseudo-registers that `mfhi`/`mflo` read back.
//!
//! The *branch delay slot* (the instruction after a transfer, which runs before it) is kept in
//! the branch's block by the CFG builder, so lifting the block in order is correct — unless the
//! delay slot writes a register the branch condition reads, a hazard compilers avoid.

use std::collections::{HashMap, VecDeque};

use orress_analysis::{EdgeKind, Function, Isa, Program};

use crate::ir::*;
use crate::lift::{Convention, import_noreturn, import_params};

pub struct MipsLifter<'a> {
    pub program: &'a Program,
    pub param_counts: &'a HashMap<u64, usize>,
}

struct State {
    /// Argument registers (1..5, i.e. a0..a3) written since the last call, for argument counting.
    written: Vec<u8>,
}

/// Maps a MIPS register number to the IR numbering (see the module docs).
fn reg_num(r: u32) -> u8 {
    match r {
        2 => 0,                   // v0 -> result
        4..=7 => (r - 3) as u8,   // a0..a3 -> 1..4
        3 => 5,                   // v1
        8..=15 => (r - 2) as u8,  // t0..t7 -> 6..13
        16..=23 => (r - 2) as u8, // s0..s7 -> 14..21
        24 | 25 => (r - 2) as u8, // t8,t9 -> 22,23
        31 => 24,                 // ra
        29 => 25,                 // sp
        28 => 26,                 // gp
        30 => 27,                 // fp/s8
        _ => 28 + (r & 7) as u8,
    }
}

const W: Width = Width::B32;

fn src(r: u32) -> Expr {
    if r == 0 {
        Expr::konst(0, W)
    } else {
        Expr::Var(Var::Reg(reg_num(r)), W)
    }
}

fn dest(r: u32) -> Option<Var> {
    (r != 0).then(|| Var::Reg(reg_num(r)))
}

/// Float registers map to `Var::Xmm` identically (`$fN` -> `Xmm(N)`), so the o32 FP return
/// register `$f0` lands on `Xmm(0)` (where `retarget_float_return` expects it) and the argument
/// registers `$f12`/`$f14` on `Xmm(12)`/`Xmm(14)` (see `simplify::float_arg_regs`).
fn fsrc(f: u32, w: Width) -> Expr {
    Expr::Var(Var::Xmm((f & 31) as u8), w)
}

fn fdest(f: u32) -> Var {
    Var::Xmm((f & 31) as u8)
}

/// The MIPS FPU condition flag that `c.cond.fmt` sets and `bc1t`/`bc1f` test.
fn fcc() -> Var {
    Var::Named("fcc")
}

fn hi() -> Var {
    Var::Named("hi")
}
fn lo() -> Var {
    Var::Named("lo")
}

impl MipsLifter<'_> {
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
            let Some(w) = self.read(addr) else {
                stmts.push((addr, Stmt::Asm("(undecodable)".into(), Vec::new())));
                continue;
            };
            term_addr = addr;
            if let Some(t) = self.lift_word(w, addr, &mut st, &mut stmts) {
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

    /// Reads the 32-bit instruction word with the program's byte order.
    fn read(&self, addr: u64) -> Option<u32> {
        let b: [u8; 4] = self
            .program
            .memory
            .read(addr, 4)?
            .get(..4)?
            .try_into()
            .ok()?;
        Some(if self.program.isa == Isa::Mips32 {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    fn note(st: &mut State, v: &Var) {
        if let Var::Reg(r) = v
            && (1..=4).contains(r)
        {
            st.written.push(*r);
        }
    }

    fn put(out: &mut Vec<(u64, Stmt)>, addr: u64, st: &mut State, v: Var, e: Expr) {
        Self::note(st, &v);
        out.push((addr, Stmt::Assign(v, e)));
    }

    fn lift_word(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let opcode = w >> 26;
        let rs = (w >> 21) & 0x1f;
        let rt = (w >> 16) & 0x1f;
        let rd = (w >> 11) & 0x1f;
        let shamt = (w >> 6) & 0x1f;
        let imm = (w & 0xffff) as i16 as i64;
        let uimm = (w & 0xffff) as u64;
        let branch = (addr + 4).wrapping_add_signed(imm << 2);
        let next = addr + 4;

        match opcode {
            0x00 => return self.special(w, addr, rs, rt, rd, shamt, st, out),
            0x01 => {
                // REGIMM: bltz/bgez.
                let (op, link) = match rt {
                    0x00 => (CmpOp::Lt, false),
                    0x01 => (CmpOp::Ge, false),
                    0x10 => (CmpOp::Lt, true),
                    0x11 => (CmpOp::Ge, true),
                    _ => return self.asm(addr, out),
                };
                let cond = Expr::cmp(op, Self::signed(src(rs)), Expr::konst(0, W), true);
                if link {
                    return Some(Term::Branch(cond, branch, next)); // link ignored
                }
                return Some(Term::Branch(cond, branch, next));
            }
            0x02 => return Some(Term::Jump(jump_target(w, addr))),
            0x03 => return self.call(addr, CallTarget::Direct(jump_target(w, addr)), st, out),
            0x04 | 0x05 => {
                let op = if opcode == 0x04 { CmpOp::Eq } else { CmpOp::Ne };
                let cond = Expr::cmp(op, src(rs), src(rt), false);
                return Some(Term::Branch(cond, branch, next));
            }
            0x06 | 0x07 => {
                let op = if opcode == 0x06 { CmpOp::Le } else { CmpOp::Gt };
                let cond = Expr::cmp(op, Self::signed(src(rs)), Expr::konst(0, W), true);
                return Some(Term::Branch(cond, branch, next));
            }
            0x08 | 0x09 => {
                // addi / addiu
                if let Some(d) = dest(rt) {
                    Self::put(
                        out,
                        addr,
                        st,
                        d,
                        Expr::bin(BinOp::Add, src(rs), Expr::konst(imm as u64, W), W),
                    );
                }
            }
            0x0a | 0x0b => {
                // slti / sltiu
                if let Some(d) = dest(rt) {
                    let signed = opcode == 0x0a;
                    let a = if signed {
                        Self::signed(src(rs))
                    } else {
                        src(rs)
                    };
                    let cond = Expr::cmp(CmpOp::Lt, a, Expr::konst(imm as u64, W), signed);
                    Self::put(out, addr, st, d, Expr::Cast(Box::new(cond), W, false));
                }
            }
            0x0c..=0x0e => {
                let op = [BinOp::And, BinOp::Or, BinOp::Xor][(opcode - 0x0c) as usize];
                if let Some(d) = dest(rt) {
                    Self::put(
                        out,
                        addr,
                        st,
                        d,
                        Expr::bin(op, src(rs), Expr::konst(uimm, W), W),
                    );
                }
            }
            0x0f => {
                // lui
                if let Some(d) = dest(rt) {
                    Self::put(out, addr, st, d, Expr::konst(uimm << 16, W));
                }
            }
            0x20 | 0x21 | 0x23 | 0x24 | 0x25 => {
                // loads
                let (width, signed) = match opcode {
                    0x20 => (Width::B8, true),
                    0x21 => (Width::B16, true),
                    0x23 => (W, false),
                    0x24 => (Width::B8, false),
                    0x25 => (Width::B16, false),
                    _ => unreachable!(),
                };
                if let Some(d) = dest(rt) {
                    let mut v = self.mem(rs, imm, width);
                    if signed && width != W {
                        v = Expr::Cast(Box::new(v), W, true);
                    }
                    Self::put(out, addr, st, d, v);
                }
            }
            0x28 | 0x29 | 0x2b => {
                // stores
                let width = match opcode {
                    0x28 => Width::B8,
                    0x29 => Width::B16,
                    _ => W,
                };
                self.store(rs, imm, src(rt), width, addr, out);
            }
            0x1c => return self.special2(w, addr, rs, rt, rd, st, out),
            // COP1 (FPU).
            0x11 => return self.lift_cop1(w, addr, st, out),
            // Float loads/stores: `op ft, imm(base)`.
            0x31 | 0x35 => {
                let width = if opcode == 0x31 {
                    Width::B32
                } else {
                    Width::B64
                };
                let v = self.mem(rs, imm, width);
                Self::put(out, addr, st, fdest(rt), v);
            }
            0x39 | 0x3d => {
                let width = if opcode == 0x39 {
                    Width::B32
                } else {
                    Width::B64
                };
                self.store(rs, imm, fsrc(rt, width), width, addr, out);
            }
            _ => return self.asm(addr, out),
        }
        None
    }

    /// COP1 (opcode 0x11): the cleanly-modelled FPU ops — arithmetic, the GPR<->FPU moves, and the
    /// `c.cond`/`bc1` compare-and-branch. The control moves, the cvt forms and the rarer predicates
    /// have no direct IR and stay as `asm!`.
    fn lift_cop1(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let sub = (w >> 21) & 0x1f;
        let ft = (w >> 16) & 0x1f;
        let fs = (w >> 11) & 0x1f;
        let fd = (w >> 6) & 0x1f;
        match sub {
            // mfc1 rt, fs — reinterpret the float's bits in a GPR.
            0x00 => {
                if let Some(d) = dest(ft) {
                    Self::put(out, addr, st, d, fsrc(fs, W));
                }
            }
            // mtc1 rt, fs — reinterpret a GPR's bits as a float.
            0x04 => Self::put(out, addr, st, fdest(fs), src(ft)),
            // BC1: branch on the FP condition flag (bit 16 selects true/false).
            0x08 => {
                let imm = (w & 0xffff) as i16 as i64;
                let branch = (addr + 4).wrapping_add_signed(imm << 2);
                let cond = if ft & 1 != 0 {
                    Expr::Var(fcc(), W) // bc1t
                } else {
                    Expr::LNot(Box::new(Expr::Var(fcc(), W))) // bc1f
                };
                return Some(Term::Branch(cond, branch, addr + 4));
            }
            // Computational formats S (single) and D (double).
            0x10 | 0x11 => {
                let fw = if sub == 0x10 { Width::B32 } else { Width::B64 };
                self.lift_cop1_compute(w & 0x3f, addr, fw, fd, fs, ft, st, out);
            }
            _ => return self.asm(addr, out),
        }
        None
    }

    /// A COP1 computational op (format `fw`), selected by `funct`.
    #[allow(clippy::too_many_arguments)]
    fn lift_cop1_compute(
        &self,
        funct: u32,
        addr: u64,
        fw: Width,
        fd: u32,
        fs: u32,
        ft: u32,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        let bin = |op| Expr::fbin(op, fsrc(fs, fw), fsrc(ft, fw), fw);
        let un = |op| Expr::FUn(op, Box::new(fsrc(fs, fw)), fw);
        match funct {
            0x00 => Self::put(out, addr, st, fdest(fd), bin(BinOp::Add)),
            0x01 => Self::put(out, addr, st, fdest(fd), bin(BinOp::Sub)),
            0x02 => Self::put(out, addr, st, fdest(fd), bin(BinOp::Mul)),
            0x03 => Self::put(out, addr, st, fdest(fd), bin(BinOp::Div)),
            0x04 => Self::put(out, addr, st, fdest(fd), un(FUnOp::Sqrt)),
            0x05 => Self::put(out, addr, st, fdest(fd), un(FUnOp::Abs)),
            0x06 => Self::put(out, addr, st, fdest(fd), fsrc(fs, fw)), // mov
            0x07 => Self::put(out, addr, st, fdest(fd), un(FUnOp::Neg)),
            // c.cond.fmt: set the FP flag from a compare (the common ordered/unordered forms).
            0x30..=0x3f => {
                let op = match funct & 0xf {
                    0x2 | 0x3 | 0xa | 0xb => CmpOp::Eq, // eq/ueq/seq/ngl
                    0x4 | 0x5 | 0xc | 0xd => CmpOp::Lt, // olt/ult/lt/nge
                    0x6 | 0x7 | 0xe | 0xf => CmpOp::Le, // ole/ule/le/ngt
                    _ => {
                        self.asm(addr, out);
                        return;
                    }
                };
                Self::put(
                    out,
                    addr,
                    st,
                    fcc(),
                    Expr::fcmp(op, fsrc(fs, fw), fsrc(ft, fw)),
                );
            }
            _ => {
                self.asm(addr, out);
            }
        }
    }

    /// SPECIAL2 (opcode 0x1c): the MIPS32 three-operand `mul rd, rs, rt`. The multiply-accumulate
    /// (`madd`/`msub`) and `clz`/`clo` forms have no direct IR and stay as `asm!`.
    #[allow(clippy::too_many_arguments)]
    fn special2(
        &self,
        w: u32,
        addr: u64,
        rs: u32,
        rt: u32,
        rd: u32,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        if w & 0x3f == 0x02 {
            if let Some(d) = dest(rd) {
                Self::put(out, addr, st, d, Expr::bin(BinOp::Mul, src(rs), src(rt), W));
            }
            return None;
        }
        self.asm(addr, out)
    }

    #[allow(clippy::too_many_arguments)]
    fn special(
        &self,
        w: u32,
        addr: u64,
        rs: u32,
        rt: u32,
        rd: u32,
        shamt: u32,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let funct = w & 0x3f;
        match funct {
            0x00 if w == 0 => {} // nop
            0x00 | 0x02 | 0x03 => {
                let op = [BinOp::Shl, BinOp::Shr, BinOp::Shr, BinOp::Sar][funct as usize];
                if let Some(d) = dest(rd) {
                    Self::put(
                        out,
                        addr,
                        st,
                        d,
                        Expr::bin(op, src(rt), Expr::konst(shamt as u64, W), W),
                    );
                }
            }
            0x04 | 0x06 | 0x07 => {
                let op = [BinOp::Shl, BinOp::Shr, BinOp::Shr, BinOp::Sar][funct as usize];
                if let Some(d) = dest(rd) {
                    Self::put(out, addr, st, d, Expr::bin(op, src(rt), src(rs), W));
                }
            }
            0x08 => {
                // jr: return through ra, else indirect jump.
                return Some(if rs == 31 {
                    Term::Return(Some(Expr::Var(Var::Reg(0), W)))
                } else {
                    Term::TailCall(Expr::Call(
                        CallTarget::Indirect(Box::new(src(rs))),
                        Vec::new(),
                    ))
                });
            }
            0x09 => return self.call(addr, CallTarget::Indirect(Box::new(src(rs))), st, out),
            0x0c => {
                out.push((
                    addr,
                    Stmt::Eval(Expr::Call(CallTarget::Builtin("syscall"), Vec::new())),
                ));
            }
            0x0d => return Some(Term::Stop), // break
            0x10 => {
                if let Some(d) = dest(rd) {
                    Self::put(out, addr, st, d, Expr::Var(hi(), W));
                }
            }
            0x12 => {
                if let Some(d) = dest(rd) {
                    Self::put(out, addr, st, d, Expr::Var(lo(), W));
                }
            }
            0x18 | 0x19 => {
                // mult / multu: low word in lo, high word in hi.
                let signed = funct == 0x18;
                let (a, b) = if signed {
                    (Self::signed(src(rs)), Self::signed(src(rt)))
                } else {
                    (src(rs), src(rt))
                };
                out.push((
                    addr,
                    Stmt::Assign(lo(), Expr::bin(BinOp::Mul, a.clone(), b.clone(), W)),
                ));
                out.push((addr, Stmt::Assign(hi(), Expr::Unknown("mulhi".into()))));
                let _ = (a, b);
            }
            0x1a | 0x1b => {
                // div / divu: quotient in lo, remainder in hi.
                let signed = funct == 0x1a;
                let (a, b) = if signed {
                    (Self::signed(src(rs)), Self::signed(src(rt)))
                } else {
                    (src(rs), src(rt))
                };
                out.push((
                    addr,
                    Stmt::Assign(lo(), Expr::bin(BinOp::Div, a.clone(), b.clone(), W)),
                ));
                out.push((addr, Stmt::Assign(hi(), Expr::bin(BinOp::Rem, a, b, W))));
            }
            // add/addu/sub/subu/and/or/xor/nor/slt/sltu.
            0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x2a | 0x2b => {
                let d = dest(rd)?;
                let (a, b) = (src(rs), src(rt));
                let value = match funct {
                    0x20 | 0x21 => Expr::bin(BinOp::Add, a, b, W),
                    0x22 | 0x23 => Expr::bin(BinOp::Sub, a, b, W),
                    0x24 => Expr::bin(BinOp::And, a, b, W),
                    0x25 => Expr::bin(BinOp::Or, a, b, W),
                    0x26 => Expr::bin(BinOp::Xor, a, b, W),
                    0x2a => Expr::Cast(
                        Box::new(Expr::cmp(CmpOp::Lt, Self::signed(a), Self::signed(b), true)),
                        W,
                        false,
                    ),
                    0x2b => Expr::Cast(Box::new(Expr::cmp(CmpOp::Lt, a, b, false)), W, false),
                    _ => unreachable!(),
                };
                Self::put(out, addr, st, d, value);
            }
            0x27 => {
                // nor
                if let Some(d) = dest(rd) {
                    let or = Expr::bin(BinOp::Or, src(rs), src(rt), W);
                    Self::put(out, addr, st, d, Expr::Not(Box::new(or), W));
                }
            }
            _ => return self.asm(addr, out),
        }
        None
    }

    fn signed(e: Expr) -> Expr {
        Expr::Cast(Box::new(e), W, true)
    }

    fn mem(&self, base: u32, off: i64, width: Width) -> Expr {
        if base == 29 {
            Expr::Var(Var::Stack(off), width)
        } else {
            let a = Expr::bin(BinOp::Add, src(base), Expr::konst(off as u64, W), W);
            Expr::Load(Box::new(a), width)
        }
    }

    fn store(
        &self,
        base: u32,
        off: i64,
        value: Expr,
        width: Width,
        addr: u64,
        out: &mut Vec<(u64, Stmt)>,
    ) {
        if base == 29 {
            out.push((addr, Stmt::Assign(Var::Stack(off), value)));
        } else {
            let a = Expr::bin(BinOp::Add, src(base), Expr::konst(off as u64, W), W);
            out.push((addr, Stmt::Store(a, value, width)));
        }
    }

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
        let regs = Convention::Mips.arg_regs();
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
        for &r in Convention::Mips.clobbered() {
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

    fn asm(&self, addr: u64, out: &mut Vec<(u64, Stmt)>) -> Option<Term> {
        let text = self.program.decode(addr).map_or_else(
            || ".word".to_owned(),
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
}

/// The 256 MiB-region jump target of a `j`/`jal`.
fn jump_target(w: u32, addr: u64) -> u64 {
    ((addr + 4) & 0xffff_ffff_f000_0000) | u64::from((w & 0x03ff_ffff) << 2)
}
