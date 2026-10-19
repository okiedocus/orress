//! Lifting PowerPC machine code (PPC32 and PPC64, big- and little-endian) into the shared
//! decompiler IR. Like the other RISC front ends it feeds the common simplify → structure →
//! types → print pipeline.
//!
//! Registers map to `Var::Reg(n)` so the SysV/PowerOpen argument and result registers land where
//! the pipeline expects: `r3` becomes IR register 0 (the result, like RISC-V's `a0`) and
//! `r3`..`r10` become registers 0..7 ([`Convention::Ppc`]). `r1` is the stack pointer, so
//! `r1`-relative loads/stores become `Var::Stack`; `r0` reads as the literal `0` where the ISA
//! treats it so (the `RA|0` address/`addi` base). Floating-point registers map `fN` to `Xmm(N-1)`
//! so the float return `f1` lands on `Xmm(0)` (where `retarget_float_return` expects it) and the
//! argument registers `f1`..`f13` on `Xmm(0)`..`Xmm(12)` (see `simplify::float_arg_regs`).
//!
//! PowerPC separates the compare (`cmpw`/`cmpwi`/…, and the record-form `.` instructions) from the
//! conditional branch (`bc`), so the lifter remembers the last compare per condition-register
//! field and reconstructs the branch condition when it reaches the `bc`, much like the x86 flags
//! model. PowerPC has no delay slots.

use std::collections::{HashMap, VecDeque};

use orress_analysis::{EdgeKind, Function, Isa, Program};

use crate::ir::*;
use crate::lift::{Convention, import_noreturn, import_params};

pub struct PpcLifter<'a> {
    pub program: &'a Program,
    pub param_counts: &'a HashMap<u64, usize>,
}

/// A remembered comparison, so a later `bc` can rebuild the branch condition.
#[derive(Clone)]
struct Cmp {
    signed: bool,
    float: bool,
    a: Expr,
    b: Expr,
}

struct State {
    /// Argument registers (0..7, i.e. r3..r10) written since the last call, for argument counting.
    written: Vec<u8>,
    /// The last compare recorded into each of the eight condition-register fields.
    cr: [Option<Cmp>; 8],
}

/// Maps a PowerPC register number to the IR numbering (see the module docs).
fn reg_num(r: u32) -> u8 {
    match r {
        3..=10 => (r - 3) as u8, // r3..r10 -> 0..7 (arguments / result)
        0 => 8,                  // r0
        1 => 9,                  // sp
        2 => 10,                 // toc
        _ => r as u8,            // r11..r31 -> 11..31
    }
}

/// Maps `fN` to `Xmm(N-1)`, with `f0` kept out of the argument range.
fn fnum(f: u32) -> u8 {
    if f == 0 { 31 } else { (f - 1) as u8 }
}

fn fdest(f: u32) -> Var {
    Var::Xmm(fnum(f))
}

fn fsrc(f: u32, w: Width) -> Expr {
    Expr::Var(Var::Xmm(fnum(f)), w)
}

fn lr() -> Var {
    Var::Named("lr")
}
fn ctr() -> Var {
    Var::Named("ctr")
}

impl PpcLifter<'_> {
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

    /// The native register/pointer width: 64-bit on PPC64, else 32-bit.
    fn rw(&self) -> Width {
        if matches!(self.program.isa, Isa::Ppc64 | Isa::Ppc64El) {
            Width::B64
        } else {
            Width::B32
        }
    }

    fn lift_block(&self, f: &Function, index: usize) -> Block {
        let fb = &f.blocks[index];
        let mut st = State {
            written: Vec::new(),
            cr: Default::default(),
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

    /// Reads the 32-bit instruction word with the program's byte order (big-endian except the
    /// little-endian `ppc64le`).
    fn read(&self, addr: u64) -> Option<u32> {
        let b: [u8; 4] = self
            .program
            .memory
            .read(addr, 4)?
            .get(..4)?
            .try_into()
            .ok()?;
        Some(if self.program.isa == Isa::Ppc64El {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn src(&self, r: u32) -> Expr {
        Expr::Var(Var::Reg(reg_num(r)), self.rw())
    }

    /// The `RA|0` operand: the register's value, or the literal `0` when `RA` is `r0`.
    fn ra0(&self, r: u32) -> Expr {
        if r == 0 {
            Expr::konst(0, self.rw())
        } else {
            self.src(r)
        }
    }

    fn konst(&self, v: u64) -> Expr {
        Expr::konst(v, self.rw())
    }

    fn note(st: &mut State, r: u32) {
        let n = reg_num(r);
        if (0..=7).contains(&n) {
            st.written.push(n);
        }
    }

    fn put(&self, out: &mut Vec<(u64, Stmt)>, addr: u64, st: &mut State, r: u32, e: Expr) {
        Self::note(st, r);
        out.push((addr, Stmt::Assign(Var::Reg(reg_num(r)), e)));
    }

    /// Records `cr0` from a record-form (`.`) result: a signed comparison of the destination
    /// against zero.
    fn record_dot(&self, st: &mut State, rc: bool, r: u32) {
        if rc {
            st.cr[0] = Some(Cmp {
                signed: true,
                float: false,
                a: self.src(r),
                b: self.konst(0),
            });
        }
    }

    fn lift_word(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let op = w >> 26;
        let rt = (w >> 21) & 0x1f;
        let ra = (w >> 16) & 0x1f;
        let simm = (w & 0xffff) as i16 as i64;
        let uimm = u64::from(w & 0xffff);
        let w_ = self.rw();

        match op {
            7 => {
                // mulli rt, ra, simm
                self.put(
                    out,
                    addr,
                    st,
                    rt,
                    Expr::bin(BinOp::Mul, self.src(ra), self.konst(simm as u64), w_),
                );
            }
            8 => {
                // subfic rt, ra, simm : rt = simm - ra
                self.put(
                    out,
                    addr,
                    st,
                    rt,
                    Expr::bin(BinOp::Sub, self.konst(simm as u64), self.src(ra), w_),
                );
            }
            10 | 11 => {
                // cmpli / cmpi: a 16-bit immediate compare into CR field crfD.
                let crf = ((w >> 23) & 7) as usize;
                let signed = op == 11;
                let b = if signed {
                    self.konst(simm as u64)
                } else {
                    self.konst(uimm)
                };
                st.cr[crf] = Some(Cmp {
                    signed,
                    float: false,
                    a: self.src(ra),
                    b,
                });
            }
            12 | 13 => {
                // addic / addic. : rt = ra + simm
                self.put(
                    out,
                    addr,
                    st,
                    rt,
                    Expr::bin(BinOp::Add, self.src(ra), self.konst(simm as u64), w_),
                );
                self.record_dot(st, op == 13, rt);
            }
            14 => {
                // addi / li: rt = (ra|0) + simm
                self.put(
                    out,
                    addr,
                    st,
                    rt,
                    Expr::bin(BinOp::Add, self.ra0(ra), self.konst(simm as u64), w_),
                );
            }
            15 => {
                // addis / lis: rt = (ra|0) + (simm << 16)
                let hi = (simm << 16) as u64;
                self.put(
                    out,
                    addr,
                    st,
                    rt,
                    Expr::bin(BinOp::Add, self.ra0(ra), self.konst(hi), w_),
                );
            }
            16 => return Some(self.lift_bc(w, addr, st)),
            17 => {
                out.push((
                    addr,
                    Stmt::Eval(Expr::Call(CallTarget::Builtin("sc"), Vec::new())),
                ));
            }
            18 => {
                let (target, lk) = b_target(w, addr);
                if lk {
                    return self.call(addr, CallTarget::Direct(target), st, out);
                }
                return Some(Term::Jump(target));
            }
            19 => return self.lift_xl(w, addr, st, out),
            21 => return self.lift_rlwinm(w, addr, st, out),
            24..=29 => {
                // Logical immediate: dest is RA, source is RS (the RT field).
                if w == 0x6000_0000 {
                    return None; // nop
                }
                let v = match op {
                    24 => uimm,
                    25 => uimm << 16,
                    26 => uimm,
                    27 => uimm << 16,
                    28 => uimm,
                    _ => uimm << 16,
                };
                let o = if op == 24 || op == 25 {
                    BinOp::Or
                } else if op == 26 || op == 27 {
                    BinOp::Xor
                } else {
                    BinOp::And
                };
                self.put(
                    out,
                    addr,
                    st,
                    ra,
                    Expr::bin(o, self.src(rt), self.konst(v), w_),
                );
                // andi./andis. are record-form against cr0.
                self.record_dot(st, op == 28 || op == 29, ra);
            }
            31 => return self.lift_x(w, addr, st, out),
            // D-form loads (zero/sign extended to the register width).
            32 | 33 => self.load(out, addr, st, rt, ra, simm, Width::B32, false),
            34 | 35 => self.load(out, addr, st, rt, ra, simm, Width::B8, false),
            40 | 41 => self.load(out, addr, st, rt, ra, simm, Width::B16, false),
            42 | 43 => self.load(out, addr, st, rt, ra, simm, Width::B16, true),
            // D-form stores.
            36 | 37 => self.store(out, addr, ra, simm, self.src(rt), Width::B32),
            38 | 39 => self.store(out, addr, ra, simm, self.src(rt), Width::B8),
            44 | 45 => self.store(out, addr, ra, simm, self.src(rt), Width::B16),
            // Floating-point loads/stores.
            48 | 49 => {
                let v = self.mem(ra, simm, Width::B32);
                out.push((addr, Stmt::Assign(fdest(rt), v)));
            }
            50 | 51 => {
                let v = self.mem(ra, simm, Width::B64);
                out.push((addr, Stmt::Assign(fdest(rt), v)));
            }
            52 | 53 => self.store(out, addr, ra, simm, fsrc(rt, Width::B32), Width::B32),
            54 | 55 => self.store(out, addr, ra, simm, fsrc(rt, Width::B64), Width::B64),
            58 if self.rw() == Width::B64 => {
                let ds = (w & 0xfffc) as i16 as i64;
                self.load(out, addr, st, rt, ra, ds, Width::B64, false);
            }
            59 => self.lift_fp(w, addr, st, out, true),
            62 if self.rw() == Width::B64 => {
                let ds = (w & 0xfffc) as i16 as i64;
                self.store(out, addr, ra, ds, self.src(rt), Width::B64);
            }
            63 => self.lift_fp(w, addr, st, out, false),
            _ => return self.asm(addr, out),
        }
        None
    }

    /// Reconstructs a `bc` branch condition from the recorded compare for the tested CR field.
    fn lift_bc(&self, w: u32, addr: u64, st: &mut State) -> Term {
        let bo = (w >> 21) & 0x1f;
        let bi = (w >> 16) & 0x1f;
        let bd = (w & 0xfffc) as i16 as i64;
        let aa = (w >> 1) & 1 != 0;
        let target = if aa {
            bd as u64
        } else {
            addr.wrapping_add_signed(bd)
        };
        let next = addr + 4;
        // "Branch always" (BO ignores the condition): an unconditional jump.
        if bo & 0x14 == 0x14 {
            return Term::Jump(target);
        }
        let crf = (bi >> 2) as usize;
        let bit = bi & 3;
        let cond = match (&st.cr[crf], bit) {
            (Some(c), 0) => self.cmp_of(c, CmpOp::Lt),
            (Some(c), 1) => self.cmp_of(c, CmpOp::Gt),
            (Some(c), 2) => self.cmp_of(c, CmpOp::Eq),
            // The summary-overflow bit, or a branch with no tracked compare.
            _ => Expr::Var(Var::Named("cr"), self.rw()),
        };
        // BO bit 0x8 selects branch-on-true; otherwise branch-on-false.
        let cond = if bo & 8 != 0 {
            cond
        } else {
            Expr::LNot(Box::new(cond))
        };
        Term::Branch(cond, target, next)
    }

    fn cmp_of(&self, c: &Cmp, op: CmpOp) -> Expr {
        if c.float {
            Expr::fcmp(op, c.a.clone(), c.b.clone())
        } else {
            Expr::cmp(op, c.a.clone(), c.b.clone(), c.signed)
        }
    }

    /// XL-form (opcode 19): the branches through LR/CTR.
    fn lift_xl(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let xo = (w >> 1) & 0x3ff;
        match xo {
            // bclr (blr): return through LR with r3 (IR register 0) as the value.
            16 => Some(Term::Return(Some(Expr::Var(Var::Reg(0), self.rw())))),
            // bcctr: a computed branch through CTR — a tail call, or a call then continue.
            528 => {
                let target = CallTarget::Indirect(Box::new(Expr::Var(ctr(), self.rw())));
                if w & 1 != 0 {
                    self.call(addr, target, st, out)
                } else {
                    Some(Term::TailCall(Expr::Call(target, Vec::new())))
                }
            }
            _ => self.asm(addr, out),
        }
    }

    /// `rlwinm` — recognised in its common `slwi`/`srwi` shift aliases; other rotate-and-mask
    /// forms stay as `asm!`.
    fn lift_rlwinm(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let rs = (w >> 21) & 0x1f;
        let ra = (w >> 16) & 0x1f;
        let sh = (w >> 11) & 0x1f;
        let mb = (w >> 6) & 0x1f;
        let me = (w >> 1) & 0x1f;
        let w_ = self.rw();
        if mb == 0 && me == 31 - sh {
            // slwi ra, rs, sh
            self.put(
                out,
                addr,
                st,
                ra,
                Expr::bin(BinOp::Shl, self.src(rs), self.konst(u64::from(sh)), w_),
            );
            None
        } else if me == 31 && mb == 32 - sh && sh != 0 {
            // srwi ra, rs, 32-sh
            self.put(
                out,
                addr,
                st,
                ra,
                Expr::bin(BinOp::Shr, self.src(rs), self.konst(u64::from(32 - sh)), w_),
            );
            None
        } else {
            self.asm(addr, out)
        }
    }

    /// X-form and related (opcode 31): register-register integer ops, extensions, the indexed
    /// loads/stores and the LR/CTR special-register moves.
    fn lift_x(
        &self,
        w: u32,
        addr: u64,
        st: &mut State,
        out: &mut Vec<(u64, Stmt)>,
    ) -> Option<Term> {
        let rt = (w >> 21) & 0x1f;
        let ra = (w >> 16) & 0x1f;
        let rb = (w >> 11) & 0x1f;
        let xo = (w >> 1) & 0x3ff;
        let rc = w & 1 != 0;
        let w_ = self.rw();

        match xo {
            // Compares into CR field crfD.
            0 | 32 => {
                let crf = ((w >> 23) & 7) as usize;
                st.cr[crf] = Some(Cmp {
                    signed: xo == 0,
                    float: false,
                    a: self.src(ra),
                    b: self.src(rb),
                });
                return None;
            }
            // Arithmetic writes RT from RA and RB.
            266 | 10 => self.rr(
                out,
                addr,
                st,
                rt,
                BinOp::Add,
                self.src(ra),
                self.src(rb),
                rc,
            ),
            40 | 8 => self.rr(
                out,
                addr,
                st,
                rt,
                BinOp::Sub,
                self.src(rb),
                self.src(ra),
                rc,
            ),
            235 | 233 => self.rr(
                out,
                addr,
                st,
                rt,
                BinOp::Mul,
                self.src(ra),
                self.src(rb),
                rc,
            ),
            491 | 489 | 459 | 457 => self.rr(
                out,
                addr,
                st,
                rt,
                BinOp::Div,
                self.src(ra),
                self.src(rb),
                rc,
            ),
            104 => {
                self.put(
                    out,
                    addr,
                    st,
                    rt,
                    Expr::bin(BinOp::Sub, self.konst(0), self.src(ra), w_),
                );
                self.record_dot(st, rc, rt);
            }
            // Logical: dest is RA, sources are RS (the RT field) and RB.
            28 => self.rr(
                out,
                addr,
                st,
                ra,
                BinOp::And,
                self.src(rt),
                self.src(rb),
                rc,
            ),
            316 => self.rr(
                out,
                addr,
                st,
                ra,
                BinOp::Xor,
                self.src(rt),
                self.src(rb),
                rc,
            ),
            444 => {
                // or; `or ra,rs,rs` is the `mr` register move.
                self.put(out, addr, st, ra, {
                    if rt == rb {
                        self.src(rt)
                    } else {
                        Expr::bin(BinOp::Or, self.src(rt), self.src(rb), w_)
                    }
                });
                self.record_dot(st, rc, ra);
            }
            124 => {
                // nor
                let or = Expr::bin(BinOp::Or, self.src(rt), self.src(rb), w_);
                self.put(out, addr, st, ra, Expr::Not(Box::new(or), w_));
                self.record_dot(st, rc, ra);
            }
            // Shifts: dest RA, source RS, amount RB (or SH for srawi).
            24 | 27 => self.rr(
                out,
                addr,
                st,
                ra,
                BinOp::Shl,
                self.src(rt),
                self.src(rb),
                rc,
            ),
            536 | 539 => self.rr(
                out,
                addr,
                st,
                ra,
                BinOp::Shr,
                self.src(rt),
                self.src(rb),
                rc,
            ),
            792 | 794 => self.rr(
                out,
                addr,
                st,
                ra,
                BinOp::Sar,
                self.src(rt),
                self.src(rb),
                rc,
            ),
            824 => {
                self.put(
                    out,
                    addr,
                    st,
                    ra,
                    Expr::bin(BinOp::Sar, self.src(rt), self.konst(u64::from(rb)), w_),
                );
                self.record_dot(st, rc, ra);
            }
            // Sign extension: dest RA, source RS.
            922 => self.extend(out, addr, st, ra, rt, Width::B16),
            954 => self.extend(out, addr, st, ra, rt, Width::B8),
            986 => self.extend(out, addr, st, ra, rt, Width::B32),
            // Special-register moves.
            339 => match spr_of(w) {
                8 => self.put(out, addr, st, rt, Expr::Var(lr(), w_)),
                9 => self.put(out, addr, st, rt, Expr::Var(ctr(), w_)),
                _ => return self.asm(addr, out),
            },
            467 => match spr_of(w) {
                8 => out.push((addr, Stmt::Assign(lr(), self.src(rt)))),
                9 => out.push((addr, Stmt::Assign(ctr(), self.src(rt)))),
                _ => return self.asm(addr, out),
            },
            // Indexed loads/stores: address is (RA|0) + RB.
            23 => self.loadx(out, addr, st, rt, ra, rb, Width::B32, false),
            87 => self.loadx(out, addr, st, rt, ra, rb, Width::B8, false),
            279 => self.loadx(out, addr, st, rt, ra, rb, Width::B16, false),
            343 => self.loadx(out, addr, st, rt, ra, rb, Width::B16, true),
            21 => self.loadx(out, addr, st, rt, ra, rb, Width::B64, false),
            151 => self.storex(out, addr, ra, rb, self.src(rt), Width::B32),
            215 => self.storex(out, addr, ra, rb, self.src(rt), Width::B8),
            407 => self.storex(out, addr, ra, rb, self.src(rt), Width::B16),
            149 => self.storex(out, addr, ra, rb, self.src(rt), Width::B64),
            _ => return self.asm(addr, out),
        }
        None
    }

    /// A register-register op writing `dest` from `a` and `b`, recording cr0 for the `.` forms.
    #[allow(clippy::too_many_arguments)]
    fn rr(
        &self,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
        st: &mut State,
        dest: u32,
        op: BinOp,
        a: Expr,
        b: Expr,
        rc: bool,
    ) {
        self.put(out, addr, st, dest, Expr::bin(op, a, b, self.rw()));
        self.record_dot(st, rc, dest);
    }

    fn extend(
        &self,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
        st: &mut State,
        dest: u32,
        src: u32,
        from: Width,
    ) {
        let narrow = Expr::Cast(Box::new(self.src(src)), from, true);
        let v = Expr::Cast(Box::new(narrow), self.rw(), true);
        self.put(out, addr, st, dest, v);
    }

    /// Floating-point arithmetic (opcode 59 single / 63 double) and the opcode-63 moves/compare.
    fn lift_fp(&self, w: u32, addr: u64, st: &mut State, out: &mut Vec<(u64, Stmt)>, single: bool) {
        let frt = (w >> 21) & 0x1f;
        let fra = (w >> 16) & 0x1f;
        let frb = (w >> 11) & 0x1f;
        let frc = (w >> 6) & 0x1f;
        let fw = if single { Width::B32 } else { Width::B64 };
        let bin = |op, b| Expr::fbin(op, fsrc(fra, fw), fsrc(b, fw), fw);
        match (w >> 1) & 0x1f {
            18 => out.push((addr, Stmt::Assign(fdest(frt), bin(BinOp::Div, frb)))),
            20 => out.push((addr, Stmt::Assign(fdest(frt), bin(BinOp::Sub, frb)))),
            21 => out.push((addr, Stmt::Assign(fdest(frt), bin(BinOp::Add, frb)))),
            25 => out.push((addr, Stmt::Assign(fdest(frt), bin(BinOp::Mul, frc)))),
            _ if single => {
                self.asm(addr, out);
            }
            // Opcode 63 X-form: fmr/fneg/fabs and the fcmpu compare.
            _ => match (w >> 1) & 0x3ff {
                72 => out.push((addr, Stmt::Assign(fdest(frt), fsrc(frb, fw)))), // fmr
                40 => out.push((
                    addr,
                    Stmt::Assign(
                        fdest(frt),
                        Expr::FUn(FUnOp::Neg, Box::new(fsrc(frb, fw)), fw),
                    ),
                )),
                264 => out.push((
                    addr,
                    Stmt::Assign(
                        fdest(frt),
                        Expr::FUn(FUnOp::Abs, Box::new(fsrc(frb, fw)), fw),
                    ),
                )),
                0 => {
                    let crf = ((w >> 23) & 7) as usize;
                    st.cr[crf] = Some(Cmp {
                        signed: true,
                        float: true,
                        a: fsrc(fra, fw),
                        b: fsrc(frb, fw),
                    });
                }
                _ => {
                    self.asm(addr, out);
                }
            },
        }
    }

    fn mem(&self, base: u32, off: i64, width: Width) -> Expr {
        if base == 1 {
            Expr::Var(Var::Stack(off), width)
        } else {
            let a = Expr::bin(
                BinOp::Add,
                self.ra0(base),
                self.konst(off as u64),
                self.rw(),
            );
            Expr::Load(Box::new(a), width)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn load(
        &self,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
        st: &mut State,
        dest: u32,
        base: u32,
        off: i64,
        aw: Width,
        signed: bool,
    ) {
        let mut v = self.mem(base, off, aw);
        if aw != self.rw() {
            v = Expr::Cast(Box::new(v), self.rw(), signed);
        }
        self.put(out, addr, st, dest, v);
    }

    #[allow(clippy::too_many_arguments)]
    fn loadx(
        &self,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
        st: &mut State,
        dest: u32,
        base: u32,
        index: u32,
        aw: Width,
        signed: bool,
    ) {
        let a = Expr::bin(BinOp::Add, self.ra0(base), self.src(index), self.rw());
        let mut v = Expr::Load(Box::new(a), aw);
        if aw != self.rw() {
            v = Expr::Cast(Box::new(v), self.rw(), signed);
        }
        self.put(out, addr, st, dest, v);
    }

    fn store(
        &self,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
        base: u32,
        off: i64,
        value: Expr,
        width: Width,
    ) {
        if base == 1 {
            out.push((addr, Stmt::Assign(Var::Stack(off), value)));
        } else {
            let a = Expr::bin(
                BinOp::Add,
                self.ra0(base),
                self.konst(off as u64),
                self.rw(),
            );
            out.push((addr, Stmt::Store(a, value, width)));
        }
    }

    fn storex(
        &self,
        out: &mut Vec<(u64, Stmt)>,
        addr: u64,
        base: u32,
        index: u32,
        value: Expr,
        width: Width,
    ) {
        let a = Expr::bin(BinOp::Add, self.ra0(base), self.src(index), self.rw());
        out.push((addr, Stmt::Store(a, value, width)));
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
        let regs = Convention::Ppc.arg_regs();
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
            .map(|&r| Expr::Var(Var::Reg(r), self.rw()))
            .collect();
        out.push((addr, Stmt::Assign(Var::Reg(0), Expr::Call(target, args))));
        for &r in Convention::Ppc.clobbered() {
            out.push((
                addr,
                Stmt::Assign(Var::Reg(r), Expr::Unknown("clobbered".into())),
            ));
        }
        st.written.clear();
        st.cr = Default::default();
        if name.as_deref().is_some_and(import_noreturn) {
            return Some(Term::Stop);
        }
        None
    }

    fn asm(&self, addr: u64, out: &mut Vec<(u64, Stmt)>) -> Option<Term> {
        let text = self.program.decode(addr).map_or_else(
            || ".long".to_owned(),
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

/// The I-form branch target and link bit of `b`/`bl`.
fn b_target(w: u32, addr: u64) -> (u64, bool) {
    let li = ((w & 0x03ff_fffc) as i32) << 6 >> 6;
    let aa = (w >> 1) & 1 != 0;
    let lk = w & 1 != 0;
    let target = if aa {
        li as i64 as u64
    } else {
        addr.wrapping_add_signed(i64::from(li))
    };
    (target, lk)
}

/// The special-purpose register number: the two 5-bit halves of bits 11-20, swapped.
fn spr_of(w: u32) -> u32 {
    let field = (w >> 11) & 0x3ff;
    ((field & 0x1f) << 5) | ((field >> 5) & 0x1f)
}
