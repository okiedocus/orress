//! The decompiler's intermediate representation: variables, expressions, statements
//! and block terminators. Machine code is lifted into this, simplified, structured
//! into `if`/`while`, and printed as Rust.

use std::fmt;

/// Value width in bytes: 1, 2, 4 or 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Width(pub u8);

impl Width {
    pub const B8: Self = Self(1);
    pub const B16: Self = Self(2);
    pub const B32: Self = Self(4);
    pub const B64: Self = Self(8);
    /// 128-bit, used only to express the double-width product of a widening multiply.
    pub const B128: Self = Self(16);

    pub fn bits(self) -> u32 {
        u32::from(self.0) * 8
    }

    pub fn mask(self) -> u64 {
        if self.0 >= 8 {
            u64::MAX
        } else {
            (1u64 << self.bits()) - 1
        }
    }

    pub fn rust(self, signed: bool) -> &'static str {
        match (self.0, signed) {
            (1, false) => "u8",
            (2, false) => "u16",
            (4, false) => "u32",
            (1, true) => "i8",
            (2, true) => "i16",
            (4, true) => "i32",
            (16, false) => "u128",
            (16, true) => "i128",
            (_, true) => "i64",
            _ => "u64",
        }
    }
}

/// A packed-vector lane: its byte width plus whether the lanes are floating-point. This lets the
/// IR render `[f32; N]` vs `[u32; N]` and pick float vs. integer helpers (the `addps`/`paddd`,
/// `maxps`/`pmaxud` distinction that the mnemonic carries but the byte width does not).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lane {
    pub width: Width,
    pub float: bool,
}

impl Lane {
    pub const fn int(width: Width) -> Self {
        Self {
            width,
            float: false,
        }
    }
    pub const fn float(width: Width) -> Self {
        Self { width, float: true }
    }
    /// The Rust element type for one lane (`f32`/`f64` for float lanes, else unsigned integer).
    pub fn rust(self) -> &'static str {
        match (self.float, self.width.0) {
            (true, 4) => "f32",
            (true, _) => "f64",
            (false, _) => self.width.rust(false),
        }
    }
}

/// A storage location the decompiler tracks as a variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Var {
    /// A general-purpose register (0 = rax ... 15 = r15), full 64 bits.
    Reg(u8),
    /// The scalar (low-lane) floating-point value in an SSE register (0 = xmm0 … 15 = xmm15).
    Xmm(u8),
    /// A split live-range of a general-purpose register: the register was reused for an
    /// unrelated value, so each disjoint def-use web becomes its own variable (`rcx_2`). The
    /// `u8` is the original register, the `u16` the version.
    Split(u8, u16),
    /// A split live-range of an SSE register (`xmm1_2`), the vector/float analogue of `Split`.
    XmmSplit(u8, u16),
    /// A stack slot at this offset from the stack pointer at function entry.
    Stack(i64),
    /// A synthesised binding introduced after structuring (e.g. a recovered `fold`
    /// accumulator or a zipped element), named directly, with no machine-level storage.
    Named(&'static str),
}

pub const REG_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
pub const RAX: u8 = 0;
pub const RCX: u8 = 1;
pub const RDX: u8 = 2;
pub const RSP: u8 = 4;
pub const RBP: u8 = 5;
pub const RSI: u8 = 6;
pub const RDI: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

impl BinOp {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr | Self::Sar => ">>",
        }
    }
}

/// The operator of a horizontal lane reduction (`VecReduce`): a vector's lanes combined to one
/// scalar. `Add`/`Mul` render as `.iter().sum()`/`.product()`; `Max`/`Min` as
/// `.iter().copied().max()/.min().unwrap()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReduceOp {
    Add,
    Mul,
    Max,
    Min,
}

/// A floating-point unary operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FUnOp {
    /// Negation (`-x`, from an `xorps` sign-bit flip).
    Neg,
    /// Absolute value (`x.abs()`, from an `andps` sign-bit mask).
    Abs,
    /// Square root (`x.sqrt()`, from `sqrtss`/`sqrtsd`).
    Sqrt,
}

/// A floating-point conversion (the `cvt*` family).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FCast {
    /// Signed integer → float (`cvtsi2sd`).
    SIntToFloat,
    /// Float → signed integer, truncating (`cvttsd2si`).
    FloatToSInt,
    /// Float → float of a different width (`cvtss2sd` / `cvtsd2ss`).
    FloatToFloat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }

    pub fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CallTarget {
    /// A function in the program, by address.
    Direct(u64),
    /// An imported function, by its import slot address.
    Import(u64),
    /// A computed address.
    Indirect(Box<Expr>),
    /// A synthetic built-in the lifter introduced (e.g. `memcpy` for `rep movs`); its
    /// name is also a valid Rust identifier, so port mode can stub it.
    Builtin(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Expr {
    Const(u64, Width),
    Var(Var, Width),
    /// Parameter `n` of the function (0-based).
    Param(usize, Width),
    /// Memory read of `width` bytes.
    Load(Box<Expr>, Width),
    Bin(BinOp, Box<Expr>, Box<Expr>, Width),
    Neg(Box<Expr>, Width),
    Not(Box<Expr>, Width),
    /// Comparison; `signed` decides between e.g. `jl` and `jb`.
    Cmp(CmpOp, Box<Expr>, Box<Expr>, bool),
    /// Logical not of a condition.
    LNot(Box<Expr>),
    LAnd(Box<Expr>, Box<Expr>),
    LOr(Box<Expr>, Box<Expr>),
    /// Zero- or sign-extension / truncation.
    Cast(Box<Expr>, Width, bool),
    Call(CallTarget, Vec<Expr>),
    /// Address of a global (data, string or function).
    Addr(u64),
    /// Address of a stack slot (`&mut local_20`), e.g. a buffer passed to a function.
    StackAddr(i64),
    /// `if cond { a } else { b }` (from cmov).
    Select(Box<Expr>, Box<Expr>, Box<Expr>, Width),
    /// A Rust method call on a value: `recv.name(args)` of the given result width — used for
    /// instructions that map to a std method (`rotate_left`, `swap_bytes`, `count_ones`, …).
    Method(Box<Expr>, &'static str, Vec<Expr>, Width),
    /// A closure `|p0, p1, …| body`; each param carries whether it is bound by the `&p`
    /// reference pattern an iterator yields. Used by recovered iterator chains such as
    /// `.map(|&x| x as u32)` and `.fold(0, |acc, &x| acc ^ x)`.
    Closure(Vec<(Var, bool)>, Box<Expr>),
    /// A packed-vector constant with all lanes set from the low bits (e.g. a zeroed register from
    /// `pxor xmm, xmm`). Carries the lane count and lane width.
    VecImm(u64, u8, Lane),
    /// A scalar broadcast across every lane (`[x; N]`), recovered from the `movd xmm, r32` +
    /// `pshufd xmm, xmm, 0` splat idiom. Carries the lane count and lane.
    VecSplat(Box<Expr>, u8, Lane),
    /// A packed-vector memory load (`movdqu`/`movaps`): `lanes` elements of `lane` type.
    VecLoad(Box<Expr>, u8, Lane),
    /// Packed per-lane arithmetic/logic (`paddd`, `psubd`, `pand`, `mulps`, …).
    VecBin(BinOp, Box<Expr>, Box<Expr>, u8, Lane),
    /// A lane permutation (`pshufd`); the `u8` is the immediate selector.
    VecShuffle(Box<Expr>, u8, u8, Lane),
    /// Extracts lane `n` as a scalar (`movd`/`pextrd`), the result being one lane wide.
    VecExtract(Box<Expr>, u8, Lane),
    /// A horizontal reduction of a vector's lanes to a scalar (sum/product/max/min), recovered
    /// from a `pshufd`/`paddd`-style shuffle-reduce chain plus a lane-0 extract.
    VecReduce(ReduceOp, Box<Expr>, Lane),
    /// A packed lane-wise greater-than mask (`pcmpgtd`): each lane is all-ones or zero.
    VecGt(Box<Expr>, Box<Expr>, u8, Lane),
    /// A packed "and-not" (`pandn`): `!a & b`, lane-wise.
    VecAndn(Box<Expr>, Box<Expr>, u8, Lane),
    /// Packed lane-wise maximum / minimum (SSE2 compare-and-blend idiom, or `maxps`/`minps`).
    VecMax(Box<Expr>, Box<Expr>, u8, Lane),
    VecMin(Box<Expr>, Box<Expr>, u8, Lane),
    /// A floating-point literal, stored as its raw bits; `width` is 4 (`f32`) or 8 (`f64`).
    FConst(u64, Width),
    /// Floating-point arithmetic (`+ - * / %`) at `width` 4 or 8.
    FBin(BinOp, Box<Expr>, Box<Expr>, Width),
    /// A floating-point unary operation (`-x`, `x.abs()`, `x.sqrt()`).
    FUn(FUnOp, Box<Expr>, Width),
    /// A floating-point comparison; the result is a `bool`.
    FCmp(CmpOp, Box<Expr>, Box<Expr>),
    /// An integer↔float / float↔float conversion; `width` is the result width.
    FCast(Box<Expr>, Width, FCast),
    /// Something the lifter does not model, kept as assembly text.
    Unknown(String),
}

impl Expr {
    pub fn konst(v: u64, w: Width) -> Self {
        Self::Const(v & w.mask(), w)
    }

    pub fn bin(op: BinOp, a: Expr, b: Expr, w: Width) -> Self {
        Self::Bin(op, Box::new(a), Box::new(b), w)
    }

    pub fn cmp(op: CmpOp, a: Expr, b: Expr, signed: bool) -> Self {
        Self::Cmp(op, Box::new(a), Box::new(b), signed)
    }

    pub fn method(recv: Expr, name: &'static str, args: Vec<Expr>, w: Width) -> Self {
        Self::Method(Box::new(recv), name, args, w)
    }

    pub fn fbin(op: BinOp, a: Expr, b: Expr, w: Width) -> Self {
        Self::FBin(op, Box::new(a), Box::new(b), w)
    }

    pub fn fcmp(op: CmpOp, a: Expr, b: Expr) -> Self {
        Self::FCmp(op, Box::new(a), Box::new(b))
    }

    pub fn width(&self) -> Width {
        match self {
            Self::Const(_, w)
            | Self::Var(_, w)
            | Self::Param(_, w)
            | Self::Load(_, w)
            | Self::Bin(_, _, _, w)
            | Self::Neg(_, w)
            | Self::Not(_, w)
            | Self::Cast(_, w, _)
            | Self::Select(_, _, _, w)
            | Self::Method(_, _, _, w)
            | Self::FConst(_, w)
            | Self::FBin(_, _, _, w)
            | Self::FUn(_, _, w)
            | Self::FCast(_, w, _) => *w,
            // Packed-vector nodes carry a `Lane`; their scalar/element width is the lane width.
            Self::VecImm(_, _, l)
            | Self::VecSplat(_, _, l)
            | Self::VecLoad(_, _, l)
            | Self::VecBin(_, _, _, _, l)
            | Self::VecShuffle(_, _, _, l)
            | Self::VecExtract(_, _, l)
            | Self::VecReduce(_, _, l)
            | Self::VecGt(_, _, _, l)
            | Self::VecAndn(_, _, _, l)
            | Self::VecMax(_, _, _, l)
            | Self::VecMin(_, _, _, l) => l.width,
            Self::Cmp(..) | Self::LNot(_) | Self::LAnd(..) | Self::LOr(..) | Self::FCmp(..) => {
                Width::B8
            }
            Self::Call(..)
            | Self::Addr(_)
            | Self::StackAddr(_)
            | Self::Closure(..)
            | Self::Unknown(_) => Width::B64,
        }
    }

    /// Whether this expression produces a packed-vector (SIMD) value.
    pub fn is_vector(&self) -> bool {
        matches!(
            self,
            Self::VecImm(..)
                | Self::VecSplat(..)
                | Self::VecLoad(..)
                | Self::VecBin(..)
                | Self::VecShuffle(..)
                | Self::VecGt(..)
                | Self::VecAndn(..)
                | Self::VecMax(..)
                | Self::VecMin(..)
        )
    }

    /// The lane count and lane of a packed-vector expression (`[T; N]` shape), if it is one.
    pub fn vec_shape(&self) -> Option<(u8, Lane)> {
        match self {
            Self::VecImm(_, n, l)
            | Self::VecSplat(_, n, l)
            | Self::VecLoad(_, n, l)
            | Self::VecBin(_, _, _, n, l)
            | Self::VecShuffle(_, _, n, l)
            | Self::VecGt(_, _, n, l)
            | Self::VecAndn(_, _, n, l)
            | Self::VecMax(_, _, n, l)
            | Self::VecMin(_, _, n, l) => Some((*n, *l)),
            _ => None,
        }
    }

    pub fn is_condition(&self) -> bool {
        matches!(
            self,
            Self::Cmp(..) | Self::LNot(_) | Self::LAnd(..) | Self::LOr(..) | Self::FCmp(..)
        )
    }

    /// Visits every sub-expression (including self).
    pub fn walk(&self, f: &mut impl FnMut(&Expr)) {
        f(self);
        match self {
            Self::Load(a, _)
            | Self::Neg(a, _)
            | Self::Not(a, _)
            | Self::LNot(a)
            | Self::Cast(a, _, _)
            | Self::FUn(_, a, _)
            | Self::FCast(a, _, _)
            | Self::VecLoad(a, _, _)
            | Self::VecSplat(a, _, _)
            | Self::VecShuffle(a, _, _, _)
            | Self::VecExtract(a, _, _)
            | Self::VecReduce(_, a, _) => a.walk(f),
            Self::Bin(_, a, b, _)
            | Self::Cmp(_, a, b, _)
            | Self::LAnd(a, b)
            | Self::LOr(a, b)
            | Self::FBin(_, a, b, _)
            | Self::FCmp(_, a, b)
            | Self::VecBin(_, a, b, _, _)
            | Self::VecGt(a, b, _, _)
            | Self::VecAndn(a, b, _, _)
            | Self::VecMax(a, b, _, _)
            | Self::VecMin(a, b, _, _) => {
                a.walk(f);
                b.walk(f);
            }
            Self::Select(c, a, b, _) => {
                c.walk(f);
                a.walk(f);
                b.walk(f);
            }
            Self::Call(t, args) => {
                if let CallTarget::Indirect(e) = t {
                    e.walk(f);
                }
                for a in args {
                    a.walk(f);
                }
            }
            Self::Method(recv, _, args, _) => {
                recv.walk(f);
                for a in args {
                    a.walk(f);
                }
            }
            Self::Closure(_, body) => body.walk(f),
            _ => {}
        }
    }

    /// Rewrites the expression bottom-up.
    pub fn map(self, f: &mut impl FnMut(Expr) -> Expr) -> Expr {
        let mapped = match self {
            Self::Load(a, w) => Self::Load(Box::new(a.map(f)), w),
            Self::Neg(a, w) => Self::Neg(Box::new(a.map(f)), w),
            Self::Not(a, w) => Self::Not(Box::new(a.map(f)), w),
            Self::LNot(a) => Self::LNot(Box::new(a.map(f))),
            Self::Cast(a, w, s) => Self::Cast(Box::new(a.map(f)), w, s),
            Self::Bin(op, a, b, w) => Self::Bin(op, Box::new(a.map(f)), Box::new(b.map(f)), w),
            Self::Cmp(op, a, b, s) => Self::Cmp(op, Box::new(a.map(f)), Box::new(b.map(f)), s),
            Self::LAnd(a, b) => Self::LAnd(Box::new(a.map(f)), Box::new(b.map(f))),
            Self::LOr(a, b) => Self::LOr(Box::new(a.map(f)), Box::new(b.map(f))),
            Self::Select(c, a, b, w) => Self::Select(
                Box::new(c.map(f)),
                Box::new(a.map(f)),
                Box::new(b.map(f)),
                w,
            ),
            Self::Call(t, args) => {
                let t = match t {
                    CallTarget::Indirect(e) => CallTarget::Indirect(Box::new(e.map(f))),
                    other => other,
                };
                Self::Call(t, args.into_iter().map(|a| a.map(f)).collect())
            }
            Self::Method(recv, name, args, w) => Self::Method(
                Box::new(recv.map(f)),
                name,
                args.into_iter().map(|a| a.map(f)).collect(),
                w,
            ),
            Self::Closure(p, body) => Self::Closure(p, Box::new(body.map(f))),
            Self::FBin(op, a, b, w) => Self::FBin(op, Box::new(a.map(f)), Box::new(b.map(f)), w),
            Self::FUn(op, a, w) => Self::FUn(op, Box::new(a.map(f)), w),
            Self::FCmp(op, a, b) => Self::FCmp(op, Box::new(a.map(f)), Box::new(b.map(f))),
            Self::FCast(a, w, k) => Self::FCast(Box::new(a.map(f)), w, k),
            Self::VecLoad(a, n, w) => Self::VecLoad(Box::new(a.map(f)), n, w),
            Self::VecSplat(a, n, w) => Self::VecSplat(Box::new(a.map(f)), n, w),
            Self::VecBin(op, a, b, n, w) => {
                Self::VecBin(op, Box::new(a.map(f)), Box::new(b.map(f)), n, w)
            }
            Self::VecShuffle(a, m, n, w) => Self::VecShuffle(Box::new(a.map(f)), m, n, w),
            Self::VecExtract(a, n, w) => Self::VecExtract(Box::new(a.map(f)), n, w),
            Self::VecReduce(op, a, w) => Self::VecReduce(op, Box::new(a.map(f)), w),
            Self::VecGt(a, b, n, w) => Self::VecGt(Box::new(a.map(f)), Box::new(b.map(f)), n, w),
            Self::VecAndn(a, b, n, w) => {
                Self::VecAndn(Box::new(a.map(f)), Box::new(b.map(f)), n, w)
            }
            Self::VecMax(a, b, n, w) => Self::VecMax(Box::new(a.map(f)), Box::new(b.map(f)), n, w),
            Self::VecMin(a, b, n, w) => Self::VecMin(Box::new(a.map(f)), Box::new(b.map(f)), n, w),
            other => other,
        };
        f(mapped)
    }

    pub fn reads(&self, var: Var) -> bool {
        let mut found = false;
        self.walk(&mut |e| {
            if let Self::Var(v, _) = e
                && *v == var
            {
                found = true;
            }
        });
        found
    }

    pub fn has_load(&self) -> bool {
        let mut found = false;
        self.walk(&mut |e| found |= matches!(e, Self::Load(..) | Self::Call(..)));
        found
    }

    pub fn has_call(&self) -> bool {
        let mut found = false;
        self.walk(&mut |e| found |= matches!(e, Self::Call(..)));
        found
    }

    pub fn vars(&self) -> Vec<Var> {
        let mut out = Vec::new();
        self.walk(&mut |e| {
            if let Self::Var(v, _) = e {
                out.push(*v);
            }
        });
        out
    }

    /// Logical negation, simplified for comparisons.
    pub fn negate(self) -> Self {
        match self {
            Self::Cmp(op, a, b, s) => Self::Cmp(op.negate(), a, b, s),
            Self::LNot(a) => *a,
            Self::LAnd(a, b) => Self::LOr(Box::new(a.negate()), Box::new(b.negate())),
            Self::LOr(a, b) => Self::LAnd(Box::new(a.negate()), Box::new(b.negate())),
            other => Self::LNot(Box::new(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt {
    Assign(Var, Expr),
    Store(Expr, Expr, Width),
    /// An expression evaluated for its side effects (a call whose result is unused).
    Eval(Expr),
    /// An instruction the lifter cannot express, kept as assembly, with its register operands
    /// (inputs, clobbers, read-writes) for a port's `asm!` block.
    Asm(String, Vec<AsmOp>),
}

/// A register operand of an un-lifted instruction, rendered per the Rust inline-assembly
/// reference: `in("reg") value`, `out("reg") _`, or `inout("reg") value => _`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsmOp {
    /// Read: the instruction reads this register; `value` is what flows in.
    In(&'static str, Expr),
    /// Write: the instruction writes this register; the result is captured into the variable.
    Out(&'static str, Var),
    /// Read-write: read `value` in, capture the result into the variable.
    InOut(&'static str, Expr, Var),
}

impl AsmOp {
    /// The input expression, for operands that read a value.
    pub fn value(&self) -> Option<&Expr> {
        match self {
            Self::In(_, e) | Self::InOut(_, e, _) => Some(e),
            Self::Out(..) => None,
        }
    }

    /// The variable the operand's result is captured into, for operands that write.
    pub fn output(&self) -> Option<Var> {
        match self {
            Self::Out(_, v) | Self::InOut(_, _, v) => Some(*v),
            Self::In(..) => None,
        }
    }

    /// Rewrites the input expression (if any) with `f`.
    pub fn map_value(self, f: &mut impl FnMut(Expr) -> Expr) -> Self {
        match self {
            Self::In(r, e) => Self::In(r, f(e)),
            Self::InOut(r, e, v) => Self::InOut(r, f(e), v),
            Self::Out(r, v) => Self::Out(r, v),
        }
    }
}

impl Stmt {
    pub fn exprs(&self) -> Vec<&Expr> {
        match self {
            Self::Assign(_, e) | Self::Eval(e) => vec![e],
            Self::Store(a, v, _) => vec![a, v],
            Self::Asm(_, ops) => ops.iter().filter_map(AsmOp::value).collect(),
        }
    }

    /// The variables this statement defines: an assignment's target, or an `asm!` operand's
    /// captured output.
    pub fn defs(&self) -> Vec<Var> {
        match self {
            Self::Assign(v, _) => vec![*v],
            Self::Asm(_, ops) => ops.iter().filter_map(AsmOp::output).collect(),
            Self::Store(..) | Self::Eval(_) => vec![],
        }
    }

    pub fn reads(&self, var: Var) -> bool {
        self.exprs().iter().any(|e| e.reads(var))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Jump(u64),
    Branch(Expr, u64, u64),
    Return(Option<Expr>),
    /// Execution stops (a call that never returns, int3, ud2 ...).
    Stop,
    /// Tail call or jump to a computed address.
    TailCall(Expr),
    /// A jump through a dense jump table (a `switch`): `index` selects a case, and `cases[i]`
    /// is the block that case value `i` jumps to.
    Switch(Expr, Vec<u64>),
}

#[derive(Clone, Debug)]
pub struct Block {
    pub addr: u64,
    pub stmts: Vec<(u64, Stmt)>,
    pub term: Term,
    pub term_addr: u64,
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => f.write_str(REG_NAMES[usize::from(*r)]),
            Self::Split(r, v) => write!(f, "{}_{v}", REG_NAMES[usize::from(*r)]),
            Self::Xmm(r) => write!(f, "xmm{r}"),
            Self::XmmSplit(r, v) => write!(f, "xmm{r}_{v}"),
            Self::Stack(off) if *off < 0 => write!(f, "local_{:x}", -off),
            Self::Stack(off) => write!(f, "arg_{off:x}"),
            Self::Named(s) => f.write_str(s),
        }
    }
}
