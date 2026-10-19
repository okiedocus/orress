//! Turning register-level IR into readable expressions: substitution, folding and
//! dead-code removal, plus parameter detection.

use std::collections::{HashMap, HashSet};

use crate::ir::*;
use crate::lift::Convention;

/// Reads something that a call or a store could change.
fn reads_memory(e: &Expr) -> bool {
    let mut found = false;
    e.walk(&mut |x| {
        found |= matches!(
            x,
            Expr::Load(..) | Expr::Call(..) | Expr::Var(Var::Stack(_), _)
        )
    });
    found
}

/// The largest expression (in nodes) forward substitution will build.
const MAX_SUBST_SIZE: usize = 256;

fn size(e: &Expr) -> usize {
    let mut n = 0;
    e.walk(&mut |_| n += 1);
    n
}

pub fn term_exprs(t: &Term) -> Vec<&Expr> {
    match t {
        Term::Branch(c, _, _) => vec![c],
        Term::Return(Some(e)) | Term::TailCall(e) | Term::Switch(e, _) => vec![e],
        _ => vec![],
    }
}

pub fn term_map(t: Term, f: &mut impl FnMut(Expr) -> Expr) -> Term {
    match t {
        Term::Branch(c, a, b) => Term::Branch(f(c), a, b),
        Term::Return(Some(e)) => Term::Return(Some(f(e))),
        Term::TailCall(e) => Term::TailCall(f(e)),
        Term::Switch(e, cases) => Term::Switch(f(e), cases),
        other => other,
    }
}

pub fn successors(t: &Term) -> Vec<u64> {
    match t {
        Term::Jump(a) => vec![*a],
        Term::Branch(_, a, b) => vec![*a, *b],
        Term::Switch(_, cases) => {
            let mut s = cases.clone();
            s.sort_unstable();
            s.dedup();
            s
        }
        _ => vec![],
    }
}

/// The XMM registers that carry floating-point arguments, in order (SysV: xmm0–7; Win64:
/// xmm0–3).
pub fn float_arg_regs(conv: Convention) -> &'static [u8] {
    match conv {
        Convention::Win64 => &[0, 1, 2, 3],
        Convention::SysV => &[0, 1, 2, 3, 4, 5, 6, 7],
        // ARM64 floating-point parameters are in v0–v7 (modelled as XMM 0–7).
        Convention::Aarch64 => &[0, 1, 2, 3, 4, 5, 6, 7],
        // RISC-V floating-point parameters are in fa0–fa7 (modelled as XMM 0–7).
        Convention::Riscv => &[0, 1, 2, 3, 4, 5, 6, 7],
        // MIPS o32 passes up to two FP arguments in $f12/$f14 (modelled as XMM 12/14 — the MIPS
        // lifter maps $fN to Xmm(N), keeping the return register $f0 on Xmm(0)).
        Convention::Mips => &[12, 14],
        // MIPS n64 passes FP arguments in $f12–$f19 (modelled as XMM 12–19).
        Convention::Mips64 => &[12, 13, 14, 15, 16, 17, 18, 19],
        // PowerPC passes FP arguments in f1–f13; the ppc lifter maps fN to Xmm(N-1), so these are
        // XMM 0–12 and the float return (f1) lands on Xmm(0).
        Convention::Ppc => &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    }
}

/// How many of a set of argument-register locations the function reads before writing them.
fn count_params(blocks: &[Block], entry: u64, locs: &[Var]) -> usize {
    let assigned_anywhere: HashSet<Var> = blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter_map(|(_, s)| match s {
            Stmt::Assign(v, _) if locs.contains(v) => Some(*v),
            _ => None,
        })
        .collect();
    let mut is_param = vec![false; locs.len()];
    for b in blocks {
        let mut written: HashSet<Var> = HashSet::new();
        let check = |e: &Expr, written: &HashSet<Var>, is_param: &mut Vec<bool>| {
            for (i, loc) in locs.iter().enumerate() {
                if !written.contains(loc)
                    && e.reads(*loc)
                    && (b.addr == entry || !assigned_anywhere.contains(loc))
                {
                    is_param[i] = true;
                }
            }
        };
        for (_, s) in &b.stmts {
            // An un-lifted instruction incidentally reads hardware registers (e.g. cpuid reads
            // ecx); that is not evidence the function takes them as parameters.
            if !matches!(s, Stmt::Asm(..)) {
                for e in s.exprs() {
                    check(e, &written, &mut is_param);
                }
            }
            for v in s.defs() {
                written.insert(v);
            }
        }
        for e in term_exprs(&b.term) {
            // A returned value is not a parameter read.
            if !matches!(b.term, Term::Return(_)) {
                check(e, &written, &mut is_param);
            }
        }
    }
    is_param.iter().rposition(|&p| p).map_or(0, |i| i + 1)
}

/// How many of the integer argument registers the function reads before writing them.
pub fn param_count(blocks: &[Block], entry: u64, conv: Convention) -> usize {
    let locs: Vec<Var> = conv.arg_regs().iter().map(|&r| Var::Reg(r)).collect();
    count_params(blocks, entry, &locs)
}

/// How many floating-point (XMM) argument registers the function reads before writing them.
pub fn float_param_count(blocks: &[Block], entry: u64, conv: Convention) -> usize {
    let locs: Vec<Var> = float_arg_regs(conv).iter().map(|&r| Var::Xmm(r)).collect();
    count_params(blocks, entry, &locs)
}

/// Replaces parameter registers by `Param(n)` where they still hold the argument: on every
/// path from the entry, nothing has written them yet. `arg_map` lists each argument-register
/// location (an integer `Reg` or a floating-point `Xmm`) and the parameter index it binds to.
pub fn bind_params(blocks: &mut [Block], entry: u64, arg_map: &[(Var, usize)]) {
    let index: HashMap<Var, usize> = arg_map.iter().map(|&(v, i)| (v, i)).collect();
    let all: HashSet<Var> = arg_map.iter().map(|&(v, _)| v).collect();
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    for b in blocks.iter() {
        for t in successors(&b.term) {
            preds.entry(t).or_default().push(b.addr);
        }
    }
    let writes: HashMap<u64, HashSet<Var>> = blocks
        .iter()
        .map(|b| {
            let w = b.stmts.iter().flat_map(|(_, s)| s.defs()).collect();
            (b.addr, w)
        })
        .collect();
    let mut live_in: HashMap<u64, HashSet<Var>> = blocks
        .iter()
        .map(|b| {
            (
                b.addr,
                if b.addr == entry || preds.contains_key(&b.addr) {
                    all.clone()
                } else {
                    HashSet::new()
                },
            )
        })
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for b in blocks.iter() {
            if b.addr == entry {
                continue;
            }
            let Some(ps) = preds.get(&b.addr) else {
                continue;
            };
            let mut new = all.clone();
            for p in ps {
                let out: HashSet<Var> = live_in[p].difference(&writes[p]).copied().collect();
                new = new.intersection(&out).copied().collect();
            }
            if new != live_in[&b.addr] {
                live_in.insert(b.addr, new);
                changed = true;
            }
        }
    }
    for b in blocks.iter_mut() {
        let mut live = live_in[&b.addr].clone();
        let replace = |e: Expr, live: &HashSet<Var>| {
            e.map(&mut |x| match x {
                Expr::Var(v, w) if live.contains(&v) => {
                    Expr::Param(*index.get(&v).expect("arg loc"), w)
                }
                other => other,
            })
        };
        for (_, s) in b.stmts.iter_mut() {
            let taken = std::mem::replace(s, Stmt::Asm(String::new(), Vec::new()));
            let defs = taken.defs();
            *s = match taken {
                Stmt::Assign(v, e) => Stmt::Assign(v, replace(e, &live)),
                Stmt::Store(a, v, w) => Stmt::Store(replace(a, &live), replace(v, &live), w),
                Stmt::Eval(e) => Stmt::Eval(replace(e, &live)),
                Stmt::Asm(t, ops) => Stmt::Asm(
                    t,
                    ops.into_iter()
                        .map(|op| op.map_value(&mut |e| replace(e, &live)))
                        .collect(),
                ),
            };
            // Once a register is written (by an assignment or captured as an asm output) it no
            // longer holds its entry value, so later reads are not the parameter.
            for v in defs {
                live.remove(&v);
            }
        }
        // Returns are remapped too: an integer `return rax` is untouched (rax is not an
        // argument register), but a floating-point `return xmm0` binds to its parameter on a
        // path where xmm0 still holds the incoming argument.
        let term = std::mem::replace(&mut b.term, Term::Stop);
        b.term = term_map(term, &mut |e| replace(e, &live));
    }
}

/// Algebraic clean-up of one expression.
pub fn fold(e: Expr) -> Expr {
    e.map(&mut |x| match x {
        Expr::Bin(op, a, b, w) => match (op, *a, *b) {
            (op, Expr::Const(x, _), Expr::Const(y, _)) => {
                let v = match op {
                    BinOp::Add => x.wrapping_add(y),
                    BinOp::Sub => x.wrapping_sub(y),
                    BinOp::Mul => x.wrapping_mul(y),
                    BinOp::And => x & y,
                    BinOp::Or => x | y,
                    BinOp::Xor => x ^ y,
                    BinOp::Shl => x.wrapping_shl(y as u32),
                    BinOp::Shr => x.wrapping_shr(y as u32),
                    _ => {
                        return Expr::Bin(
                            op,
                            Box::new(Expr::Const(x, w)),
                            Box::new(Expr::Const(y, w)),
                            w,
                        );
                    }
                };
                Expr::konst(v, w)
            }
            (
                BinOp::Add
                | BinOp::Sub
                | BinOp::Or
                | BinOp::Xor
                | BinOp::Shl
                | BinOp::Shr
                | BinOp::Sar,
                a,
                Expr::Const(0, _),
            ) => a,
            // `0 OP a` for commutative ops (ARM's `mov` is `orr Rd, xzr, Rm` → `0 | a`).
            (BinOp::Add | BinOp::Or | BinOp::Xor, Expr::Const(0, _), a) => a,
            (BinOp::Mul, a, Expr::Const(1, _)) => a,
            (BinOp::Xor | BinOp::Sub, a, b) if a == b => Expr::konst(0, w),
            // `lea` multiply-by-constant: `x + x*k` is `x * (k + 1)` (the x3/x5/x9 idiom).
            (BinOp::Add, a, Expr::Bin(BinOp::Mul, x, k, _))
                if matches!(&*k, Expr::Const(..)) && a == *x =>
            {
                let Expr::Const(k, _) = *k else {
                    unreachable!()
                };
                Expr::bin(BinOp::Mul, a, Expr::konst(k.wrapping_add(1), w), w)
            }
            (BinOp::Add, Expr::Bin(BinOp::Mul, x, k, _), a)
                if matches!(&*k, Expr::Const(..)) && *x == a =>
            {
                let Expr::Const(k, _) = *k else {
                    unreachable!()
                };
                Expr::bin(BinOp::Mul, a, Expr::konst(k.wrapping_add(1), w), w)
            }
            // All-ones minus x is bitwise NOT (the `not reg` of the inline `strlen` idiom
            // shows up as `0xffff.. - x` once `or reg,-1` folds to all-ones).
            (BinOp::Sub, Expr::Const(c, _), x) if c == w.mask() => Expr::Not(Box::new(x), w),
            // `__scasb(ptr, 0) - 1` is `strlen(ptr)` (bytes scanned to the NUL, less the NUL).
            (BinOp::Sub, Expr::Call(CallTarget::Builtin("__scasb"), args), Expr::Const(1, _))
                if args.len() == 2 && matches!(args[1], Expr::Const(0, _)) =>
            {
                let mut args = args;
                Expr::Call(CallTarget::Builtin("strlen"), vec![args.swap_remove(0)])
            }
            // (x + a) + b and (x - a) + b: one constant.
            (
                BinOp::Add | BinOp::Sub,
                Expr::Bin(inner @ (BinOp::Add | BinOp::Sub), x, k1, _),
                Expr::Const(k2, _),
            ) if matches!(*k1, Expr::Const(..)) => {
                let Expr::Const(k1, _) = *k1 else {
                    unreachable!()
                };
                let a = if inner == BinOp::Add {
                    k1
                } else {
                    k1.wrapping_neg()
                };
                let b = if op == BinOp::Add {
                    k2
                } else {
                    k2.wrapping_neg()
                };
                fold(Expr::bin(
                    BinOp::Add,
                    *x,
                    Expr::konst(a.wrapping_add(b), w),
                    w,
                ))
            }
            // x + -1 -> x - 1
            (BinOp::Add | BinOp::Sub, x, Expr::Const(k, kw))
                if !matches!(x, Expr::StackAddr(_) | Expr::Addr(_))
                    && k > w.mask() >> 1
                    && k != (w.mask() >> 1) + 1 =>
            {
                let flipped = if op == BinOp::Add {
                    BinOp::Sub
                } else {
                    BinOp::Add
                };
                Expr::bin(flipped, x, Expr::konst(k.wrapping_neg(), kw), w)
            }
            (BinOp::Add, Expr::StackAddr(o), Expr::Const(k, _)) => {
                Expr::StackAddr(o.wrapping_add(k as i64))
            }
            (BinOp::Add, Expr::Addr(a), Expr::Const(k, _)) => Expr::Addr(a.wrapping_add(k)),
            (op, a, b) => Expr::Bin(op, Box::new(a), Box::new(b), w),
        },
        Expr::Cmp(op, a, b, s) => match (op, *a, *b) {
            (CmpOp::Eq | CmpOp::Ne, Expr::Bin(BinOp::Sub, x, y, _), Expr::Const(0, _)) => {
                Expr::Cmp(op, x, y, s)
            }
            // `x + y == y` (flags of a `sub` whose result overwrote x) is `x == 0`.
            (CmpOp::Eq | CmpOp::Ne, Expr::Bin(BinOp::Add, x, y, w), z) if *y == z => {
                Expr::Cmp(op, x, Box::new(Expr::konst(0, w)), s)
            }
            (CmpOp::Ne, c, Expr::Const(0, _)) if c.is_condition() => c,
            (CmpOp::Eq, c, Expr::Const(0, _)) if c.is_condition() => c.negate(),
            (CmpOp::Ne, Expr::Cast(c, _, _), Expr::Const(0, _)) if c.is_condition() => *c,
            (CmpOp::Eq, Expr::Cast(c, _, _), Expr::Const(0, _)) if c.is_condition() => c.negate(),
            (op, Expr::Const(x, w), Expr::Const(y, _)) => {
                let sext = |v: u64| {
                    if w.0 < 8 && (v >> (w.bits() - 1)) & 1 == 1 {
                        (v | !w.mask()) as i64
                    } else {
                        v as i64
                    }
                };
                let ord = if s { sext(x).cmp(&sext(y)) } else { x.cmp(&y) };
                let r = match op {
                    CmpOp::Eq => ord.is_eq(),
                    CmpOp::Ne => ord.is_ne(),
                    CmpOp::Lt => ord.is_lt(),
                    CmpOp::Le => ord.is_le(),
                    CmpOp::Gt => ord.is_gt(),
                    CmpOp::Ge => ord.is_ge(),
                };
                Expr::Const(u64::from(r), Width::B8)
            }
            (op, Expr::Const(x, w), b) if !matches!(b, Expr::Const(..)) => {
                // Constant on the right reads more naturally: 5 < x -> x > 5.
                let flipped = match op {
                    CmpOp::Lt => CmpOp::Gt,
                    CmpOp::Le => CmpOp::Ge,
                    CmpOp::Gt => CmpOp::Lt,
                    CmpOp::Ge => CmpOp::Le,
                    other => other,
                };
                Expr::Cmp(flipped, Box::new(b), Box::new(Expr::Const(x, w)), s)
            }
            // A comparison a known-bits analysis proves is always true/false (an opaque predicate)
            // folds to a constant; otherwise it is rebuilt unchanged.
            (op, a, b) => crate::deobfuscate::fold_bool(Expr::Cmp(op, Box::new(a), Box::new(b), s)),
        },
        // `!!x` is `x`; `!const` folds.
        Expr::Not(a, w) => match *a {
            Expr::Not(inner, _) => *inner,
            Expr::Const(c, _) => Expr::konst(!c & w.mask(), w),
            inner => Expr::Not(Box::new(inner), w),
        },
        Expr::LNot(a) if a.is_condition() => a.negate(),
        Expr::Cast(a, w, s) => match *a {
            Expr::Const(v, from) => {
                let v = if s && from.0 < 8 && (v >> (from.bits() - 1)) & 1 == 1 {
                    v | !from.mask()
                } else {
                    v
                };
                Expr::konst(v, w)
            }
            // A same-width *unsigned* cast is a no-op; a same-width *signed* cast reinterprets
            // the bits (e.g. the operands of a signed division) and must survive.
            inner if inner.width() == w && !inner.is_condition() && !s => inner,
            // Collapsing `Cast(Cast(inner, mid, s2), w, s)` when `mid >= w`: the outer cast is a
            // truncation (or same-width reinterpret), so the result bits up to `w` are fixed by the
            // INNER extension `s2` — the outer `s` doesn't change them. Using `s2 && s` dropped the
            // inner sign-extension (e.g. `movsx r32,r8` then a 16-bit unsigned use).
            Expr::Cast(inner, mid, s2) if mid >= w => Expr::Cast(inner, w, s2),
            // Truncation: read the low part directly, and push it into arithmetic
            // (`(a + b) as u32` == `a as u32 + b as u32` in wrapping arithmetic).
            Expr::Param(i, from) if w < from => Expr::Param(i, w),
            Expr::Var(v, from) if w < from => Expr::Var(v, w),
            Expr::Bin(
                op @ (BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor),
                a,
                b,
                from,
            ) if w < from => {
                let a = fold(Expr::Cast(a, w, false));
                let b = fold(Expr::Cast(b, w, false));
                Expr::Bin(op, Box::new(a), Box::new(b), w)
            }
            inner => Expr::Cast(Box::new(inner), w, s),
        },
        Expr::Load(a, w) => match *a {
            Expr::StackAddr(o) => Expr::Var(Var::Stack(o), w),
            inner => Expr::Load(Box::new(inner), w),
        },
        Expr::Select(c, a, b, _) if matches!(*c, Expr::Const(..)) => {
            if matches!(*c, Expr::Const(0, _)) {
                *b
            } else {
                *a
            }
        }
        Expr::Select(c, a, b, _) if a == b => {
            let _ = c;
            *a
        }
        // `if x > y { x } else { y }` is `x.max(y)`; the mirror cases give `min`.
        Expr::Select(c, a, b, w) => match *c {
            Expr::Cmp(op, x, y, s) => {
                let name = if a == x && b == y {
                    match op {
                        CmpOp::Gt | CmpOp::Ge => Some("max"),
                        CmpOp::Lt | CmpOp::Le => Some("min"),
                        _ => None,
                    }
                } else if a == y && b == x {
                    match op {
                        CmpOp::Gt | CmpOp::Ge => Some("min"),
                        CmpOp::Lt | CmpOp::Le => Some("max"),
                        _ => None,
                    }
                } else {
                    None
                };
                match name {
                    // A signed comparison is a signed max/min: wrap the operands in signed casts
                    // so `.max()/.min()` operate on iN, the result var types signed (is_signed_expr
                    // handles max/min), and a slice operand's element type infers as `&[iN]`.
                    Some(n) if s => Expr::Method(
                        Box::new(Expr::Cast(x, w, true)),
                        n,
                        vec![Expr::Cast(y, w, true)],
                        w,
                    ),
                    Some(n) => Expr::Method(x, n, vec![*y], w),
                    None => Expr::Select(Box::new(Expr::Cmp(op, x, y, s)), a, b, w),
                }
            }
            // The same shape over a floating-point comparison (`fcsel`) → `x.max(y)` / `.min()`.
            Expr::FCmp(op, x, y) => {
                let name = if a == x && b == y {
                    match op {
                        CmpOp::Gt | CmpOp::Ge => Some("max"),
                        CmpOp::Lt | CmpOp::Le => Some("min"),
                        _ => None,
                    }
                } else if a == y && b == x {
                    match op {
                        CmpOp::Gt | CmpOp::Ge => Some("min"),
                        CmpOp::Lt | CmpOp::Le => Some("max"),
                        _ => None,
                    }
                } else {
                    None
                };
                match name {
                    Some(n) => Expr::Method(x, n, vec![*y], w),
                    None => Expr::Select(Box::new(Expr::FCmp(op, x, y)), a, b, w),
                }
            }
            other => Expr::Select(Box::new(other), a, b, w),
        },
        // `movd xmm, r32` (lifted as a scalar `fN::from_bits` bitcast into lane 0) then
        // `pshufd xmm, xmm, 0` (immediate 0 selects lane 0 for every lane) is a scalar splat
        // `[x; N]` — the usual way a loop-invariant is broadcast before a packed loop.
        Expr::VecShuffle(a, 0, n, w) if scalar_bitcast(&a).is_some() => {
            Expr::VecSplat(Box::new(scalar_bitcast(&a).unwrap()), n, w)
        }
        // The SSE2 packed max/min idiom `(a & (a>b)) | (!(a>b) & b)` (compare + blend) → VecMax
        // (and its mirror → VecMin).
        Expr::VecBin(BinOp::Or, a, b, _, _) if vec_blend(&a, &b).is_some() => {
            vec_blend(&a, &b).unwrap()
        }
        // `movd eax, xmm` (lifted as `xmm.to_bits()`) where xmm holds a vector is a lane extract.
        // When that vector is a `pshufd`/`paddd` horizontal-sum chain, it is a lane reduction.
        Expr::Method(recv, "to_bits", args, w) if args.is_empty() && recv.is_vector() => {
            // The extracted scalar's lane type is the vector's lane (so a float vector extracts
            // an `f32`/`f64`).
            let lane = recv.vec_shape().map_or(Lane::int(w), |(_, l)| l);
            match hreduce_base(&recv) {
                Some((op, base)) => Expr::VecReduce(op, Box::new(base), lane),
                None => Expr::VecExtract(recv, 0, lane),
            }
        }
        // Peel any further same-operator reduce levels that only folded to `VecMax`/`VecBin` after
        // this `VecReduce` first formed (the shuffle-reduce chain is assembled across several
        // substitution/fold passes, so the first `to_bits` fold may capture a partial base).
        Expr::VecReduce(op, base, w) if hreduce_base(&base).map(|(o, _)| o) == Some(op) => {
            let (_, inner) = hreduce_base(&base).expect("guard checked");
            Expr::VecReduce(op, Box::new(inner), w)
        }
        // Fold opaque predicates — comparisons a known-bits analysis proves are always true or
        // always false — to a constant, so the dead arm is then removed. Sound: only genuinely
        // constant conditions fold (see `deobfuscate`).
        other => crate::deobfuscate::fold_bool(other),
    })
}

/// The scalar inside a `movd`-style register→XMM bitcast (`fN::from_bits(x)`), i.e. the integer
/// that `movd xmm, r32` placed in lane 0. Used to recover the scalar-broadcast (`pshufd ..,0`) idiom.
fn scalar_bitcast(e: &Expr) -> Option<Expr> {
    match e {
        Expr::Call(CallTarget::Builtin("f32::from_bits" | "f64::from_bits"), args)
            if args.len() == 1 =>
        {
            Some(args[0].clone())
        }
        _ => None,
    }
}

/// Recognises the SSE2 packed max/min blend `(a & m) | andn(m, c)` where `m = (a > b)` is a
/// lane-wise compare. `max(a,b) = (a & m) | andn(m, b)`; `min(a,b) = (b & m) | andn(m, a)`.
fn vec_blend(l: &Expr, r: &Expr) -> Option<Expr> {
    // Split into the `and` half and the `andn` half (either `Or` order).
    let (and_part, andn) = match (l, r) {
        (Expr::VecBin(BinOp::And, ..), Expr::VecAndn(..)) => (l, r),
        (Expr::VecAndn(..), Expr::VecBin(BinOp::And, ..)) => (r, l),
        _ => return None,
    };
    let Expr::VecBin(BinOp::And, aa, ab, n, w) = and_part else {
        return None;
    };
    let Expr::VecAndn(na, nb, _, _) = andn else {
        return None;
    };
    // The `and` half keeps one operand under the mask; pull out the mask and the kept value.
    let (gt, kept) = match (&**aa, &**ab) {
        (Expr::VecGt(..), _) => (&**aa, &**ab),
        (_, Expr::VecGt(..)) => (&**ab, &**aa),
        _ => return None,
    };
    if **na != *gt {
        return None; // both halves must use the same compare mask.
    }
    let Expr::VecGt(g0, g1, ..) = gt else {
        return None;
    };
    // kept = a, andn-value = b → max(a, b); kept = b, andn-value = a → min(a, b).
    if kept == &**g0 && **nb == **g1 {
        Some(Expr::VecMax(g0.clone(), g1.clone(), *n, *w))
    } else if kept == &**g1 && **nb == **g0 {
        Some(Expr::VecMin(g0.clone(), g1.clone(), *n, *w))
    } else {
        None
    }
}

/// The base vector and operator of a `pshufd`/`paddd`-style horizontal reduce chain: peels each
/// `op(x, shuffle(x))` level (the compiler's `log2(lanes)` pairwise-combine epilogue) down to the
/// base vector, or `None` if `e` is not such a chain. Every level must use the same reduction
/// operator — a sum (`paddd`), product (`pmulld`) or max/min (`pmaxsd`/the recovered `VecMax`).
fn hreduce_base(e: &Expr) -> Option<(ReduceOp, Expr)> {
    // One reduction level: `op(x, shuffle(x))` or `op(shuffle(x), x)` (lanes combined pairwise).
    let level = |e: &Expr| -> Option<(ReduceOp, Expr)> {
        let (op, a, b) = match e {
            Expr::VecBin(BinOp::Add, a, b, _, _) => (ReduceOp::Add, a, b),
            Expr::VecBin(BinOp::Mul, a, b, _, _) => (ReduceOp::Mul, a, b),
            Expr::VecMax(a, b, _, _) => (ReduceOp::Max, a, b),
            Expr::VecMin(a, b, _, _) => (ReduceOp::Min, a, b),
            _ => return None,
        };
        match (&**a, &**b) {
            (Expr::VecShuffle(inner, _, _, _), other) if **inner == *other => {
                Some((op, other.clone()))
            }
            (other, Expr::VecShuffle(inner, _, _, _)) if **inner == *other => {
                Some((op, other.clone()))
            }
            _ => None,
        }
    };
    let (op, mut cur) = level(e)?;
    while let Some((op2, next)) = level(&cur) {
        if op2 != op {
            break; // a mixed-operator chain is not one reduction.
        }
        cur = next;
    }
    Some((op, cur))
}

fn fold_stmt(s: Stmt) -> Stmt {
    match s {
        Stmt::Assign(v, e) => Stmt::Assign(v, fold(e)),
        Stmt::Store(a, v, w) => match fold(a) {
            Expr::StackAddr(o) => Stmt::Assign(Var::Stack(o), fold(v)),
            a => Stmt::Store(a, fold(v), w),
        },
        Stmt::Eval(e) => Stmt::Eval(fold(e)),
        Stmt::Asm(t, ops) => Stmt::Asm(
            t,
            ops.into_iter().map(|op| op.map_value(&mut fold)).collect(),
        ),
    }
}

fn substitute(e: Expr, pending: &mut HashMap<Var, Pending>) -> Expr {
    e.map(&mut |x| match x {
        Expr::Var(v, w) => match pending.get_mut(&v) {
            Some(p) => {
                p.uses += 1;
                let val = p.expr.clone();
                match val {
                    Expr::Const(c, _) => Expr::konst(c, w),
                    val if val.width() > w && !val.is_condition() => {
                        Expr::Cast(Box::new(val), w, false)
                    }
                    val => val,
                }
            }
            None => Expr::Var(v, w),
        },
        other => other,
    })
}

struct Pending {
    expr: Expr,
    /// Statement that defined it, removable once the value is used.
    origin: usize,
    removable: bool,
    uses: usize,
}

/// For every statement `i` of a block that assigns a variable `v`: the number of uses of `v` after
/// `i` before it is redefined, and whether it is still live at the end of the block — computed in
/// one backward pass (scanning forward from every statement, as [`uses_after`] does, is quadratic
/// in the block length). Entries for non-assignments are `(0, false)`.
fn use_counts(stmts: &[(u64, Stmt)], term: &Term, live_out: &HashSet<Var>) -> Vec<(usize, bool)> {
    // Uses of each variable from the current position up to (and including the reads of) its
    // next redefinition, or to the end of the block (terminator included) if there is none.
    let mut cnt: HashMap<Var, usize> = HashMap::new();
    let mut redefined: HashSet<Var> = HashSet::new();
    for e in term_exprs(term) {
        for v in e.vars() {
            *cnt.entry(v).or_default() += 1;
        }
    }
    let mut out = vec![(0, false); stmts.len()];
    for (i, (_, s)) in stmts.iter().enumerate().rev() {
        if let Stmt::Assign(v, _) = s {
            out[i] = (
                cnt.get(v).copied().unwrap_or(0),
                !redefined.contains(v) && live_out.contains(v),
            );
        }
        // Extend the "after" region backwards to include statement `i`.
        let reads: Vec<Var> = s.exprs().iter().flat_map(|e| e.vars()).collect();
        match s {
            Stmt::Assign(d, _) => {
                // A redefinition ends the region for `d`: only its own reads of `d` count.
                for v in &reads {
                    if v != d {
                        *cnt.entry(*v).or_default() += 1;
                    }
                }
                cnt.insert(*d, reads.iter().filter(|x| *x == d).count());
                redefined.insert(*d);
            }
            _ => {
                for v in reads {
                    *cnt.entry(v).or_default() += 1;
                }
            }
        }
    }
    out
}

/// Number of uses of `v` after statement `i` before it is redefined, and whether it is
/// still live at the end of the block. The reference definition [`use_counts`] is tested against.
#[cfg(test)]
fn uses_after(block: &Block, i: usize, v: Var, live_out: &HashSet<Var>) -> (usize, bool) {
    let mut n = 0;
    for (_, s) in &block.stmts[i + 1..] {
        n += s
            .exprs()
            .iter()
            .map(|e| e.vars().iter().filter(|x| **x == v).count())
            .sum::<usize>();
        if let Stmt::Assign(d, _) = s
            && *d == v
        {
            return (n, false);
        }
    }
    n += term_exprs(&block.term)
        .iter()
        .map(|e| e.vars().iter().filter(|x| **x == v).count())
        .sum::<usize>();
    (n, live_out.contains(&v))
}

fn substitute_block(block: &mut Block, live_out: &HashSet<Var>) {
    let mut pending: HashMap<Var, Pending> = HashMap::new();
    let mut remove: HashSet<usize> = HashSet::new();
    let stmts = std::mem::take(&mut block.stmts);
    let mut out: Vec<(u64, Stmt)> = Vec::with_capacity(stmts.len());
    // Pre-compute use counts on the original statements.
    let counts = use_counts(&stmts, &block.term, live_out);
    for (i, (addr, s)) in stmts.into_iter().enumerate() {
        let s = match s {
            Stmt::Assign(v, e) => Stmt::Assign(v, substitute(e, &mut pending)),
            Stmt::Store(a, v, w) => {
                Stmt::Store(substitute(a, &mut pending), substitute(v, &mut pending), w)
            }
            Stmt::Eval(e) => Stmt::Eval(substitute(e, &mut pending)),
            Stmt::Asm(t, ops) => Stmt::Asm(
                t,
                ops.into_iter()
                    .map(|op| op.map_value(&mut |e| substitute(e, &mut pending)))
                    .collect(),
            ),
        };
        // Mark consumed single-use calls for removal.
        for p in pending.values() {
            if p.removable && p.uses > 0 {
                remove.insert(p.origin);
            }
        }
        match &s {
            Stmt::Assign(v, e) => {
                let v = *v;
                pending.retain(|k, p| *k != v && !p.expr.reads(v));
                if e.has_call() {
                    pending.retain(|k, p| !reads_memory(&p.expr) && !matches!(k, Var::Stack(_)));
                }
                let (uses, live) = counts[i];
                // Never build an expression past MAX_SUBST_SIZE nodes: a long single-use chain
                // (a straight-line hash, an unrolled loop) would otherwise nest without bound and
                // blow up every later recursive pass and the printer.
                let simple =
                    !matches!(e, Expr::Unknown(_)) && !e.reads(v) && size(e) <= MAX_SUBST_SIZE;
                if simple && e.has_call() {
                    if uses == 1 && !live {
                        pending.insert(
                            v,
                            Pending {
                                expr: e.clone(),
                                origin: i,
                                removable: true,
                                uses: 0,
                            },
                        );
                    }
                } else if simple && (uses <= 1 || size(e) <= 12) {
                    pending.insert(
                        v,
                        Pending {
                            expr: e.clone(),
                            origin: i,
                            removable: false,
                            uses: 0,
                        },
                    );
                }
            }
            Stmt::Store(..) | Stmt::Eval(_) => {
                pending.retain(|k, p| !reads_memory(&p.expr) && !matches!(k, Var::Stack(_)));
            }
            Stmt::Asm(..) => pending.clear(),
        }
        out.push((addr, s));
    }
    let term = std::mem::replace(&mut block.term, Term::Stop);
    block.term = term_map(term, &mut |e| substitute(e, &mut pending));
    for p in pending.values() {
        if p.removable && p.uses > 0 {
            remove.insert(p.origin);
        }
    }
    block.stmts = out
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !remove.contains(i))
        .map(|(_, s)| s)
        .collect();
}

fn stmt_uses(s: &Stmt) -> Vec<Var> {
    s.exprs().iter().flat_map(|e| e.vars()).collect()
}

/// Live variables at the end of each block.
fn liveness(blocks: &[Block]) -> HashMap<u64, HashSet<Var>> {
    let index: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, i))
        .collect();
    let mut live_in: Vec<HashSet<Var>> = vec![HashSet::new(); blocks.len()];
    let mut live_out: Vec<HashSet<Var>> = vec![HashSet::new(); blocks.len()];
    let mut changed = true;
    while changed {
        changed = false;
        for (i, b) in blocks.iter().enumerate().rev() {
            let mut out: HashSet<Var> = HashSet::new();
            for s in successors(&b.term) {
                if let Some(&j) = index.get(&s) {
                    out.extend(live_in[j].iter().copied());
                }
            }
            let mut live = out.clone();
            for e in term_exprs(&b.term) {
                live.extend(e.vars());
            }
            for (_, s) in b.stmts.iter().rev() {
                for v in s.defs() {
                    live.remove(&v);
                }
                live.extend(stmt_uses(s));
            }
            if live != live_in[i] || out != live_out[i] {
                live_in[i] = live;
                live_out[i] = out;
                changed = true;
            }
        }
    }
    blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, live_out[i].clone()))
        .collect()
}

/// The lowest stack offset whose address is taken (`&mut local_48` passed to a call).
/// Slots from there upwards may be read or written through that pointer, so they are
/// memory, not plain variables.
fn escaped(blocks: &[Block]) -> Option<i64> {
    let mut min: Option<i64> = None;
    for b in blocks {
        let mut visit = |e: &Expr| {
            e.walk(&mut |x| {
                if let Expr::StackAddr(o) = x {
                    min = Some(min.map_or(*o, |m: i64| m.min(*o)));
                }
            })
        };
        for (_, s) in &b.stmts {
            s.exprs().into_iter().for_each(&mut visit);
        }
        term_exprs(&b.term).into_iter().for_each(&mut visit);
    }
    min
}

fn is_escaped(v: Var, esc: Option<i64>) -> bool {
    matches!((v, esc), (Var::Stack(o), Some(m)) if o >= m)
}

fn remove_dead(blocks: &mut [Block], live_out: &HashMap<u64, HashSet<Var>>) -> bool {
    let esc = escaped(blocks);
    let mut changed = false;
    for b in blocks.iter_mut() {
        let mut live = live_out.get(&b.addr).cloned().unwrap_or_default();
        for e in term_exprs(&b.term) {
            live.extend(e.vars());
        }
        let mut kept: Vec<(u64, Stmt)> = Vec::with_capacity(b.stmts.len());
        for (addr, s) in std::mem::take(&mut b.stmts).into_iter().rev() {
            let s = match s {
                Stmt::Assign(v, e) if !live.contains(&v) && !is_escaped(v, esc) => {
                    changed = true;
                    if e.has_call() {
                        Stmt::Eval(e)
                    } else {
                        continue;
                    }
                }
                other => other,
            };
            for v in s.defs() {
                live.remove(&v);
            }
            live.extend(stmt_uses(&s));
            kept.push((addr, s));
        }
        kept.reverse();
        b.stmts = kept;
    }
    changed
}

/// Variables assigned exactly once in the whole function to a value made only of
/// parameters, constants and addresses are replaced by that value everywhere (e.g. a
/// parameter saved in another register or spilled to the stack).
fn propagate_single_defs(blocks: &mut [Block]) -> bool {
    // Variables whose every assignment stores the same pure value (a spilled
    // parameter is often stored again before each use).
    let esc = escaped(blocks);
    let mut defs: HashMap<Var, (bool, Expr)> = HashMap::new();
    for (_, s) in blocks.iter().flat_map(|b| &b.stmts) {
        if let Stmt::Assign(v, e) = s {
            let entry = defs.entry(*v).or_insert((!is_escaped(*v, esc), e.clone()));
            entry.0 &= entry.1 == *e;
        }
    }
    let replace: HashMap<Var, Expr> = defs
        .into_iter()
        .filter(|(_, (same, e))| {
            *same && {
                let mut pure = true;
                e.walk(&mut |x| {
                    pure &= matches!(
                        x,
                        Expr::Param(..)
                            | Expr::Const(..)
                            | Expr::Addr(_)
                            | Expr::StackAddr(_)
                            | Expr::Cast(..)
                    )
                });
                pure
            }
        })
        .map(|(v, (_, e))| (v, e))
        .collect();
    if replace.is_empty() {
        return false;
    }
    let sub = |e: Expr| {
        e.map(&mut |x| match x {
            Expr::Var(v, w) => match replace.get(&v) {
                Some(Expr::Const(c, _)) => Expr::konst(*c, w),
                Some(e) => e.clone(),
                None => Expr::Var(v, w),
            },
            other => other,
        })
    };
    for b in blocks.iter_mut() {
        b.stmts = std::mem::take(&mut b.stmts)
            .into_iter()
            .filter(|(_, s)| !matches!(s, Stmt::Assign(v, _) if replace.contains_key(v)))
            .map(|(a, s)| {
                (
                    a,
                    match s {
                        Stmt::Assign(v, e) => Stmt::Assign(v, sub(e)),
                        Stmt::Store(x, y, w) => Stmt::Store(sub(x), sub(y), w),
                        Stmt::Eval(e) => Stmt::Eval(sub(e)),
                        other => other,
                    },
                )
            })
            .collect();
        let term = std::mem::replace(&mut b.term, Term::Stop);
        b.term = term_map(term, &mut |e| sub(e));
    }
    true
}

/// Runs all simplifications to a fixed point (bounded).
/// Strips value-preserving zero-extension casts so a load and its widened form share one value
/// number: `x` and `x as u32` (an unsigned widening) are the same non-negative value.
fn cse_canon(e: &Expr) -> Expr {
    match e {
        Expr::Cast(inner, w, false) if w.0 >= inner.width().0 => cse_canon(inner),
        other => other.clone(),
    }
}

/// A pure, non-trivial expression worth giving a value number (so a repeat can reuse it). Bare
/// variables, constants and addresses are already trivial; calls and un-lifted asm are impure.
fn cse_worth(e: &Expr) -> bool {
    if e.has_call() {
        return false;
    }
    let mut pure = true;
    e.walk(&mut |x| {
        if matches!(x, Expr::Unknown(_) | Expr::Call(..)) {
            pure = false;
        }
    });
    // Only scalar memory loads (and their zero-extended forms). Arithmetic is cheap to recompute
    // and re-numbering it disturbs the structural patterns later passes match (e.g. vector-max
    // recovery); the duplication worth removing is a reloaded value, which is always a load.
    pure && match e {
        Expr::Load(..) => true,
        Expr::Cast(inner, _, false) => matches!(inner.as_ref(), Expr::Load(..)),
        _ => false,
    }
}

/// Rewrites `e`, replacing any sub-expression that an earlier statement already computed into a
/// variable with that variable (common-subexpression elimination).
fn cse_rewrite(e: Expr, avail: &[(Expr, Var, Width)]) -> Expr {
    e.map(&mut |sub| {
        if cse_worth(&sub) {
            let key = cse_canon(&sub);
            if let Some((_, var, w)) = avail.iter().find(|(k, _, _)| *k == key) {
                return Expr::Var(*var, *w);
            }
        }
        sub
    })
}

/// Block-local value numbering: reuse a variable that already holds a repeated pure expression,
/// instead of recomputing it. This collapses the duplicated load left by a `black_box`
/// store-to-stack/reload (`x = *p; … if *p > 9`) into `x = *p; … if x > 9`. Conservative on
/// aliasing: any memory write (or call) drops every memory-reading value number.
fn cse_block(block: &mut Block) {
    let mut avail: Vec<(Expr, Var, Width)> = Vec::new();
    let placeholder = Expr::Const(0, Width::B8);
    let mut stmts = std::mem::take(&mut block.stmts);
    for (_, s) in &mut stmts {
        match s {
            Stmt::Assign(v, e) => {
                *e = cse_rewrite(std::mem::replace(e, placeholder.clone()), &avail);
                let v = *v;
                // A call on the right-hand side may write memory: drop memory-reading numbers too.
                if e.has_call() {
                    avail.retain(|(k, _, _)| !reads_memory(k));
                }
                avail.retain(|(k, var, _)| *var != v && !k.reads(v));
                if cse_worth(e) {
                    avail.push((cse_canon(e), v, e.width()));
                }
            }
            Stmt::Store(a, val, _) => {
                *a = cse_rewrite(std::mem::replace(a, placeholder.clone()), &avail);
                *val = cse_rewrite(std::mem::replace(val, placeholder.clone()), &avail);
                avail.retain(|(k, _, _)| !reads_memory(k));
            }
            Stmt::Eval(e) => {
                *e = cse_rewrite(std::mem::replace(e, placeholder.clone()), &avail);
                if e.has_call() {
                    avail.retain(|(k, _, _)| !reads_memory(k));
                }
            }
            Stmt::Asm(..) => avail.clear(),
        }
    }
    block.stmts = stmts;
    let term = std::mem::replace(&mut block.term, Term::Stop);
    block.term = term_map(term, &mut |e| cse_rewrite(e, &avail));
}

pub fn simplify(blocks: &mut Vec<Block>, entry: u64) {
    for _ in 0..8 {
        for b in blocks.iter_mut() {
            b.stmts = std::mem::take(&mut b.stmts)
                .into_iter()
                .map(|(a, s)| (a, fold_stmt(s)))
                .collect();
            let term = std::mem::replace(&mut b.term, Term::Stop);
            b.term = term_map(term, &mut fold);
        }
        let live = liveness(blocks);
        for b in blocks.iter_mut() {
            let out = live.get(&b.addr).cloned().unwrap_or_default();
            substitute_block(b, &out);
        }
        let live = liveness(blocks);
        let removed = remove_dead(blocks, &live);
        let propagated = propagate_single_defs(blocks);
        let jumps = constant_branches(blocks);
        let merged = merge_blocks(blocks, entry);
        if !removed && !propagated && !jumps && !merged {
            break;
        }
    }
    for b in blocks.iter_mut() {
        cse_block(b);
    }
    for b in blocks.iter_mut() {
        let term = std::mem::replace(&mut b.term, Term::Stop);
        b.term = term_map(term, &mut fold);
    }
    constant_branches(blocks);
}

/// Joins `a` and `b` when `a` always jumps to `b` and nothing else reaches `b`; drops
/// blocks that became unreachable.
fn merge_blocks(blocks: &mut Vec<Block>, entry: u64) -> bool {
    let mut changed = false;
    loop {
        let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
        for b in blocks.iter() {
            for t in successors(&b.term) {
                preds.entry(t).or_default().push(b.addr);
            }
        }
        let before = blocks.len();
        blocks.retain(|b| b.addr == entry || preds.contains_key(&b.addr));
        changed |= blocks.len() != before;
        let pair = blocks.iter().enumerate().find_map(|(i, b)| match b.term {
            Term::Jump(t)
                if t != b.addr && t != entry && preds.get(&t).is_some_and(|p| p.len() == 1) =>
            {
                blocks.iter().position(|x| x.addr == t).map(|j| (i, j))
            }
            _ => None,
        });
        let Some((i, j)) = pair else {
            return changed;
        };
        let next = blocks.remove(j);
        let i = if j < i { i - 1 } else { i };
        blocks[i].stmts.extend(next.stmts);
        blocks[i].term = next.term;
        blocks[i].term_addr = next.term_addr;
        changed = true;
    }
}

/// `if true` / `if false` become plain jumps (e.g. bounds checks against a known length).
fn constant_branches(blocks: &mut [Block]) -> bool {
    let mut changed = false;
    for b in blocks.iter_mut() {
        if let Term::Branch(Expr::Const(v, _), t, f) = &b.term {
            b.term = Term::Jump(if *v != 0 { *t } else { *f });
            changed = true;
        }
    }
    changed
}

/// For a function that returns nothing, drops the implicit `ret rax` so the leftover scratch
/// `rax` assignments become dead and are removed.
pub fn drop_void_return(blocks: &mut [Block]) {
    for b in blocks.iter_mut() {
        if matches!(&b.term, Term::Return(Some(Expr::Var(Var::Reg(RAX), _)))) {
            b.term = Term::Return(None);
        }
    }
    let live = liveness(blocks);
    remove_dead(blocks, &live);
}

/// Blocks that lie on a cycle (i.e. inside a loop): a block that can reach itself.
fn looping(blocks: &[Block]) -> HashSet<u64> {
    let succ: HashMap<u64, Vec<u64>> = blocks
        .iter()
        .map(|b| (b.addr, successors(&b.term)))
        .collect();
    let mut out = HashSet::new();
    for b in blocks {
        let mut seen = HashSet::new();
        let mut stack = succ.get(&b.addr).cloned().unwrap_or_default();
        while let Some(n) = stack.pop() {
            if n == b.addr {
                out.insert(b.addr);
                break;
            }
            if seen.insert(n) {
                stack.extend(succ.get(&n).cloned().unwrap_or_default());
            }
        }
    }
    out
}

/// If the function returns its value in `xmm0` (a floating-point return) rather than `rax`,
/// rewrites every `return` to yield the xmm0 value and reports its width. Runs before
/// substitution, so the xmm0 definition then folds into the return expression.
pub fn retarget_float_return(blocks: &mut [Block]) -> Option<Width> {
    // rax is the result if a block assigns it a *computed* value. A bare call result in rax is
    // just the ABI modelling of a call (whose real result may be a float in xmm0); and a plain
    // copy of a parameter/register (e.g. `mov eax, esi` staging a loop bound) is not a result
    // either — a float-returning function routinely leaves such scratch in rax. Only a genuine
    // computation makes this an integer return.
    fn trivial(e: &Expr) -> bool {
        match e {
            Expr::Param(..) | Expr::Var(..) | Expr::Const(..) | Expr::Call(..) => true,
            Expr::Cast(a, _, _) => trivial(a),
            _ => false,
        }
    }
    let rax_computed = blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .any(|(_, s)| matches!(s, Stmt::Assign(Var::Reg(RAX), e) if !trivial(e)));
    if rax_computed {
        return None;
    }
    // A function whose work is writing through pointer parameters (not stack spills) is not a
    // float-returning function: a scalar left in xmm0 is the data it just stored, read by the
    // trailing `ret` by accident. (Genuine float returns — reductions, math — do not write heap.)
    let writes_heap = blocks.iter().flat_map(|b| &b.stmts).any(|(_, s)| {
        matches!(s, Stmt::Store(a, _, _)
            if !matches!(a, Expr::StackAddr(_)) && !a.reads(Var::Reg(RSP)) && !a.reads(Var::Reg(RBP)))
    });
    if writes_heap {
        return None;
    }
    // The width xmm0 is given (ss → f32, sd → f64). A packed-vector result in xmm0 is not a
    // scalar float return.
    let last = blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter_map(|(_, s)| match s {
            Stmt::Assign(Var::Xmm(0), e) => Some(e),
            _ => None,
        })
        .next_back()?;
    if last.is_vector() {
        return None;
    }
    let w = last.width();
    let mut any = false;
    for b in blocks.iter_mut() {
        if matches!(&b.term, Term::Return(Some(_))) {
            b.term = Term::Return(Some(Expr::Var(Var::Xmm(0), w)));
            any = true;
        }
    }
    any.then_some(w)
}

/// Whether any statement stores through memory (the mark of a function whose work is a side
/// effect, so a value left in rax is likely scratch, not a result).
fn writes_memory(blocks: &[Block]) -> bool {
    blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .any(|(_, s)| matches!(s, Stmt::Store(..)))
}

fn reads_param(e: &Expr, i: usize) -> bool {
    let mut hit = false;
    e.walk(&mut |x| hit |= matches!(x, Expr::Param(j, _) if *j == i));
    hit
}

/// If `e` is (a cast of) a bare parameter that the function never dereferences — a scalar argument
/// such as a length, count or flag — returns its index. Such a value returned from a function whose
/// real work is writing through its *pointer* parameters is leftover the trailing `ret` reads by
/// accident, not a result. (A returned pointer parameter — `strcpy` yielding its dst — is
/// dereferenced, so it is excluded; and `id(x)` writes no memory, so this never applies to it.)
fn leftover_scalar_param(e: &Expr, blocks: &[Block]) -> bool {
    let mut inner = e;
    while let Expr::Cast(a, _, _) = inner {
        inner = a;
    }
    let Expr::Param(p, _) = inner else {
        return false;
    };
    // Used as a pointer anywhere? (a load or store based on it) → it is a real pointer result.
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Store(a, _, _) = s
                && reads_param(a, *p)
            {
                return false;
            }
            for ex in s.exprs() {
                let mut deref = false;
                ex.walk(&mut |x| {
                    if let Expr::Load(a, _) = x
                        && reads_param(a, *p)
                    {
                        deref = true;
                    }
                });
                if deref {
                    return false;
                }
            }
        }
    }
    true
}

/// Whether the function returns a value in rax (otherwise it returns nothing).
///
/// A plain `rax = v` counts as a result — except a value computed *inside a loop* that is
/// not an accumulation (does not read rax) in a block that also writes memory. That is a
/// per-iteration scratch temp whose last value the trailing `ret` reads by accident, not a
/// real return (e.g. the register holding `src[i]` in a slice-to-slice copy, whose purpose
/// is the store). An in-loop `rax = s[i]` with no store in its block *is* a return (a `find`
/// that returns the element). A function that writes through its pointer parameters and leaves a
/// bare scalar parameter (a length/count) in rax is void — the trailing `ret` reads leftover
/// scratch. Narrowing only ever turns a spurious return into void.
pub fn returns_value(blocks: &[Block]) -> bool {
    let in_loop = looping(blocks);
    let writes_mem = writes_memory(blocks);
    // Whether rax is used as a pointer (dereferenced). A self-incrementing pointer is a walk
    // whose final value is not a meaningful return; a self-incrementing *non-pointer* is a real
    // accumulator/counter that the function returns.
    let mut rax_is_pointer = false;
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Store(a, _, _) = s
                && a.reads(Var::Reg(RAX))
            {
                rax_is_pointer = true;
            }
            for e in s.exprs() {
                e.walk(&mut |x| {
                    if let Expr::Load(a, _) = x
                        && a.reads(Var::Reg(RAX))
                    {
                        rax_is_pointer = true;
                    }
                });
            }
        }
    }
    blocks.iter().any(|b| {
        if let Term::Return(Some(e)) = &b.term
            && !matches!(e, Expr::Var(Var::Reg(RAX), _))
        {
            // A returned expression is a result — unless it is a bare scalar parameter left in rax
            // by a function whose work is writing through its pointer parameters.
            return !(writes_mem && leftover_scalar_param(e, blocks));
        }
        let writes_memory_here = b.stmts.iter().any(|(_, s)| matches!(s, Stmt::Store(..)));
        b.stmts.iter().any(|(_, s)| {
            // A register captured as an `asm!` output (e.g. rax after cpuid) is a real result.
            matches!(s, Stmt::Asm(..)) && s.defs().contains(&Var::Reg(RAX))
                || matches!(s, Stmt::Assign(Var::Reg(RAX), e)
                    if !e.has_call()
                        && !(in_loop.contains(&b.addr) && !e.reads(Var::Reg(RAX)) && writes_memory_here)
                        // An in-loop `rax = rax ± const` where rax is a *pointer* is a walk, not
                        // a returned value (a non-pointer self-increment is a real accumulator).
                        && !(in_loop.contains(&b.addr) && rax_is_pointer && is_induction(e))
                        // A bare scalar parameter left in rax by a memory-writing function is
                        // leftover scratch, not a result.
                        && !(writes_mem && leftover_scalar_param(e, blocks)))
        })
    })
}

/// Whether `e` is a self-increment `v ± const` — the shape of a loop induction variable.
fn is_induction(e: &Expr) -> bool {
    matches!(e, Expr::Bin(BinOp::Add | BinOp::Sub, a, b, _)
        if matches!(&**a, Expr::Var(..)) && matches!(&**b, Expr::Const(..)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(r: u8) -> Expr {
        Expr::Var(Var::Reg(r), Width::B64)
    }

    #[test]
    fn use_counts_match_the_per_statement_scan() {
        // A pseudo-random straight-line block over a few registers, with self-reads,
        // redefinitions, stores and a returning terminator.
        let mut seed = 0x1234_5678u32;
        let mut next = |n: u32| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (seed >> 16) % n
        };
        let mut stmts = Vec::new();
        for i in 0..200 {
            let a = var(next(6) as u8);
            let b = var(next(6) as u8);
            let s = match next(4) {
                0 => Stmt::Store(a, b, Width::B64),
                1 => Stmt::Eval(Expr::bin(BinOp::Add, a, b, Width::B64)),
                _ => Stmt::Assign(
                    Var::Reg(next(6) as u8),
                    Expr::bin(BinOp::Xor, a, b, Width::B64),
                ),
            };
            stmts.push((i, s));
        }
        let block = Block {
            addr: 0,
            stmts,
            term: Term::Return(Some(Expr::bin(BinOp::Add, var(0), var(1), Width::B64))),
            term_addr: 0,
        };
        let live: HashSet<Var> = [Var::Reg(2), Var::Reg(3)].into();
        let fast = use_counts(&block.stmts, &block.term, &live);
        for (i, (_, s)) in block.stmts.iter().enumerate() {
            if let Stmt::Assign(v, _) = s {
                assert_eq!(fast[i], uses_after(&block, i, *v, &live), "statement {i}");
            }
        }
    }

    #[test]
    fn single_use_chains_stop_growing_at_the_cap() {
        // 1000 times `t = prev * 31 + 7` through alternating single-use temporaries: substituting
        // every link would nest a 4000-node expression.
        let mut stmts = Vec::new();
        let mut prev = var(1);
        for i in 0..1000u64 {
            let r = if i % 2 == 0 { 2 } else { 3 };
            let e = Expr::bin(
                BinOp::Add,
                Expr::bin(BinOp::Mul, prev, Expr::konst(31, Width::B64), Width::B64),
                Expr::konst(7, Width::B64),
                Width::B64,
            );
            stmts.push((i, Stmt::Assign(Var::Reg(r), e)));
            prev = var(r);
        }
        let mut block = Block {
            addr: 0,
            stmts,
            term: Term::Return(Some(prev)),
            term_addr: 0,
        };
        substitute_block(&mut block, &HashSet::new());
        let biggest = block
            .stmts
            .iter()
            .flat_map(|(_, s)| s.exprs().into_iter().map(size).collect::<Vec<_>>())
            .chain(term_exprs(&block.term).into_iter().map(size))
            .max()
            .unwrap();
        assert!(
            biggest <= MAX_SUBST_SIZE + 8,
            "expression grew to {biggest} nodes"
        );
    }
}
