//! A small symbolic bitvector expression layer. Input bytes are variables; everything the
//! symbolic executor computes is an `Expr`. Expressions evaluate concretely under an input
//! assignment (used by the built-in brute-force solver) and export to SMT-LIB2 (for scaling
//! out to an external z3). Reference-counted so the executor can clone register values cheaply.

use std::collections::BTreeSet;
use std::rc::Rc;

pub type Expr = Rc<Node>;

/// Binary bitvector operators (operands share a width).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Lshr,
    Ashr,
}

/// Relational operators (produce a 1-bit boolean).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rel {
    Eq,
    Ult,
    Ule,
    Slt,
    Sle,
}

#[derive(Debug)]
pub enum Node {
    Const(u64, u32),
    /// An input byte (8-bit).
    Var(u32),
    Bin(Op, Expr, Expr),
    Not(Expr),
    Neg(Expr),
    ZeroExt(Expr, u32),
    SignExt(Expr, u32),
    /// Bits `[hi, lo]` inclusive.
    Extract(Expr, u32, u32),
    Rel(Rel, Expr, Expr),
    BoolNot(Expr),
    BoolAnd(Expr, Expr),
    BoolOr(Expr, Expr),
    Ite(Expr, Expr, Expr),
}

fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

// --- constructors ---------------------------------------------------------

pub fn konst(v: u64, bits: u32) -> Expr {
    Rc::new(Node::Const(v & mask(bits), bits))
}
pub fn var(i: u32) -> Expr {
    Rc::new(Node::Var(i))
}
pub fn bin(op: Op, a: Expr, b: Expr) -> Expr {
    Rc::new(Node::Bin(op, a, b))
}
pub fn not(a: Expr) -> Expr {
    Rc::new(Node::Not(a))
}
pub fn neg(a: Expr) -> Expr {
    Rc::new(Node::Neg(a))
}
pub fn zext(a: Expr, bits: u32) -> Expr {
    Rc::new(Node::ZeroExt(a, bits))
}
pub fn sext(a: Expr, bits: u32) -> Expr {
    Rc::new(Node::SignExt(a, bits))
}
pub fn extract(a: Expr, hi: u32, lo: u32) -> Expr {
    Rc::new(Node::Extract(a, hi, lo))
}
pub fn rel(r: Rel, a: Expr, b: Expr) -> Expr {
    Rc::new(Node::Rel(r, a, b))
}
pub fn bnot(a: Expr) -> Expr {
    Rc::new(Node::BoolNot(a))
}
pub fn band(a: Expr, b: Expr) -> Expr {
    Rc::new(Node::BoolAnd(a, b))
}
pub fn bor(a: Expr, b: Expr) -> Expr {
    Rc::new(Node::BoolOr(a, b))
}
pub fn ite(c: Expr, a: Expr, b: Expr) -> Expr {
    Rc::new(Node::Ite(c, a, b))
}

impl Node {
    /// The bit width of this expression (1 for booleans). Iterative: it follows the single
    /// width-determining operand down, so a deeply nested expression can't overflow the stack.
    pub fn width(&self) -> u32 {
        let mut cur = self;
        loop {
            match cur {
                Node::Const(_, b) => return *b,
                Node::Var(_) => return 8,
                Node::ZeroExt(_, b) | Node::SignExt(_, b) => return *b,
                Node::Extract(_, hi, lo) => return hi - lo + 1,
                Node::Rel(..) | Node::BoolNot(_) | Node::BoolAnd(..) | Node::BoolOr(..) => return 1,
                Node::Bin(_, a, _) | Node::Not(a) | Node::Neg(a) | Node::Ite(_, a, _) => cur = a,
            }
        }
    }

    /// Evaluates concretely under `assign` (one byte per input variable).
    pub fn eval(&self, assign: &[u8]) -> u64 {
        match self {
            Node::Const(v, b) => v & mask(*b),
            Node::Var(i) => u64::from(assign.get(*i as usize).copied().unwrap_or(0)),
            Node::Bin(op, a, b) => {
                let (x, y) = (a.eval(assign), b.eval(assign));
                let w = a.width();
                let m = mask(w);
                let r = match op {
                    Op::Add => x.wrapping_add(y),
                    Op::Sub => x.wrapping_sub(y),
                    Op::Mul => x.wrapping_mul(y),
                    Op::And => x & y,
                    Op::Or => x | y,
                    Op::Xor => x ^ y,
                    Op::Shl => x.wrapping_shl((y & 63) as u32),
                    Op::Lshr => (x & m) >> (y & 63),
                    Op::Ashr => (sign_ext(x, w) >> (y & 63)) as u64,
                };
                r & m
            }
            Node::Not(a) => !a.eval(assign) & mask(a.width()),
            Node::Neg(a) => a.eval(assign).wrapping_neg() & mask(a.width()),
            Node::ZeroExt(a, b) => a.eval(assign) & mask(*b),
            Node::SignExt(a, b) => sign_ext(a.eval(assign), a.width()) as u64 & mask(*b),
            Node::Extract(a, hi, lo) => (a.eval(assign) >> lo) & mask(hi - lo + 1),
            Node::Rel(r, a, b) => {
                let (x, y) = (a.eval(assign), b.eval(assign));
                let w = a.width();
                let res = match r {
                    Rel::Eq => (x & mask(w)) == (y & mask(w)),
                    Rel::Ult => (x & mask(w)) < (y & mask(w)),
                    Rel::Ule => (x & mask(w)) <= (y & mask(w)),
                    Rel::Slt => sign_ext(x, w) < sign_ext(y, w),
                    Rel::Sle => sign_ext(x, w) <= sign_ext(y, w),
                };
                u64::from(res)
            }
            Node::BoolNot(a) => u64::from(a.eval(assign) == 0),
            Node::BoolAnd(a, b) => u64::from(a.eval(assign) != 0 && b.eval(assign) != 0),
            Node::BoolOr(a, b) => u64::from(a.eval(assign) != 0 || b.eval(assign) != 0),
            Node::Ite(c, a, b) => {
                if c.eval(assign) != 0 {
                    a.eval(assign)
                } else {
                    b.eval(assign)
                }
            }
        }
    }

    /// Collects the input-variable indices this expression references. Iterative (explicit stack)
    /// so a deeply nested expression — e.g. a widened `memcmp` building a long `BoolAnd` chain in a
    /// single step — can't overflow the stack.
    pub fn vars(&self, out: &mut BTreeSet<u32>) {
        let mut stack: Vec<&Node> = vec![self];
        while let Some(n) = stack.pop() {
            if let Node::Var(i) = n {
                out.insert(*i);
            } else {
                stack.extend(kids(n).into_iter().flatten());
            }
        }
    }

    /// Whether this expression contains no input variables (a concrete value). Iterative, with an
    /// early exit on the first variable.
    pub fn is_concrete(&self) -> bool {
        let mut stack: Vec<&Node> = vec![self];
        while let Some(n) = stack.pop() {
            if matches!(n, Node::Var(_)) {
                return false;
            }
            stack.extend(kids(n).into_iter().flatten());
        }
        true
    }
}

/// The child expressions of a node (up to three), for iterative tree walks. `None` slots are
/// skipped by `.into_iter().flatten()`.
pub(crate) fn kids(n: &Node) -> [Option<&Node>; 3] {
    match n {
        Node::Const(..) | Node::Var(_) => [None, None, None],
        Node::Not(a)
        | Node::Neg(a)
        | Node::ZeroExt(a, _)
        | Node::SignExt(a, _)
        | Node::Extract(a, ..)
        | Node::BoolNot(a) => [Some(&**a), None, None],
        Node::Bin(_, a, b) | Node::Rel(_, a, b) | Node::BoolAnd(a, b) | Node::BoolOr(a, b) => {
            [Some(&**a), Some(&**b), None]
        }
        Node::Ite(c, a, b) => [Some(&**c), Some(&**a), Some(&**b)],
    }
}

/// Whether the longest root-to-leaf path in `e` exceeds `cap`. Iterative post-order with
/// memoization over shared sub-terms and an early exit once the cap is passed, so it is bounded and
/// can't itself overflow. The symbolic executor uses this to abandon a function whose check builds
/// an unboundedly deep expression (a multi-round hash) rather than crash or spin on it.
pub fn too_deep(e: &Expr, cap: usize) -> bool {
    use std::collections::HashMap;
    let addr = |n: &Node| std::ptr::from_ref(n) as usize;
    let mut depth: HashMap<usize, usize> = HashMap::new();
    let mut stack: Vec<(&Node, bool)> = vec![(&**e, false)];
    while let Some((n, expanded)) = stack.pop() {
        let k = addr(n);
        if depth.contains_key(&k) {
            continue;
        }
        if expanded {
            let d = 1 + kids(n)
                .into_iter()
                .flatten()
                .map(|c| depth.get(&addr(c)).copied().unwrap_or(0))
                .max()
                .unwrap_or(0);
            if d > cap {
                return true;
            }
            depth.insert(k, d);
        } else {
            stack.push((n, true));
            stack.extend(kids(n).into_iter().flatten().map(|c| (c, false)));
        }
    }
    false
}

/// Depth beyond which the (recursive) display/export helpers bail to a placeholder rather than
/// risk a deep recursion. The executor keeps live expressions far shallower than this; it is a
/// backstop for anything that slips through to rendering.
const DISPLAY_DEPTH_GUARD: usize = 4096;

fn sign_ext(v: u64, bits: u32) -> i64 {
    if bits >= 64 {
        return v as i64;
    }
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

// --- readable rendering ---------------------------------------------------

/// Structural equality (two expressions compute the same tree). Cheap for the small per-byte
/// constraints the VM lift produces; used to recognise shared sub-terms (e.g. a rotate's operand).
fn same(a: &Expr, b: &Expr) -> bool {
    if Rc::ptr_eq(a, b) {
        return true;
    }
    match (&**a, &**b) {
        (Node::Const(v1, w1), Node::Const(v2, w2)) => v1 == v2 && w1 == w2,
        (Node::Var(i), Node::Var(j)) => i == j,
        (Node::Bin(o1, a1, b1), Node::Bin(o2, a2, b2)) => o1 == o2 && same(a1, a2) && same(b1, b2),
        (Node::Not(x), Node::Not(y)) | (Node::Neg(x), Node::Neg(y)) => same(x, y),
        (Node::ZeroExt(x, w1), Node::ZeroExt(y, w2))
        | (Node::SignExt(x, w1), Node::SignExt(y, w2)) => w1 == w2 && same(x, y),
        (Node::Extract(x, h1, l1), Node::Extract(y, h2, l2)) => h1 == h2 && l1 == l2 && same(x, y),
        (Node::Rel(r1, a1, b1), Node::Rel(r2, a2, b2)) => r1 == r2 && same(a1, a2) && same(b1, b2),
        (Node::BoolNot(x), Node::BoolNot(y)) => same(x, y),
        (Node::BoolAnd(a1, b1), Node::BoolAnd(a2, b2))
        | (Node::BoolOr(a1, b1), Node::BoolOr(a2, b2)) => same(a1, a2) && same(b1, b2),
        (Node::Ite(c1, a1, b1), Node::Ite(c2, a2, b2)) => {
            same(c1, c2) && same(a1, a2) && same(b1, b2)
        }
        _ => false,
    }
}

/// Simplifies an expression for display — strips the width-juggling (`zero_extend`/`extract`
/// no-ops from `movzx`/sub-register moves) and identity arithmetic that the symbolic executor
/// leaves behind, so the underlying per-byte check (`rol(in[0] ^ 0x3b, 1)`) is visible. Every
/// rewrite is value-preserving; `simplify_preserves_value` differential-tests that against `eval`.
pub fn simplify(e: &Expr) -> Expr {
    // Backstop: never recurse into a pathologically deep tree (the executor keeps live expressions
    // far shallower, but a slipped-through monster would overflow the recursive rewrites below).
    if too_deep(e, DISPLAY_DEPTH_GUARD) {
        return e.clone();
    }
    if e.is_concrete() {
        return konst(e.eval(&[]), e.width());
    }
    match &**e {
        Node::Const(..) | Node::Var(_) => e.clone(),
        Node::Bin(op, a, b) => {
            let (a, b) = (simplify(a), simplify(b));
            match (op, &*a, &*b) {
                (Op::Or | Op::Add | Op::Sub | Op::Xor, _, Node::Const(0, _)) => return a,
                (Op::Or | Op::Add | Op::Xor, Node::Const(0, _), _) => return b,
                (Op::And, _, Node::Const(m, w)) if *m == mask(*w) => return a,
                (Op::And, Node::Const(m, w), _) if *m == mask(*w) => return b,
                _ => {}
            }
            // `e & m` where `e` is a zero-extend: its bits above the original width are 0, so the
            // mask either clears everything it touches there or leaves `e` unchanged.
            if *op == Op::And
                && let Node::ZeroExt(inner, _) = &*a
                && let Node::Const(m, w) = &*b
            {
                let low = m & mask(inner.width());
                if low == 0 {
                    return konst(0, *w);
                }
                if low == mask(inner.width()) {
                    return a; // keeps all live bits; the high bits are 0 regardless of `m`
                }
            }
            // A 16-bit value split into bytes and rejoined: `(x[7:0]) | (x[15:8] << 8)` == x.
            if *op == Op::Or
                && let Some(x) = byte_join(&a, &b).or_else(|| byte_join(&b, &a))
            {
                return x;
            }
            bin(*op, a, b)
        }
        Node::ZeroExt(a, b) => {
            let a = simplify(a);
            if a.width() == *b {
                return a;
            }
            // zero-extend of a zero-extend is a single zero-extend of the innermost value.
            if let Node::ZeroExt(inner, _) = &*a {
                return zext(inner.clone(), *b);
            }
            zext(a, *b)
        }
        Node::SignExt(a, b) => {
            let a = simplify(a);
            if a.width() == *b { a } else { sext(a, *b) }
        }
        Node::Extract(a, hi, lo) => {
            let a = simplify(a);
            if *lo == 0 && *hi + 1 == a.width() {
                return a; // full-width extract is a no-op
            }
            match &*a {
                // Extracting bits that live entirely within a zero/sign extension's original value.
                Node::ZeroExt(inner, _) | Node::SignExt(inner, _) if *hi < inner.width() => {
                    simplify(&extract(inner.clone(), *hi, *lo))
                }
                // Extracting only the zero-padding of a zero-extend is just 0.
                Node::ZeroExt(inner, _) if *lo >= inner.width() => konst(0, hi - lo + 1),
                // Composing nested extracts.
                Node::Extract(inner, _, lo2) => {
                    simplify(&extract(inner.clone(), hi + lo2, lo + lo2))
                }
                // Extracting the low bits through an OR where one side is zero in that range
                // (a value held in a wider register: `(hi_bits_kept) | value`).
                Node::Bin(Op::Or, x, y) if *lo == 0 => {
                    let zero_low = |e: &Expr| {
                        matches!(&**e, Node::Bin(Op::And, _, c)
                            if matches!(&**c, Node::Const(m, _) if m & mask(*hi + 1) == 0))
                    };
                    if zero_low(x) {
                        simplify(&extract(y.clone(), *hi, 0))
                    } else if zero_low(y) {
                        simplify(&extract(x.clone(), *hi, 0))
                    } else {
                        extract(a.clone(), *hi, *lo)
                    }
                }
                _ => extract(a, *hi, *lo),
            }
        }
        Node::Not(a) => not(simplify(a)),
        Node::Neg(a) => neg(simplify(a)),
        Node::Rel(r, a, b) => rel(*r, simplify(a), simplify(b)),
        Node::BoolNot(a) => bnot(simplify(a)),
        Node::BoolAnd(a, b) => band(simplify(a), simplify(b)),
        Node::BoolOr(a, b) => bor(simplify(a), simplify(b)),
        Node::Ite(c, a, b) => ite(simplify(c), simplify(a), simplify(b)),
    }
}

/// Recognises a value split into a low and high byte-slice and rejoined — `zext(x[lo..=k-1]) |
/// (zext(x[k..=hi]) << k)` covering all of `x` — and returns `x`. `lo`/`hi` are the low and high
/// pieces (this arm order); the low piece must start at bit 0 and the high piece reach the top.
fn byte_join(lo: &Expr, hi: &Expr) -> Option<Expr> {
    let (Node::ZeroExt(le, lw), Node::Bin(Op::Shl, hz, hk)) = (&**lo, &**hi) else {
        return None;
    };
    let (Node::Extract(lx, lh, ll), Node::Const(k, _)) = (&**le, &**hk) else {
        return None;
    };
    let (Node::ZeroExt(he, _), true) = (&**hz, *ll == 0) else {
        return None;
    };
    let Node::Extract(hx, hh, hlo) = &**he else {
        return None;
    };
    (same(lx, hx)
        && *hlo == *lh + 1 // the high slice begins just past the low slice
        && *k == u64::from(*lh) + 1 // shifted exactly into place
        && *lw == *hh + 1) // rejoined at the width of the bits it covers
        .then(|| simplify(&extract(lx.clone(), *hh, 0)))
}

/// Recognises a rotate built as `(x << k) | (x >> (w-k))` (either arm order) and returns
/// `(x, amount, is_left)` — the shape [`crate::SymExec`] emits for `rol`/`ror`.
fn as_rotate(e: &Node) -> Option<(Expr, u32, bool)> {
    let Node::Bin(Op::Or, p, q) = e else {
        return None;
    };
    let pair = |hi: &Expr, lo: &Expr| -> Option<(Expr, u32, u32)> {
        if let (Node::Bin(Op::Shl, x1, k1), Node::Bin(Op::Lshr, x2, k2)) = (&**hi, &**lo)
            && same(x1, x2)
            && let (Node::Const(k, _), Node::Const(wk, _)) = (&**k1, &**k2)
        {
            return Some((x1.clone(), *k as u32, *wk as u32));
        }
        None
    };
    for (a, b, left) in [(p, q, true), (q, p, false)] {
        if let Some((x, k, wk)) = pair(a, b)
            && k + wk == x.width()
        {
            return Some((x, k, left));
        }
    }
    None
}

/// Renders an expression as a readable, Rust-flavoured string (input bytes as `in[i]`), with the
/// rotate idiom printed as `rol`/`ror`. Intended for a *simplified* expression.
pub fn render(e: &Expr) -> String {
    if too_deep(e, DISPLAY_DEPTH_GUARD) {
        return "<expression too deep to render>".to_string();
    }
    if let Some((x, amt, left)) = as_rotate(e) {
        return format!(
            "{}({}, {amt})",
            if left { "rol" } else { "ror" },
            render(&x)
        );
    }
    match &**e {
        Node::Const(v, _) => {
            if *v < 10 {
                v.to_string()
            } else {
                format!("{v:#x}")
            }
        }
        Node::Var(i) => format!("in[{i}]"),
        Node::Bin(op, a, b) => {
            let s = match op {
                Op::Add => "+",
                Op::Sub => "-",
                Op::Mul => "*",
                Op::And => "&",
                Op::Or => "|",
                Op::Xor => "^",
                Op::Shl => "<<",
                Op::Lshr | Op::Ashr => ">>",
            };
            format!("({} {s} {})", render(a), render(b))
        }
        Node::Not(a) => format!("~{}", render(a)),
        Node::Neg(a) => format!("-{}", render(a)),
        Node::ZeroExt(a, b) => format!("zext{b}({})", render(a)),
        Node::SignExt(a, b) => format!("sext{b}({})", render(a)),
        Node::Extract(a, hi, lo) => format!("{}[{hi}:{lo}]", render(a)),
        Node::Rel(r, a, b) => {
            let s = match r {
                Rel::Eq => "==",
                Rel::Ult | Rel::Slt => "<",
                Rel::Ule | Rel::Sle => "<=",
            };
            format!("{} {s} {}", render(a), render(b))
        }
        Node::BoolNot(a) => format!("!({})", render(a)),
        Node::BoolAnd(a, b) => format!("{} && {}", render(a), render(b)),
        Node::BoolOr(a, b) => format!("{} || {}", render(a), render(b)),
        Node::Ite(c, a, b) => format!(
            "if {} {{ {} }} else {{ {} }}",
            render(c),
            render(a),
            render(b)
        ),
    }
}

// --- SMT-LIB2 export ------------------------------------------------------

/// Emits an SMT-LIB2 script asserting every constraint, for solving with an external z3.
/// `n` is the number of input-byte variables.
pub fn to_smt2(constraints: &[Expr], n: u32) -> String {
    let mut s = String::from("(set-logic QF_BV)\n");
    for i in 0..n {
        s.push_str(&format!("(declare-const b{i} (_ BitVec 8))\n"));
    }
    for c in constraints {
        if too_deep(c, DISPLAY_DEPTH_GUARD) {
            s.push_str("(assert true) ; omitted: expression too deep\n");
            continue;
        }
        s.push_str(&format!("(assert {})\n", smt(c)));
    }
    s.push_str("(check-sat)\n(get-model)\n");
    s
}

fn smt(e: &Node) -> String {
    let bv = |v: u64, b: u32| format!("(_ bv{} {b})", v & mask(b));
    match e {
        Node::Const(v, b) => bv(*v, *b),
        Node::Var(i) => format!("b{i}"),
        Node::Bin(op, a, b) => {
            let o = match op {
                Op::Add => "bvadd",
                Op::Sub => "bvsub",
                Op::Mul => "bvmul",
                Op::And => "bvand",
                Op::Or => "bvor",
                Op::Xor => "bvxor",
                Op::Shl => "bvshl",
                Op::Lshr => "bvlshr",
                Op::Ashr => "bvashr",
            };
            format!("({o} {} {})", smt(a), smt(b))
        }
        Node::Not(a) => format!("(bvnot {})", smt(a)),
        Node::Neg(a) => format!("(bvneg {})", smt(a)),
        Node::ZeroExt(a, b) => format!("((_ zero_extend {}) {})", b - a.width(), smt(a)),
        Node::SignExt(a, b) => format!("((_ sign_extend {}) {})", b - a.width(), smt(a)),
        Node::Extract(a, hi, lo) => format!("((_ extract {hi} {lo}) {})", smt(a)),
        Node::Rel(r, a, b) => {
            let o = match r {
                Rel::Eq => "=",
                Rel::Ult => "bvult",
                Rel::Ule => "bvule",
                Rel::Slt => "bvslt",
                Rel::Sle => "bvsle",
            };
            format!("({o} {} {})", smt(a), smt(b))
        }
        Node::BoolNot(a) => format!("(not {})", smt(a)),
        Node::BoolAnd(a, b) => format!("(and {} {})", smt(a), smt(b)),
        Node::BoolOr(a, b) => format!("(or {} {})", smt(a), smt(b)),
        Node::Ite(c, a, b) => format!("(ite {} {} {})", smt(c), smt(a), smt(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A long accumulator chain — `((… (v0 + v1) + v2) …)`, depth ≈ `n` — is exactly what an
    /// input-dependent loop builds. The recursive tree-walks used to overflow the stack on this;
    /// the iterative `width`/`vars`/`is_concrete`/`too_deep` must handle it without recursing.
    #[test]
    fn deep_expression_does_not_overflow() {
        // Build/walk the deep chain on a large-stack thread: the iterative walks below never
        // recurse, but `Rc<Node>`'s own Drop does, so tearing a 200k-deep chain down at end of
        // scope needs headroom. (In the executor, depth caps keep live expressions shallow, so its
        // drops are safe on an ordinary stack — this is only to let the test build an extreme case.)
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(|| {
                let n = 200_000u32;
                let mut acc = var(0);
                for i in 1..n {
                    acc = bin(Op::Add, acc, var(i % 8));
                }
                assert_eq!(acc.width(), 8);
                assert!(!acc.is_concrete());
                let mut vs = BTreeSet::new();
                acc.vars(&mut vs);
                assert_eq!(vs.len(), 8);
                assert!(too_deep(&acc, 512));
                assert!(!too_deep(&var(0), 512));
            })
            .expect("spawn deep-test thread")
            .join()
            .expect("deep-expression walks must not overflow");

        // A shallow expression is not flagged; a modest concrete chain still evaluates correctly.
        let mut small = konst(0, 8);
        for _ in 0..200 {
            small = bin(Op::Add, small, konst(1, 8));
        }
        assert_eq!(small.eval(&[]), 200 & 0xff);
        assert!(!too_deep(&small, 512));
    }

    /// `too_deep` must not blow up on a shared DAG (a node reachable by many paths is counted once).
    #[test]
    fn too_deep_handles_sharing() {
        let mut e = var(0);
        for _ in 0..40 {
            e = bin(Op::Xor, e.clone(), e.clone()); // doubling fan-in, but shared via Rc
        }
        // Depth is only 40 despite 2^40 root-to-leaf paths; memoization keeps it linear.
        assert!(!too_deep(&e, 512));
    }
}
