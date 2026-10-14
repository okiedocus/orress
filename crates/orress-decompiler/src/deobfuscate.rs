//! Opaque-predicate deobfuscation via a known-bits abstraction. Obfuscators guard real code with
//! predicates that always evaluate the same way but are not literal constants — e.g. `(x & 1) == 2`
//! (always false) or `(x | 1) != 0` (always true). A bitwise known-bits analysis proves many of
//! these, folding the comparison to a constant so the existing constant-branch and dead-code passes
//! remove the bogus edge and its unreachable arm.
//!
//! The analysis is *sound* (never claims a bit is known unless it provably is), so a fold only ever
//! happens when the predicate is genuinely constant — it cannot change a program's meaning.
//! `known_bits_are_sound` differential-tests it against concrete evaluation.

use crate::ir::{BinOp, Block, CmpOp, Expr, Stmt, Term, Var, Width};

/// A bit set in `zeros` is provably 0; a bit set in `ones` is provably 1; a bit in neither is
/// unknown. Both are confined to the value's width, and `zeros & ones == 0`.
pub fn known_bits(e: &Expr) -> (u64, u64) {
    let m = e.width().mask();
    match e {
        Expr::Const(v, _) => (!v & m, v & m),
        Expr::Not(a, _) => {
            let (z, o) = known_bits(a);
            (o & m, z & m)
        }
        Expr::Bin(op, a, b, _) => bin_bits(*op, a, b, m),
        Expr::Cast(a, w, signed) => cast_bits(a, *w, *signed),
        // Booleans are 0 or 1, so bits above bit 0 are always known-zero.
        Expr::Cmp(..) | Expr::LNot(_) | Expr::LAnd(..) | Expr::LOr(..) | Expr::FCmp(..) => {
            match opaque_value(e) {
                Some(true) => (m & !1, 1),
                Some(false) => (m, 0),
                None => (m & !1, 0),
            }
        }
        // Everything else (loads, calls, multiplies, …) is treated as fully unknown — sound.
        _ => (0, 0),
    }
}

fn bin_bits(op: BinOp, a: &Expr, b: &Expr, m: u64) -> (u64, u64) {
    let (za, oa) = known_bits(a);
    let (zb, ob) = known_bits(b);
    match op {
        BinOp::And => ((za | zb) & m, (oa & ob) & m),
        BinOp::Or => ((za & zb) & m, (oa | ob) & m),
        BinOp::Xor => (((oa & ob) | (za & zb)) & m, ((oa & zb) | (za & ob)) & m),
        BinOp::Shl | BinOp::Shr => {
            let Expr::Const(k, _) = b else { return (0, 0) };
            let k = *k;
            if k >= 64 {
                return (m, 0); // everything shifted out → all zero
            }
            if op == BinOp::Shl {
                let vacated = (1u64 << k) - 1; // low k bits become 0
                (((za << k) | vacated) & m, (oa << k) & m)
            } else {
                let vacated = m & !(m >> k); // high k bits become 0
                (((za >> k) | vacated) & m, (oa >> k) & m)
            }
        }
        // Add/Sub/Mul/Div/Rem/Sar propagate carries or signs across bits — stay sound by claiming
        // nothing.
        _ => (0, 0),
    }
}

fn cast_bits(a: &Expr, w: Width, signed: bool) -> (u64, u64) {
    let (za, oa) = known_bits(a);
    let am = a.width().mask();
    let m = w.mask();
    if w.bits() <= a.width().bits() {
        return (za & m, oa & m); // truncation (or same width)
    }
    let high = m & !am; // the newly added high bits
    if !signed {
        return ((za & am) | high, oa & am); // zero-extend: new bits are 0
    }
    // Sign-extend: the new bits copy the source's top bit, if it is known.
    let sign = 1u64 << (a.width().bits() - 1);
    if oa & sign != 0 {
        (za & am, (oa & am) | high)
    } else if za & sign != 0 {
        ((za & am) | high, oa & am)
    } else {
        (za & am, oa & am)
    }
}

/// If a boolean expression is provably constant, the value it always takes.
pub fn opaque_value(e: &Expr) -> Option<bool> {
    match e {
        Expr::Const(v, _) => Some(*v != 0),
        Expr::Cmp(op, a, b, signed) => cmp_value(*op, a, b, *signed),
        Expr::LNot(a) => opaque_value(a).map(|v| !v),
        Expr::LAnd(a, b) => match (opaque_value(a), opaque_value(b)) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        },
        Expr::LOr(a, b) => match (opaque_value(a), opaque_value(b)) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn cmp_value(op: CmpOp, a: &Expr, b: &Expr, signed: bool) -> Option<bool> {
    let (za, oa) = known_bits(a);
    let (zb, ob) = known_bits(b);
    let ma = a.width().mask();
    let mb = b.width().mask();
    let a_known = (za | oa) == ma;
    let b_known = (zb | ob) == mb;
    match op {
        CmpOp::Eq | CmpOp::Ne => {
            // A bit where one side is known 1 and the other known 0 makes equality impossible.
            let disagree = (oa & zb) | (za & ob);
            let eq = if disagree != 0 {
                Some(false)
            } else if a_known && b_known {
                Some(oa == ob)
            } else {
                None
            };
            eq.map(|v| if op == CmpOp::Eq { v } else { !v })
        }
        // Ordering only when both sides are fully known (otherwise the result genuinely varies).
        _ if a_known && b_known => {
            let (x, y) = if signed {
                (sign_ext(oa, a.width()), sign_ext(ob, b.width()))
            } else {
                (oa as i64, ob as i64)
            };
            // For unsigned, compare as u64 (both masked, non-negative); for signed, as i64.
            Some(if signed {
                match op {
                    CmpOp::Lt => x < y,
                    CmpOp::Le => x <= y,
                    CmpOp::Gt => x > y,
                    CmpOp::Ge => x >= y,
                    _ => unreachable!(),
                }
            } else {
                match op {
                    CmpOp::Lt => oa < ob,
                    CmpOp::Le => oa <= ob,
                    CmpOp::Gt => oa > ob,
                    CmpOp::Ge => oa >= ob,
                    _ => unreachable!(),
                }
            })
        }
        _ => None,
    }
}

fn sign_ext(v: u64, w: Width) -> i64 {
    let bits = w.bits();
    if bits >= 64 {
        return v as i64;
    }
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

/// Folds a provably-constant boolean expression to `true`/`false`; leaves everything else as is.
/// Called from the main `fold` pass, so it runs on every expression bottom-up.
pub fn fold_bool(e: Expr) -> Expr {
    match &e {
        Expr::Cmp(..) | Expr::LNot(_) | Expr::LAnd(..) | Expr::LOr(..) => match opaque_value(&e) {
            Some(b) => Expr::konst(u64::from(b), Width::B8),
            None => e,
        },
        _ => e,
    }
}

// --- control-flow-flattening unflattening ---------------------------------

/// Undoes control-flow flattening (OLLVM-style): a central dispatcher — a dense `switch(state)` or
/// a chain of `if (state == cᵢ) goto Bᵢ` compares — that every real block jumps back to after
/// setting `state` to a constant for the next block. We relink each such block directly to its real
/// successor, so the dispatcher's bogus hub edges disappear and the later dead-code/merge passes
/// drop the dispatcher.
///
/// Sound and conservative: a predecessor is relinked only when its last write to the dispatcher's
/// state variable is a constant (one successor) or a `select` of two constants (a recovered
/// conditional) — the recovered edge is then exactly what the flattened code does. Anything that
/// cannot be resolved that precisely is left flattened (still a correct CFG, just not simplified).
/// Returns whether it changed the CFG.
pub fn unflatten(blocks: &mut [Block]) -> bool {
    let Some(d) = find_dispatcher(blocks) else {
        return false;
    };
    let target = |v: u64| d.map.get(&v).copied();
    let mut changed = false;
    for b in blocks.iter_mut() {
        // Redirect any edge that lands on the dispatcher, from a block that set the state to a
        // value the dispatcher resolves — the edge then goes straight to the real successor.
        if b.addr == d.entry || !crate::simplify::successors(&b.term).contains(&d.entry) {
            continue;
        }
        match last_state_value(b, d.state) {
            Some(StateVal::Const(c)) => {
                if let Some(t) = target(c) {
                    redirect_edge(&mut b.term, d.entry, t);
                    changed = true;
                }
            }
            // A select-of-constants only decodes to a branch when the whole edge is a plain jump
            // to the dispatcher (otherwise we would be grafting a branch onto a branch).
            Some(StateVal::Select(cond, c1, c2)) if b.term == Term::Jump(d.entry) => {
                if let (Some(t1), Some(t2)) = (target(c1), target(c2)) {
                    b.term = Term::Branch(cond, t1, t2);
                    changed = true;
                }
            }
            _ => {} // unresolved: leave this edge routed through the dispatcher
        }
    }
    changed
}

/// Redirects the edge(s) in `term` that target `from` to `to`, preserving the terminator's shape
/// (a branch keeps its other edge; a branch both of whose edges pointed at `from` collapses to a
/// jump).
fn redirect_edge(term: &mut Term, from: u64, to: u64) {
    let swap = |t: u64| if t == from { to } else { t };
    *term = match std::mem::replace(term, Term::Stop) {
        Term::Jump(t) => Term::Jump(swap(t)),
        Term::Branch(c, a, b) => {
            let (a, b) = (swap(a), swap(b));
            if a == b {
                Term::Jump(a)
            } else {
                Term::Branch(c, a, b)
            }
        }
        Term::Switch(e, cases) => Term::Switch(e, cases.into_iter().map(swap).collect()),
        other => other,
    };
}

/// A recovered dispatcher: the address real blocks jump back to, the state variable it reads, and
/// the state-value → real-block map.
struct Dispatcher {
    entry: u64,
    state: Var,
    map: std::collections::HashMap<u64, u64>,
}

/// Finds a flattening dispatcher the real blocks route through — either a dense `switch(state)`
/// block or the head of an `if (state == cᵢ)` compare chain — requiring at least three blocks to
/// jump back to it (an ordinary switch/if has one predecessor, so it is never mistaken for a hub).
fn find_dispatcher(blocks: &[Block]) -> Option<Dispatcher> {
    // A hub: at least three blocks have a CFG edge landing on it (a flattened function's blocks all
    // route back; an ordinary switch/if has one predecessor). Edges include branch arms, not just
    // jumps, because a handler often reaches the dispatcher on one side of its own test.
    let hub = |addr: u64| {
        blocks
            .iter()
            .filter(|p| crate::simplify::successors(&p.term).contains(&addr))
            .count()
            >= 3
    };
    // Dense jump-table form: `switch(state)`. The dispatcher may compute the jump index from the
    // state (a scrutinee copy + a table load), as long as it has no side effects and the values it
    // defines are used only for its own dispatch — then bypassing it to the resolved case is exact.
    for b in blocks {
        if let Term::Switch(Expr::Var(sw, _), cases) = &b.term
            && hub(b.addr)
            && is_pure_hub(b)
            && switch_local(blocks, b)
            && let Some(state) = trace_state(b, *sw)
        {
            let map = cases
                .iter()
                .enumerate()
                .map(|(i, &t)| (i as u64, t))
                .collect();
            return Some(Dispatcher {
                entry: b.addr,
                state,
                map,
            });
        }
    }
    // Compare-chain form: a run of pure `if (state == cᵢ) goto Bᵢ else <next compare>` blocks.
    for b in blocks {
        if b.stmts.is_empty()
            && hub(b.addr)
            && let Some((state, map)) = walk_chain(blocks, b.addr)
            && map.len() >= 3
        {
            return Some(Dispatcher {
                entry: b.addr,
                state,
                map,
            });
        }
    }
    None
}

/// The dispatcher must compute only its dispatch: no stores, calls, or un-lifted instructions
/// (which could have observable effects we would skip by bypassing it).
fn is_pure_hub(b: &Block) -> bool {
    b.stmts.iter().all(|(_, s)| match s {
        Stmt::Assign(_, e) => !contains_call(e),
        Stmt::Store(..) | Stmt::Eval(_) | Stmt::Asm(..) => false,
    })
}

fn contains_call(e: &Expr) -> bool {
    let mut found = false;
    e.clone().map(&mut |x| {
        if matches!(x, Expr::Call(..)) {
            found = true;
        }
        x
    });
    found
}

/// Every variable the dispatcher defines is read only inside the dispatcher itself (its scrutinee
/// copies and jump-index temporaries), so relinking around it drops nothing a successor needs.
fn switch_local(blocks: &[Block], d: &Block) -> bool {
    let defs: std::collections::HashSet<Var> = d.stmts.iter().flat_map(|(_, s)| s.defs()).collect();
    if defs.is_empty() {
        return true;
    }
    !blocks.iter().filter(|o| o.addr != d.addr).any(|o| {
        o.stmts
            .iter()
            .any(|(_, s)| defs.iter().any(|&v| s.reads(v)))
            || crate::simplify::term_exprs(&o.term)
                .iter()
                .any(|e| defs.iter().any(|&v| e.reads(v)))
    })
}

/// Resolves the real state variable the dispatcher switches on, following scrutinee copies
/// (`sel = s3`, `s3 = state`) back to the variable that is live into the dispatcher. Returns `None`
/// if the switch variable is produced by anything other than a chain of copies inside the block.
fn trace_state(d: &Block, sw: Var) -> Option<Var> {
    let mut v = sw;
    // Each copy's source is read *at* that copy, so the next definition to follow is strictly
    // earlier in the block. Searching only before the current definition guarantees termination,
    // even through a copy cycle (`y = x; x = y`).
    let mut end = d.stmts.len();
    loop {
        match d.stmts[..end]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (_, s))| s.defs().contains(&v))
        {
            Some((i, (_, Stmt::Assign(_, Expr::Var(u, _))))) => {
                v = *u;
                end = i;
            }
            Some(_) => return None, // defined by a non-copy here — can't trace through soundly
            None => return Some(v), // not defined in the dispatcher → it is the live-in state
        }
    }
}

/// Walks a compare chain from `head`, collecting the state-value → target map while every block is
/// a pure `if (state == const)` test on the same variable. Stops at the first block that is not.
fn walk_chain(blocks: &[Block], head: u64) -> Option<(Var, std::collections::HashMap<u64, u64>)> {
    let mut map = std::collections::HashMap::new();
    let mut state: Option<Var> = None;
    let mut seen = std::collections::HashSet::new();
    let mut cur = head;
    while seen.insert(cur) {
        let Some(b) = blocks.iter().find(|x| x.addr == cur) else {
            break;
        };
        let (Term::Branch(cond, eq, next), true) = (&b.term, b.stmts.is_empty()) else {
            break;
        };
        let Some((sv, c)) = eq_state_const(cond) else {
            break;
        };
        match state {
            None => state = Some(sv),
            Some(s) if s != sv => break,
            _ => {}
        }
        map.entry(c).or_insert(*eq);
        cur = *next;
    }
    state.map(|s| (s, map))
}

/// Matches `state == const` (either operand order), returning the variable and constant.
fn eq_state_const(cond: &Expr) -> Option<(Var, u64)> {
    let Expr::Cmp(CmpOp::Eq, a, b, _) = cond else {
        return None;
    };
    match (&**a, &**b) {
        (Expr::Var(v, _), Expr::Const(c, _)) | (Expr::Const(c, _), Expr::Var(v, _)) => {
            Some((*v, *c))
        }
        _ => None,
    }
}

/// The value a block leaves in `state` on its way out: the last assignment to it, when that is a
/// constant or a `select` of two constants.
enum StateVal {
    Const(u64),
    Select(Expr, u64, u64),
}

fn last_state_value(block: &Block, state: Var) -> Option<StateVal> {
    let (_, last) = block
        .stmts
        .iter()
        .rev()
        .find(|(_, s)| s.defs().contains(&state))?;
    let Stmt::Assign(_, e) = last else {
        return None;
    };
    match e {
        Expr::Const(c, _) => Some(StateVal::Const(*c)),
        Expr::Select(cond, a, b, _) => match (&**a, &**b) {
            (Expr::Const(c1, _), Expr::Const(c2, _)) => {
                Some(StateVal::Select((**cond).clone(), *c1, *c2))
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny concrete evaluator over the integer/boolean subset known_bits reasons about, with
    /// `Var(0)` bound to `x`. Used only to differential-test the abstraction.
    fn eval(e: &Expr, x: u64) -> u64 {
        let m = e.width().mask();
        match e {
            Expr::Const(v, _) => v & m,
            Expr::Var(..) => x & m,
            Expr::Not(a, _) => !eval(a, x) & m,
            Expr::Bin(op, a, b, _) => {
                let (l, r) = (eval(a, x), eval(b, x));
                let v = match op {
                    BinOp::Add => l.wrapping_add(r),
                    BinOp::Sub => l.wrapping_sub(r),
                    BinOp::Mul => l.wrapping_mul(r),
                    BinOp::And => l & r,
                    BinOp::Or => l | r,
                    BinOp::Xor => l ^ r,
                    BinOp::Shl => l.wrapping_shl(r as u32),
                    BinOp::Shr => l.wrapping_shr(r as u32),
                    _ => 0,
                };
                v & m
            }
            Expr::Cast(a, w, signed) => {
                let v = eval(a, x);
                if *signed && w.bits() > a.width().bits() {
                    (sign_ext(v, a.width()) as u64) & m
                } else {
                    v & m
                }
            }
            Expr::Cmp(op, a, b, _) => {
                let (l, r) = (eval(a, x), eval(b, x));
                u64::from(match op {
                    CmpOp::Eq => l == r,
                    CmpOp::Ne => l != r,
                    CmpOp::Lt => l < r,
                    CmpOp::Le => l <= r,
                    CmpOp::Gt => l > r,
                    CmpOp::Ge => l >= r,
                })
            }
            _ => 0,
        }
    }

    fn c(v: u64) -> Expr {
        Expr::konst(v, Width::B32)
    }
    fn x() -> Expr {
        Expr::Var(crate::ir::Var::Reg(0), Width::B32)
    }
    fn bin(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::bin(op, a, b, Width::B32)
    }

    #[test]
    fn known_bits_are_sound() {
        // For every concrete x, the bits known_bits claims must actually hold. Exhaustive over a
        // byte of entropy in the low bits plus some spread-out values.
        let exprs = vec![
            bin(BinOp::And, x(), c(1)),
            bin(BinOp::Or, x(), c(0xff)),
            bin(BinOp::Xor, bin(BinOp::And, x(), c(0xf0)), c(0x0f)),
            bin(BinOp::Shl, bin(BinOp::And, x(), c(0xff)), c(8)),
            bin(BinOp::Shr, x(), c(28)),
            Expr::Cast(
                Box::new(Expr::Var(crate::ir::Var::Reg(0), Width::B8)),
                Width::B32,
                false,
            ),
            bin(BinOp::And, bin(BinOp::Shl, x(), c(4)), c(0xf)),
        ];
        for e in &exprs {
            let (z, o) = known_bits(e);
            assert_eq!(z & o, 0, "zeros and ones overlap for {e:?}");
            for x in (0u64..=0x3ff).chain([0x5555_5555, 0xffff_ffff, 0xdead_beef]) {
                let v = eval(e, x);
                assert_eq!(v & z, 0, "claimed-zero bit was 1: {e:?} at x={x:#x}");
                assert_eq!(v & o, o, "claimed-one bit was 0: {e:?} at x={x:#x}");
            }
        }
    }

    fn cmp(op: CmpOp, a: Expr, b: Expr) -> Expr {
        Expr::Cmp(op, Box::new(a), Box::new(b), false)
    }

    #[test]
    fn folds_opaque_predicates() {
        // (x & 1) == 2 is always false; != always true.
        let lo = bin(BinOp::And, x(), c(1));
        assert_eq!(opaque_value(&cmp(CmpOp::Eq, lo.clone(), c(2))), Some(false));
        assert_eq!(opaque_value(&cmp(CmpOp::Ne, lo, c(2))), Some(true));
        // (x | 1) == 0 is always false (bit 0 is forced to 1).
        let hi = bin(BinOp::Or, x(), c(1));
        assert_eq!(opaque_value(&cmp(CmpOp::Eq, hi, c(0))), Some(false));
        // ((x << 4) & 0xf) == 0 is always true (the low nibble is shifted-in zeros).
        let masked = bin(BinOp::And, bin(BinOp::Shl, x(), c(4)), c(0xf));
        assert_eq!(opaque_value(&cmp(CmpOp::Eq, masked, c(0))), Some(true));
        // A genuine data-dependent predicate must NOT be folded.
        assert_eq!(opaque_value(&cmp(CmpOp::Eq, x(), c(7))), None);
    }

    #[test]
    fn fold_bool_rewrites_only_constants() {
        let lo = bin(BinOp::And, x(), c(1));
        assert_eq!(
            fold_bool(cmp(CmpOp::Eq, lo.clone(), c(2))),
            Expr::konst(0, Width::B8)
        );
        // Data-dependent: left untouched.
        let live = cmp(CmpOp::Eq, x(), c(7));
        assert_eq!(fold_bool(live.clone()), live);
    }

    fn blk(addr: u64, stmts: Vec<Stmt>, term: Term) -> Block {
        Block {
            addr,
            stmts: stmts.into_iter().map(|s| (addr, s)).collect(),
            term,
            term_addr: addr,
        }
    }
    const SV: Var = Var::Reg(1);
    fn set_state(v: u64) -> Stmt {
        Stmt::Assign(SV, Expr::konst(v, Width::B32))
    }

    #[test]
    fn unflatten_relinks_constant_state_transitions() {
        // entry -> D; D switches on state; B0/B1 set the next state and loop back; B2 returns.
        let mut blocks = vec![
            blk(0x10, vec![set_state(0)], Term::Jump(0x100)),
            blk(
                0x100,
                vec![],
                Term::Switch(Expr::Var(SV, Width::B32), vec![0x20, 0x30, 0x40]),
            ),
            blk(0x20, vec![set_state(1)], Term::Jump(0x100)),
            blk(0x30, vec![set_state(2)], Term::Jump(0x100)),
            blk(0x40, vec![], Term::Return(None)),
        ];
        assert!(unflatten(&mut blocks));
        // entry -> cases[0]=0x20; B0 -> cases[1]=0x30; B1 -> cases[2]=0x40. Dispatcher bypassed.
        assert_eq!(blocks[0].term, Term::Jump(0x20));
        assert_eq!(blocks[2].term, Term::Jump(0x30));
        assert_eq!(blocks[3].term, Term::Jump(0x40));
    }

    #[test]
    fn unflatten_recovers_a_conditional_as_a_branch() {
        // A block whose next state is `cond ? 1 : 2` is a flattened if/else.
        let cond = cmp(CmpOp::Lt, x(), c(5));
        let sel = Expr::Select(
            Box::new(cond.clone()),
            Box::new(Expr::konst(1, Width::B32)),
            Box::new(Expr::konst(2, Width::B32)),
            Width::B32,
        );
        let mut blocks = vec![
            blk(0x10, vec![set_state(0)], Term::Jump(0x100)),
            blk(
                0x100,
                vec![],
                Term::Switch(Expr::Var(SV, Width::B32), vec![0x20, 0x30, 0x40, 0x50]),
            ),
            blk(0x20, vec![Stmt::Assign(SV, sel)], Term::Jump(0x100)),
            blk(0x30, vec![set_state(3)], Term::Jump(0x100)), // a third hub edge
            blk(0x40, vec![], Term::Return(None)),
            blk(0x50, vec![], Term::Return(None)),
        ];
        assert!(unflatten(&mut blocks));
        // cases[1]=0x30, cases[2]=0x40 → the recovered conditional branches to those.
        assert_eq!(blocks[2].term, Term::Branch(cond, 0x30, 0x40));
    }

    #[test]
    fn unflatten_handles_a_compare_chain_dispatcher() {
        // A dispatcher lowered as `if (state==0) B0; else if (state==1) B1; else if (state==2) B2`.
        let chain = |addr: u64, sval: u64, eq: u64, next: u64| {
            let cond = cmp(CmpOp::Eq, Expr::Var(SV, Width::B32), c(sval));
            blk(addr, vec![], Term::Branch(cond, eq, next))
        };
        let mut blocks = vec![
            blk(0x10, vec![set_state(0)], Term::Jump(0x100)),
            chain(0x100, 0, 0x20, 0x101),
            chain(0x101, 1, 0x30, 0x102),
            chain(0x102, 2, 0x40, 0x103),
            blk(0x103, vec![], Term::Return(None)), // default
            blk(0x20, vec![set_state(1)], Term::Jump(0x100)),
            blk(0x30, vec![set_state(2)], Term::Jump(0x100)),
            blk(0x40, vec![], Term::Return(None)),
        ];
        assert!(unflatten(&mut blocks));
        assert_eq!(blocks[0].term, Term::Jump(0x20)); // entry: state 0 -> B0
        assert_eq!(blocks[5].term, Term::Jump(0x30)); // B0: state 1 -> B1
        assert_eq!(blocks[6].term, Term::Jump(0x40)); // B1: state 2 -> B2
    }

    #[test]
    fn unflatten_leaves_an_ordinary_switch_alone() {
        // A normal switch (one predecessor, not a hub) must not be touched.
        let mut blocks = vec![
            blk(0x10, vec![set_state(1)], Term::Jump(0x100)),
            blk(
                0x100,
                vec![],
                Term::Switch(Expr::Var(SV, Width::B32), vec![0x20, 0x30]),
            ),
            blk(0x20, vec![], Term::Return(None)),
            blk(0x30, vec![], Term::Return(None)),
        ];
        assert!(!unflatten(&mut blocks));
        assert_eq!(blocks[0].term, Term::Jump(0x100));
    }

    #[test]
    fn trace_state_terminates_on_a_copy_cycle() {
        use crate::ir::Var;
        let (x, y) = (Var::Reg(1), Var::Reg(2));
        let copy = |d: Var, s: Var| Stmt::Assign(d, Expr::Var(s, Width::B32));
        // y = x; x = y; switch on x — the cycle resolves to the live-in x.
        let d = blk(
            0x100,
            vec![copy(y, x), copy(x, y)],
            Term::Switch(Expr::Var(x, Width::B32), vec![0x20]),
        );
        assert_eq!(trace_state(&d, x), Some(x));
        // A self-copy (x = x) as well.
        let d = blk(
            0x100,
            vec![copy(x, x)],
            Term::Switch(Expr::Var(x, Width::B32), vec![0x20]),
        );
        assert_eq!(trace_state(&d, x), Some(x));
    }
}
