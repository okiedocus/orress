//! The built-in constraint solver. The path constraint from a byte-wise check decomposes into
//! groups of input bytes that interact; each small group is solved by bounded brute-force. This
//! handles the usual crackme transforms (xor/add/sub/mul/rotate/and-compare) completely and
//! fast. Tightly-coupled constraints over many bytes are left to external z3 via the SMT export.

use std::collections::BTreeSet;

use crate::expr::{Expr, Node, Rel};

/// The largest search space for one group of coupled bytes (256^3).
const MAX_SPACE: u64 = 1 << 24;

/// The outcome of a solve.
#[derive(Debug, Clone)]
pub struct SolveResult {
    /// The recovered input (filler `A` for bytes no constraint touched).
    pub input: Vec<u8>,
    /// True if every constraint was satisfied.
    pub complete: bool,
    pub message: String,
}

/// [`solve`], then — if it came up short — the external z3 fallback. z3's model is *verified*
/// against the real constraints before it is trusted, so an assertion z3 saw in simplified form
/// (or not at all, if it was too deep for the SMT export) can never turn into a false solve. A
/// no-op beyond the built-in result when z3 isn't installed.
pub fn solve_with_fallback(constraints: &[Expr], n: usize) -> SolveResult {
    let built_in = solve(constraints, n);
    if built_in.complete {
        return built_in;
    }
    if let Some(model) = crate::smt::solve_z3(constraints, n as u32)
        && model.len() == n
        && constraints.iter().all(|c| c.eval(&model) != 0)
    {
        return SolveResult {
            input: model,
            complete: true,
            message: "solved by z3".into(),
        };
    }
    built_in
}

/// Finds an `n`-byte input satisfying every constraint, by solving each connected group of
/// bytes with bounded brute-force.
pub fn solve(constraints: &[Expr], n: usize) -> SolveResult {
    let mut assign = vec![b'A'; n];

    // Any constant (variable-free) constraint must already hold.
    for c in constraints {
        if c.is_concrete() && c.eval(&assign) == 0 {
            return SolveResult {
                input: assign,
                complete: false,
                message: "a constant constraint is unsatisfiable (wrong path?)".into(),
            };
        }
    }

    // Union-find over byte indices by co-occurrence in a constraint.
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    let sets: Vec<BTreeSet<u32>> = constraints
        .iter()
        .map(|c| {
            let mut s = BTreeSet::new();
            c.vars(&mut s);
            s
        })
        .collect();
    for set in &sets {
        let mut it = set.iter();
        if let Some(&first) = it.next() {
            let r = find(&mut parent, first as usize);
            for &v in it {
                let rv = find(&mut parent, v as usize);
                parent[rv] = r;
            }
        }
    }

    // Group byte indices by component root.
    let mut groups: std::collections::HashMap<usize, Vec<usize>> = Default::default();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut complete = true;
    let mut notes = Vec::new();
    for idxs in groups.values() {
        // Constraints that live entirely within this group.
        let group_set: BTreeSet<u32> = idxs.iter().map(|&i| i as u32).collect();
        let group_constraints: Vec<&Expr> = constraints
            .iter()
            .zip(&sets)
            .filter(|(_, vs)| !vs.is_empty() && vs.is_subset(&group_set))
            .map(|(c, _)| c)
            .collect();
        if group_constraints.is_empty() {
            continue; // unconstrained bytes keep the filler
        }
        let k = idxs.len() as u32;
        let space = 256u64.checked_pow(k).unwrap_or(u64::MAX);
        let mut found = false;
        if space <= MAX_SPACE {
            // Small group: exhaustive brute force (if this finds nothing, nothing satisfies it).
            for combo in 0..space {
                for (j, &bi) in idxs.iter().enumerate() {
                    assign[bi] = (combo >> (8 * j)) as u8;
                }
                if group_constraints.iter().all(|c| c.eval(&assign) != 0) {
                    found = true;
                    break;
                }
            }
        } else {
            // Too many coupled bytes to enumerate — the shape of a wide equality
            // (`*(u64*)input == K`, i.e. a `memcmp` / `== b"..."` the compiler widened). Coordinate
            // descent on a Hamming-distance cost solves these: each input byte controls a distinct
            // byte of the compared value, so fixing bytes one at a time converges.
            found = descend(idxs, &group_constraints, &mut assign);
        }
        if !found {
            complete = false;
            notes.push(format!("no solution for bytes {idxs:?}"));
        }
    }

    let message = if complete {
        "solved".into()
    } else {
        format!("partial — {}", notes.join("; "))
    };
    SolveResult {
        input: assign,
        complete,
        message,
    }
}

fn bits_mask(w: u32) -> u64 {
    if w >= 64 { u64::MAX } else { (1u64 << w) - 1 }
}



/// A cost for one constraint under `assign`: 0 when satisfied, otherwise a distance coordinate
/// descent can minimise. For an equality the distance is the Hamming distance between the two
/// sides, so each input byte that controls a distinct byte of the compared value can be fixed
/// independently; other unsatisfied shapes get a flat penalty (still drives descent off them).
fn constraint_cost(c: &Expr, assign: &[u8]) -> u64 {
    if c.eval(assign) != 0 {
        return 0;
    }
    // Smooth gradient from the equalities inside the (possibly register-merged, extended, masked)
    // verdict expression; at least 1 so descent knows it is unsatisfied.
    eq_cost(c, assign).max(1)
}

/// Sum of the Hamming distances of every `Eq` subexpression currently violated, anywhere in the
/// tree. The verdict a `setcc` leaves is wrapped in register merges / `zext` / masks, so the
/// deciding `a == K` can be buried under `Or`/`And`/`Extract`; walking the whole tree finds it.
/// Each input byte that controls one bit of a compared value then lowers the distance by one, so
/// descent converges. Equalities over only concrete bits contribute a constant (ignored by descent).
fn eq_cost(c: &Expr, assign: &[u8]) -> u64 {
    match c.as_ref() {
        Node::Rel(Rel::Eq, a, b) => {
            let w = a.width().max(b.width());
            ((a.eval(assign) ^ b.eval(assign)) & bits_mask(w)).count_ones() as u64
        }
        Node::Bin(_, a, b) | Node::Rel(_, a, b) | Node::BoolAnd(a, b) | Node::BoolOr(a, b) => {
            eq_cost(a, assign) + eq_cost(b, assign)
        }
        Node::Not(a)
        | Node::Neg(a)
        | Node::ZeroExt(a, _)
        | Node::SignExt(a, _)
        | Node::Extract(a, _, _)
        | Node::BoolNot(a) => eq_cost(a, assign),
        Node::Ite(c, a, b) => eq_cost(c, assign) + eq_cost(a, assign) + eq_cost(b, assign),
        Node::Const(..) | Node::Var(_) => 0,
    }
}

/// Coordinate descent over a group of coupled bytes: repeatedly set each byte to the value that
/// minimises the total constraint cost, until everything is satisfied or no byte can improve.
/// Solves separable wide equalities (the widened `memcmp` pattern) that are too large to brute.
fn descend(idxs: &[usize], group_constraints: &[&Expr], assign: &mut [u8]) -> bool {
    let satisfied = |assign: &[u8]| group_constraints.iter().all(|c| c.eval(assign) != 0);
    let total = |assign: &[u8]| -> u64 {
        group_constraints
            .iter()
            .map(|c| constraint_cost(c, assign))
            .sum()
    };
    if satisfied(assign) {
        return true;
    }
    let mut cur = total(assign);
    // A pass per byte-bit of the group plus slack is ample for a separable equality to converge.
    for _ in 0..(idxs.len() * 8 + 16) {
        let mut improved = false;
        for &bi in idxs {
            let mut best = assign[bi];
            let mut best_cost = cur;
            for v in 0..=u8::MAX {
                assign[bi] = v;
                let cost = total(assign);
                if cost < best_cost {
                    best_cost = cost;
                    best = v;
                }
            }
            assign[bi] = best;
            if best_cost < cur {
                cur = best_cost;
                improved = true;
            }
            if satisfied(assign) {
                return true;
            }
        }
        if !improved {
            break;
        }
    }
    satisfied(assign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::{self, Op, Rel};

    /// A 64-bit little-endian load of input bytes 0..8 as an expression.
    fn load64_le() -> Expr {
        let mut acc = expr::konst(0, 64);
        for i in 0..8u32 {
            let b = expr::zext(expr::var(i), 64);
            let shifted = expr::bin(Op::Shl, b, expr::konst(u64::from(8 * i), 64));
            acc = expr::bin(Op::Or, acc, shifted);
        }
        acc
    }

    #[test]
    fn solves_a_wide_u64_equality_by_descent() {
        // `*(u64*)input == K` — 8 coupled bytes, too many to brute force; descent must recover the
        // little-endian bytes of K. K spells "Pa55w0rd".
        let k = u64::from_le_bytes(*b"Pa55w0rd");
        let eq = expr::rel(Rel::Eq, load64_le(), expr::konst(k, 64));
        let r = solve(&[eq], 8);
        assert!(r.complete, "wide equality should solve: {}", r.message);
        assert_eq!(&r.input, b"Pa55w0rd");
    }

    #[test]
    fn small_group_still_brute_forces() {
        // A per-byte transform-and-compare: in[0] ^ 0x41 == 0x10 -> in[0] == 0x51.
        let lhs = expr::bin(Op::Xor, expr::zext(expr::var(0), 8), expr::konst(0x41, 8));
        let eq = expr::rel(Rel::Eq, lhs, expr::konst(0x10, 8));
        let r = solve(&[eq], 1);
        assert!(r.complete);
        assert_eq!(r.input[0], 0x51);
    }

    #[test]
    fn two_independent_wide_equalities() {
        // Two u64 loads over disjoint byte groups (the `== b"16 bytes"` shape).
        let k0 = u64::from_le_bytes(*b"n0_debug");
        let eq0 = expr::rel(Rel::Eq, load64_le(), expr::konst(k0, 64));
        // Second load over bytes 8..16.
        let mut hi = expr::konst(0, 64);
        for i in 0..8u32 {
            let b = expr::zext(expr::var(8 + i), 64);
            hi = expr::bin(Op::Or, hi, expr::bin(Op::Shl, b, expr::konst(u64::from(8 * i), 64)));
        }
        let k1 = u64::from_le_bytes(*b"ger_here");
        let eq1 = expr::rel(Rel::Eq, hi, expr::konst(k1, 64));
        let r = solve(&[eq0, eq1], 16);
        assert!(r.complete, "{}", r.message);
        assert_eq!(&r.input, b"n0_debugger_here");
    }
}
