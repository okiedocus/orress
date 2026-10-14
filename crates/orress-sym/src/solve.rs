//! The built-in constraint solver. The path constraint from a byte-wise check decomposes into
//! groups of input bytes that interact; each small group is solved by bounded brute-force. This
//! handles the usual crackme transforms (xor/add/sub/mul/rotate/and-compare) completely and
//! fast. Tightly-coupled constraints over many bytes are left to external z3 via the SMT export.

use std::collections::BTreeSet;

use crate::expr::Expr;

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
        if space > MAX_SPACE {
            complete = false;
            notes.push(format!("{k} coupled bytes exceed the brute-force limit"));
            continue;
        }
        let mut found = false;
        for combo in 0..space {
            for (j, &bi) in idxs.iter().enumerate() {
                assign[bi] = (combo >> (8 * j)) as u8;
            }
            if group_constraints.iter().all(|c| c.eval(&assign) != 0) {
                found = true;
                break;
            }
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
