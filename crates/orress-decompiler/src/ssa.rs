//! Live-range splitting of general-purpose registers (a light, SSA-style renaming).
//!
//! A compiler freely reuses one register for unrelated values; the decompiler would otherwise
//! model that as a single variable with a confused (widest) type. This pass finds a register's
//! disjoint def-use *webs* (via reaching definitions + union-find) and renames each extra web to
//! its own `Var::Split(reg, version)`, so each use types independently.
//!
//! Runs before parameter binding. The web that holds the register's entry value keeps the plain
//! `Var::Reg` name, so an argument register still binds to its parameter. The result register
//! (`rax`/`x0`) and the stack/frame pointers are left untouched, so return and stack handling are
//! unaffected.

use std::collections::{HashMap, HashSet};

use crate::ir::*;
use crate::simplify::successors;

const ENTRY: usize = usize::MAX;
const RSP: u8 = 4;
const RBP: u8 = 5;

/// Splits every reusable general-purpose register into its disjoint live-range webs.
/// `arg_regs` is the convention's argument registers: if register 0 is one of them (ARM64's
/// `x0`, which is both the first argument and the result) it is left alone; otherwise (x86's
/// `rax`, a result-only register) it is split, keeping the web that reaches the return.
pub fn split_registers(blocks: &mut [Block], entry: u64, arg_regs: &[u8]) {
    let split_r0 = !arg_regs.contains(&0);
    // General-purpose registers that appear as a target (skip rsp/rbp; skip rax only when it is
    // also an argument register, i.e. ARM64's x0).
    let mut gp: HashSet<u8> = HashSet::new();
    let mut xmm: HashSet<u8> = HashSet::new();
    for b in blocks.iter() {
        for (_, s) in &b.stmts {
            for v in s.defs() {
                match v {
                    Var::Reg(r) if r != RSP && r != RBP && (r != 0 || split_r0) => {
                        gp.insert(r);
                    }
                    Var::Xmm(r) => {
                        xmm.insert(r);
                    }
                    _ => {}
                }
            }
        }
    }
    let mut gp: Vec<u8> = gp.into_iter().collect();
    gp.sort_unstable();
    for r in gp {
        // For a result-only register, the web reaching the return keeps the plain name; for
        // everything else it is the web holding the entry value.
        split_one(
            blocks,
            entry,
            Var::Reg(r),
            &|v| Var::Split(r, v),
            split_r0 && r == 0,
        );
    }
    let mut xmm: Vec<u8> = xmm.into_iter().collect();
    xmm.sort_unstable();
    for r in xmm {
        // An XMM register reused as both an accumulator and a scratch (e.g. the blend scratch of a
        // packed max) splits into distinct variables. xmm0 is the float/vector result register, so
        // its return-reaching web (after `retarget_float_return`) keeps the plain name.
        split_one(blocks, entry, Var::Xmm(r), &|v| Var::XmmSplit(r, v), r == 0);
    }
}

fn defines(s: &Stmt, base: Var) -> bool {
    s.defs().contains(&base)
}

fn reads(s: &Stmt, base: Var) -> bool {
    s.exprs().iter().any(|e| e.reads(base))
}

fn split_one(
    blocks: &mut [Block],
    entry: u64,
    base: Var,
    mk_split: &dyn Fn(u16) -> Var,
    ret_reg: bool,
) {
    let addrs: Vec<u64> = blocks.iter().map(|b| b.addr).collect();
    let idx: HashMap<u64, usize> = addrs.iter().enumerate().map(|(i, &a)| (a, i)).collect();

    // Definition sites of r, and the last def-id within each block.
    let mut defs: Vec<(usize, usize)> = Vec::new(); // (block index, stmt index)
    let mut last_def: Vec<Option<usize>> = vec![None; blocks.len()];
    for (bi, b) in blocks.iter().enumerate() {
        for (si, (_, s)) in b.stmts.iter().enumerate() {
            if defines(s, base) {
                last_def[bi] = Some(defs.len());
                defs.push((bi, si));
            }
        }
    }
    if defs.len() <= 1 {
        return; // a single definition never needs splitting.
    }

    // Predecessors.
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for b in blocks.iter() {
        let from = idx[&b.addr];
        for t in successors(&b.term) {
            if let Some(&to) = idx.get(&t) {
                preds[to].push(from);
            }
        }
    }

    // Reaching definitions (block granularity). `reach_in[b]` is the set of def-ids (and ENTRY)
    // live at the block's start; `reach_out[b]` is the last def in the block, or `reach_in` if
    // the block does not redefine r.
    let entry_bi = idx[&entry];
    let mut reach_in: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    reach_in[entry_bi].insert(ENTRY);
    let out = |bi: usize, reach_in: &[HashSet<usize>]| -> HashSet<usize> {
        match last_def[bi] {
            Some(d) => HashSet::from([d]),
            None => reach_in[bi].clone(),
        }
    };
    let mut changed = true;
    while changed {
        changed = false;
        for bi in 0..blocks.len() {
            let mut new = if bi == entry_bi {
                HashSet::from([ENTRY])
            } else {
                HashSet::new()
            };
            for &p in &preds[bi] {
                new.extend(out(p, &reach_in));
            }
            if new != reach_in[bi] {
                reach_in[bi] = new;
                changed = true;
            }
        }
    }

    // Union-find over def-ids (+ ENTRY). A use merges all definitions reaching it.
    let mut uf = UnionFind::new(defs.len() + 1);
    let entry_id = defs.len(); // ENTRY sentinel maps to this slot
    let slot = |d: usize| if d == ENTRY { entry_id } else { d };
    // Definitions reaching the function's return(s) — for a result register these all become the
    // single return-value web.
    let mut ret_ids: Vec<usize> = Vec::new();
    for (bi, b) in blocks.iter().enumerate() {
        let mut cur = reach_in[bi].clone();
        for (si, (_, s)) in b.stmts.iter().enumerate() {
            if reads(s, base) {
                let ids: Vec<usize> = cur.iter().map(|&d| slot(d)).collect();
                for w in ids.windows(2) {
                    uf.union(w[0], w[1]);
                }
            }
            if defines(s, base) {
                let d = last_def_at(&defs, bi, si);
                cur = HashSet::from([d]);
            }
        }
        if term_reads(&b.term, base) {
            let ids: Vec<usize> = cur.iter().map(|&d| slot(d)).collect();
            for w in ids.windows(2) {
                uf.union(w[0], w[1]);
            }
            if ret_reg && matches!(b.term, Term::Return(_)) {
                ret_ids.extend(ids);
            }
        }
    }
    // All definitions reaching any return form one web (the return value keeps the plain name).
    for w in ret_ids.windows(2) {
        uf.union(w[0], w[1]);
    }

    // The register's definitions coalesce into one or more webs. One web (the "primary") keeps
    // the plain `Reg(r)` name; the rest become fresh versions. Nothing to do if there is only a
    // single web — the register is one logical variable even if written several times (a loop
    // counter/accumulator).
    let distinct: HashSet<usize> = (0..defs.len()).map(|d| uf.find(d)).collect();
    if distinct.len() <= 1 {
        return;
    }
    // The primary web keeps the plain `Reg(r)` name; every other web is a reuse and gets a fresh
    // version. For a result register it is the return-value web (so return handling is unchanged);
    // otherwise the web holding the entry value (so an argument register still binds to its
    // parameter and a live-in read is unchanged).
    let entry_web = if ret_reg && !ret_ids.is_empty() {
        uf.find(ret_ids[0])
    } else {
        uf.find(entry_id)
    };
    let mut version: HashMap<usize, u16> = HashMap::new();
    let mut next: u16 = 1;
    let mut web_var = |web: usize| -> Var {
        if web == entry_web {
            base
        } else {
            let v = *version.entry(web).or_insert_with(|| {
                let v = next;
                next += 1;
                v
            });
            mk_split(v)
        }
    };

    // Rewrite every read/def of r to its web's variable.
    for bi in 0..blocks.len() {
        let mut cur = reach_in[bi].clone();
        let stmts = std::mem::take(&mut blocks[bi].stmts);
        let mut new_stmts = Vec::with_capacity(stmts.len());
        for (si, (addr, s)) in stmts.into_iter().enumerate() {
            let read_var = read_var(&cur, &mut uf, slot, entry_id, base, &mut web_var);
            let is_def = defines(&s, base);
            let def_var = is_def.then(|| web_var(uf.find(last_def_at(&defs, bi, si))));
            new_stmts.push((addr, rewrite_stmt(s, base, read_var, def_var)));
            if is_def {
                cur = HashSet::from([last_def_at(&defs, bi, si)]);
            }
        }
        blocks[bi].stmts = new_stmts;
        let read_var = read_var(&cur, &mut uf, slot, entry_id, base, &mut web_var);
        let term = std::mem::replace(&mut blocks[bi].term, Term::Stop);
        blocks[bi].term = crate::simplify::term_map(term, &mut |e| rename_reads(e, base, read_var));
    }
}

/// The variable a read of `r` resolves to, from the current reaching set (all reaching defs share
/// a web, so any representative works). An empty set (unreachable) keeps `Reg(r)`.
fn read_var(
    cur: &HashSet<usize>,
    uf: &mut UnionFind,
    slot: impl Fn(usize) -> usize,
    _entry_id: usize,
    base: Var,
    web_var: &mut impl FnMut(usize) -> Var,
) -> Var {
    match cur.iter().next() {
        Some(&d) => web_var(uf.find(slot(d))),
        None => base,
    }
}

fn last_def_at(defs: &[(usize, usize)], bi: usize, si: usize) -> usize {
    defs.iter()
        .position(|&(b, s)| b == bi && s == si)
        .expect("def id")
}

fn rename_reads(e: Expr, base: Var, to: Var) -> Expr {
    e.map(&mut |x| match x {
        Expr::Var(v, w) if v == base => Expr::Var(to, w),
        other => other,
    })
}

fn rewrite_stmt(s: Stmt, base: Var, read_var: Var, def_var: Option<Var>) -> Stmt {
    match s {
        Stmt::Assign(v, e) => {
            let e = rename_reads(e, base, read_var);
            let v = if v == base { def_var.unwrap_or(v) } else { v };
            Stmt::Assign(v, e)
        }
        Stmt::Store(a, val, w) => Stmt::Store(
            rename_reads(a, base, read_var),
            rename_reads(val, base, read_var),
            w,
        ),
        Stmt::Eval(e) => Stmt::Eval(rename_reads(e, base, read_var)),
        Stmt::Asm(t, ops) => Stmt::Asm(
            t,
            ops.into_iter()
                .map(|op| {
                    let op = op.map_value(&mut |e| rename_reads(e, base, read_var));
                    match (op.output(), def_var) {
                        (Some(v), Some(dv)) if v == base => retarget_output(op, dv),
                        _ => op,
                    }
                })
                .collect(),
        ),
    }
}

fn retarget_output(op: AsmOp, to: Var) -> AsmOp {
    match op {
        AsmOp::Out(reg, _) => AsmOp::Out(reg, to),
        AsmOp::InOut(reg, v, _) => AsmOp::InOut(reg, v, to),
        other => other,
    }
}

fn term_reads(t: &Term, base: Var) -> bool {
    crate::simplify::term_exprs(t).iter().any(|e| e.reads(base))
}

struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }
    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cur = x;
        while self.parent[cur] != root {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra] = rb;
        }
    }
}
