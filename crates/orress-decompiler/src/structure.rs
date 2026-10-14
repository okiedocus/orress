//! Control-flow structuring: from basic blocks and jumps to `if`, `while`, `loop`,
//! `break`, `continue` and `return`.
//!
//! The approach: loops are found from back edges (a jump to a block that dominates the
//! jump); for an `if`, the two branches run until the immediate post-dominator (the
//! first block both paths reach again). Anything that does not fit becomes a labelled
//! jump comment, so the output never silently drops code.

use std::collections::{HashMap, HashSet};

use crate::ir::*;
use crate::simplify::successors;

#[derive(Clone, Debug)]
// `For` carries the recovered-iterator shape (bounds, slice, zip/index bindings); boxing it
// would spread indirection across every match for little gain on this short-lived AST.
#[allow(clippy::large_enum_variant)]
pub enum Node {
    Stmt(u64, Stmt),
    If {
        addr: u64,
        cond: Expr,
        then: Vec<Node>,
        els: Vec<Node>,
    },
    Loop {
        addr: u64,
        body: Vec<Node>,
    },
    While {
        addr: u64,
        cond: Expr,
        body: Vec<Node>,
    },
    /// `for var in start..end` (or `..=end`): a counted loop recovered from a
    /// `while i < len { ...; i += 1 }` shape. When `iter` is `Some(slice)`, the counter was
    /// only ever used to index that slice, so it prints as element iteration and `var` binds
    /// the element: `for &var in slice` (read-only) or, when `by_ref` is set, `for var in
    /// slice.iter_mut()` with each access a `*var`.
    For {
        addr: u64,
        var: Var,
        start: Expr,
        end: Expr,
        inclusive: bool,
        iter: Option<Expr>,
        by_ref: bool,
        /// A second slice iterated in lock-step: `for (var, &elem) in iter.iter_mut().zip(src)`.
        zip: Option<(Expr, Var)>,
        /// The index binding of `for (index, &var) in iter.iter().enumerate()`, when the
        /// counter is used both as an index and to read the element.
        index: Option<Var>,
        body: Vec<Node>,
    },
    /// `match index { v0 | v1 => …, _ => {} }` recovered from a jump table.
    Match {
        addr: u64,
        index: Expr,
        arms: Vec<(Vec<u64>, Vec<Node>)>,
    },
    Break(u64),
    Continue(u64),
    /// `break`/`continue` of an ENCLOSING (non-innermost) loop, identified by that loop's header
    /// address, which becomes a Rust loop label (`break 'l<addr>`). Kept distinct from the plain
    /// `Break`/`Continue` so the while/for recognizers — which only match those — never mistake a
    /// jump out of an inner loop for this loop's own exit.
    BreakLabel(u64),
    ContinueLabel(u64),
    Return(u64, Option<Expr>),
    Stop(u64),
    TailCall(u64, Expr),
    /// A jump the structurer could not express.
    Goto(u64, u64),
    /// Target of such a jump.
    Label(u64),
}

struct Graph {
    blocks: HashMap<u64, Block>,
    succs: HashMap<u64, Vec<u64>>,
    preds: HashMap<u64, Vec<u64>>,
    entry: u64,
    order: Vec<u64>,
    rpo: HashMap<u64, usize>,
}

/// Iterative dominators (Cooper, Harvey, Kennedy) over `order` (reverse post-order).
fn dominators(order: &[u64], preds: &HashMap<u64, Vec<u64>>, entry: u64) -> HashMap<u64, u64> {
    let index: HashMap<u64, usize> = order.iter().enumerate().map(|(i, &b)| (b, i)).collect();
    let mut idom: HashMap<u64, u64> = HashMap::from([(entry, entry)]);
    let intersect = |idom: &HashMap<u64, u64>, mut a: u64, mut b: u64| {
        while a != b {
            while index[&a] > index[&b] {
                a = idom[&a];
            }
            while index[&b] > index[&a] {
                b = idom[&b];
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &b in order.iter().skip(1) {
            let mut new: Option<u64> = None;
            for &p in preds.get(&b).map_or(&[][..], Vec::as_slice) {
                if !idom.contains_key(&p) || !index.contains_key(&p) {
                    continue;
                }
                new = Some(match new {
                    None => p,
                    Some(n) => intersect(&idom, p, n),
                });
            }
            if let Some(n) = new
                && idom.get(&b) != Some(&n)
            {
                idom.insert(b, n);
                changed = true;
            }
        }
    }
    idom
}

fn reverse_postorder(entry: u64, succs: &HashMap<u64, Vec<u64>>) -> Vec<u64> {
    let mut seen = HashSet::new();
    let mut post = Vec::new();
    let mut stack = vec![(entry, 0usize)];
    seen.insert(entry);
    while let Some((n, i)) = stack.pop() {
        let next = succs.get(&n).and_then(|s| s.get(i)).copied();
        match next {
            Some(m) => {
                stack.push((n, i + 1));
                if seen.insert(m) {
                    stack.push((m, 0));
                }
            }
            None => post.push(n),
        }
    }
    post.reverse();
    post
}

fn dominates(idom: &HashMap<u64, u64>, a: u64, mut b: u64) -> bool {
    loop {
        if a == b {
            return true;
        }
        match idom.get(&b) {
            Some(&p) if p != b => b = p,
            _ => return false,
        }
    }
}

struct Structurer {
    g: Graph,
    idom: HashMap<u64, u64>,
    /// Immediate post-dominators (u64::MAX = the virtual exit).
    ipdom: HashMap<u64, u64>,
    loop_headers: HashSet<u64>,
    /// Blocks of each loop.
    loop_body: HashMap<u64, HashSet<u64>>,
    emitted: HashSet<u64>,
    /// (header, follow) of the loops being structured, innermost last.
    loops: Vec<(u64, Option<u64>)>,
    gotos: HashSet<u64>,
}

const EXIT: u64 = u64::MAX;

impl Structurer {
    fn new(blocks: Vec<Block>, entry: u64) -> Self {
        let mut succs = HashMap::new();
        let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
        let addrs: HashSet<u64> = blocks.iter().map(|b| b.addr).collect();
        for b in &blocks {
            let s: Vec<u64> = successors(&b.term)
                .into_iter()
                .filter(|t| addrs.contains(t))
                .collect();
            for &t in &s {
                preds.entry(t).or_default().push(b.addr);
            }
            succs.insert(b.addr, s);
        }
        let order = reverse_postorder(entry, &succs);
        let idom = dominators(&order, &preds, entry);

        // Post-dominators: dominators of the reversed graph from a virtual exit.
        let mut rsuccs: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut rpreds: HashMap<u64, Vec<u64>> = HashMap::new();
        for (&b, s) in &succs {
            if s.is_empty() {
                rsuccs.entry(EXIT).or_default().push(b);
                rpreds.entry(b).or_default().push(EXIT);
            }
            for &t in s {
                rsuccs.entry(t).or_default().push(b);
                rpreds.entry(b).or_default().push(t);
            }
        }
        let rorder = reverse_postorder(EXIT, &rsuccs);
        let ipdom = dominators(&rorder, &rpreds, EXIT);

        let mut loop_headers = HashSet::new();
        let mut loop_body: HashMap<u64, HashSet<u64>> = HashMap::new();
        for (&b, s) in &succs {
            for &t in s {
                if dominates(&idom, t, b) {
                    loop_headers.insert(t);
                    // Natural loop: everything that reaches b without passing t.
                    let body = loop_body.entry(t).or_insert_with(|| HashSet::from([t]));
                    let mut stack = vec![b];
                    while let Some(n) = stack.pop() {
                        if body.insert(n) {
                            stack.extend(preds.get(&n).cloned().unwrap_or_default());
                        }
                    }
                }
            }
        }
        Self {
            g: Graph {
                blocks: blocks.into_iter().map(|b| (b.addr, b)).collect(),
                succs,
                preds,
                entry,
                rpo: order.iter().enumerate().map(|(i, &b)| (b, i)).collect(),
                order,
            },
            idom,
            ipdom,
            loop_headers,
            loop_body,
            emitted: HashSet::new(),
            loops: Vec::new(),
            gotos: HashSet::new(),
        }
    }

    /// The block after a loop: the first exit target in address order.
    fn loop_follow(&self, header: u64) -> Option<u64> {
        let body = &self.loop_body[&header];
        let mut exits: Vec<u64> = body
            .iter()
            .flat_map(|b| self.g.succs.get(b).cloned().unwrap_or_default())
            .filter(|t| !body.contains(t))
            .collect();
        exits.sort_unstable();
        exits.dedup();
        // Prefer the exit the header itself branches to (a while-loop condition).
        let from_header = self
            .g
            .succs
            .get(&header)
            .and_then(|s| s.iter().find(|t| !body.contains(t)).copied());
        from_header.or_else(|| exits.first().copied())
    }

    /// Classify a flow target `x` against the enclosing loop stack (innermost first):
    /// `Some((loop_header, is_continue, is_innermost))` when `x` is some enclosing loop's header
    /// (a continue/back-edge) or its follow (a break). Used to recover labeled break/continue of
    /// outer loops, not just the innermost one.
    fn classify_target(&self, x: u64) -> Option<(u64, bool, bool)> {
        let inner = self.loops.last().map(|&(h, _)| h);
        for &(h, lf) in self.loops.iter().rev() {
            if x == h {
                return Some((h, true, inner == Some(h)));
            }
            if Some(x) == lf {
                return Some((h, false, inner == Some(h)));
            }
        }
        None
    }

    fn region(&mut self, start: u64, stop: Option<u64>) -> Vec<Node> {
        let mut out = Vec::new();
        let mut cur = Some(start);
        while let Some(b) = cur {
            if Some(b) == stop {
                break;
            }
            if let Some((h, is_cont, innermost)) = self.classify_target(b) {
                // A continue applies only to an already-emitted header (a back-edge); an unemitted
                // header here means we are entering that loop, which is handled further below.
                if !is_cont || self.emitted.contains(&b) {
                    out.push(match (is_cont, innermost) {
                        (true, true) => Node::Continue(b),
                        (true, false) => Node::ContinueLabel(h),
                        (false, true) => Node::Break(b),
                        (false, false) => Node::BreakLabel(h),
                    });
                    break;
                }
            }
            // A short block that just returns is repeated rather than jumped to.
            if self.emitted.contains(&b) && self.is_small_exit(b) {
                self.block(b, stop, &mut out);
                break;
            }
            if self.emitted.contains(&b) || !self.g.blocks.contains_key(&b) {
                self.gotos.insert(b);
                out.push(Node::Goto(b, b));
                break;
            }
            if self.loop_headers.contains(&b) && !self.loops.iter().any(|(h, _)| *h == b) {
                let follow = self.loop_follow(b);
                self.loops.push((b, follow));
                let body = self.region_from(b, None);
                self.loops.pop();
                out.push(make_loop(b, body));
                cur = follow;
                continue;
            }
            cur = self.block(b, stop, &mut out);
        }
        out
    }

    /// Like `region`, but `start` is emitted even though it is the loop header.
    fn region_from(&mut self, start: u64, stop: Option<u64>) -> Vec<Node> {
        let mut out = Vec::new();
        let next = self.block(start, stop, &mut out);
        if let Some(n) = next {
            out.extend(self.region(n, stop));
        }
        out
    }

    /// Emits one block; returns where structured flow continues.
    fn block(&mut self, b: u64, stop: Option<u64>, out: &mut Vec<Node>) -> Option<u64> {
        self.emitted.insert(b);
        let block = self.g.blocks[&b].clone();
        if self.gotos.contains(&b) {
            out.push(Node::Label(b));
        }
        out.extend(block.stmts.iter().map(|(a, s)| Node::Stmt(*a, s.clone())));
        match block.term {
            Term::Jump(t) => Some(t),
            Term::Return(e) => {
                out.push(Node::Return(block.term_addr, e));
                None
            }
            Term::Stop => {
                out.push(Node::Stop(block.term_addr));
                None
            }
            Term::TailCall(e) => {
                out.push(Node::TailCall(block.term_addr, e));
                None
            }
            Term::Switch(index, cases) => {
                // The cases reconverge at the switch's post-dominator.
                let mut follow = self.ipdom.get(&b).copied().filter(|&p| p != EXIT);
                if let Some(&(h, lf)) = self.loops.last() {
                    let body = &self.loop_body[&h];
                    if follow.is_some_and(|p| !body.contains(&p)) {
                        follow = lf;
                    }
                }
                // Group case values by target block, keeping first-seen order.
                let mut order: Vec<u64> = Vec::new();
                let mut groups: HashMap<u64, Vec<u64>> = HashMap::new();
                for (val, &target) in cases.iter().enumerate() {
                    if groups.entry(target).or_default().is_empty() {
                        order.push(target);
                    }
                    groups.get_mut(&target).unwrap().push(val as u64);
                }
                let arms = order
                    .into_iter()
                    .map(|target| {
                        let values = groups[&target].clone();
                        let body = if Some(target) == follow {
                            Vec::new()
                        } else {
                            self.branch(target, follow)
                        };
                        (values, body)
                    })
                    .collect();
                out.push(Node::Match {
                    addr: block.term_addr,
                    index,
                    arms,
                });
                follow
            }
            Term::Branch(cond, t, f) => {
                // Leaving or restarting a loop (possibly an outer one): `if c { break; }` and
                // carry on. Classify each target against the whole loop stack.
                let (jt, jf) = (self.classify_target(t), self.classify_target(f));
                let picked = match (jt, jf) {
                    (Some(j), None) => Some((cond.clone(), j, t, f)),
                    (None, Some(j)) => Some((cond.clone().negate(), j, f, t)),
                    _ => None,
                };
                if let Some((cond, (h, is_cont, innermost), out_to, stay)) = picked {
                    let jump = match (is_cont, innermost) {
                        (true, true) => Node::Continue(out_to),
                        (true, false) => Node::ContinueLabel(h),
                        (false, true) => Node::Break(out_to),
                        (false, false) => Node::BreakLabel(h),
                    };
                    out.push(Node::If {
                        addr: block.term_addr,
                        cond,
                        then: vec![jump],
                        els: Vec::new(),
                    });
                    return Some(stay);
                }
                let mut follow = self.ipdom.get(&b).copied().filter(|&p| p != EXIT);
                // Inside a loop, never run past the loop's own boundaries.
                if let Some(&(h, lf)) = self.loops.last() {
                    let body = &self.loop_body[&h];
                    if follow.is_some_and(|p| !body.contains(&p)) {
                        follow = lf;
                    }
                }
                if let Some(s) = stop
                    && follow.is_none_or(|p| !dominates(&self.idom, b, p) && p != s)
                {
                    follow =
                        follow.filter(|&p| self.g.preds.get(&p).is_some_and(|ps| ps.len() > 1));
                }
                if follow.is_none() {
                    follow = self.join(t, f);
                }
                // When the two branches reconverge at a shared tail *before* the chosen
                // post-dominator (e.g. one branch takes an early exit, pushing the ipdom all the
                // way to the function's end), prefer that nearer merge. Otherwise the branch that
                // reaches the shared tail directly would have to jump forward to it (a `goto`).
                if let Some(j) = self.join(t, f)
                    && follow.is_some_and(|p| {
                        j != p && self.g.rpo.get(&j).copied() < self.g.rpo.get(&p).copied()
                    })
                {
                    follow = Some(j);
                }
                // A branch must never reconverge past its enclosing region's boundary; otherwise
                // it would structure blocks that belong after the region (and the other path, on
                // reaching that shared block, would have to jump into it — a `goto`).
                if let Some(s) = stop
                    && follow
                        .is_some_and(|p| self.g.rpo.get(&p).copied() > self.g.rpo.get(&s).copied())
                {
                    follow = Some(s);
                }
                // Branches never run past the end of the region they are in.
                if follow.is_none() {
                    follow = stop;
                }
                let then = self.branch(t, follow);
                let els = self.branch(f, follow);
                let (cond, then, els) = if then.is_empty() && !els.is_empty() {
                    (cond.negate(), els, Vec::new())
                } else {
                    (cond, then, els)
                };
                // Guard clauses: `if c { return; } rest` instead of `if c { return; } else { rest }`.
                let (cond, then, rest) = if !els.is_empty() && diverges(&then) {
                    (cond, then, els)
                } else if !els.is_empty() && diverges(&els) {
                    (cond.negate(), els, then)
                } else {
                    out.push(Node::If {
                        addr: block.term_addr,
                        cond,
                        then,
                        els,
                    });
                    return follow;
                };
                out.push(Node::If {
                    addr: block.term_addr,
                    cond,
                    then,
                    els: Vec::new(),
                });
                out.extend(rest);
                follow
            }
        }
    }

    fn is_small_exit(&self, b: u64) -> bool {
        self.g.blocks.get(&b).is_some_and(|blk| {
            matches!(blk.term, Term::Return(_) | Term::Stop | Term::TailCall(_))
                && blk.stmts.len() <= 3
        })
    }

    /// Where two branches that never meet at a post-dominator come together again:
    /// the earliest block reachable from both (staying inside the current loop).
    fn join(&self, t: u64, f: u64) -> Option<u64> {
        let body = self.loops.last().map(|(h, _)| (&self.loop_body[h], *h));
        let reach = |start: u64| {
            let mut seen = HashSet::new();
            let mut stack = vec![start];
            while let Some(n) = stack.pop() {
                if body.is_some_and(|(b, h)| !b.contains(&n) || n == h) || !seen.insert(n) {
                    continue;
                }
                stack.extend(self.g.succs.get(&n).cloned().unwrap_or_default());
            }
            seen
        };
        let (a, b) = (reach(t), reach(f));
        a.intersection(&b)
            .copied()
            .filter(|n| !self.is_small_exit(*n) && !self.emitted.contains(n))
            .min_by_key(|n| self.g.rpo[n])
    }

    fn branch(&mut self, target: u64, follow: Option<u64>) -> Vec<Node> {
        if Some(target) == follow {
            return Vec::new();
        }
        self.region(target, follow)
    }
}

/// Whether control never falls out of the end of these nodes.
fn diverges(nodes: &[Node]) -> bool {
    match nodes.last() {
        Some(
            Node::Return(..)
            | Node::Break(_)
            | Node::Continue(_)
            | Node::Stop(_)
            | Node::TailCall(..)
            | Node::Goto(..),
        ) => true,
        Some(Node::If { then, els, .. }) => !els.is_empty() && diverges(then) && diverges(els),
        _ => false,
    }
}

fn make_loop(addr: u64, mut body: Vec<Node>) -> Node {
    // A trailing `continue` is implied.
    if matches!(body.last(), Some(Node::Continue(_))) {
        body.pop();
    }
    // `loop { if c { break } ... }` -> `while !c { ... }`
    if let Some(Node::If {
        cond, then, els, ..
    }) = body.first()
        && els.is_empty()
        && matches!(then.as_slice(), [Node::Break(_)])
    {
        let cond = cond.clone().negate();
        body.remove(0);
        return Node::While { addr, cond, body };
    }
    Node::Loop { addr, body }
}

/// Does any node here read `v`?
fn reads_var(nodes: &[Node], v: Var) -> bool {
    fn in_expr(e: &Expr, v: Var) -> bool {
        e.reads(v)
    }
    nodes.iter().any(|n| match n {
        Node::Stmt(_, s) => s.exprs().iter().any(|e| in_expr(e, v)),
        Node::If {
            cond, then, els, ..
        } => in_expr(cond, v) || reads_var(then, v) || reads_var(els, v),
        Node::While { cond, body, .. } => in_expr(cond, v) || reads_var(body, v),
        Node::For {
            start, end, body, ..
        } => in_expr(start, v) || in_expr(end, v) || reads_var(body, v),
        Node::Loop { body, .. } => reads_var(body, v),
        Node::Match { index, arms, .. } => {
            in_expr(index, v) || arms.iter().any(|(_, b)| reads_var(b, v))
        }
        Node::Return(_, Some(e)) | Node::TailCall(_, e) => in_expr(e, v),
        _ => false,
    })
}

/// Does any node here assign `v`?
fn assigns_var(nodes: &[Node], v: Var) -> bool {
    nodes.iter().any(|n| match n {
        Node::Stmt(_, Stmt::Assign(d, _)) => *d == v,
        Node::If { then, els, .. } => assigns_var(then, v) || assigns_var(els, v),
        Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
            assigns_var(body, v)
        }
        Node::Match { arms, .. } => arms.iter().any(|(_, b)| assigns_var(b, v)),
        _ => false,
    })
}

/// Recovers `for i in start..end` from the `i = start; while i < end { ...; i += 1 }` shape,
/// where `i` is a plain counter not used after the loop.
/// Normalises a loop body of the form `if G { ...; i += 1; continue } REST` (where REST
/// diverges) into `if !G { REST } ...; i += 1`, moving the counter increment to the tail so
/// [`recover_for_loops`] can recognise the loop. This is the shape compilers emit for a
/// search loop with an early `continue`.
/// Tidies a `loop` with a bottom test (a do-while): the trailing `if cond { continue } break`
/// becomes `if !cond { break }`, and a redundant trailing `continue` is dropped. Purely a
/// readability rewrite — the control flow is identical.
pub fn normalize_do_while(nodes: &mut [Node]) {
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                normalize_do_while(then);
                normalize_do_while(els);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                normalize_do_while(body)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    normalize_do_while(b);
                }
            }
            _ => {}
        }
    }
    for n in nodes.iter_mut() {
        if let Node::Loop { body, .. } = n {
            tidy_loop_tail(body);
        }
    }
}

fn tidy_loop_tail(body: &mut Vec<Node>) {
    let is_continue_guard = |n: &Node| {
        matches!(n, Node::If { then, els, .. }
            if els.is_empty() && then.len() == 1 && matches!(then[0], Node::Continue(_)))
    };
    // `if cond { continue } break`  ->  `if !cond { break }`.
    if body.len() >= 2
        && matches!(body[body.len() - 1], Node::Break(_))
        && is_continue_guard(&body[body.len() - 2])
    {
        let brk = body.pop().unwrap();
        if let Some(Node::If {
            addr,
            cond,
            then,
            els,
        }) = body.last_mut()
        {
            *then = vec![brk];
            *els = Vec::new();
            *cond = cond.clone().negate();
            let _ = addr;
        }
        return;
    }
    // `if cond { continue } else { break }`  ->  `if !cond { break }`.
    if let Some(Node::If {
        cond, then, els, ..
    }) = body.last_mut()
        && then.len() == 1
        && matches!(then[0], Node::Continue(_))
        && els.len() == 1
        && matches!(els[0], Node::Break(_))
    {
        *then = std::mem::take(els);
        *cond = cond.clone().negate();
        return;
    }
    // A trailing `continue` falls through to the loop top anyway.
    if matches!(body.last(), Some(Node::Continue(_))) {
        body.pop();
    }
}

fn normalize_guard_continue(body: &mut Vec<Node>) {
    // The guard is the `if G { …; i += 1; continue }` — it may follow a prefix that runs each
    // iteration (e.g. loading the element into a register).
    let is_guard = |n: &Node| {
        matches!(n, Node::If { then, els, .. }
            if els.is_empty()
                && then.len() >= 2
                && matches!(then.last(), Some(Node::Continue(_)))
                && matches!(&then[then.len() - 2],
                    Node::Stmt(_, Stmt::Assign(d, Expr::Bin(BinOp::Add, l, r, _)))
                        if matches!(&**l, Expr::Var(v, _) if v == d)
                            && matches!(&**r, Expr::Const(1, _))))
    };
    let Some(pos) = body.iter().position(is_guard) else {
        return;
    };
    let rest: Vec<Node> = body[pos + 1..].to_vec();
    if !diverges(&rest) {
        return;
    }
    let Node::If {
        addr, cond, then, ..
    } = &body[pos]
    else {
        return;
    };
    let inc_at = then.len() - 2;
    let addr = *addr;
    let guard = Node::If {
        addr,
        cond: cond.clone().negate(),
        then: rest,
        els: Vec::new(),
    };
    let then_prefix: Vec<Node> = then[..inc_at].to_vec();
    let inc = then[inc_at].clone();
    let mut nb: Vec<Node> = body[..pos].to_vec();
    nb.push(guard);
    nb.extend(then_prefix);
    nb.push(inc);
    *body = nb;
}

pub fn recover_for_loops(nodes: &mut Vec<Node>) {
    // Recurse first so inner loops convert before their enclosing ones.
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_for_loops(then);
                recover_for_loops(els);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_for_loops(body)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_for_loops(b);
                }
            }
            _ => {}
        }
    }
    for n in nodes.iter_mut() {
        if let Node::While { body, .. } = n {
            normalize_guard_continue(body);
        }
    }

    let mut i = 0;
    while i < nodes.len() {
        let Node::While { addr, cond, body } = &nodes[i] else {
            i += 1;
            continue;
        };
        // The condition must be `counter <op> end`, op `<` or `<=`.
        let (op, counter, end) = match cond {
            Expr::Cmp(op @ (CmpOp::Lt | CmpOp::Le), a, b, _) => match &**a {
                Expr::Var(v, _) => (*op, *v, (**b).clone()),
                _ => {
                    i += 1;
                    continue;
                }
            },
            _ => {
                i += 1;
                continue;
            }
        };
        // The loop body must end in `counter += 1`, and not touch the counter otherwise,
        // and the bound must not depend on the counter.
        let inc_ok = matches!(
            body.last(),
            Some(Node::Stmt(_, Stmt::Assign(d, Expr::Bin(BinOp::Add, l, r, _))))
                if *d == counter
                    && matches!(&**l, Expr::Var(v, _) if *v == counter)
                    && matches!(&**r, Expr::Const(1, _))
        );
        let body_head = &body[..body.len().saturating_sub(1)];
        if !inc_ok || assigns_var(body_head, counter) || end.reads(counter) {
            i += 1;
            continue;
        }
        // The statement just before the loop must initialise the counter, and the counter
        // must be dead after the loop (a `for` binds it to the loop).
        let init = i.checked_sub(1).and_then(|p| match &nodes[p] {
            Node::Stmt(_, Stmt::Assign(d, e)) if *d == counter => Some(e.clone()),
            _ => None,
        });
        let Some(start) = init else {
            i += 1;
            continue;
        };
        if reads_var(&nodes[i + 1..], counter) {
            i += 1;
            continue;
        }

        // Rewrite.
        let addr = *addr;
        let inclusive = op == CmpOp::Le;
        let Node::While { body, .. } = nodes.remove(i) else {
            unreachable!()
        };
        let mut body = body;
        body.pop(); // the `i += 1`
        nodes[i - 1] = Node::For {
            addr,
            var: counter,
            start,
            end,
            inclusive,
            iter: None,
            by_ref: false,
            zip: None,
            index: None,
            body,
        };
        // `nodes[i - 1]` is now the For; continue scanning after it.
    }
}

/// Is `addr` the element address `slice[counter]` for a byte slice (`param_si + counter`)?
fn is_elem_addr(addr: &Expr, counter: Var, si: usize) -> bool {
    matches!(
        crate::types::base_param(addr),
        Some((i, Some(idx))) if i == si && matches!(idx, Expr::Var(v, _) if *v == counter)
    )
}

/// Is `e` the element read `slice[counter]` (`Load` of a byte at `param_si + counter`)?
fn is_elem_read(e: &Expr, counter: Var, si: usize) -> bool {
    matches!(e, Expr::Load(addr, w) if *w == Width::B8 && is_elem_addr(addr, counter, si))
}

/// Visits every expression in `nodes` (read-only).
fn each_node_expr(nodes: &[Node], f: &mut impl FnMut(&Expr)) {
    for n in nodes {
        match n {
            Node::Stmt(_, s) => {
                for e in s.exprs() {
                    e.walk(f);
                }
            }
            Node::If {
                cond, then, els, ..
            } => {
                cond.walk(f);
                each_node_expr(then, f);
                each_node_expr(els, f);
            }
            Node::While { cond, body, .. } => {
                cond.walk(f);
                each_node_expr(body, f);
            }
            Node::For {
                start,
                end,
                iter,
                body,
                ..
            } => {
                start.walk(f);
                end.walk(f);
                if let Some(it) = iter {
                    it.walk(f);
                }
                each_node_expr(body, f);
            }
            Node::Loop { body, .. } => each_node_expr(body, f),
            Node::Match { index, arms, .. } => {
                index.walk(f);
                for (_, b) in arms {
                    each_node_expr(b, f);
                }
            }
            Node::Return(_, Some(e)) | Node::TailCall(_, e) => e.walk(f),
            _ => {}
        }
    }
}

/// Rewrites every expression in `nodes` bottom-up with `f`.
fn map_node_exprs(nodes: &mut [Node], f: &mut impl FnMut(Expr) -> Expr) {
    fn one(e: &mut Expr, f: &mut impl FnMut(Expr) -> Expr) {
        let taken = std::mem::replace(e, Expr::Const(0, Width::B64));
        *e = taken.map(f);
    }
    for n in nodes {
        match n {
            Node::Stmt(_, s) => match s {
                Stmt::Assign(_, e) | Stmt::Eval(e) => one(e, f),
                Stmt::Store(a, v, _) => {
                    one(a, f);
                    one(v, f);
                }
                Stmt::Asm(..) => {}
            },
            Node::If {
                cond, then, els, ..
            } => {
                one(cond, f);
                map_node_exprs(then, f);
                map_node_exprs(els, f);
            }
            Node::While { cond, body, .. } => {
                one(cond, f);
                map_node_exprs(body, f);
            }
            Node::For {
                start,
                end,
                iter,
                body,
                ..
            } => {
                one(start, f);
                one(end, f);
                if let Some(it) = iter {
                    one(it, f);
                }
                map_node_exprs(body, f);
            }
            Node::Loop { body, .. } => map_node_exprs(body, f),
            Node::Match { index, arms, .. } => {
                one(index, f);
                for (_, b) in arms {
                    map_node_exprs(b, f);
                }
            }
            Node::Return(_, Some(e)) | Node::TailCall(_, e) => one(e, f),
            _ => {}
        }
    }
}

/// Counts the `slice[counter]` element *stores* in `nodes`.
fn count_elem_writes(nodes: &[Node], counter: Var, si: usize) -> usize {
    let mut n = 0;
    for node in nodes {
        match node {
            Node::Stmt(_, Stmt::Store(addr, _, w)) => {
                if *w == Width::B8 && is_elem_addr(addr, counter, si) {
                    n += 1;
                }
            }
            Node::If { then, els, .. } => {
                n += count_elem_writes(then, counter, si) + count_elem_writes(els, counter, si);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                n += count_elem_writes(body, counter, si)
            }
            Node::Match { arms, .. } => {
                n += arms
                    .iter()
                    .map(|(_, b)| count_elem_writes(b, counter, si))
                    .sum::<usize>();
            }
            _ => {}
        }
    }
    n
}

/// Turns `for i in 0..s.len() { ... s[i] ... }` into element iteration when the counter only
/// ever accesses the byte slice `s` (clippy's `needless_range_loop`). Read-only access gives
/// `for &x in s` (`s[i]` → the value `x`); writing gives `for x in s.iter_mut()` (`s[i]` →
/// `*x`). The counter variable is reused as the element binding.
pub fn recover_iterators(nodes: &mut [Node], sig: &crate::types::Signature) {
    use crate::types::Ty;
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_iterators(then, sig);
                recover_iterators(els, sig);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_iterators(body, sig)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_iterators(b, sig);
                }
            }
            _ => {}
        }
    }
    for n in nodes.iter_mut() {
        let Node::For {
            var,
            start,
            end,
            inclusive,
            iter,
            by_ref,
            index,
            body,
            ..
        } = n
        else {
            continue;
        };
        if iter.is_some() || *inclusive || !matches!(start, Expr::Const(0, _)) {
            continue;
        }
        // The bound must be a byte slice's length.
        let Expr::Param(len_idx, _) = end else {
            continue;
        };
        let len_idx = *len_idx;
        if len_idx == 0 || sig.params.get(len_idx) != Some(&Ty::SliceLen) {
            continue;
        }
        let si = len_idx - 1;
        let counter = *var;
        let (mut total, mut reads) = (0usize, 0usize);
        each_node_expr(body, &mut |x| {
            if matches!(x, Expr::Var(v, _) if *v == counter) {
                total += 1;
            }
            if is_elem_read(x, counter, si) {
                reads += 1;
            }
        });
        let writes = count_elem_writes(body, counter, si);
        if reads + writes == 0 || total < reads + writes {
            continue; // the bound slice isn't accessed by the counter.
        }
        // Counter uses that are not element accesses of this slice (a bare index).
        let bare = total - reads - writes;
        let mutable = writes > 0;
        // A written slice must be `&mut [u8]`; a read one `&[u8]` (either mutability).
        match sig.params.get(si) {
            Some(Ty::Slice(w, m, _, _)) if *w == Width::B8 && (!mutable || *m) => {}
            _ => continue,
        }
        if mutable && bare != 0 {
            continue; // index arithmetic through a mutable slice: leave as a range loop.
        }
        if mutable {
            // `s[counter]` → `*x`: rewrite the address so a load/store through it prints `*x`.
            map_node_exprs(body, &mut |e| {
                if is_elem_addr(&e, counter, si) {
                    Expr::Var(counter, Width::B64)
                } else {
                    e
                }
            });
            *iter = Some(Expr::Param(si, Width::B64));
            *by_ref = true;
        } else if bare == 0 {
            // `for &x in s`: the counter is only ever `s[counter]`, so it becomes the element.
            map_node_exprs(body, &mut |e| {
                if is_elem_read(&e, counter, si) {
                    Expr::Var(counter, Width::B8)
                } else {
                    e
                }
            });
            *iter = Some(Expr::Param(si, Width::B64));
        } else {
            // `for (i, &x) in s.iter().enumerate()`: the counter stays the index `i`, and a
            // fresh binding `x` takes each `s[i]` read.
            let elem = Var::Named("x");
            map_node_exprs(body, &mut |e| {
                if is_elem_read(&e, counter, si) {
                    Expr::Var(elem, Width::B8)
                } else {
                    e
                }
            });
            *var = elem;
            *index = Some(counter);
            *iter = Some(Expr::Param(si, Width::B64));
        }
    }
}

/// Collects element accesses by slice in `nodes`: `(slice, reads, writes)` counts for each
/// slice param indexed by `counter`.
fn slice_accesses(
    nodes: &[Node],
    counter: Var,
) -> std::collections::HashMap<usize, (usize, usize)> {
    let mut map: std::collections::HashMap<usize, (usize, usize)> =
        std::collections::HashMap::new();
    // Writes: stores whose address is `slice + counter`.
    fn writes(
        nodes: &[Node],
        counter: Var,
        map: &mut std::collections::HashMap<usize, (usize, usize)>,
    ) {
        for n in nodes {
            match n {
                Node::Stmt(_, Stmt::Store(addr, _, w)) if *w == Width::B8 => {
                    if let Some((i, Some(idx))) = crate::types::base_param(addr)
                        && matches!(idx, Expr::Var(v, _) if *v == counter)
                    {
                        map.entry(i).or_default().1 += 1;
                    }
                }
                Node::If { then, els, .. } => {
                    writes(then, counter, map);
                    writes(els, counter, map);
                }
                Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                    writes(body, counter, map)
                }
                _ => {}
            }
        }
    }
    writes(nodes, counter, &mut map);
    // Reads: byte loads of `slice + counter`.
    each_node_expr(nodes, &mut |e| {
        if let Expr::Load(addr, w) = e
            && *w == Width::B8
            && let Some((i, Some(idx))) = crate::types::base_param(addr)
            && matches!(idx, Expr::Var(v, _) if *v == counter)
        {
            map.entry(i).or_default().0 += 1;
        }
    });
    map
}

/// Turns `for i in 0..n { dst[i] = f(src[i]) }` into a zipped element map:
/// `for (d, &s) in dst.iter_mut().zip(src) { *d = f(s) }`, when the counter only accesses a
/// written byte slice `dst` and a read-only byte slice `src`.
pub fn recover_zip_map(nodes: &mut [Node], sig: &crate::types::Signature) {
    use crate::types::Ty;
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_zip_map(then, sig);
                recover_zip_map(els, sig);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_zip_map(body, sig)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_zip_map(b, sig);
                }
            }
            _ => {}
        }
    }
    for n in nodes.iter_mut() {
        let Node::For {
            var,
            start,
            end,
            inclusive,
            iter,
            by_ref,
            zip,
            body,
            ..
        } = n
        else {
            continue;
        };
        if iter.is_some() || *inclusive || !matches!(start, Expr::Const(0, _)) {
            continue;
        }
        let Expr::Param(len_idx, _) = end else {
            continue;
        };
        let len_idx = *len_idx;
        if len_idx == 0 || sig.params.get(len_idx) != Some(&Ty::SliceLen) {
            continue;
        }
        let counter = *var;
        let accesses = slice_accesses(body, counter);
        // Exactly one written slice (dst) and one read-only slice (src), distinct.
        let dst = accesses
            .iter()
            .filter(|(_, (_, w))| *w > 0)
            .map(|(s, _)| *s)
            .collect::<Vec<_>>();
        let src = accesses
            .iter()
            .filter(|(_, (r, w))| *r > 0 && *w == 0)
            .map(|(s, _)| *s)
            .collect::<Vec<_>>();
        if dst.len() != 1 || src.len() != 1 {
            continue;
        }
        let (dst, src) = (dst[0], src[0]);
        // `dst` is only written (a pure map output), the bound is one of the two slices, and
        // every counter use is one of these accesses.
        let (dr, dw) = accesses[&dst];
        let (sr, sw) = accesses[&src];
        let total_accesses = dr + dw + sr + sw;
        let mut counter_uses = 0;
        each_node_expr(body, &mut |x| {
            if matches!(x, Expr::Var(v, _) if *v == counter) {
                counter_uses += 1;
            }
        });
        if dr != 0 || sw != 0 || counter_uses != total_accesses {
            continue; // dst must be write-only, src read-only, nothing else uses the counter.
        }
        if len_idx - 1 != dst && len_idx - 1 != src {
            continue;
        }
        if !matches!(sig.params.get(dst), Some(Ty::Slice(w, true, _, _)) if *w == Width::B8)
            || !matches!(sig.params.get(src), Some(Ty::Slice(w, false, _, _)) if *w == Width::B8)
        {
            continue;
        }

        let s_bind = Var::Named("s");
        map_node_exprs(body, &mut |e| {
            if is_elem_addr(&e, counter, dst) {
                Expr::Var(counter, Width::B64) // `dst[i]` place → `*d`
            } else if is_elem_read(&e, counter, src) {
                Expr::Var(s_bind, Width::B8) // `src[i]` value → `s`
            } else {
                e
            }
        });
        *iter = Some(Expr::Param(dst, Width::B64));
        *by_ref = true;
        *zip = Some((Expr::Param(src, Width::B64), s_bind));
    }
}

/// Collapses `acc = init; for &x in s { acc = acc OP f(x) }` into an iterator fold:
/// `.map(|&x| f(x)).sum()` for `+ 0`, `.product()` for `* 1`, else
/// `.fold(init, |acc, &x| acc OP f(x))`.
pub fn recover_sum(nodes: &mut Vec<Node>) {
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_sum(then);
                recover_sum(els);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_sum(body)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_sum(b);
                }
            }
            _ => {}
        }
    }
    let mut i = 0;
    while i < nodes.len() {
        // A read-only element loop whose body is a single `acc = acc OP f(x)`.
        let Node::For {
            var,
            iter: Some(slice),
            by_ref: false,
            index: None,
            body,
            addr,
            ..
        } = &nodes[i]
        else {
            i += 1;
            continue;
        };
        let counter = *var;
        if body.len() != 1 {
            i += 1;
            continue;
        }
        // The reduction: `acc = E` where `E` reads both the accumulator and the element.
        let Node::Stmt(_, Stmt::Assign(acc, e)) = &body[0] else {
            i += 1;
            continue;
        };
        let acc = *acc;
        let e = e.clone();
        if acc == counter || !e.reads(counter) || !e.reads(acc) {
            i += 1;
            continue;
        }
        // The preceding statement must initialise the accumulator.
        let init = i.checked_sub(1).and_then(|p| match &nodes[p] {
            Node::Stmt(_, Stmt::Assign(v, e)) if *v == acc && !e.reads(counter) => Some(e.clone()),
            _ => None,
        });
        let Some(init) = init else {
            i += 1;
            continue;
        };
        let init_at = i - 1;

        let addr = *addr;
        let slice = slice.clone();
        let iter = Expr::method(slice, "iter", Vec::new(), Width::B64);
        // `acc = acc + f` with init 0 is `sum`; `acc = acc * f` with init 1 is `product`;
        // `f` must not itself read the accumulator.
        let reduction = match &e {
            Expr::Bin(op @ (BinOp::Add | BinOp::Mul), a, b, _)
                if matches!(&**a, Expr::Var(v, _) if *v == acc) && !b.reads(acc) =>
            {
                let ident = matches!(
                    (op, &init),
                    (BinOp::Add, Expr::Const(0, _)) | (BinOp::Mul, Expr::Const(1, _))
                );
                ident.then(|| {
                    let name = if *op == BinOp::Add { "sum" } else { "product" };
                    (name, (**b).clone())
                })
            }
            _ => None,
        };
        let chain = match reduction {
            // `acc += x` with no transform is a bare `.sum()`; only wrap in `.map()` when the
            // element is actually transformed.
            Some((name, Expr::Var(v, _))) if v == counter => {
                Expr::method(iter, name, Vec::new(), Width::B64)
            }
            Some((name, f)) => {
                let map = Expr::method(
                    iter,
                    "map",
                    vec![Expr::Closure(vec![(counter, true)], Box::new(f))],
                    Width::B64,
                );
                Expr::method(map, name, Vec::new(), Width::B64)
            }
            // Any other accumulation is a general `fold`: replace the accumulator in `E` with
            // a fresh binding. This covers xor, min/max (`acc.max(x)`) and keyed comparisons
            // (`if key(x) > key(acc) { x } else { acc }`, i.e. min_by / max_by).
            None => {
                let acc_bind = Var::Named("acc");
                let body = e.map(&mut |x| match x {
                    Expr::Var(v, w) if v == acc => Expr::Var(acc_bind, w),
                    other => other,
                });
                let closure =
                    Expr::Closure(vec![(acc_bind, false), (counter, true)], Box::new(body));
                Expr::method(iter, "fold", vec![init, closure], Width::B64)
            }
        };
        nodes[i] = Node::Stmt(addr, Stmt::Assign(acc, chain));
        nodes.remove(init_at); // the `acc = init`
        i = init_at + 1;
    }
}

/// The operator of a whole-slice reduction.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RedOp {
    Sum,
    Product,
    Max,
    Min,
}

/// Reduction recognition: proves (via prefix-range reasoning, not instruction shape-matching) that
/// the function reduces a whole slice — even when the compiler vectorised it into an `n < K`
/// dispatch, a packed loop, a horizontal reduce and a scalar remainder — and rewrites the body to
/// `return s.iter()…`. Handles sum (`+`), product (`*`), and max/min, over integer or float lanes.
///
/// The checks are semantic (the accumulator, the reduced slice, one operator throughout, the
/// identity/seed, and that a vectorised prefix plus the scalar remainder cover the slice), so it
/// folds only a genuine whole-slice reduction.
pub fn recover_reduction(body: &mut Vec<Node>, sig: &crate::types::Signature) {
    let Some((slice, op, addr)) = full_slice_reduction(body, sig) else {
        return;
    };
    // The element width (`&[T]`) sets a sum/product's type; max/min infer it.
    let w = match sig.params.get(slice) {
        Some(crate::types::Ty::Slice(ew, _, _, _)) => *ew,
        _ => Width::B32,
    };
    let s = Expr::Param(slice, Width::B64);
    let iter = Expr::method(s, "iter", Vec::new(), Width::B64);
    let expr = match op {
        RedOp::Sum => Expr::method(iter, "sum", Vec::new(), w),
        RedOp::Product => Expr::method(iter, "product", Vec::new(), w),
        RedOp::Max | RedOp::Min => {
            // No one std method reduces both integer and float lanes (`f32` is not `Ord`), so fold
            // with the element's own method: `s.iter().copied().reduce(|a, b| a.max(b)).unwrap()`.
            let name = if op == RedOp::Max { "max" } else { "min" };
            let copied = Expr::method(iter, "copied", Vec::new(), w);
            let (a, b) = (Var::Named("a"), Var::Named("b"));
            let call = Expr::method(Expr::Var(a, w), name, vec![Expr::Var(b, w)], w);
            let closure = Expr::Closure(vec![(a, false), (b, false)], Box::new(call));
            let reduced = Expr::method(copied, "reduce", vec![closure], w);
            Expr::method(reduced, "unwrap", Vec::new(), w)
        }
    };
    *body = vec![Node::Return(addr, Some(expr))];
}

fn as_var(e: &Expr) -> Option<Var> {
    match e {
        Expr::Var(v, _) => Some(*v),
        _ => None,
    }
}

/// The non-accumulator operand of `acc OP x` — where exactly one side is `acc` and the other does
/// not read it again.
fn non_acc<'a>(acc: Var, a: &'a Expr, b: &'a Expr) -> Option<&'a Expr> {
    if matches!(a, Expr::Var(v, _) if *v == acc) && !b.reads(acc) {
        Some(b)
    } else if matches!(b, Expr::Var(v, _) if *v == acc) && !a.reads(acc) {
        Some(a)
    } else {
        None
    }
}

/// Peels off any outer casts (e.g. the signed casts of a signed max/min).
fn strip_cast(e: &Expr) -> &Expr {
    match e {
        Expr::Cast(inner, ..) => strip_cast(inner),
        _ => e,
    }
}

/// If `e` is `acc OP x` for a recognised reduction operator, returns `(op, x)`: integer or float
/// `+`/`*`, or the `.max()`/`.min()` methods (both the scalar `maxss` idiom and `pmax` recovery).
fn reduction_op(e: &Expr, acc: Var) -> Option<(RedOp, &Expr)> {
    match e {
        Expr::Bin(BinOp::Add, a, b, _) | Expr::FBin(BinOp::Add, a, b, _) => {
            non_acc(acc, a, b).map(|x| (RedOp::Sum, x))
        }
        Expr::Bin(BinOp::Mul, a, b, _) | Expr::FBin(BinOp::Mul, a, b, _) => {
            non_acc(acc, a, b).map(|x| (RedOp::Product, x))
        }
        // A signed max/min wraps both operands in a signed cast (`(a as iN).max(b as iN)`); strip
        // them so the accumulator/element match still fires.
        Expr::Method(r, "max", args, _) if args.len() == 1 => {
            non_acc(acc, strip_cast(r), strip_cast(&args[0])).map(|x| (RedOp::Max, x))
        }
        Expr::Method(r, "min", args, _) if args.len() == 1 => {
            non_acc(acc, strip_cast(r), strip_cast(&args[0])).map(|x| (RedOp::Min, x))
        }
        _ => None,
    }
}

/// Visits every node depth-first, descending into every nested block.
fn visit_nodes(nodes: &[Node], f: &mut impl FnMut(&Node)) {
    for n in nodes {
        f(n);
        match n {
            Node::If { then, els, .. } => {
                visit_nodes(then, f);
                visit_nodes(els, f);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                visit_nodes(body, f)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms {
                    visit_nodes(b, f);
                }
            }
            _ => {}
        }
    }
}

/// A scalar remainder loop `{ acc = acc OP s[idx]; idx += 1; if idx == len { break } }` folding the
/// slice from `idx` to its length. Returns the slice, the operator and the index.
fn match_reduction_tail(
    loop_body: &[Node],
    acc: Var,
    sig: &crate::types::Signature,
) -> Option<(usize, RedOp, Var)> {
    let mut found: Option<(usize, RedOp, Var)> = None;
    let mut counts_to_len = false;
    for node in loop_body {
        match node {
            Node::Stmt(_, Stmt::Assign(v, e)) if *v == acc => {
                if let Some((op, elem)) = reduction_op(e, acc)
                    && let Some((si, iv)) = slice_elem(elem, sig)
                {
                    found = Some((si, op, iv));
                }
            }
            // The `if idx == len { break }` exit.
            Node::If {
                cond: Expr::Cmp(CmpOp::Eq, a, b, _),
                then,
                ..
            } if matches!(then.first(), Some(Node::Break(_))) => {
                for side in [&**a, &**b] {
                    if matches!(side, Expr::Param(i, _) if matches!(sig.params.get(*i), Some(crate::types::Ty::SliceLen)))
                    {
                        counts_to_len = true;
                    }
                }
            }
            _ => {}
        }
    }
    found.filter(|_| counts_to_len)
}

/// Whether `e` seeds the accumulator with the reduction's identity — `0` for sum, `1` for product —
/// or, for max/min (which have no identity the compiler uses), the slice's first element `s[0]`.
fn is_init(e: &Expr, op: RedOp, slice: usize) -> bool {
    match op {
        RedOp::Sum => matches!(e, Expr::Const(0, _) | Expr::FConst(0, _)),
        RedOp::Product => matches!(e, Expr::Const(1, _)),
        RedOp::Max | RedOp::Min => matches!(e, Expr::Load(addr, _)
            if matches!(crate::types::base_param(addr), Some((i, None)) if i == slice)),
    }
}

/// Whether `e` reads a packed-vector value (the horizontal reduce's result flowing into `acc`).
fn reads_vector(e: &Expr) -> bool {
    let mut hit = false;
    e.walk(&mut |x| {
        hit |= matches!(
            x,
            Expr::VecExtract(..)
                | Expr::VecReduce(..)
                | Expr::VecBin(..)
                | Expr::VecShuffle(..)
                | Expr::VecMax(..)
                | Expr::VecMin(..)
                | Expr::Var(Var::Xmm(_) | Var::XmmSplit(..), _)
        );
    });
    hit
}

/// Returns `(slice, op, return addr)` if the body provably computes a whole-slice reduction: a
/// vectorised prefix and a scalar remainder (counting to the length) fold the slice with one
/// operator, seeded by that operator's identity (sum/product) or the first element (max/min).
fn full_slice_reduction(
    body: &[Node],
    sig: &crate::types::Signature,
) -> Option<(usize, RedOp, u64)> {
    let (ret_addr, acc) = match body.last()? {
        Node::Return(a, Some(e)) => (*a, as_var(e)?),
        _ => return None,
    };
    // The scalar remainder loop (wherever it sits in the structure) fixes the slice, the operator
    // and the index.
    let mut tail = None;
    visit_nodes(body, &mut |n| {
        if tail.is_none()
            && let Node::Loop { body, .. } = n
        {
            tail = match_reduction_tail(body, acc, sig);
        }
    });
    let (slice, op, idx) = tail?;
    // Confidence signals gathered over the whole (possibly nested) body: the slice is loaded as a
    // packed vector, the horizontal reduce lands in `acc`, `idx` is a length-derived element count,
    // and `acc` is seeded with the operator's identity / first element.
    let mut vec_loads_slice = false;
    let mut acc_from_vector = false;
    let mut idx_from_len = false;
    let mut seeded = false;
    visit_nodes(body, &mut |n| {
        if let Node::Stmt(_, Stmt::Assign(v, e)) = n {
            if *v == acc && is_init(e, op, slice) {
                seeded = true;
            }
            if *v == acc && reads_vector(e) {
                acc_from_vector = true;
            }
            if *v == idx {
                e.walk(&mut |x| {
                    if matches!(x, Expr::Param(i, _) if matches!(sig.params.get(*i), Some(crate::types::Ty::SliceLen))) {
                        idx_from_len = true;
                    }
                });
            }
        }
    });
    each_node_expr(body, &mut |e| {
        e.walk(&mut |x| {
            if let Expr::VecLoad(a, _, _) = x
                && crate::types::addr_param(a) == Some(slice)
            {
                vec_loads_slice = true;
            }
        });
    });
    (vec_loads_slice && acc_from_vector && idx_from_len && seeded).then_some((slice, op, ret_addr))
}

/// The slice parameter and index variable of a slice element access `s[idx]`.
fn slice_elem(e: &Expr, sig: &crate::types::Signature) -> Option<(usize, Var)> {
    let Expr::Load(addr, _) = e else {
        return None;
    };
    let (i, off) = crate::types::base_param(addr)?;
    if !matches!(sig.params.get(i), Some(crate::types::Ty::Slice(..))) {
        return None;
    }
    let iv = match off? {
        Expr::Var(v, _) => *v,
        Expr::Bin(BinOp::Mul, a, _, _) => match &**a {
            Expr::Var(v, _) => *v,
            _ => return None,
        },
        _ => return None,
    };
    Some((i, iv))
}

/// Folds a fill loop `for x in s.iter_mut() { *x = v }` (where `v` does not depend on the
/// element) into `s.fill(v)`.
pub fn recover_fill(nodes: &mut [Node]) {
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_fill(then);
                recover_fill(els);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_fill(body)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_fill(b);
                }
            }
            _ => {}
        }
    }
    for n in nodes.iter_mut() {
        let Node::For {
            var,
            iter: Some(slice),
            by_ref: true,
            index: None,
            zip: None,
            body,
            addr,
            ..
        } = n
        else {
            continue;
        };
        if body.len() != 1 {
            continue;
        }
        let Node::Stmt(_, Stmt::Store(a, v, _)) = &body[0] else {
            continue;
        };
        if !matches!(a, Expr::Var(b, _) if *b == *var) || v.reads(*var) {
            continue;
        }
        let call = Expr::method(slice.clone(), "fill", vec![v.clone()], Width::B64);
        *n = Node::Stmt(*addr, Stmt::Eval(call));
    }
}

/// Recovers a counted **pointer-walk** loop — `p = base; c = len; loop { x = *p; p += W; c -= 1;
/// …; if c == 0 { break } }` — into element iteration `for &x in base { … }`, marking the base
/// parameter `&[T]` and the length parameter its `len()`. This is the compiler-idiomatic loop
/// shape (induction over a moving pointer rather than an index), common on ARM64 and optimized
/// x86. Downstream `recover_sum`/`recover_search` then fold reductions and searches as usual.
pub fn recover_pointer_loops(
    nodes: &mut Vec<Node>,
    sig: &mut crate::types::Signature,
    arg_regs: &[u8],
) {
    use crate::types::Ty;
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_pointer_loops(then, sig, arg_regs);
                recover_pointer_loops(els, sig, arg_regs);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_pointer_loops(body, sig, arg_regs)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_pointer_loops(b, sig, arg_regs);
                }
            }
            _ => {}
        }
    }
    let mut i = 0;
    while i < nodes.len() {
        let Node::Loop { addr, body } = &nodes[i] else {
            i += 1;
            continue;
        };
        let Some(w) = analyze_ptr_walk(body) else {
            i += 1;
            continue;
        };
        // The base and counter come from parameters: either an explicit `reg = Param` in a
        // preceding sibling, or an unmodified argument register walked in place.
        let base_param = nearest_init(&nodes[..i], w.ptr, arg_regs);
        let len_param = nearest_init(&nodes[..i], w.counter, arg_regs);
        let (Some((pb, pb_at)), Some((pc, pc_at))) = (base_param, len_param) else {
            i += 1;
            continue;
        };
        if pb >= sig.params.len() || pc >= sig.params.len() || pb == pc {
            i += 1;
            continue;
        }
        let addr = *addr;
        let mut payload = w.payload;
        // Canonicalise a commutative reduction so the accumulator is the left operand
        // (`x = e + x` → `x = x + e`), which lets `recover_sum` recognise `sum`/`product`.
        for n in &mut payload {
            if let Node::Stmt(
                _,
                Stmt::Assign(v, Expr::Bin(op @ (BinOp::Add | BinOp::Mul), a, b, bw)),
            ) = n
                && matches!(&**b, Expr::Var(x, _) if x == v)
                && !matches!(&**a, Expr::Var(x, _) if x == v)
            {
                std::mem::swap(a, b);
                let _ = (op, bw);
            }
        }
        // Retype: the base parameter is `&[T]` (`&mut` for a writing walk), the length parameter
        // is its `len()`.
        let signed = matches!(sig.params[pb], Ty::Slice(_, _, _, true));
        sig.params[pb] = Ty::Slice(w.elem, w.by_ref, false, signed);
        sig.params[pc] = Ty::SliceLen;
        nodes[i] = Node::For {
            addr,
            var: w.elem_var,
            start: Expr::konst(0, Width::B64),
            end: Expr::Param(pc, Width::B64),
            inclusive: false,
            iter: Some(Expr::Param(pb, Width::B64)),
            by_ref: w.by_ref,
            zip: None,
            index: None,
            body: payload,
        };
        // Drop any explicit base/counter initialisers (they are now the slice). An argument
        // register walked in place has no initialiser to remove.
        let mut dead: Vec<usize> = [pb_at, pc_at].into_iter().flatten().collect();
        dead.sort_unstable();
        for &idx in dead.iter().rev() {
            nodes.remove(idx);
        }
        i = i + 1 - dead.len(); // advance past the new `For`, accounting for removed siblings.
    }
}

/// What a recognised pointer-walk loop yields.
struct PtrWalk {
    ptr: u8,
    counter: u8,
    elem: Width,
    /// The element binding and whether it is `&mut` (`for x in s.iter_mut()`, each `*p` → `*x`)
    /// or by-value (`for &x in s`).
    elem_var: Var,
    by_ref: bool,
    payload: Vec<Node>,
}

/// Recognises the body of a counted pointer-walk loop and returns its parts, or `None`.
fn analyze_ptr_walk(body: &[Node]) -> Option<PtrWalk> {
    // The loop exits on `if c == 0 { break }` as its last node (after do-while tidying).
    let Node::If {
        cond, then, els, ..
    } = body.last()?
    else {
        return None;
    };
    if !els.is_empty() || then.len() != 1 || !matches!(then[0], Node::Break(_)) {
        return None;
    }
    let counter = match cond {
        Expr::Cmp(CmpOp::Eq, a, b, _) if matches!(&**b, Expr::Const(0, _)) => match &**a {
            Expr::Var(Var::Reg(c), _) => *c,
            _ => return None,
        },
        _ => return None,
    };
    let mut ptr = None;
    let mut stride = None;
    let mut counter_dec = false;
    let mut payload = Vec::new();
    for n in &body[..body.len() - 1] {
        match n {
            // `p = p + W` — the pointer bump; its stride is the element width.
            Node::Stmt(_, Stmt::Assign(Var::Reg(p), Expr::Bin(BinOp::Add, a, b, _)))
                if matches!(&**a, Expr::Var(Var::Reg(q), _) if q == p)
                    && matches!(&**b, Expr::Const(..)) =>
            {
                if ptr.is_some() {
                    return None; // two pointer bumps: not a simple walk.
                }
                ptr = Some(*p);
                if let Expr::Const(s, _) = &**b {
                    stride = Some(*s);
                }
            }
            // `c = c - 1` — the counter decrement.
            Node::Stmt(_, Stmt::Assign(Var::Reg(c), Expr::Bin(BinOp::Sub, a, b, _)))
                if *c == counter
                    && matches!(&**a, Expr::Var(Var::Reg(q), _) if *q == counter)
                    && matches!(&**b, Expr::Const(1, _)) =>
            {
                counter_dec = true;
            }
            other => payload.push(other.clone()),
        }
    }
    let ptr = ptr?;
    let stride = stride?;
    if !counter_dec {
        return None;
    }
    // The width (and `&[T]` element type) comes from the `*p` accesses, which must match the
    // walk stride.
    let elem = Width(stride as u8);
    if u64::from(elem.0) != stride {
        return None;
    }
    let writes = payload.iter().any(|n| writes_through(n, ptr));
    if writes {
        // Mutable walk: `for p in s.iter_mut() { … *p … }`. The pointer register is reused as
        // the element binding; its `*p` loads/stores print through the `iter_mut` binding.
        if !payload.iter().any(|n| accesses(n, ptr, elem)) {
            return None;
        }
        Some(PtrWalk {
            ptr,
            counter,
            elem,
            elem_var: Var::Reg(ptr),
            by_ref: true,
            payload,
        })
    } else {
        // Read-only walk: the first `x = *p` names the element; the rest of the body uses `x`.
        let pos = payload.iter().position(|n| {
            matches!(n, Node::Stmt(_, Stmt::Assign(_, Expr::Load(a, w)))
                if *w == elem && matches!(&**a, Expr::Var(Var::Reg(q), _) if *q == ptr))
        })?;
        let Node::Stmt(_, Stmt::Assign(elem_var, _)) = payload.remove(pos) else {
            return None;
        };
        if !payload.iter().any(|n| node_reads(n, elem_var)) {
            return None; // the element is never used.
        }
        Some(PtrWalk {
            ptr,
            counter,
            elem,
            elem_var,
            by_ref: false,
            payload,
        })
    }
}

/// The parameter a loop register holds entering the loop. If a preceding sibling assigns
/// `reg = Param(i)`, returns `(i, Some(node_idx))` (the initialiser can be dropped). If `reg` is
/// never assigned before the loop and is an argument register, it still holds its parameter, so
/// returns `(i, None)`. Any other assignment means it is not a clean parameter, so `None`.
fn nearest_init(prev: &[Node], reg: u8, arg_regs: &[u8]) -> Option<(usize, Option<usize>)> {
    for (idx, n) in prev.iter().enumerate().rev() {
        if let Node::Stmt(_, Stmt::Assign(Var::Reg(r), rhs)) = n
            && *r == reg
        {
            return match rhs {
                Expr::Param(p, _) => Some((*p, Some(idx))),
                _ => None,
            };
        }
    }
    arg_regs.iter().position(|&a| a == reg).map(|p| (p, None))
}

/// Whether a (flat) body node stores through the pointer register `ptr` (a bare `*p` write).
fn writes_through(n: &Node, ptr: u8) -> bool {
    matches!(n, Node::Stmt(_, Stmt::Store(a, _, _))
        if matches!(a, Expr::Var(Var::Reg(q), _) if *q == ptr))
}

/// Whether a (flat) body node loads or stores `*p` of width `w` through pointer `ptr`.
fn accesses(n: &Node, ptr: u8, w: Width) -> bool {
    let is_p = |e: &Expr| matches!(e, Expr::Var(Var::Reg(q), _) if *q == ptr);
    match n {
        Node::Stmt(_, Stmt::Store(a, _, sw)) => *sw == w && is_p(a),
        Node::Stmt(_, s) => {
            let mut hit = false;
            for e in s.exprs() {
                e.walk(&mut |x| {
                    if let Expr::Load(a, lw) = x
                        && *lw == w
                        && is_p(a)
                    {
                        hit = true;
                    }
                });
            }
            hit
        }
        _ => false,
    }
}

/// Whether a (flat) body node reads variable `v`.
fn node_reads(n: &Node, v: Var) -> bool {
    match n {
        Node::Stmt(_, s) => s.exprs().iter().any(|e| e.reads(v)),
        _ => false,
    }
}

/// Collapses an early-return search loop into `any` / `all`:
/// `for &x in s { if C { return R } } return D` becomes `return s.iter().any(|&x| C)` when
/// `R`/`D` are `true`/`false`, or `return s.iter().all(|&x| !C)` for `false`/`true`.
pub fn recover_search(nodes: &mut Vec<Node>) {
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                recover_search(then);
                recover_search(els);
            }
            Node::While { body, .. } | Node::Loop { body, .. } | Node::For { body, .. } => {
                recover_search(body)
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    recover_search(b);
                }
            }
            _ => {}
        }
    }
    let mut i = 0;
    while i < nodes.len() {
        let Node::For {
            var,
            iter: Some(slice),
            by_ref: false,
            index: None,
            body,
            addr,
            ..
        } = &nodes[i]
        else {
            i += 1;
            continue;
        };
        let counter = *var;
        // A leading `alias = x` copy (the element held in a register) is folded away so the
        // body is just the guard; references to `alias` then mean the element.
        let (guard_if, alias) = match body.as_slice() {
            [only] => (only, None),
            [Node::Stmt(_, Stmt::Assign(a, Expr::Var(v, _))), rest] if *v == counter => {
                (rest, Some(*a))
            }
            _ => {
                i += 1;
                continue;
            }
        };
        let subst = |e: &Expr| match alias {
            Some(a) => e.clone().map(&mut |x| match x {
                Expr::Var(v, w) if v == a => Expr::Var(counter, w),
                other => other,
            }),
            None => e.clone(),
        };
        // The body is a single `if C { return <value> }`.
        let (cond, ret) = match guard_if {
            Node::If {
                cond, then, els, ..
            } if els.is_empty() => match then.as_slice() {
                [Node::Return(_, Some(e))] => (subst(cond), subst(e)),
                _ => {
                    i += 1;
                    continue;
                }
            },
            _ => {
                i += 1;
                continue;
            }
        };
        // Followed by `return <default>`.
        let Some(Node::Return(_, Some(default))) = nodes.get(i + 1) else {
            i += 1;
            continue;
        };
        let default = default.clone();
        let addr = *addr;
        let iter = Expr::method(slice.clone(), "iter", Vec::new(), Width::B64);
        let call = match (&ret, &default) {
            // `if C { return true } … return false` → `any`; the mirror is `all`.
            (Expr::Const(r, _), Expr::Const(d, _)) => {
                let (name, test) = match (*r != 0, *d != 0) {
                    (true, false) => ("any", cond),
                    (false, true) => ("all", cond.negate()),
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                let closure = Expr::Closure(vec![(counter, true)], Box::new(test));
                Expr::method(iter, name, vec![closure], Width::B8)
            }
            // `if C { return x } … return d` → `s.iter().copied().find(|&x| C).unwrap_or(d)`.
            (Expr::Var(v, _), _) if *v == counter => {
                let copied = Expr::method(iter, "copied", Vec::new(), Width::B64);
                let closure = Expr::Closure(vec![(counter, true)], Box::new(cond));
                let found = Expr::method(copied, "find", vec![closure], Width::B64);
                Expr::method(found, "unwrap_or", vec![default], Width::B8)
            }
            _ => {
                i += 1;
                continue;
            }
        };
        nodes[i] = Node::Return(addr, Some(call));
        nodes.remove(i + 1); // the trailing `return <default>`
        i += 1;
    }
}

/// Closure parameters (from recovered iterator chains), which bind their own name and so
/// must not also be declared as locals.
pub fn closure_params(nodes: &[Node], out: &mut HashSet<Var>) {
    each_node_expr(nodes, &mut |e| {
        if let Expr::Closure(params, _) = e {
            out.extend(params.iter().map(|(v, _)| *v));
        }
    });
}

/// Loop variables bound by a recovered `for`, which should not also be declared as locals.
pub fn for_vars(nodes: &[Node], out: &mut HashSet<Var>) {
    for n in nodes {
        match n {
            Node::For {
                var, index, body, ..
            } => {
                out.insert(*var);
                if let Some(idx) = index {
                    out.insert(*idx);
                }
                for_vars(body, out);
            }
            Node::If { then, els, .. } => {
                for_vars(then, out);
                for_vars(els, out);
            }
            Node::While { body, .. } | Node::Loop { body, .. } => for_vars(body, out),
            Node::Match { arms, .. } => {
                for (_, b) in arms {
                    for_vars(b, out);
                }
            }
            _ => {}
        }
    }
}

/// Structures a function's blocks into nested nodes.
/// Drop statements that follow an unconditional divergence (break/continue/return/stop/tail-call)
/// within a node list — they are unreachable (e.g. a `continue` followed by a dead `break` from a
/// loop with a duplicated exit tail). Recurses into nested control flow.
fn prune_after_diverge(nodes: &mut Vec<Node>) {
    for n in nodes.iter_mut() {
        match n {
            Node::If { then, els, .. } => {
                prune_after_diverge(then);
                prune_after_diverge(els);
            }
            Node::Loop { body, .. } | Node::While { body, .. } | Node::For { body, .. } => {
                prune_after_diverge(body);
            }
            Node::Match { arms, .. } => {
                for (_, b) in arms.iter_mut() {
                    prune_after_diverge(b);
                }
            }
            _ => {}
        }
    }
    if let Some(i) = nodes.iter().position(|n| {
        matches!(
            n,
            Node::Break(_)
                | Node::Continue(_)
                | Node::BreakLabel(_)
                | Node::ContinueLabel(_)
                | Node::Return(..)
                | Node::Stop(_)
                | Node::TailCall(..)
        )
    }) {
        nodes.truncate(i + 1);
    }
}

pub fn structure(blocks: Vec<Block>, entry: u64) -> Vec<Node> {
    let mut s = Structurer::new(blocks, entry);
    let mut nodes = s.region(entry, None);
    // Blocks never reached by structured flow (only through gotos) come last.
    let mut rest: Vec<u64> =
        s.g.order
            .iter()
            .copied()
            .filter(|b| !s.emitted.contains(b))
            .collect();
    rest.sort_unstable();
    for b in rest {
        if !s.emitted.contains(&b) {
            s.gotos.insert(b);
            nodes.extend(s.region(b, None));
        }
    }
    let _ = s.g.entry;
    prune_after_diverge(&mut nodes);
    nodes
}
