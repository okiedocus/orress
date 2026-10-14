//! Type recovery, in the spirit of decy's ownership inference: how a value is *used*
//! decides its Rust type. A parameter that is dereferenced is a reference; one that is
//! written through is `&mut`; a pointer followed by a length that the code compares
//! is a slice (`&[u8]` / `&str` arrive as exactly such a pair); a function that only
//! returns comparisons and 0/1 returns `bool`.

use std::collections::{BTreeMap, HashMap};

use crate::ir::*;

/// A recovered struct field: its byte offset from the start of the struct, its access width,
/// and whether it is used as a signed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub offset: u64,
    pub width: Width,
    pub signed: bool,
}

impl Field {
    /// The field's Rust name, which encodes its byte offset (`field_8`).
    pub fn name(&self) -> String {
        format!("field_{}", self.offset)
    }
}

/// A recovered struct layout: the fields a pointer parameter is accessed through, by offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructLayout {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Int(Width, bool),
    Bool,
    /// `&T` / `&mut T` where T is an integer of this width.
    Ref(Width, bool),
    /// `&[T]` / `&mut [T]`; the length is the next parameter. The bools are, in order: `&mut`,
    /// floating-point element (`&[f32]` / `&[f64]`, set when accessed as a packed-float vector),
    /// and signed element (`&[i32]` vs `&[u32]`, set when an element feeds a signed operation).
    Slice(Width, bool, bool, bool),
    /// The length half of a slice parameter.
    SliceLen,
    /// A floating-point value (`f32` for width 4, `f64` for width 8).
    Float(Width),
    /// `&Struct` / `&mut Struct`: a pointer accessed through constant field offsets.
    Struct(StructLayout, bool),
}

impl Ty {
    pub fn rust(&self) -> String {
        match self {
            Self::Int(w, s) => w.rust(*s).to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::Ref(w, m) => format!("&{}{}", if *m { "mut " } else { "" }, w.rust(false)),
            Self::Slice(w, m, f, s) => {
                let elem = if *f {
                    if w.0 == 4 { "f32" } else { "f64" }
                } else {
                    w.rust(*s)
                };
                format!("&{}[{}]", if *m { "mut " } else { "" }, elem)
            }
            Self::SliceLen => "usize".to_owned(),
            Self::Float(w) => if w.0 == 4 { "f32" } else { "f64" }.to_owned(),
            Self::Struct(l, m) => format!("&{}{}", if *m { "mut " } else { "" }, l.name),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub params: Vec<Ty>,
    pub ret: Option<Ty>,
}

#[derive(Default, Clone, Copy)]
struct Use {
    width: u8,
    deref: Option<Width>,
    written: bool,
    indexed: bool,
    signed: bool,
    compared: bool,
    /// The parameter's elements are accessed as floating-point (a packed-float vector load/store),
    /// so a slice of it is `&[f32]` / `&[f64]`.
    float: bool,
}

/// The parameter index an address is ultimately based on, seeing through nested offsets such as
/// `(p + i*4) + 4` (a vector loop that starts at element 1). Used for the float-element signal,
/// where only *which* parameter the access is on matters, not the exact offset form.
pub fn addr_param(addr: &Expr) -> Option<usize> {
    let mut found = None;
    addr.walk(&mut |x| {
        if let Expr::Param(i, _) = x {
            found = Some(*i);
        }
    });
    found
}

/// The parameter an address is based on: `p`, `p + x` or `x + p`.
pub fn base_param(addr: &Expr) -> Option<(usize, Option<&Expr>)> {
    match addr {
        Expr::Param(i, _) => Some((*i, None)),
        Expr::Bin(BinOp::Add, a, b, _) => match (&**a, &**b) {
            (Expr::Param(i, _), x) | (x, Expr::Param(i, _)) => Some((*i, Some(x))),
            _ => None,
        },
        _ => None,
    }
}

fn strip_cast(e: &Expr) -> &Expr {
    match e {
        Expr::Cast(a, _, _) => strip_cast(a),
        other => other,
    }
}

/// Records a dereference of a pointer parameter at a byte offset: a constant offset is a struct
/// field (widening the field if seen at multiple widths); a variable offset marks the parameter
/// as array-indexed instead.
fn record_field(
    map: &mut BTreeMap<u64, Width>,
    var_indexed: &mut bool,
    off: Option<&Expr>,
    w: Width,
) {
    let k = match off {
        None => 0,
        Some(Expr::Const(k, _)) => *k,
        Some(_) => {
            *var_indexed = true;
            return;
        }
    };
    let e = map.entry(k).or_insert(w);
    *e = (*e).max(w);
}

fn all_exprs(blocks: &[Block]) -> Vec<(&Expr, bool)> {
    let mut out = Vec::new();
    for b in blocks {
        for (_, s) in &b.stmts {
            match s {
                // The address of a store is written through.
                Stmt::Store(a, v, _) => {
                    out.push((a, true));
                    out.push((v, false));
                }
                other => out.extend(other.exprs().into_iter().map(|e| (e, false))),
            }
        }
        match &b.term {
            Term::Branch(c, _, _) => out.push((c, false)),
            Term::Return(Some(e)) | Term::TailCall(e) => out.push((e, false)),
            _ => {}
        }
    }
    out
}

fn is_boolish(e: &Expr) -> bool {
    e.is_condition()
        || matches!(e, Expr::Const(0 | 1, _))
        || matches!(e, Expr::Cast(a, _, false) if a.is_condition())
}

/// Infers the signature of a simplified function.
/// Recovers the function signature. `n_int` is how many of the `params` are passed in integer
/// registers; the rest (`params - n_int`) are floating-point parameters in XMM registers.
/// `float_ret`, when set, is the width of a floating-point return value (in xmm0).
pub fn infer(
    blocks: &[Block],
    params: usize,
    returns: bool,
    n_int: usize,
    float_ret: Option<Width>,
) -> Signature {
    let mut uses = vec![Use::default(); params];
    // Per-parameter struct evidence: the constant offsets it is dereferenced at (with their
    // widths), and whether it is ever indexed by a variable (which makes it an array, not a
    // struct).
    let mut field_map: Vec<BTreeMap<u64, Width>> = vec![BTreeMap::new(); params];
    let mut field_signed: Vec<BTreeMap<u64, bool>> = vec![BTreeMap::new(); params];
    let mut var_indexed = vec![false; params];
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Store(a, val, w) = s
                && !val.is_vector()
                && let Some((i, off)) = base_param(a)
                && i < params
            {
                uses[i].deref = Some(uses[i].deref.map_or(*w, |d| d.max(*w)));
                uses[i].written = true;
                uses[i].indexed |= off.is_some_and(|o| !matches!(o, Expr::Const(..)));
                record_field(&mut field_map[i], &mut var_indexed[i], off, *w);
            }
            // A packed *float* store to a parameter marks the element type float, so that — once
            // the parameter is a slice from its scalar-element evidence — it types as `&[f32]`.
            // (Slice-vs-pointer is still decided by the scalar/length evidence, so a pure-vector
            // pointer with no length stays a raw pointer.)
            if let Stmt::Store(a, val, _) = s
                && val.vec_shape().is_some_and(|(_, l)| l.float)
                && let Some(i) = addr_param(a)
                && i < params
            {
                uses[i].float = true;
            }
        }
    }
    for (e, _) in all_exprs(blocks) {
        e.walk(&mut |x| match x {
            Expr::Param(i, w) if *i < params => uses[*i].width = uses[*i].width.max(w.0),
            Expr::Load(a, w) => {
                if let Some((i, off)) = base_param(a)
                    && i < params
                {
                    uses[i].deref = Some(uses[i].deref.map_or(*w, |d| d.max(*w)));
                    uses[i].indexed |= off.is_some_and(|o| !matches!(o, Expr::Const(..)));
                    // A constant offset beyond the first element also means "array".
                    uses[i].indexed |=
                        off.is_some_and(|o| matches!(o, Expr::Const(k, _) if *k > 0));
                    record_field(&mut field_map[i], &mut var_indexed[i], off, *w);
                }
            }
            // A packed *float* load from a parameter marks its element type float (so a slice of
            // it is `&[f32]`); slice-vs-pointer stays decided by the scalar/length evidence.
            Expr::VecLoad(a, _, lane) if lane.float => {
                if let Some(i) = addr_param(a)
                    && i < params
                {
                    uses[i].float = true;
                }
            }
            Expr::Cmp(_, a, c, signed) => {
                for side in [a, c] {
                    if let Expr::Param(i, _) = strip_cast(side)
                        && *i < params
                    {
                        uses[*i].compared = true;
                        uses[*i].signed |= *signed;
                    }
                }
            }
            // A parameter reinterpreted by a signed cast (e.g. a signed-division operand), or
            // converted to a float by the signed `cvtsi2*`, is itself signed.
            Expr::Cast(a, _, true) | Expr::FCast(a, _, FCast::SIntToFloat) => {
                if let Expr::Param(i, _) = strip_cast(a)
                    && *i < params
                {
                    uses[*i].signed = true;
                }
                // A sign-extended field load (`movsx eax, byte [rdi+4]`) → that field is signed.
                if let Expr::Load(addr, _) = strip_cast(a)
                    && let Some((i, off)) = base_param(addr)
                    && i < params
                {
                    let k = match off {
                        Some(Expr::Const(k, _)) => *k,
                        None => 0,
                        // A variable index is a slice element, not a fixed field: the slice's
                        // element type is signed (`&[i32]`).
                        _ => {
                            uses[i].signed = true;
                            return;
                        }
                    };
                    field_signed[i].insert(k, true);
                }
            }
            _ => {}
        });
    }

    let mut tys: Vec<Ty> = uses
        .iter()
        .map(|u| match u.deref {
            Some(w) if u.indexed => Ty::Slice(w, u.written, u.float, u.signed),
            Some(w) => Ty::Ref(w, u.written),
            None => Ty::Int(Width(if u.width == 0 { 8 } else { u.width }), u.signed),
        })
        .collect();
    // A pointer dereferenced through constant offsets with *mixed widths* (which an array
    // cannot express), or at a single non-zero offset, is a struct: `&Struct` / `&mut Struct`.
    // Uniform-width offsets stay an array/slice (ambiguous, and `p[0]`/`p[1]` reads fine). A
    // variable index is a definite array, never a struct.
    let mut next_struct = 0;
    for i in 0..params {
        if var_indexed[i] {
            continue;
        }
        let fm = &field_map[i];
        let widths: std::collections::BTreeSet<u8> = fm.values().map(|w| w.0).collect();
        let has_nonzero = fm.keys().any(|&k| k > 0);
        if !fm.is_empty() && (widths.len() > 1 || (fm.len() == 1 && has_nonzero)) {
            next_struct += 1;
            let fields = fm
                .iter()
                .map(|(&offset, &width)| Field {
                    offset,
                    width,
                    signed: field_signed[i].get(&offset).copied().unwrap_or(false),
                })
                .collect();
            let name = format!("Struct{next_struct}");
            tys[i] = Ty::Struct(StructLayout { name, fields }, uses[i].written);
        }
    }
    // (pointer, length) pairs become one slice parameter.
    for i in 0..tys.len().saturating_sub(1) {
        let as_slice = match &tys[i] {
            Ty::Ref(w, m) => Some((*w, *m, uses[i].float, uses[i].signed)),
            Ty::Slice(w, m, f, s) => Some((*w, *m, *f, *s)),
            _ => None,
        };
        if let Some((w, m, f, s)) = as_slice
            && matches!(tys[i + 1], Ty::Int(..))
            && uses[i + 1].compared
        {
            tys[i] = Ty::Slice(w, m, f, s);
            tys[i + 1] = Ty::SliceLen;
        }
    }
    // Floating-point parameters (the trailing XMM arguments) are `f32`/`f64`; their width
    // comes from how they are used (an `sd` op reads 8 bytes, `ss` 4).
    for (i, ty) in tys.iter_mut().enumerate().skip(n_int) {
        *ty = Ty::Float(Width(if uses[i].width == 0 { 8 } else { uses[i].width }));
    }

    if let Some(w) = float_ret {
        return Signature {
            params: tys,
            ret: Some(Ty::Float(w)),
        };
    }

    let ret = returns.then(|| {
        let mut rets = Vec::new();
        let mut rax_defs = Vec::new();
        for b in blocks {
            if let Term::Return(Some(e)) = &b.term {
                rets.push(e);
            }
            for (_, s) in &b.stmts {
                if let Stmt::Assign(Var::Reg(RAX), e) = s {
                    rax_defs.push(e);
                }
            }
        }
        let boolish = |e: &&Expr| match e {
            Expr::Var(Var::Reg(RAX), _) => {
                !rax_defs.is_empty() && rax_defs.iter().all(|d| is_boolish(d))
            }
            other => is_boolish(other),
        };
        if !rets.is_empty()
            && rets.iter().all(boolish)
            && rets
                .iter()
                .chain(&rax_defs)
                .any(|e| !matches!(e, Expr::Const(..)) || matches!(e, Expr::Const(1, _)))
        {
            Ty::Bool
        } else {
            // The width of the actual computed value pins the return type; a bare `return rax`
            // takes it from rax's definitions. Constants (e.g. a `return 0` fallthrough, which
            // the lifter widens to the register) do not pin it, since a small constant fits any
            // integer width. Only if every return is constant do the constants decide.
            let defs_width = |consts: bool| {
                rax_defs
                    .iter()
                    .filter(|d| consts || !matches!(d, Expr::Const(..)))
                    .map(|d| d.width())
                    .max()
            };
            let value_width = |e: &&Expr, consts: bool| match e {
                Expr::Var(Var::Reg(RAX), _) => defs_width(consts),
                Expr::Const(..) if !consts => None,
                other => Some(other.width()),
            };
            let w = rets
                .iter()
                .filter_map(|e| value_width(e, false))
                .max()
                .or_else(|| rets.iter().filter_map(|e| value_width(e, true)).max())
                .unwrap_or(Width::B64);
            // Signed when the returned value is produced by a signed operation (a bare
            // `return rax` takes it from rax's definitions).
            let signed = rax_defs.iter().any(|e| is_signed_expr(e))
                || rets
                    .iter()
                    .any(|e| !matches!(e, Expr::Var(Var::Reg(RAX), _)) && is_signed_expr(e));
            Ty::Int(w, signed)
        }
    });
    Signature { params: tys, ret }
}

/// Local variables that are slice indices or lengths and so should be `usize`: a value derived
/// from a slice-length parameter, used to index a slice, or compared against either (propagated
/// through `==`/`!=` comparisons to a fixpoint).
pub fn usize_locals(blocks: &[Block], sig: &Signature) -> std::collections::BTreeSet<Var> {
    use std::collections::BTreeSet;
    let is_len = |i: usize| matches!(sig.params.get(i), Some(Ty::SliceLen));
    let is_slice = |i: usize| matches!(sig.params.get(i), Some(Ty::Slice(..)));
    let reads_len = |e: &Expr| {
        let mut hit = false;
        e.walk(&mut |x| {
            if let Expr::Param(i, _) = x
                && is_len(*i)
            {
                hit = true;
            }
        });
        hit
    };
    // The variable used to index `off` (`v` or `v * stride`).
    let index_var = |off: &Expr| -> Option<Var> {
        match off {
            Expr::Var(v, _) => Some(*v),
            Expr::Bin(BinOp::Mul, a, _, _) => match &**a {
                Expr::Var(v, _) => Some(*v),
                _ => None,
            },
            _ => None,
        }
    };
    let mut set: BTreeSet<Var> = BTreeSet::new();
    // `==`/`!=` comparisons link two operands' usize-ness; a SliceLen operand seeds it.
    let mut edges: Vec<(Var, Option<Var>)> = Vec::new(); // (local, other local or None = a length)
    let note_cmp =
        |a: &Expr, b: &Expr, set: &mut BTreeSet<Var>, edges: &mut Vec<(Var, Option<Var>)>| {
            let var = |e: &Expr| {
                matches!(strip_cast(e), Expr::Var(_, _)).then(|| match strip_cast(e) {
                    Expr::Var(v, _) => *v,
                    _ => unreachable!(),
                })
            };
            let len = |e: &Expr| matches!(strip_cast(e), Expr::Param(i, _) if is_len(*i));
            match (var(a), var(b)) {
                (Some(va), Some(vb)) => edges.push((va, Some(vb))),
                (Some(va), None) if len(b) => {
                    set.insert(va);
                }
                (None, Some(vb)) if len(a) => {
                    set.insert(vb);
                }
                _ => {}
            }
        };
    let scan_expr = |e: &Expr, set: &mut BTreeSet<Var>, edges: &mut Vec<(Var, Option<Var>)>| {
        e.walk(&mut |x| match x {
            Expr::Load(a, _) => {
                if let Some((i, Some(off))) = base_param(a)
                    && is_slice(i)
                    && let Some(v) = index_var(off)
                {
                    set.insert(v);
                }
            }
            Expr::Cmp(CmpOp::Eq | CmpOp::Ne, a, b, _) => note_cmp(a, b, set, edges),
            _ => {}
        });
    };
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Assign(v, e) = s
                && reads_len(e)
            {
                set.insert(*v);
            }
            if let Stmt::Store(a, _, _) = s
                && let Some((i, Some(off))) = base_param(a)
                && is_slice(i)
                && let Some(iv) = index_var(off)
            {
                set.insert(iv);
            }
            for e in s.exprs() {
                scan_expr(e, &mut set, &mut edges);
            }
        }
        if let Term::Branch(e, _, _) = &b.term {
            scan_expr(e, &mut set, &mut edges);
        }
    }
    // Propagate usize-ness across comparison edges to a fixpoint.
    let mut changed = true;
    while changed {
        changed = false;
        for &(a, b) in &edges {
            let (ina, inb) = (set.contains(&a), b.is_some_and(|v| set.contains(&v)));
            if ina != inb {
                if ina && let Some(v) = b {
                    changed |= set.insert(v);
                } else if inb {
                    changed |= set.insert(a);
                }
            }
        }
    }
    set
}

/// Whether an expression is floating-point: a float literal, float arithmetic, a conversion
/// whose result is a float, or an XMM-register value.
pub fn is_float_expr(e: &Expr) -> bool {
    matches!(
        e,
        Expr::FConst(..)
            | Expr::FBin(..)
            | Expr::FUn(..)
            | Expr::FCast(_, _, FCast::SIntToFloat | FCast::FloatToFloat)
            | Expr::Var(Var::Xmm(_), _)
    )
}

/// Local variables (stack slots) that hold a floating-point value, so they declare as `f32`/`f64`
/// rather than an integer. The width comes from [`locals`].
pub fn float_locals(blocks: &[Block]) -> std::collections::BTreeSet<Var> {
    let mut out = std::collections::BTreeSet::new();
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Assign(v, e) = s
                && is_float_expr(e)
            {
                out.insert(*v);
            }
        }
    }
    out
}

/// Local variables (registers/stack slots) that hold a packed vector, with their `[T; N]`
/// shape (lane count, lane width) — so they declare as a lane array.
pub fn vec_locals(blocks: &[Block]) -> std::collections::BTreeMap<Var, (u8, Lane)> {
    let mut out = std::collections::BTreeMap::new();
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Assign(v, e) = s
                && let Some(shape) = e.vec_shape()
            {
                out.insert(*v, shape);
            }
        }
    }
    out
}

/// Whether an expression produces a signed value: a sign-extending cast, an arithmetic
/// shift, a negation, or signed arithmetic built from those.
pub fn is_signed_expr(e: &Expr) -> bool {
    match e {
        Expr::Cast(_, _, true) | Expr::Neg(..) => true,
        // A float → integer truncation (`cvttsd2si`) yields a signed integer.
        Expr::FCast(_, _, FCast::FloatToSInt) => true,
        Expr::Bin(BinOp::Sar, ..) => true,
        Expr::Bin(_, a, b, _) => is_signed_expr(a) || is_signed_expr(b),
        // A signed max/min (built with signed-cast operands) yields a signed value.
        Expr::Method(recv, "max" | "min", ..) => is_signed_expr(recv),
        _ => false,
    }
}

/// Marks variables compared with a signed comparison as signed.
fn mark_signed_cmps(e: &Expr, signed: &mut std::collections::HashSet<Var>) {
    e.walk(&mut |x| {
        if let Expr::Cmp(_, a, b, true) = x {
            for side in [&**a, &**b] {
                if let Expr::Var(v, _) = strip_cast(side) {
                    signed.insert(*v);
                }
            }
        }
    });
}

/// Declared types of the local variables (stack slots and leftover registers): width, and
/// whether the variable is used as a signed value.
pub fn locals(blocks: &[Block]) -> BTreeMap<Var, (Width, bool)> {
    let mut out: HashMap<Var, Width> = HashMap::new();
    let mut signed: std::collections::HashSet<Var> = std::collections::HashSet::new();
    let widen = |e: &Expr, out: &mut HashMap<Var, Width>| {
        e.walk(&mut |x| {
            if let Expr::Var(v, w) = x {
                let cur = out.entry(*v).or_insert(*w);
                *cur = (*cur).max(*w);
            }
        });
    };
    for b in blocks {
        for (_, s) in &b.stmts {
            if let Stmt::Assign(v, e) = s {
                let w = out.entry(*v).or_insert(e.width());
                *w = (*w).max(e.width());
                if is_signed_expr(e) {
                    signed.insert(*v);
                }
            }
            // A register captured as an `asm!` output is a 64-bit local too.
            for v in s.defs() {
                out.entry(v).or_insert(Width::B64);
            }
            for e in s.exprs() {
                widen(e, &mut out);
                mark_signed_cmps(e, &mut signed);
            }
        }
        match &b.term {
            // A bare `return reg` reads the whole register, so its width is the ABI
            // register width (always 64-bit from the lifter), not the variable's. Letting
            // it widen the local inflates e.g. a `u32` accumulator to `u64`, so the port's
            // `acc += x as u32` and `return acc;` no longer type-check. The function's
            // return type (from `infer`) governs what is returned, so skip the bare case.
            Term::Return(Some(Expr::Var(..))) => {}
            Term::Branch(e, _, _) | Term::Return(Some(e)) => {
                widen(e, &mut out);
                mark_signed_cmps(e, &mut signed);
            }
            _ => {}
        }
    }
    out.into_iter()
        .map(|(v, w)| (v, (w, signed.contains(&v))))
        .collect()
}
