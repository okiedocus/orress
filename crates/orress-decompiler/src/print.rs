//! Printing structured IR as Rust-syntax pseudocode, as coloured tokens with the
//! machine address each line came from (so the view can follow the cursor).

use std::collections::{BTreeMap, HashMap};

use orress_analysis::Program;

use crate::ir::*;
use crate::structure::Node;
use crate::types::{Signature, Ty, base_param};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokKind {
    Keyword,
    Type,
    /// A function name; `Span::target` holds its address.
    Function,
    Variable,
    Param,
    Number,
    Str,
    Comment,
    Punct,
}

#[derive(Clone, Debug)]
pub struct Span {
    pub text: String,
    pub kind: TokKind,
    /// The address this token refers to (a function or global), for navigation.
    pub target: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Line {
    /// The first machine instruction this line was produced from.
    pub addr: Option<u64>,
    pub indent: usize,
    pub spans: Vec<Span>,
}

impl Line {
    pub fn text(&self) -> String {
        let mut s = "    ".repeat(self.indent);
        for sp in &self.spans {
            s.push_str(&sp.text);
        }
        s
    }
}

pub struct Printer<'a> {
    pub program: &'a Program,
    pub sig: &'a Signature,
    pub locals: &'a BTreeMap<Var, (Width, bool)>,
    /// Local stack slots that hold a floating-point value (declared `f32`/`f64`).
    pub float_locals: &'a std::collections::BTreeSet<Var>,
    /// Locals that hold a packed vector, with their `[T; N]` shape (lanes, lane width).
    pub vec_locals: &'a std::collections::BTreeMap<Var, (u8, Lane)>,
    /// Locals that are slice indices/lengths, declared `usize`.
    pub usize_locals: &'a std::collections::BTreeSet<Var>,
    pub returns: bool,
    lines: Vec<Line>,
    cur: Line,
    indent: usize,
    /// Lengths of string literals, from the (pointer, length) pairs Rust passes around.
    str_lens: HashMap<u64, usize>,
    /// Port mode: emit compilable Rust (qualified `orress_rt::` helpers, real inline `asm!`)
    /// rather than readable pseudocode.
    port: bool,
    /// Element bindings of the enclosing `for x in s.iter_mut()` loops: a load/store through
    /// one of these prints as `*x` / `*x = v`.
    iter_mut: Vec<Var>,
}

/// Binding strength, higher binds tighter (Rust's operator precedence).
/// Whether any `BreakLabel`/`ContinueLabel` within `nodes` targets loop `header` (recursing into
/// nested control-flow), i.e. whether that loop needs a printed Rust label.
fn body_has_label(nodes: &[Node], header: u64) -> bool {
    nodes.iter().any(|n| match n {
        Node::BreakLabel(h) | Node::ContinueLabel(h) => *h == header,
        Node::If { then, els, .. } => body_has_label(then, header) || body_has_label(els, header),
        Node::Loop { body, .. } | Node::While { body, .. } | Node::For { body, .. } => {
            body_has_label(body, header)
        }
        Node::Match { arms, .. } => arms.iter().any(|(_, b)| body_has_label(b, header)),
        _ => false,
    })
}

fn prec(e: &Expr) -> u8 {
    match e {
        Expr::LOr(..) => 1,
        Expr::LAnd(..) => 2,
        Expr::Cmp(..) => 3,
        Expr::Bin(op, ..) => match op {
            BinOp::Or => 4,
            BinOp::Xor => 5,
            BinOp::And => 6,
            BinOp::Shl | BinOp::Shr | BinOp::Sar => 7,
            BinOp::Add | BinOp::Sub => 8,
            BinOp::Mul | BinOp::Div | BinOp::Rem => 9,
        },
        Expr::FCmp(..) => 3,
        Expr::FBin(op, ..) => match op {
            BinOp::Or => 4,
            BinOp::Xor => 5,
            BinOp::And => 6,
            BinOp::Shl | BinOp::Shr | BinOp::Sar => 7,
            BinOp::Add | BinOp::Sub => 8,
            BinOp::Mul | BinOp::Div | BinOp::Rem => 9,
        },
        Expr::Cast(..) | Expr::FCast(..) => 10,
        Expr::Neg(..) | Expr::Not(..) | Expr::LNot(..) | Expr::FUn(FUnOp::Neg, ..) => 11,
        Expr::Select(..) | Expr::Closure(..) => 0,
        _ => 12,
    }
}

pub fn param_name(i: usize) -> String {
    format!("a{}", i + 1)
}

/// A Rust float literal from raw bits, suffixed with its type (`3.5f64`, `1.5f32`), or a named
/// constant for a non-finite value.
fn float_literal(bits: u64, w: Width) -> String {
    let (v, ty) = if w.0 == 4 {
        (f64::from(f32::from_bits(bits as u32)), "f32")
    } else {
        (f64::from_bits(bits), "f64")
    };
    if !v.is_finite() {
        return if v.is_nan() {
            format!("{ty}::NAN")
        } else if v > 0.0 {
            format!("{ty}::INFINITY")
        } else {
            format!("{ty}::NEG_INFINITY")
        };
    }
    let mut s = format!("{v:?}");
    if !s.contains(['.', 'e', 'E']) {
        s.push_str(".0");
    }
    // `f64` is Rust's default float type, so a bare literal already infers it; only `f32`
    // literals need the suffix to type-check (and to read unambiguously).
    if ty == "f32" {
        s.push_str(ty);
    }
    s
}

fn escape(s: &str) -> String {
    s.chars().flat_map(char::escape_default).collect()
}

impl<'a> Printer<'a> {
    pub fn new(
        program: &'a Program,
        sig: &'a Signature,
        locals: &'a BTreeMap<Var, (Width, bool)>,
        float_locals: &'a std::collections::BTreeSet<Var>,
        vec_locals: &'a std::collections::BTreeMap<Var, (u8, Lane)>,
        usize_locals: &'a std::collections::BTreeSet<Var>,
        returns: bool,
    ) -> Self {
        Self {
            program,
            sig,
            locals,
            float_locals,
            vec_locals,
            usize_locals,
            returns,
            lines: Vec::new(),
            cur: Line::default(),
            indent: 0,
            str_lens: HashMap::new(),
            port: false,
            iter_mut: Vec::new(),
        }
    }

    /// Switches to port mode: the output is a compilable Rust scaffold.
    pub fn port_mode(mut self) -> Self {
        self.port = true;
        self
    }

    /// Prints `e` coerced to `to`, as `(e) as uN`, when its width differs and we are emitting
    /// compilable Rust.
    ///
    /// Rust has no implicit integer conversions, and a decompiled body mixes widths constantly: a
    /// 64-bit register holding a 32-bit argument, a byte loaded into a word, a 32-bit result
    /// returned from a function the ABI types as 64-bit. Every one is a hard error, and they were
    /// the single largest reason no emitted port compiled.
    ///
    /// Always parenthesised. `as` binds tighter than any binary operator, so `a - b as u64` would
    /// cast only `b` — silently changing the arithmetic rather than failing to build.
    fn coerced(&mut self, e: &Expr, to: Width, signed: bool, prec_level: u8) {
        let Some((have, _)) = self.declared_int(e) else {
            self.value(e, prec_level);
            return;
        };
        if !self.port || have == to {
            self.value(e, prec_level);
            return;
        }
        self.p("(");
        self.value(e, 0);
        self.p(")");
        self.kw(" as ");
        self.tok(to.rust(signed), TokKind::Type);
    }

    /// Whether an expression has a **concrete** integer type that a cast can safely restate.
    ///
    /// An allow-list, not a deny-list, because the dangerous cases are the ones that infer their
    /// type from where they are used: casting `a1.iter().map(..).sum()` makes it
    /// `(..).sum() as u32`, and `sum` then has nothing to infer its output from, so the port stops
    /// compiling for a new reason. Floating-point and packed-vector expressions are excluded for
    /// the obvious reason — an integer cast would change what they mean, or not typecheck at all.
    fn declared_int(&self, e: &Expr) -> Option<(Width, bool)> {
        match e {
            // A variable prints with the type it was DECLARED with, which type inference may have
            // narrowed below the register width the IR node still carries. Comparing the IR width
            // is what left `rax_2 = arg_4` (u64 = u32) without a cast.
            Expr::Var(v, w) => match self.int_local_width(v) {
                Some(decl) => Some(decl),
                // Not in `locals` and not a float/vector/usize local: a plain register temporary,
                // which does print at its IR width.
                None if !self.float_locals.contains(v)
                    && !self.usize_locals.contains(v)
                    && !self.vec_locals.contains_key(v) =>
                {
                    Some((*w, false))
                }
                None => None,
            },
            // A parameter only has an integer type when the signature says so. A slice-length
            // parameter prints as `a3.len()` and is a `usize`; casting it makes the whole
            // expression that width, and the `usize` local it feeds then rejects it.
            Expr::Param(i, _) => match self.sig.params.get(*i as usize) {
                Some(Ty::Int(w, signed)) => Some((*w, *signed)),
                _ => None,
            },
            Expr::Const(_, w) | Expr::Load(_, w) | Expr::Bin(_, _, _, w) | Expr::Neg(_, w)
            | Expr::Not(_, w) | Expr::Cast(_, w, _) => Some((*w, false)),
            // Everything else — iterator chains, methods, floats, vectors — infers its type from
            // context or is not an integer at all.
            _ => None,
        }
    }

    /// The declared integer type of a local, for assignments to coerce to. `None` for anything
    /// that is not a plain integer — floats, vectors and `usize` locals have their own types and a
    /// width cast would be wrong.
    fn int_local_width(&self, v: &Var) -> Option<(Width, bool)> {
        if self.float_locals.contains(v)
            || self.usize_locals.contains(v)
            || self.vec_locals.contains_key(v)
        {
            return None;
        }
        self.locals.get(v).copied()
    }

    /// The module path prefix for memory helpers (`orress_rt::` in port mode, nothing otherwise).
    fn rt(&self) -> &'static str {
        if self.port { "orress_rt::" } else { "" }
    }

    fn tok(&mut self, text: impl Into<String>, kind: TokKind) {
        self.cur.spans.push(Span {
            text: text.into(),
            kind,
            target: None,
        });
    }

    fn link(&mut self, text: impl Into<String>, kind: TokKind, target: u64) {
        self.cur.spans.push(Span {
            text: text.into(),
            kind,
            target: Some(target),
        });
    }

    fn p(&mut self, text: &str) {
        self.tok(text, TokKind::Punct);
    }

    fn kw(&mut self, text: &str) {
        self.tok(text, TokKind::Keyword);
    }

    fn start(&mut self, addr: Option<u64>) {
        self.cur.addr = addr;
        self.cur.indent = self.indent;
    }

    fn end(&mut self) {
        let line = std::mem::take(&mut self.cur);
        self.lines.push(line);
    }

    /// A variable's printed name. Registers are named per architecture (ARM64 `x0`… vs x86
    /// `rax`…); stack slots and synthesised bindings are architecture-neutral.
    fn var_name(&self, v: &Var) -> String {
        match v {
            _ if self.program.isa != orress_analysis::Isa::Arm64 => v.to_string(),
            Var::Reg(r) => format!("x{r}"),
            Var::Split(r, v) => format!("x{r}_{v}"),
            Var::Xmm(r) => format!("d{r}"),
            Var::XmmSplit(r, v) => format!("d{r}_{v}"),
            _ => v.to_string(),
        }
    }

    fn func_name(&self, addr: u64) -> String {
        let raw = self
            .program
            .name(addr)
            .map_or_else(|| format!("sub_{addr:x}"), |n| n.text.clone());
        // Readable output keeps the symbol exactly as the binary spells it; a port has to be
        // valid Rust, and the two must agree with the stub declarations either way.
        if self.port { rust_ident(&raw) } else { raw }
    }

    fn number(&mut self, v: u64, w: Width) {
        // Print the true unsigned value. An all-ones constant is NOT rendered as `-1` here: this
        // path has no signedness context, and `-1` is wrong (value and port type) in an unsigned
        // position such as `x & 0xffffffff` or an unsigned `x == 0xff`. Signed contexts that want a
        // negative literal (e.g. a signed comparison) render it themselves before calling here.
        let _ = w;
        let text = if v < 10 {
            v.to_string()
        } else if v >= 0x100 || v.is_multiple_of(0x10) && v >= 0x10 {
            format!("{v:#x}")
        } else {
            v.to_string()
        };
        self.tok(text, TokKind::Number);
    }

    fn byte_or_number(&mut self, e: &Expr) {
        if let Expr::Const(v, w) = e
            && w.0 == 1
            && (0x20..0x7f).contains(v)
        {
            let c = char::from(*v as u8);
            let lit = match c {
                '\'' => "b'\\''".to_owned(),
                '\\' => "b'\\\\'".to_owned(),
                c => format!("b'{c}'"),
            };
            self.tok(lit, TokKind::Str);
            return;
        }
        self.expr(e, 0);
    }

    fn param(&mut self, i: usize) {
        let ty = self.sig.params.get(i);
        if ty == Some(&Ty::SliceLen) && i > 0 {
            self.tok(param_name(i - 1), TokKind::Param);
            self.p(".");
            self.tok("len", TokKind::Function);
            self.p("()");
        } else {
            self.tok(param_name(i), TokKind::Param);
        }
    }

    /// Whether an inline-asm input value can be bound: a constant, parameter or computed value
    /// that simplification resolved to a register-sized integer. A bare register that stayed
    /// unresolved has no known value (risking an uninitialised-variable port), and a non-integer
    /// parameter (a slice or reference) is not a register value, so both are left unbound.
    fn asm_input_ok(&self, e: &Expr) -> bool {
        match e {
            Expr::Var(Var::Reg(_), _) => false,
            Expr::Param(i, _) => matches!(self.sig.params.get(*i), Some(Ty::Int(..)) | None),
            _ => true,
        }
    }

    /// Prints an inline-asm input value cast to the register width (`… as u64`), so the input
    /// type matches the output register.
    fn asm_input(&mut self, e: &Expr) {
        self.expr(e, 11);
        self.kw(" as ");
        self.tok("u64", TokKind::Type);
    }

    /// Prints a slice index expression — cast to `usize` in port mode (a slice index must be
    /// `usize`, but the recovered arithmetic is a register width). Readable mode keeps `x`.
    fn idx(&mut self, e: &Expr) {
        if self.port {
            self.expr(e, 11);
            self.kw(" as ");
            self.tok("usize", TokKind::Type);
        } else {
            self.expr(e, 0);
        }
    }

    /// If `addr` is a slice parameter plus some byte offset, returns that parameter's index and
    /// the offset expression (a vector access base that should read/write slice-relatively).
    fn vec_slice_base(&self, addr: &Expr) -> Option<(usize, Expr)> {
        fn peel(e: &Expr) -> Option<(usize, Expr)> {
            match e {
                Expr::Param(i, _) => Some((*i, Expr::konst(0, Width::B64))),
                Expr::Bin(BinOp::Add, a, b, w) => peel(a)
                    .map(|(i, off)| (i, Expr::bin(BinOp::Add, off, (**b).clone(), *w)))
                    .or_else(|| {
                        peel(b).map(|(i, off)| (i, Expr::bin(BinOp::Add, off, (**a).clone(), *w)))
                    }),
                _ => None,
            }
        }
        let (i, off) = peel(addr)?;
        matches!(self.sig.params.get(i), Some(Ty::Slice(..))).then_some((i, off))
    }

    /// Prints a vector access's element index from its byte offset: `(off / elem) as usize`,
    /// or `0` when the offset is zero.
    fn vec_index(&mut self, byte_off: &Expr, elem: Width) {
        let byte_off = crate::simplify::fold(byte_off.clone());
        if matches!(byte_off, Expr::Const(0, _)) {
            self.number(0, Width::B64);
            return;
        }
        self.p("(");
        self.expr(&byte_off, 9);
        self.p(" / ");
        self.number(u64::from(elem.0), Width::B64);
        self.p(")");
        self.kw(" as ");
        self.tok("usize", TokKind::Type);
    }

    /// `s[i]` for an element read from a slice / reference parameter.
    fn element(&mut self, addr: &Expr, w: Width) -> bool {
        let Some((i, off)) = base_param(addr) else {
            return false;
        };
        match self.sig.params.get(i) {
            Some(Ty::Slice(ew, _, _, _)) if *ew == w => {
                self.tok(param_name(i), TokKind::Param);
                self.p("[");
                match off {
                    None => self.number(0, Width::B64),
                    Some(Expr::Const(k, cw)) => self.number(k / u64::from(w.0), *cw),
                    Some(Expr::Bin(BinOp::Mul, x, k, _)) if matches!(&**k, Expr::Const(n, _) if *n == u64::from(w.0)) => {
                        self.idx(x)
                    }
                    Some(x) if w.0 == 1 => self.idx(x),
                    Some(x) => {
                        // A scaled offset `x / w`, cast to `usize` in port mode.
                        if self.port {
                            self.p("(");
                        }
                        self.expr(x, 9);
                        self.p(" / ");
                        self.number(u64::from(w.0), Width::B64);
                        if self.port {
                            self.p(")");
                            self.kw(" as ");
                            self.tok("usize", TokKind::Type);
                        }
                    }
                }
                self.p("]");
                true
            }
            Some(Ty::Ref(rw, _)) if *rw == w && off.is_none() => {
                self.p("*");
                self.tok(param_name(i), TokKind::Param);
                true
            }
            // `p.field_8` for a field access of a struct pointer parameter.
            Some(Ty::Struct(layout, _)) => {
                let o = match off {
                    None => 0,
                    Some(Expr::Const(k, _)) => *k,
                    _ => return false,
                };
                let Some(f) = layout.fields.iter().find(|f| f.offset == o && f.width == w) else {
                    return false;
                };
                self.tok(param_name(i), TokKind::Param);
                self.p(".");
                self.tok(layout.field_name(f), TokKind::Variable);
                true
            }
            _ => false,
        }
    }

    pub fn expr(&mut self, e: &Expr, min: u8) {
        let paren = prec(e) < min;
        if paren {
            self.p("(");
        }
        match e {
            Expr::Const(v, w) => self.number(*v, *w),
            Expr::Var(v, _) => self.tok(self.var_name(v), TokKind::Variable),
            Expr::Param(i, _) => self.param(*i),
            Expr::Load(a, w) => {
                if let Expr::Var(v, _) = &**a
                    && self.iter_mut.contains(v)
                {
                    // `*x` for a read through an `iter_mut` element binding.
                    self.p("*");
                    self.tok(self.var_name(v), TokKind::Variable);
                } else if !self.element(a, *w) {
                    self.tok(format!("{}read", self.rt()), TokKind::Function);
                    self.p("::<");
                    self.tok(w.rust(false), TokKind::Type);
                    self.p(">(");
                    self.expr(a, 0);
                    self.p(")");
                }
            }
            Expr::Bin(op, a, b, w) => {
                let pr = prec(e);
                // `Sar` is an arithmetic shift-right; Rust `>>` is arithmetic only when the left
                // operand is signed, so cast it (`(a as iN) >> b`). `Shr` stays logical.
                if matches!(op, BinOp::Sar) {
                    self.signed(a);
                } else {
                    self.coerced(a, *w, false, pr);
                }
                self.p(&format!(" {} ", op.symbol()));
                // A shift's right operand is a count, not a value of the result type: Rust accepts
                // any integer width there, and casting it would only add noise.
                if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                    self.value(b, pr + 1);
                } else {
                    self.coerced(b, *w, false, pr + 1);
                }
            }
            Expr::Neg(a, _) => {
                self.p("-");
                self.expr(a, 11);
            }
            Expr::Not(a, _) => {
                self.p("!");
                self.expr(a, 11);
            }
            Expr::LNot(a) => {
                self.p("!");
                self.expr(a, 11);
            }
            Expr::Cmp(op, a, b, signed) => {
                let (a, b) = (strip_trivial_cast(a), strip_trivial_cast(b));
                // In a signed comparison the left operand must be signed. Type inference already
                // types plain Var/Param operands (`mark_signed_cmps`), but not a Load or other
                // expression — cast those explicitly, including when the RHS is a constant (the
                // `x < 5` signed case, which previously printed an unsigned compare).
                if *signed
                    && (!matches!(a, Expr::Var(..) | Expr::Param(..))
                        || !matches!(b, Expr::Const(..)))
                {
                    self.signed(a);
                } else {
                    self.expr(a, 4);
                }
                self.p(&format!(" {} ", op.symbol()));
                if *signed && matches!(b, Expr::Const(v, w) if *v > w.mask() >> 1) {
                    // Negative constant in a signed comparison.
                    if let Expr::Const(v, w) = b {
                        let neg = (w.mask() - v + 1) & w.mask();
                        self.tok(format!("-{neg}"), TokKind::Number);
                    }
                } else if *signed && !matches!(b, Expr::Const(..)) {
                    self.signed(b);
                } else {
                    self.byte_or_number_at(b, 4);
                }
            }
            Expr::LAnd(a, b) => {
                self.expr(a, 2);
                self.p(" && ");
                self.expr(b, 3);
            }
            Expr::LOr(a, b) => {
                self.expr(a, 1);
                self.p(" || ");
                self.expr(b, 2);
            }
            // The low half of a call result (`eax` after a call) is just the call — but in
            // port mode keep the `as` cast, since the stub returns a fixed-width `u64`.
            Expr::Cast(a, _, _) if !self.port && matches!(&**a, Expr::Call(..)) => {
                self.expr(a, min)
            }
            // A signed cast of a parameter already of that signed type is redundant (e.g. a
            // signed-division operand whose parameter was inferred `iN`).
            Expr::Cast(a, w, true)
                if matches!(&**a, Expr::Param(i, pw)
                    if pw == w && self.sig.params.get(*i) == Some(&Ty::Int(*w, true))) =>
            {
                if let Expr::Param(i, _) = &**a {
                    self.param(*i);
                }
            }
            Expr::Cast(a, w, s) => {
                self.expr(a, 10);
                self.kw(" as ");
                self.tok(w.rust(*s), TokKind::Type);
            }
            Expr::Call(t, args) => self.call(t, args),
            Expr::Addr(a) => self.global(*a),
            Expr::StackAddr(off) => {
                // A port needs a `u64` it can do arithmetic on, and the address of the local is
                // exactly what the original code had. The pseudocode keeps the readable borrow.
                if self.port {
                    self.p("(&mut ");
                    self.tok(Var::Stack(*off).to_string(), TokKind::Variable);
                    self.kw(" as ");
                    self.p("*mut _");
                    self.kw(" as ");
                    self.tok("u64", TokKind::Type);
                    self.p(")");
                } else {
                    self.p("&mut ");
                    self.tok(Var::Stack(*off).to_string(), TokKind::Variable);
                }
            }
            Expr::Select(c, a, b, _) => {
                self.kw("if ");
                self.expr(c, 0);
                self.p(" { ");
                self.expr(a, 0);
                self.p(" } ");
                self.kw("else");
                self.p(" { ");
                self.expr(b, 0);
                self.p(" }");
            }
            // `movd eax, xmm` (lifted as `xmm.to_bits()`) where `xmm` is a vector local extracts
            // lane 0.
            Expr::Method(recv, "to_bits", args, _)
                if args.is_empty()
                    && matches!(&**recv, Expr::Var(v, _) if self.vec_locals.contains_key(v)) =>
            {
                self.value(recv, 12);
                self.p("[0]");
            }
            Expr::Method(recv, name, args, _) => {
                // The receiver binds tightest; parenthesise it if it's looser. A `Load` can
                // render as a deref (`*a1`), which must be parenthesised before `.method()`.
                if matches!(&**recv, Expr::Load(..)) {
                    self.p("(");
                    self.expr(recv, 0);
                    self.p(")");
                } else {
                    self.value(recv, 12);
                }
                self.p(".");
                self.tok(*name, TokKind::Function);
                self.p("(");
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        self.p(", ");
                    }
                    self.expr(a, 0);
                }
                self.p(")");
            }
            Expr::Closure(params, body) => {
                self.p("|");
                for (i, (v, by_ref)) in params.iter().enumerate() {
                    if i > 0 {
                        self.p(", ");
                    }
                    if *by_ref {
                        self.p("&");
                    }
                    self.tok(self.var_name(v), TokKind::Variable);
                }
                self.p("| ");
                self.expr(body, 0);
            }
            Expr::FConst(bits, w) => {
                self.tok(float_literal(*bits, *w), TokKind::Number);
            }
            Expr::FBin(op, a, b, _) => {
                let pr = prec(e);
                self.fexpr(a, pr);
                self.p(&format!(" {} ", op.symbol()));
                self.fexpr(b, pr + 1);
            }
            Expr::FUn(FUnOp::Neg, a, _) => {
                self.p("-");
                self.fexpr(a, 11);
            }
            Expr::FUn(op, a, _) => {
                self.fexpr(a, 12);
                self.p(".");
                self.tok(
                    if *op == FUnOp::Abs { "abs" } else { "sqrt" },
                    TokKind::Function,
                );
                self.p("()");
            }
            Expr::FCmp(op, a, b) => {
                self.fexpr(a, 4);
                self.p(&format!(" {} ", op.symbol()));
                self.fexpr(b, 4);
            }
            // Float → float (`cvtss2sd`): `x as f64`. Int → float and float → int are the same
            // `as` surface syntax; the result width and kind pick the target type.
            Expr::FCast(a, w, kind) => {
                let ty = match kind {
                    FCast::FloatToSInt => w.rust(true),
                    FCast::SIntToFloat | FCast::FloatToFloat => {
                        if w.0 == 4 {
                            "f32"
                        } else {
                            "f64"
                        }
                    }
                };
                // Int → float casts from a plain integer operand; float → * from a float one.
                if matches!(kind, FCast::SIntToFloat) {
                    self.expr(a, 10);
                } else {
                    self.fexpr(a, 10);
                }
                self.kw(" as ");
                self.tok(ty, TokKind::Type);
            }
            // Packed-vector (SIMD) values, modelled as `[T; N]` lane arrays with `orress_rt`
            // element-wise helpers (the vector-IR groundwork; a later pass folds a vectorised
            // reduction into `.iter().sum()`).
            Expr::VecImm(v, n, w) => {
                self.p("[");
                self.number(*v, w.width);
                self.kw(" as ");
                self.tok(w.rust(), TokKind::Type);
                self.p(&format!("; {n}]"));
            }
            Expr::VecSplat(a, n, w) => {
                self.p("[");
                self.expr(a, 10);
                self.kw(" as ");
                self.tok(w.rust(), TokKind::Type);
                self.p(&format!("; {n}]"));
            }
            Expr::VecLoad(a, n, w) => {
                // A vector load whose base is a slice parameter reads slice-relatively
                // (`vload_slice(a1, i)`), so the one `&[T]` type serves the vector and element
                // uses; otherwise it is a raw-address load.
                if let Some((i, byte_off)) = self.vec_slice_base(a) {
                    self.tok(format!("{}vload_slice", self.rt()), TokKind::Function);
                    self.p("::<");
                    self.tok(w.rust(), TokKind::Type);
                    self.p(&format!(", {n}>("));
                    self.tok(param_name(i), TokKind::Param);
                    self.p(", ");
                    self.vec_index(&byte_off, w.width);
                    self.p(")");
                } else {
                    self.tok(format!("{}vload", self.rt()), TokKind::Function);
                    self.p("::<");
                    self.tok(w.rust(), TokKind::Type);
                    self.p(&format!(", {n}>("));
                    self.expr(a, 0);
                    self.p(")");
                }
            }
            Expr::VecBin(op, a, b, _, _) => {
                let name = match op {
                    BinOp::Add => "vadd",
                    BinOp::Sub => "vsub",
                    BinOp::Mul => "vmul",
                    BinOp::Div => "vdiv",
                    BinOp::And => "vand",
                    BinOp::Or => "vor",
                    _ => "vxor",
                };
                self.tok(format!("{}{name}", self.rt()), TokKind::Function);
                self.p("(");
                self.expr(a, 0);
                self.p(", ");
                self.expr(b, 0);
                self.p(")");
            }
            Expr::VecShuffle(a, imm, _, w) => {
                self.tok(format!("{}vshuffle", self.rt()), TokKind::Function);
                self.p("::<");
                self.tok(w.rust(), TokKind::Type);
                self.p(">(");
                self.expr(a, 0);
                self.p(", ");
                self.number(u64::from(*imm), Width::B8);
                self.p(")");
            }
            Expr::VecExtract(a, lane, _) => {
                self.value(a, 12);
                self.p(&format!("[{lane}]"));
            }
            // Packed lane-wise max/min and the compare/blend primitives.
            Expr::VecMax(a, b, _, _) => self.vec_call("vmax", a, b),
            Expr::VecMin(a, b, _, _) => self.vec_call("vmin", a, b),
            Expr::VecGt(a, b, _, _) => self.vec_call("vgt", a, b),
            Expr::VecAndn(a, b, _, _) => self.vec_call("vandn", a, b),
            // A horizontal lane reduction: `v.iter().sum::<T>()` / `.product::<T>()`, or
            // `v.iter().copied().max()/.min().unwrap()` (a lane array is non-empty, so `unwrap`).
            Expr::VecReduce(op, a, w) => {
                self.value(a, 12);
                self.p(".");
                self.tok("iter", TokKind::Function);
                self.p("()");
                match op {
                    ReduceOp::Add | ReduceOp::Mul => {
                        self.p(".");
                        let name = if *op == ReduceOp::Mul {
                            "product"
                        } else {
                            "sum"
                        };
                        self.tok(name, TokKind::Function);
                        self.p("::<");
                        self.tok(w.rust(), TokKind::Type);
                        self.p(">()");
                    }
                    ReduceOp::Max | ReduceOp::Min => {
                        self.p(".");
                        self.tok("copied", TokKind::Function);
                        self.p("().");
                        self.tok(
                            if *op == ReduceOp::Max { "max" } else { "min" },
                            TokKind::Function,
                        );
                        self.p("().");
                        self.tok("unwrap", TokKind::Function);
                        self.p("()");
                    }
                }
            }
            Expr::Unknown(s) => {
                let what = if s == "clobbered" {
                    "changed by the call above"
                } else {
                    s.as_str()
                };
                self.tok(format!("{}unknown", self.rt()), TokKind::Function);
                // `unknown<T>` panics, so T is never used — but Rust still has to know it, and an
                // `Unknown` node carries no width to pick from. In a comparison such as
                // `unknown("dh") != 0` there is nothing to infer from either, which left three
                // ports failing on `E0283` alone.
                if self.port {
                    self.p("::<");
                    self.tok("u64", TokKind::Type);
                    self.p(">");
                }
                self.p("(");
                self.tok(format!("\"{}\"", escape(what)), TokKind::Str);
                self.p(")");
            }
        }
        if paren {
            self.p(")");
        }
    }

    /// Prints an expression known to be floating-point. A raw memory `Load` becomes a typed
    /// float read (`read::<f64>(addr)`); every other float value already carries its type (a
    /// float node, a float parameter, a register value), so it prints normally.
    fn fexpr(&mut self, e: &Expr, min: u8) {
        if let Expr::Load(a, w) = e {
            // A float element of a float slice parameter reads as `s[i]` (already `f32`/`f64`),
            // not a raw `read::<f32>(ptr)`.
            if self.is_float_slice_base(a) && self.element(a, *w) {
                return;
            }
            self.tok(format!("{}read", self.rt()), TokKind::Function);
            self.p("::<");
            self.tok(if w.0 == 4 { "f32" } else { "f64" }, TokKind::Type);
            self.p(">(");
            self.expr(a, 0);
            self.p(")");
        } else {
            self.expr(e, min);
        }
    }

    /// Whether `addr` is an element of a floating-point slice parameter (`&[f32]` / `&[f64]`).
    fn is_float_slice_base(&self, addr: &Expr) -> bool {
        base_param(addr)
            .is_some_and(|(i, _)| matches!(self.sig.params.get(i), Some(Ty::Slice(_, _, true, _))))
    }

    /// A two-operand packed-vector helper call `rt::name(a, b)`.
    fn vec_call(&mut self, name: &str, a: &Expr, b: &Expr) {
        self.tok(format!("{}{name}", self.rt()), TokKind::Function);
        self.p("(");
        self.expr(a, 0);
        self.p(", ");
        self.expr(b, 0);
        self.p(")");
    }

    /// A condition used as a number: `(a < b) as u64`.
    fn value(&mut self, e: &Expr, min: u8) {
        if e.is_condition() {
            self.p("(");
            self.expr(e, 0);
            self.p(")");
            self.kw(" as ");
            self.tok("u64", TokKind::Type);
        } else {
            self.expr(e, min);
        }
    }

    fn byte_or_number_at(&mut self, e: &Expr, min: u8) {
        if matches!(e, Expr::Const(..)) {
            self.byte_or_number(e);
        } else {
            self.expr(e, min);
        }
    }

    fn signed(&mut self, e: &Expr) {
        match e {
            Expr::Param(i, w) if matches!(self.sig.params.get(*i), Some(Ty::Int(_, true))) => {
                let _ = w;
                self.param(*i);
            }
            Expr::Const(..) => self.expr(e, 4),
            other => {
                // Parenthesize the cast: as a comparison LHS, `x as i32 < y` is otherwise parsed
                // by Rust as generic arguments to `i32` and fails to compile.
                self.p("(");
                self.expr(other, 10);
                self.kw(" as ");
                self.tok(other.width().rust(true), TokKind::Type);
                self.p(")");
            }
        }
    }

    fn global(&mut self, a: u64) {
        if let Some(s) = self.program.string_refs.get(&a) {
            let text = match self.str_lens.get(&a) {
                Some(&n) if n <= s.len() && s.is_char_boundary(n) => s[..n].to_owned(),
                // One past the end: the text ended in a newline the string scan stopped at.
                Some(&n) if n == s.len() + 1 => format!(
                    "{s}
"
                ),
                _ => s.clone(),
            };
            self.link(format!("\"{}\"", escape(&text)), TokKind::Str, a);
        } else if let Some(n) = self.program.name(a) {
            let is_fn = self.program.functions.contains_key(&a);
            let kind = if is_fn { TokKind::Function } else { TokKind::Variable };
            let text = if self.port { rust_ident(&n.text) } else { n.text.clone() };
            if is_fn {
                // A function name is an *item* in Rust: it cannot be added to or subtracted from,
                // which is what `__mingw_SEH_error_handler - rbp` tried to do.
                if self.port {
                    self.p("(");
                    self.link(text, kind, a);
                    self.kw(" as ");
                    self.tok("usize", TokKind::Type);
                    self.kw(" as ");
                    self.tok("u64", TokKind::Type);
                    self.p(")");
                } else {
                    self.link(text, kind, a);
                }
            } else {
                // In a port the global is declared as its ADDRESS (`const data_x: u64 = 0x...`),
                // so the name alone is already the `u64` the read/write helpers want.
                if !self.port {
                    self.p("&");
                }
                self.link(text, kind, a);
            }
        } else if self.program.functions.contains_key(&a) {
            let name = format!("sub_{a:x}");
            if self.port {
                self.p("(");
                self.link(name, TokKind::Function, a);
                self.kw(" as ");
                self.tok("usize", TokKind::Type);
                self.kw(" as ");
                self.tok("u64", TokKind::Type);
                self.p(")");
            } else {
                self.link(name, TokKind::Function, a);
            }
        } else {
            if !self.port {
                self.p("&");
            }
            self.link(format!("data_{a:x}"), TokKind::Variable, a);
        }
    }

    fn call(&mut self, t: &CallTarget, args: &[Expr]) {
        match t {
            CallTarget::Direct(a) | CallTarget::Import(a) => {
                let name = self.func_name(*a);
                self.link(name, TokKind::Function, *a);
            }
            // A call through a known function's address is just a call to it. Without this the
            // port emitted `((name as usize as u64))(args)` -- the address cast that makes a
            // function usable in arithmetic, applied where a callable was wanted.
            CallTarget::Indirect(e)
                if matches!(&**e, Expr::Addr(a) if self.program.functions.contains_key(a)) =>
            {
                let Expr::Addr(a) = &**e else { unreachable!() };
                let name = self.func_name(*a);
                self.link(name, TokKind::Function, *a);
            }
            CallTarget::Indirect(e) => {
                self.p("(");
                self.expr(e, 0);
                self.p(")");
            }
            CallTarget::Builtin(name) => self.tok(*name, TokKind::Function),
        }
        self.p("(");
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                self.p(", ");
            }
            self.expr(a, 0);
        }
        self.p(")");
    }

    fn stmt(&mut self, addr: u64, s: &Stmt) {
        self.start(Some(addr));
        match s {
            Stmt::Assign(v, e) => {
                self.tok(self.var_name(v), TokKind::Variable);
                // `x = x + 1` -> `x += 1`
                if let Expr::Bin(op, a, b, _) = e
                    && matches!(&**a, Expr::Var(av, _) if av == v)
                    && !matches!(op, BinOp::Sar)
                {
                    self.p(&format!(" {}= ", op.symbol()));
                    if b.is_condition() {
                        self.value(b, 0);
                    } else {
                        self.byte_or_number_at(b, 0);
                    }
                } else {
                    self.p(" = ");
                    // The local was declared from its own inferred width, which is routinely wider
                    // than the value being stored into it (a 64-bit register holding a 32-bit
                    // argument).
                    match self.int_local_width(v) {
                        Some((w, signed)) => self.coerced(e, w, signed, 0),
                        None => self.value(e, 0),
                    }
                }
            }
            Stmt::Store(a, v, w) => {
                if let Expr::Var(bind, _) = a
                    && self.iter_mut.contains(bind)
                {
                    // `*x = v` for a write through an `iter_mut` element binding.
                    self.p("*");
                    self.tok(self.var_name(bind), TokKind::Variable);
                    // `*x = *x OP k` → `*x OP= k` (the read is the deref of the same binding).
                    let deref_of_bind = |e: &Expr| {
                        matches!(e, Expr::Load(la, _)
                            if matches!(&**la, Expr::Var(b2, _) if b2 == bind))
                    };
                    match v {
                        Expr::Bin(op, l, r, _) if !matches!(op, BinOp::Sar) && deref_of_bind(l) => {
                            self.p(&format!(" {}= ", op.symbol()));
                            self.byte_or_number_at(r, 0);
                        }
                        Expr::Bin(op, l, r, _)
                            if matches!(
                                op,
                                BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
                            ) && deref_of_bind(r) =>
                        {
                            self.p(&format!(" {}= ", op.symbol()));
                            self.byte_or_number_at(l, 0);
                        }
                        _ => {
                            self.p(" = ");
                            self.byte_or_number_at(v, 0);
                        }
                    }
                } else if v.is_vector() {
                    // A packed-vector store (`movdqu [mem], xmm`); slice-relative when the base
                    // is a slice parameter.
                    if let Some((i, byte_off)) = self.vec_slice_base(a) {
                        let lane = v.vec_shape().map_or(Width::B32, |(_, lw)| lw.width);
                        self.tok(format!("{}vstore_slice", self.rt()), TokKind::Function);
                        self.p("(");
                        self.tok(param_name(i), TokKind::Param);
                        self.p(", ");
                        self.vec_index(&byte_off, lane);
                        self.p(", ");
                        self.expr(v, 0);
                        self.p(")");
                    } else {
                        self.tok(format!("{}vstore", self.rt()), TokKind::Function);
                        self.p("(");
                        self.expr(a, 0);
                        self.p(", ");
                        self.expr(v, 0);
                        self.p(")");
                    }
                } else if self.element(a, *w) {
                    // A slice element, reference, or struct field (`p[i]` / `*p` / `p.field_8`).
                    self.p(" = ");
                    self.byte_or_number_at(v, 0);
                } else {
                    self.tok(format!("{}write", self.rt()), TokKind::Function);
                    self.p("::<");
                    self.tok(w.rust(false), TokKind::Type);
                    self.p(">(");
                    self.expr(a, 0);
                    self.p(", ");
                    self.expr(v, 0);
                    self.p(")");
                }
            }
            Stmt::Eval(e) => self.expr(e, 0),
            Stmt::Asm(text, ops) => {
                if self.port {
                    // A faithful, compilable inline-asm fallback (the IDA/Ghidra `__asm` analogue).
                    // Braces are doubled so asm!'s template parser treats them literally. The
                    // instruction's registers are declared as operands (undeclared clobbers are
                    // undefined behaviour — see the inline-assembly reference): `in` passes the
                    // live value, `out("reg") _` declares a clobber, `inout(...) => _` both.
                    let safe = escape(text).replace('{', "{{").replace('}', "}}");
                    self.kw("unsafe ");
                    self.p("{ ");
                    self.tok("core::arch::asm!", TokKind::Function);
                    self.p("(");
                    self.tok(format!("\"{safe}\""), TokKind::Str);
                    self.p(", ");
                    for op in ops {
                        match op {
                            // Only pass an input we can name a value for; an undefined register
                            // read is dropped (In) or becomes a plain output (InOut).
                            AsmOp::In(reg, v) if self.asm_input_ok(v) => {
                                self.tok("in", TokKind::Function);
                                self.p(&format!("(\"{reg}\") "));
                                self.asm_input(v);
                                self.p(", ");
                            }
                            AsmOp::In(..) => {}
                            // The written result is captured into the register variable.
                            AsmOp::Out(reg, var) => {
                                self.tok("out", TokKind::Function);
                                self.p(&format!("(\"{reg}\") "));
                                self.tok(self.var_name(var), TokKind::Variable);
                                self.p(", ");
                            }
                            AsmOp::InOut(reg, v, var) if self.asm_input_ok(v) => {
                                self.tok("inout", TokKind::Function);
                                self.p(&format!("(\"{reg}\") "));
                                self.asm_input(v);
                                self.p(" => ");
                                self.tok(self.var_name(var), TokKind::Variable);
                                self.p(", ");
                            }
                            AsmOp::InOut(reg, _, var) => {
                                self.tok("out", TokKind::Function);
                                self.p(&format!("(\"{reg}\") "));
                                self.tok(self.var_name(var), TokKind::Variable);
                                self.p(", ");
                            }
                        }
                    }
                    self.tok("options", TokKind::Function);
                    self.p("(");
                    self.kw("nostack");
                    self.p(")) }");
                } else {
                    self.tok("asm!", TokKind::Function);
                    self.p("(");
                    self.tok(format!("\"{}\"", escape(text)), TokKind::Str);
                    self.p(")");
                }
            }
        }
        self.p(";");
        self.end();
    }

    fn block(&mut self, nodes: &[Node]) {
        self.indent += 1;
        self.nodes(nodes);
        self.indent -= 1;
    }

    fn nodes(&mut self, nodes: &[Node]) {
        for n in nodes {
            self.node(n);
        }
    }

    fn node(&mut self, n: &Node) {
        match n {
            Node::Stmt(a, s) => self.stmt(*a, s),
            Node::Match { addr, index, arms } => {
                self.start(Some(*addr));
                self.kw("match ");
                self.expr(index, 0);
                self.p(" {");
                self.end();
                self.indent += 1;
                for (values, body) in arms {
                    self.start(None);
                    for (i, v) in values.iter().enumerate() {
                        if i > 0 {
                            self.p(" | ");
                        }
                        self.number(*v, Width::B64);
                    }
                    self.p(" => {");
                    self.end();
                    self.block(body);
                    self.close();
                }
                self.start(None);
                self.p("_ => {}");
                self.end();
                self.indent -= 1;
                self.close();
            }
            Node::If {
                addr,
                cond,
                then,
                els,
            } => {
                self.start(Some(*addr));
                self.kw("if ");
                self.expr(cond, 0);
                self.p(" {");
                self.end();
                self.block(then);
                self.else_chain(els);
            }
            Node::Loop { addr, body } => {
                self.start(Some(*addr));
                self.loop_label(*addr, body);
                self.kw("loop");
                self.p(" {");
                self.end();
                self.block(body);
                self.close();
            }
            Node::While { addr, cond, body } => {
                self.start(Some(*addr));
                self.loop_label(*addr, body);
                self.kw("while ");
                self.expr(cond, 0);
                self.p(" {");
                self.end();
                self.block(body);
                self.close();
            }
            Node::For {
                addr,
                var,
                start,
                end,
                inclusive,
                iter,
                by_ref,
                zip,
                index,
                body,
            } => {
                self.start(Some(*addr));
                self.loop_label(*addr, body);
                self.kw("for ");
                match iter {
                    // `for (i, &x) in s.iter().enumerate()`: index plus element.
                    Some(slice) if index.is_some() => {
                        let i = index.expect("index");
                        self.p("(");
                        self.tok(self.var_name(&i), TokKind::Variable);
                        self.p(", &");
                        self.tok(self.var_name(var), TokKind::Variable);
                        self.p(")");
                        self.kw(" in ");
                        self.value(slice, 12);
                        self.p(".");
                        self.tok("iter", TokKind::Function);
                        self.p("().");
                        self.tok("enumerate", TokKind::Function);
                        self.p("()");
                    }
                    // `for (d, &s) in dst.iter_mut().zip(src)`: a two-slice element map.
                    Some(slice) if zip.is_some() => {
                        let (src, bind) = zip.as_ref().expect("zip");
                        self.p("(");
                        self.tok(self.var_name(var), TokKind::Variable);
                        self.p(", &");
                        self.tok(self.var_name(bind), TokKind::Variable);
                        self.p(")");
                        self.kw(" in ");
                        self.value(slice, 12);
                        self.p(".");
                        self.tok("iter_mut", TokKind::Function);
                        self.p("().");
                        self.tok("zip", TokKind::Function);
                        self.p("(");
                        self.expr(src, 0);
                        self.p(")");
                    }
                    // `for x in s.iter_mut()`: each `s[i]` becomes `*x`.
                    Some(slice) if *by_ref => {
                        self.tok(self.var_name(var), TokKind::Variable);
                        self.kw(" in ");
                        self.value(slice, 12);
                        self.p(".");
                        self.tok("iter_mut", TokKind::Function);
                        self.p("()");
                    }
                    // `for &x in s`: the element is bound by value (slices of Copy types).
                    Some(slice) => {
                        self.p("&");
                        self.tok(self.var_name(var), TokKind::Variable);
                        self.kw(" in ");
                        self.expr(slice, 0);
                    }
                    None => {
                        // A counter the body never reads is just a repeat count: `for _ in …`.
                        let mut used = std::collections::HashSet::new();
                        collect_used_vars(body, &mut used);
                        if used.contains(var) {
                            self.tok(self.var_name(var), TokKind::Variable);
                        } else {
                            self.tok("_", TokKind::Variable);
                        }
                        self.kw(" in ");
                        self.expr(start, 0);
                        self.p(if *inclusive { "..=" } else { ".." });
                        self.expr(end, 0);
                    }
                }
                self.p(" {");
                self.end();
                if *by_ref {
                    self.iter_mut.push(*var);
                }
                self.block(body);
                if *by_ref {
                    self.iter_mut.pop();
                }
                self.close();
            }
            Node::Break(a) => self.simple(*a, "break"),
            Node::Continue(a) => self.simple(*a, "continue"),
            Node::BreakLabel(h) => self.simple(*h, &format!("break 'l{h:x}")),
            Node::ContinueLabel(h) => self.simple(*h, &format!("continue 'l{h:x}")),
            Node::Return(a, e) => {
                self.start(Some(*a));
                self.kw("return");
                if self.returns
                    && let Some(e) = e
                {
                    self.p(" ");
                    if self.sig.ret == Some(Ty::Bool) {
                        self.bool_value(e);
                    } else if let Some(Ty::Int(w, signed)) = self.sig.ret {
                        // The signature width comes from the ABI (often a full register), while the
                        // returned expression is whatever the body computed. Mismatches here were
                        // the second-commonest reason an emitted port did not compile.
                        self.coerced(e, w, signed, 0);
                    } else {
                        self.expr(e, 0);
                    }
                }
                self.p(";");
                self.end();
            }
            Node::Stop(a) => {
                self.start(Some(*a));
                self.tok("unreachable!", TokKind::Function);
                self.p("();");
                self.tok(" // execution stops here", TokKind::Comment);
                self.end();
            }
            Node::TailCall(a, e) => {
                self.start(Some(*a));
                self.kw("return ");
                self.expr(e, 0);
                self.p(";");
                self.tok(" // tail call", TokKind::Comment);
                self.end();
            }
            Node::Goto(a, t) if self.port => {
                // Rust has no `goto`. A comment would silently fall through to the next
                // statement — wrong semantics in a port — so fail loudly at run time instead.
                self.start(Some(*a));
                self.tok("unimplemented!", TokKind::Function);
                self.p(&format!(
                    "(\"goto label_{t:x}: control flow the structurer could not express\");"
                ));
                self.end();
            }
            Node::Goto(a, t) => {
                self.start(Some(*a));
                self.tok(
                    format!("// goto label_{t:x}; (flow the structurer could not express)"),
                    TokKind::Comment,
                );
                self.end();
            }
            Node::Label(a) => {
                self.start(Some(*a));
                self.tok(format!("// label_{a:x}:"), TokKind::Comment);
                self.end();
            }
        }
    }

    fn bool_value(&mut self, e: &Expr) {
        match e {
            Expr::Const(0, _) => self.kw("false"),
            Expr::Const(_, _) => self.kw("true"),
            Expr::Cast(a, _, _) if a.is_condition() => self.expr(a, 0),
            // Recovered iterator predicates already return `bool`.
            Expr::Method(_, "any" | "all", ..) => self.expr(e, 0),
            other if other.is_condition() => self.expr(other, 0),
            other => {
                self.expr(other, 4);
                self.p(" != ");
                self.number(0, Width::B8);
            }
        }
    }

    fn else_chain(&mut self, els: &[Node]) {
        if els.is_empty() {
            self.close();
            return;
        }
        // `else if` for an else-branch that is just another `if`.
        if let [
            Node::If {
                addr,
                cond,
                then,
                els,
            },
        ] = els
        {
            self.start(Some(*addr));
            self.p("} ");
            self.kw("else if ");
            self.expr(cond, 0);
            self.p(" {");
            self.end();
            self.block(then);
            self.else_chain(els);
            return;
        }
        self.start(None);
        self.p("} ");
        self.kw("else");
        self.p(" {");
        self.end();
        self.block(els);
        self.close();
    }

    fn close(&mut self) {
        self.start(None);
        self.p("}");
        self.end();
    }

    fn simple(&mut self, addr: u64, kw: &str) {
        self.start(Some(addr));
        self.kw(kw);
        self.p(";");
        self.end();
    }

    /// Prefix a loop with a Rust label (`'l<addr>: `) when some break/continue inside targets it
    /// (i.e. an inner loop breaks/continues this outer one).
    fn loop_label(&mut self, header: u64, body: &[Node]) {
        if body_has_label(body, header) {
            self.p(&format!("'l{header:x}: "));
        }
    }

    /// Finds string lengths: `f(ptr, len)` call arguments (newer Rust encodes literal
    /// lengths as `len * 2 + 1`) and `(ptr, len)` pairs stored in adjacent stack slots.
    fn collect_lengths(&mut self, nodes: &[Node]) {
        let mut ptrs: HashMap<i64, u64> = HashMap::new();
        let mut lens: HashMap<i64, u64> = HashMap::new();
        let mut calls: Vec<(u64, u64)> = Vec::new();
        fn walk(
            nodes: &[Node],
            ptrs: &mut HashMap<i64, u64>,
            lens: &mut HashMap<i64, u64>,
            calls: &mut Vec<(u64, u64)>,
        ) {
            for n in nodes {
                match n {
                    Node::Stmt(_, s) => {
                        if let Stmt::Assign(Var::Stack(o), e) = s {
                            match e {
                                Expr::Addr(a) => {
                                    ptrs.insert(*o, *a);
                                }
                                Expr::Const(k, _) => {
                                    lens.insert(*o, *k);
                                }
                                _ => {}
                            }
                        }
                        for e in s.exprs() {
                            e.walk(&mut |x| {
                                if let Expr::Call(_, args) = x {
                                    for w in args.windows(2) {
                                        if let [Expr::Addr(a), Expr::Const(k, _)] = w {
                                            calls.push((*a, *k));
                                        }
                                    }
                                }
                            });
                        }
                    }
                    Node::If { then, els, .. } => {
                        walk(then, ptrs, lens, calls);
                        walk(els, ptrs, lens, calls);
                    }
                    Node::Loop { body, .. } | Node::While { body, .. } | Node::For { body, .. } => {
                        walk(body, ptrs, lens, calls)
                    }
                    Node::Match { arms, .. } => {
                        for (_, body) in arms {
                            walk(body, ptrs, lens, calls);
                        }
                    }
                    _ => {}
                }
            }
        }
        walk(nodes, &mut ptrs, &mut lens, &mut calls);
        for (o, a) in ptrs {
            if let Some(&k) = lens.get(&(o + 8)) {
                self.str_lens.entry(a).or_insert(k as usize);
            }
        }
        for (a, k) in calls {
            let k = if k % 2 == 1 { k >> 1 } else { k };
            self.str_lens.entry(a).or_insert(k as usize);
        }
    }

    /// Stack slots only used by address (`&mut local_38`), with their size: up to the
    /// next known slot.
    fn buffers(&self, body: &[Node], locals: &[(Var, Width, bool)]) -> Vec<(i64, usize)> {
        fn visit(e: &Expr, out: &mut std::collections::BTreeSet<i64>) {
            e.walk(&mut |x| {
                if let Expr::StackAddr(o) = x
                    && *o < 0
                {
                    out.insert(*o);
                }
            });
        }
        fn walk(nodes: &[Node], out: &mut std::collections::BTreeSet<i64>) {
            for n in nodes {
                match n {
                    Node::Stmt(_, s) => s.exprs().into_iter().for_each(|e| visit(e, out)),
                    Node::If {
                        cond, then, els, ..
                    } => {
                        visit(cond, out);
                        walk(then, out);
                        walk(els, out);
                    }
                    Node::While { cond, body, .. } => {
                        visit(cond, out);
                        walk(body, out);
                    }
                    Node::For {
                        start, end, body, ..
                    } => {
                        visit(start, out);
                        visit(end, out);
                        walk(body, out);
                    }
                    Node::Loop { body, .. } => walk(body, out),
                    Node::Match { index, arms, .. } => {
                        visit(index, out);
                        for (_, body) in arms {
                            walk(body, out);
                        }
                    }
                    Node::Return(_, Some(e)) | Node::TailCall(_, e) => visit(e, out),
                    _ => {}
                }
            }
        }
        let mut addressed = std::collections::BTreeSet::new();
        walk(body, &mut addressed);
        let mut known: std::collections::BTreeSet<i64> = addressed.clone();
        known.extend(locals.iter().filter_map(|(v, _, _)| match v {
            Var::Stack(o) => Some(*o),
            Var::Reg(_) | Var::Split(..) | Var::Xmm(_) | Var::XmmSplit(..) | Var::Named(_) => None,
        }));
        known.insert(0);
        addressed
            .into_iter()
            .filter(|o| !locals.iter().any(|(v, _, _)| *v == Var::Stack(*o)))
            .map(|o| {
                let next = known.range(o + 1..).next().copied().unwrap_or(0);
                (o, usize::try_from(next - o).unwrap_or(8).min(0x1000))
            })
            .collect()
    }

    /// Prints the whole function.
    /// Emits each recovered struct definition (used by `&Struct` parameters) once, before the
    /// function, so the field accesses in the body resolve and a port compiles.
    fn emit_struct_decls(&mut self) {
        let mut seen = std::collections::HashSet::new();
        for ty in self.sig.params.clone() {
            let Ty::Struct(layout, _) = ty else { continue };
            if !seen.insert(layout.name.clone()) {
                continue;
            }
            self.start(None);
            self.kw("#[repr(C)]");
            self.end();
            self.start(None);
            self.kw("struct ");
            self.tok(layout.name.clone(), TokKind::Type);
            self.p(" {");
            self.end();
            self.indent += 1;
            for f in &layout.fields {
                self.start(None);
                self.tok(layout.field_name(f), TokKind::Variable);
                self.p(": ");
                self.tok(f.width.rust(f.signed), TokKind::Type);
                self.p(",");
                self.end();
            }
            self.indent -= 1;
            self.start(None);
            self.p("}");
            self.end();
            self.start(None);
            self.end();
        }
    }

    /// Prints the lifted, simplified IR blocks (before structuring) as readable text — the
    /// stage between raw assembly and structured pseudocode. Reuses [`Printer::expr`] for the
    /// expression tree; only the block/statement/terminator framing is IL-specific.
    pub fn il_function(mut self, name: &str, blocks: &[Block]) -> Vec<Line> {
        self.start(None);
        self.tok(format!("// lifted IR of {name}"), TokKind::Comment);
        self.end();
        for block in blocks {
            self.start(Some(block.addr));
            self.link(
                format!("block_{:x}:", block.addr),
                TokKind::Function,
                block.addr,
            );
            self.end();
            self.indent = 1;
            for (addr, stmt) in &block.stmts {
                self.start(Some(*addr));
                self.il_stmt(stmt);
                self.end();
            }
            self.start(Some(block.term_addr));
            self.il_term(&block.term);
            self.end();
            self.indent = 0;
        }
        self.lines
    }

    fn il_stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Assign(v, e) => {
                let name = self.var_name(v);
                self.tok(name, TokKind::Variable);
                self.p(" = ");
                self.expr(e, 0);
            }
            Stmt::Store(addr, val, w) => {
                self.kw("store");
                self.p(&format!(".{} [", w.bits()));
                self.expr(addr, 0);
                self.p("] = ");
                self.expr(val, 0);
            }
            Stmt::Eval(e) => self.expr(e, 0),
            Stmt::Asm(text, _) => {
                self.kw("asm ");
                self.tok(format!("{text:?}"), TokKind::Str);
            }
        }
    }

    fn il_term(&mut self, t: &Term) {
        match t {
            Term::Jump(a) => {
                self.kw("jump ");
                self.link(format!("block_{a:x}"), TokKind::Function, *a);
            }
            Term::Branch(cond, taken, not) => {
                self.kw("branch ");
                self.expr(cond, 0);
                self.p(" ? ");
                self.link(format!("block_{taken:x}"), TokKind::Function, *taken);
                self.p(" : ");
                self.link(format!("block_{not:x}"), TokKind::Function, *not);
            }
            Term::Return(Some(e)) => {
                self.kw("return ");
                self.expr(e, 0);
            }
            Term::Return(None) => self.kw("return"),
            Term::Stop => self.kw("stop"),
            Term::TailCall(e) => {
                self.kw("tailcall ");
                self.expr(e, 0);
            }
            Term::Switch(e, cases) => {
                self.kw("switch ");
                self.expr(e, 0);
                self.p(&format!("  // {} cases", cases.len()));
            }
        }
    }

    pub fn function(mut self, entry: u64, name: &str, body: &[Node]) -> Vec<Line> {
        self.collect_lengths(body);
        self.emit_struct_decls();
        self.start(Some(entry));
        self.kw("fn ");
        // The ported function's OWN name also has to be a valid Rust identifier. It arrives from
        // the decompiler rather than through `func_name`, which is why sanitising the call sites
        // and the stubs was not enough: one corpus binary exports `AntiRevGetTC()`, parentheses
        // included, and the port opened with `fn AntiRevGetTC()() -> bool`.
        let shown = if self.port { rust_ident(name) } else { name.to_string() };
        self.link(shown, TokKind::Function, entry);
        self.p("(");
        let mut first = true;
        for (i, ty) in self.sig.params.clone().iter().enumerate() {
            if *ty == Ty::SliceLen {
                continue;
            }
            if !first {
                self.p(", ");
            }
            first = false;
            self.tok(param_name(i), TokKind::Param);
            self.p(": ");
            self.tok(ty.rust(), TokKind::Type);
        }
        self.p(")");
        if let Some(ret) = self.sig.ret.clone() {
            self.p(" -> ");
            self.tok(ret.rust(), TokKind::Type);
        }
        self.p(" {");
        self.end();
        self.indent = 1;
        // A recovered `for` binds its counter, so it must not also be declared here.
        let mut bound = std::collections::HashSet::new();
        crate::structure::for_vars(body, &mut bound);
        crate::structure::closure_params(body, &mut bound);
        // Only declare locals the body actually uses (iterator recovery can leave a stack
        // slot or register with no remaining references).
        let mut used = std::collections::HashSet::new();
        collect_used_vars(body, &mut used);
        let locals: Vec<(Var, Width, bool)> = self
            .locals
            .iter()
            .filter(|(v, _)| !matches!(v, Var::Reg(RSP)) && !bound.contains(v) && used.contains(v))
            .map(|(v, (w, s))| (*v, *w, *s))
            .collect();
        let buffers = self.buffers(body, &locals);
        for (v, w, signed) in &locals {
            self.start(None);
            self.kw("let mut ");
            self.tok(self.var_name(v), TokKind::Variable);
            self.p(": ");
            // A port also needs an initialiser: a slot may be read on a path whose store was
            // never lifted, and Rust rejects that. Zero is what a fresh frame holds.
            let zero = if let Some((n, lane)) = self.vec_locals.get(v) {
                self.p(&format!("[{}; {n}]", lane.rust()));
                format!("[{}; {n}]", if lane.float { "0.0" } else { "0" })
            } else if self.usize_locals.contains(v) {
                self.tok("usize", TokKind::Type);
                "0".to_string()
            } else {
                let float = self.float_locals.contains(v);
                let ty = if float {
                    if w.0 == 4 { "f32" } else { "f64" }
                } else {
                    w.rust(*signed)
                };
                self.tok(ty, TokKind::Type);
                if float { "0.0".to_string() } else { "0".to_string() }
            };
            if self.port {
                self.p(" = ");
                self.p(&zero);
            }
            self.p(";");
            self.end();
        }
        for (o, size) in &buffers {
            self.start(None);
            self.kw("let mut ");
            self.tok(Var::Stack(*o).to_string(), TokKind::Variable);
            self.p(": ");
            let zero = if *size > 8 {
                self.p("[");
                self.tok("u8", TokKind::Type);
                self.p("; ");
                self.number(*size as u64, Width::B64);
                self.p("]");
                format!("[0u8; {size}]")
            } else {
                self.tok("u64", TokKind::Type);
                "0".to_string()
            };
            if self.port {
                self.p(" = ");
                self.p(&zero);
            }
            self.p(";");
            self.tok(" // its address is passed on", TokKind::Comment);
            self.end();
        }
        if !locals.is_empty() || !buffers.is_empty() {
            self.start(None);
            self.end();
        }
        // A final bare `return;` adds nothing.
        let mut body = body.to_vec();
        if !self.returns && matches!(body.last(), Some(Node::Return(..))) {
            body.pop();
        }
        self.nodes(&body);
        self.indent = 0;
        self.close();
        self.lines
    }
}

/// Collects every variable referenced in `nodes` (assigned or read), to prune locals that
/// no longer appear after the structuring and iterator-recovery passes.
fn collect_used_vars(nodes: &[Node], out: &mut std::collections::HashSet<Var>) {
    let note = |e: &Expr, out: &mut std::collections::HashSet<Var>| {
        e.walk(&mut |x| {
            if let Expr::Var(v, _) = x {
                out.insert(*v);
            }
        });
    };
    for n in nodes {
        match n {
            Node::Stmt(_, s) => {
                for v in s.defs() {
                    out.insert(v);
                }
                for e in s.exprs() {
                    note(e, out);
                }
            }
            Node::If {
                cond, then, els, ..
            } => {
                note(cond, out);
                collect_used_vars(then, out);
                collect_used_vars(els, out);
            }
            Node::While { cond, body, .. } => {
                note(cond, out);
                collect_used_vars(body, out);
            }
            Node::For {
                start,
                end,
                iter,
                body,
                ..
            } => {
                note(start, out);
                note(end, out);
                if let Some(it) = iter {
                    note(it, out);
                }
                collect_used_vars(body, out);
            }
            Node::Loop { body, .. } => collect_used_vars(body, out),
            Node::Match { index, arms, .. } => {
                note(index, out);
                for (_, body) in arms {
                    collect_used_vars(body, out);
                }
            }
            Node::Return(_, Some(e)) | Node::TailCall(_, e) => note(e, out),
            _ => {}
        }
    }
}

fn strip_trivial_cast(e: &Expr) -> &Expr {
    // `(x as u64) == 5` reads better as `x == 5` when the cast only zero-extends.
    match e {
        Expr::Cast(a, w, false) if a.width() <= *w && !a.is_condition() => a,
        other => other,
    }
}

/// The name a call / address uses for the symbol at `a` (matching [`Printer::call`]
/// and [`Printer::global`]).
fn ext_name(program: &Program, a: u64) -> String {
    // Only used for the port's stub declarations, so it is always sanitised.
    program
        .name(a)
        .map_or_else(|| format!("sub_{a:x}"), |n| rust_ident(&n.text))
}

/// `s` mangled into a valid Rust identifier, for port mode.
///
/// A symbol from the binary is not necessarily a Rust name. A decorated C name can carry `@`, a
/// demangled C++ one carries `<`, `>`, `:`, spaces and parentheses, and one corpus binary exports
/// `AntiRevGetTC()` -- parentheses and all -- which was emitted verbatim as
/// `fn AntiRevGetTC()() -> bool` and could not parse. The ported function's own name, its call
/// sites and its stubs all go through this, so they keep agreeing with each other.
pub(crate) fn rust_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' });
    }
    // A Rust identifier cannot start with a digit, and an empty name is not a name.
    if out.is_empty() {
        return "unnamed".into();
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Can `s` be declared as a Rust item name, so a stub for it compiles?
fn is_ident(s: &str) -> bool {
    let mut cs = s.chars();
    if !matches!(cs.next(), Some(c) if c == '_' || c.is_ascii_alphabetic()) {
        return false;
    }
    if s.len() == 1 && s.starts_with('_') {
        return false; // `_` alone is not a name.
    }
    if !cs.all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        return false;
    }
    !matches!(
        s,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
            | "try"
    )
}

/// Collects compilable stub declarations for everything a port scaffold *references*
/// but does not *define*: external `sub_*` / import functions it calls, and global data
/// symbols whose address it takes. Each stub function is generic over its arguments
/// (so it type-checks against whatever is passed) and returns `u64` via `orress_rt::unknown`;
/// each global becomes a `static`. The result is empty when nothing is referenced.
pub fn stub_decls(program: &Program, entry: u64, body: &[Node]) -> String {
    // function name -> argument count (the widest call site wins).
    let mut fns: BTreeMap<String, usize> = BTreeMap::new();
    // name -> address, so each can be declared as the constant the port's helpers need.
    let mut globals: BTreeMap<String, u64> = BTreeMap::new();

    fn each_expr(nodes: &[Node], f: &mut impl FnMut(&Expr)) {
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
                    each_expr(then, f);
                    each_expr(els, f);
                }
                Node::While { cond, body, .. } => {
                    cond.walk(f);
                    each_expr(body, f);
                }
                Node::For {
                    start, end, body, ..
                } => {
                    start.walk(f);
                    end.walk(f);
                    each_expr(body, f);
                }
                Node::Loop { body, .. } => each_expr(body, f),
                Node::Match { index, arms, .. } => {
                    index.walk(f);
                    for (_, body) in arms {
                        each_expr(body, f);
                    }
                }
                Node::Return(_, Some(e)) | Node::TailCall(_, e) => e.walk(f),
                _ => {}
            }
        }
    }

    each_expr(body, &mut |x| match x {
        Expr::Call(CallTarget::Direct(a) | CallTarget::Import(a), args) if *a != entry => {
            let name = ext_name(program, *a);
            if is_ident(&name) {
                let argc = fns.entry(name).or_insert(0);
                *argc = (*argc).max(args.len());
            }
        }
        // A path-qualified builtin (`f64::from_bits`) is a real std item, not something to stub.
        Expr::Call(CallTarget::Builtin(name), args) if !name.contains("::") => {
            let argc = fns.entry((*name).to_owned()).or_insert(0);
            *argc = (*argc).max(args.len());
        }
        Expr::Addr(a) if *a != entry => {
            if program.string_refs.contains_key(a) {
                // A string literal — printed inline, nothing to declare.
            } else if program.functions.contains_key(a) {
                let name = ext_name(program, *a);
                if is_ident(&name) {
                    fns.entry(name).or_insert(0);
                }
            } else {
                let name = program
                    .name(*a)
                    .map_or_else(|| format!("data_{a:x}"), |n| rust_ident(&n.text));
                if is_ident(&name) {
                    globals.insert(name, *a);
                }
            }
        }
        _ => {}
    });
    // A symbol that is called wins over a data declaration of the same name.
    globals.retain(|g, _| !fns.contains_key(g));

    if fns.is_empty() && globals.is_empty() {
        return String::new();
    }

    let mut s = String::from(
        "\n// --- Stubs for externals ORRESS could not resolve; replace with the real items. ---\n",
    );
    for (name, argc) in &fns {
        if *argc == 0 {
            s.push_str(&format!(
                "fn {name}() -> u64 {{ orress_rt::unknown(\"{name}\") }}\n"
            ));
        } else {
            let gens = (0..*argc).map(|i| format!("A{i}")).collect::<Vec<_>>();
            let params = (0..*argc).map(|i| format!("_: A{i}")).collect::<Vec<_>>();
            s.push_str(&format!(
                "fn {name}<{}>({}) -> u64 {{ orress_rt::unknown(\"{name}\") }}\n",
                gens.join(", "),
                params.join(", "),
            ));
        }
    }
    for (g, addr) in &globals {
        // The ADDRESS, not a value: the body reads through `orress_rt::read(addr)`, so what it
        // needs from a global is where it lives. A `static ... = 0` both failed to compile at the
        // call (a `&u64` where a `u64` was wanted) and would have been the wrong number.
        s.push_str(&format!("const {g}: u64 = {addr:#x};\n"));
    }
    s
}
