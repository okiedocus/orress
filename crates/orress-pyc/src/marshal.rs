//! A reader for CPython's `marshal` serialization format (the body of a `.pyc` file). It recovers
//! the object tree — code objects, constants, names, strings, numbers, containers — needed to
//! inspect and disassemble compiled Python. Pure `std`; tolerant of bad input (returns `Err`
//! rather than panicking, and caps recursion/sizes).
//!
//! The format is a stream of tagged objects. The high bit (`FLAG_REF`, 0x80) of a tag means the
//! decoded object is appended to a reference table that later `TYPE_REF` tags point back into.

use crate::CodeLayout;

const FLAG_REF: u8 = 0x80;
/// Guard against hostile/looping input.
const MAX_DEPTH: u32 = 100;
const MAX_ITEMS: usize = 50_000_000;
/// Total decode budget (objects + string/bytes payload in 16-byte units), charged again every
/// time a `TYPE_REF` back-reference is materialized. Without it a hostile stream can nest refs to
/// refs and blow up memory exponentially from a few hundred input bytes.
const MAX_BUDGET: u64 = 4_000_000;

/// A decoded marshal object.
#[derive(Debug, Clone, PartialEq)]
pub enum Obj {
    Null,
    None,
    Bool(bool),
    StopIter,
    Ellipsis,
    Int(i64),
    /// An integer too large for `i64`, rendered in decimal.
    BigInt(String),
    Float(f64),
    Complex(f64, f64),
    Bytes(Vec<u8>),
    Str(String),
    Tuple(Vec<Obj>),
    List(Vec<Obj>),
    Set(Vec<Obj>),
    FrozenSet(Vec<Obj>),
    Dict(Vec<(Obj, Obj)>),
    Code(Box<CodeObject>),
    /// A `slice(start, stop, step)` constant (`TYPE_SLICE`, marshal v5 / Python 3.14+).
    Slice(Box<(Obj, Obj, Obj)>),
    /// A tag ORRESS doesn't decode; carries the raw type byte.
    Unknown(u8),
}

impl Obj {
    /// A short human rendering for a constant/argument (strings quoted, code objects named).
    pub fn render(&self) -> String {
        match self {
            Obj::Null => "NULL".into(),
            Obj::None => "None".into(),
            Obj::Bool(b) => if *b { "True" } else { "False" }.into(),
            Obj::StopIter => "StopIteration".into(),
            Obj::Ellipsis => "...".into(),
            Obj::Int(i) => i.to_string(),
            Obj::BigInt(s) => s.clone(),
            Obj::Float(f) => f.to_string(),
            Obj::Complex(r, i) => format!("{r}+{i}j"),
            Obj::Bytes(b) => format!("b{:?}", String::from_utf8_lossy(b)),
            Obj::Str(s) => format!("{s:?}"),
            Obj::Tuple(v) => format!("({})", render_list(v)),
            Obj::List(v) => format!("[{}]", render_list(v)),
            Obj::Set(v) => format!("{{{}}}", render_list(v)),
            Obj::FrozenSet(v) => format!("frozenset({{{}}})", render_list(v)),
            Obj::Dict(_) => "{...}".into(),
            Obj::Code(c) => format!("<code {}>", c.name),
            Obj::Slice(s) => format!(
                "slice({}, {}, {})",
                s.0.render(),
                s.1.render(),
                s.2.render()
            ),
            Obj::Unknown(t) => format!("<unknown 0x{t:02x}>"),
        }
    }

    fn as_string(&self) -> String {
        match self {
            Obj::Str(s) => s.clone(),
            Obj::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => "?".into(),
        }
    }

    /// Flattens a tuple/list of strings to `Vec<String>` (for names/varnames).
    fn as_string_vec(&self) -> Vec<String> {
        match self {
            Obj::Tuple(v) | Obj::List(v) => v.iter().map(Obj::as_string).collect(),
            _ => Vec::new(),
        }
    }
}

fn render_list(v: &[Obj]) -> String {
    v.iter()
        .take(8)
        .map(Obj::render)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A decoded Python code object (one function / module / comprehension body).
#[derive(Debug, Clone, PartialEq)]
pub struct CodeObject {
    pub argcount: u32,
    pub posonlyargcount: u32,
    pub kwonlyargcount: u32,
    pub stacksize: u32,
    pub flags: u32,
    /// Raw bytecode (`co_code`).
    pub code: Vec<u8>,
    pub consts: Vec<Obj>,
    pub names: Vec<String>,
    /// 3.11+: `co_localsplusnames` (args, locals, cells, frees). Earlier: varnames + cell + free.
    pub localsplus: Vec<String>,
    pub filename: String,
    pub name: String,
    /// 3.11+ qualified name; equal to `name` on older versions.
    pub qualname: String,
    pub firstlineno: u32,
}

impl CodeObject {
    /// A `def`-style signature reconstructed from the argument count and local names
    /// (`def check(pw)`), with `/` for positional-only and `*` before keyword-only args.
    pub fn signature(&self) -> String {
        if self.name == "<module>" {
            return "<module>".to_string();
        }
        let mut parts: Vec<String> = Vec::new();
        let pos = self.argcount as usize;
        for (i, name) in self.localsplus.iter().take(pos).enumerate() {
            parts.push(name.clone());
            if i + 1 == self.posonlyargcount as usize {
                parts.push("/".to_string());
            }
        }
        if self.kwonlyargcount > 0 {
            parts.push("*".to_string());
            for name in self
                .localsplus
                .iter()
                .skip(pos)
                .take(self.kwonlyargcount as usize)
            {
                parts.push(name.clone());
            }
        }
        format!("def {}({})", self.name, parts.join(", "))
    }

    /// The function/module docstring: `co_consts[0]` when it is a string.
    pub fn docstring(&self) -> Option<&str> {
        match self.consts.first() {
            Some(Obj::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// Nested code objects found in this object's constants (inner functions, comprehensions).
    pub fn nested(&self) -> Vec<&CodeObject> {
        self.consts
            .iter()
            .filter_map(|c| match c {
                Obj::Code(c) => Some(c.as_ref()),
                _ => None,
            })
            .collect()
    }
}

/// Reads a marshal stream.
pub struct Unmarshal<'a> {
    data: &'a [u8],
    pos: usize,
    /// Back-reference table: each object with the cost charged to decode it.
    refs: Vec<(Obj, u64)>,
    /// Budget units spent so far (see [`MAX_BUDGET`]).
    spent: u64,
    layout: CodeLayout,
}

impl<'a> Unmarshal<'a> {
    pub fn new(data: &'a [u8], layout: CodeLayout) -> Self {
        Self {
            data,
            pos: 0,
            refs: Vec::new(),
            spent: 0,
            layout,
        }
    }

    pub fn read(&mut self) -> Result<Obj, String> {
        self.r_object(0)
    }

    fn u8(&mut self) -> Result<u8, String> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or("unexpected end of marshal data")?;
        self.pos += 1;
        Ok(b)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let end = self.pos + 4;
        let s = self.data.get(self.pos..end).ok_or("truncated u32")?;
        self.pos = end;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn i32(&mut self) -> Result<i32, String> {
        Ok(self.u32()? as i32)
    }

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        if n > MAX_ITEMS {
            return Err(format!("implausible length {n}"));
        }
        let end = self.pos.checked_add(n).ok_or("length overflow")?;
        let s = self.data.get(self.pos..end).ok_or("truncated bytes")?;
        self.pos = end;
        Ok(s.to_vec())
    }

    fn charge(&mut self, units: u64) -> Result<(), String> {
        self.spent = self.spent.saturating_add(units);
        if self.spent > MAX_BUDGET {
            return Err("marshal data expands too much (reference bomb?)".into());
        }
        Ok(())
    }

    fn count(&mut self) -> Result<usize, String> {
        let n = self.i32()?;
        if n < 0 || n as usize > MAX_ITEMS {
            return Err(format!("implausible count {n}"));
        }
        Ok(n as usize)
    }

    fn r_object(&mut self, depth: u32) -> Result<Obj, String> {
        if depth > MAX_DEPTH {
            return Err("marshal nesting too deep".into());
        }
        let tag = self.u8()?;
        let flag_ref = tag & FLAG_REF != 0;
        let ty = tag & !FLAG_REF;

        // Reserve a reference slot before decoding, so back-references resolve.
        let slot = if flag_ref {
            let i = self.refs.len();
            self.refs.push((Obj::Null, 1));
            Some(i)
        } else {
            None
        };

        let start = self.spent;
        self.charge(1)?;
        let obj = self.decode(ty, depth)?;
        if let Some(i) = slot {
            // The cost of this subtree (including any refs it materialized) is what a later
            // `TYPE_REF` to it costs again.
            self.refs[i] = (obj.clone(), self.spent - start);
        }
        Ok(obj)
    }

    fn decode(&mut self, ty: u8, depth: u32) -> Result<Obj, String> {
        let obj = match ty {
            b'0' => Obj::Null,
            b'N' => Obj::None,
            b'F' => Obj::Bool(false),
            b'T' => Obj::Bool(true),
            b'S' => Obj::StopIter,
            b'.' => Obj::Ellipsis,
            b'i' => Obj::Int(self.i32()? as i64),
            b'I' => Obj::Int(self.u32()? as i64 | ((self.u32()? as i64) << 32)),
            b'l' => self.r_long()?,
            b'g' => {
                let b = self.bytes(8)?;
                Obj::Float(f64::from_le_bytes(b.try_into().unwrap()))
            }
            b'y' => {
                let r = self.bytes(8)?;
                let i = self.bytes(8)?;
                Obj::Complex(
                    f64::from_le_bytes(r.try_into().unwrap()),
                    f64::from_le_bytes(i.try_into().unwrap()),
                )
            }
            // Byte strings.
            b's' => {
                let n = self.count()?;
                self.charge(n as u64 / 16)?;
                Obj::Bytes(self.bytes(n)?)
            }
            // Unicode / ASCII strings (various interning + length encodings).
            b'u' | b't' | b'a' | b'A' => {
                let n = self.count()?;
                self.charge(n as u64 / 16)?;
                let b = self.bytes(n)?;
                Obj::Str(String::from_utf8_lossy(&b).into_owned())
            }
            b'z' | b'Z' => {
                let n = self.u8()? as usize;
                let b = self.bytes(n)?;
                Obj::Str(String::from_utf8_lossy(&b).into_owned())
            }
            b'r' => {
                let i = self.count()?;
                let cost = self.refs.get(i).ok_or("marshal ref out of range")?.1;
                self.charge(cost)?;
                self.refs[i].0.clone()
            }
            b')' => {
                let n = self.u8()? as usize;
                Obj::Tuple(self.items(n, depth)?)
            }
            b'(' => {
                let n = self.count()?;
                Obj::Tuple(self.items(n, depth)?)
            }
            b'[' => {
                let n = self.count()?;
                Obj::List(self.items(n, depth)?)
            }
            b'<' => {
                let n = self.count()?;
                Obj::Set(self.items(n, depth)?)
            }
            b'>' => {
                let n = self.count()?;
                Obj::FrozenSet(self.items(n, depth)?)
            }
            b'{' => Obj::Dict(self.r_dict(depth)?),
            b'c' => Obj::Code(Box::new(self.r_code(depth)?)),
            b':' => {
                let start = self.r_object(depth + 1)?;
                let stop = self.r_object(depth + 1)?;
                let step = self.r_object(depth + 1)?;
                Obj::Slice(Box::new((start, stop, step)))
            }
            other => {
                return Err(format!(
                    "unsupported marshal type 0x{other:02x} ('{}')",
                    other as char
                ));
            }
        };
        Ok(obj)
    }

    fn items(&mut self, n: usize, depth: u32) -> Result<Vec<Obj>, String> {
        if n > MAX_ITEMS {
            return Err(format!("implausible item count {n}"));
        }
        let mut v = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            v.push(self.r_object(depth + 1)?);
        }
        Ok(v)
    }

    fn r_dict(&mut self, depth: u32) -> Result<Vec<(Obj, Obj)>, String> {
        let mut v = Vec::new();
        loop {
            // A NULL key terminates the dict.
            let key = self.r_object(depth + 1)?;
            if key == Obj::Null {
                break;
            }
            let val = self.r_object(depth + 1)?;
            v.push((key, val));
        }
        Ok(v)
    }

    /// Arbitrary-precision integer (`TYPE_LONG`): a signed digit count, then 15-bit little-endian
    /// digits. Values beyond `i128` are rendered to a decimal string.
    fn r_long(&mut self) -> Result<Obj, String> {
        let n = self.i32()?;
        let negative = n < 0;
        let ndigits = n.unsigned_abs() as usize;
        if ndigits > 1_000_000 {
            return Err("implausible bigint size".into());
        }
        let mut value: i128 = 0;
        let mut overflow = false;
        for i in 0..ndigits {
            let digit = {
                let s = self
                    .data
                    .get(self.pos..self.pos + 2)
                    .ok_or("truncated bigint")?;
                self.pos += 2;
                u16::from_le_bytes([s[0], s[1]]) as i128
            };
            if !overflow {
                // `checked_shl` only rejects shift amounts >= 128, not bits shifted out, so check
                // the magnitude explicitly: the digit's bits shifted by `i*15` must stay within
                // 126 bits (i128 holds 127; one bit of headroom keeps the sum safe).
                let shift = (i as u32).saturating_mul(15);
                let width = 128 - digit.leading_zeros();
                if digit != 0 && shift.saturating_add(width) > 126 {
                    overflow = true;
                } else if digit != 0 {
                    match value.checked_add(digit << shift) {
                        Some(v) => value = v,
                        None => overflow = true,
                    }
                }
            }
        }
        if overflow {
            // Rare; report rather than lose precision silently.
            return Ok(Obj::BigInt(format!("<big int, {ndigits} digits>")));
        }
        if negative {
            value = -value;
        }
        match i64::try_from(value) {
            Ok(v) => Ok(Obj::Int(v)),
            Err(_) => Ok(Obj::BigInt(value.to_string())),
        }
    }

    fn r_code(&mut self, depth: u32) -> Result<CodeObject, String> {
        let argcount = self.u32()?;
        let posonlyargcount = if self.layout.has_posonly {
            self.u32()?
        } else {
            0
        };
        let kwonlyargcount = self.u32()?;
        if self.layout.has_nlocals {
            let _nlocals = self.u32()?;
        }
        let stacksize = self.u32()?;
        let flags = self.u32()?;
        let code = match self.r_object(depth + 1)? {
            Obj::Bytes(b) => b,
            other => return Err(format!("co_code is not bytes: {}", other.render())),
        };
        let consts = match self.r_object(depth + 1)? {
            Obj::Tuple(v) | Obj::List(v) => v,
            other => vec![other],
        };
        let names = self.r_object(depth + 1)?.as_string_vec();
        let localsplus = if self.layout.modern {
            let lp = self.r_object(depth + 1)?.as_string_vec();
            let _kinds = self.r_object(depth + 1)?; // co_localspluskinds (bytes)
            lp
        } else {
            let varnames = self.r_object(depth + 1)?.as_string_vec();
            let freevars = self.r_object(depth + 1)?.as_string_vec();
            let cellvars = self.r_object(depth + 1)?.as_string_vec();
            // Fast-locals index space on <3.11: varnames, then cells, then frees.
            let mut lp = varnames;
            lp.extend(cellvars);
            lp.extend(freevars);
            lp
        };
        let filename = self.r_object(depth + 1)?.as_string();
        let name = self.r_object(depth + 1)?.as_string();
        let qualname = if self.layout.modern {
            self.r_object(depth + 1)?.as_string()
        } else {
            name.clone()
        };
        let firstlineno = self.u32()?;
        // Line table / lnotab, and (3.11+) the exception table — read and discard.
        let _linetable = self.r_object(depth + 1)?;
        if self.layout.modern {
            let _exctable = self.r_object(depth + 1)?;
        }

        Ok(CodeObject {
            argcount,
            posonlyargcount,
            kwonlyargcount,
            stacksize,
            flags,
            code,
            consts,
            names,
            localsplus,
            filename,
            name,
            qualname,
            firstlineno,
        })
    }
}
