//! Java class-file (`.class`) loading for ORRESS.
//!
//! [`parse`] reads the JVM class-file format — the constant pool, this/super class, interfaces,
//! fields and methods with their descriptors and attributes — and [`disassemble`] turns a method's
//! `Code` attribute into JVM bytecode instructions with constant-pool references resolved. Pure
//! `std`, no dependencies, and tolerant of hostile input (errors rather than panics; counts and
//! sizes are bounded).
//!
//! Java bytecode is common in CTF (and Android work starts here before DEX); the format and opcode
//! set are stable, so this covers every class version. Part of ORRESS's M10 managed-code track.

mod dis;

pub use dis::{Insn, disassemble};

/// A constant-pool entry (1-indexed in the file; `Unusable` fills index 0 and the second slot of
/// `Long`/`Double`).
#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Unusable,
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class(u16),
    String(u16),
    FieldRef { class: u16, nat: u16 },
    MethodRef { class: u16, nat: u16 },
    InterfaceMethodRef { class: u16, nat: u16 },
    NameAndType { name: u16, desc: u16 },
    MethodHandle { kind: u8, index: u16 },
    MethodType(u16),
    Dynamic { bootstrap: u16, nat: u16 },
    InvokeDynamic { bootstrap: u16, nat: u16 },
    Module(u16),
    Package(u16),
}

/// The constant pool: resolves indices to strings, names and references.
#[derive(Debug, Clone, Default)]
pub struct ConstantPool(Vec<Constant>);

impl ConstantPool {
    pub fn get(&self, i: u16) -> Option<&Constant> {
        self.0.get(i as usize)
    }

    /// The UTF-8 text at `i`, if that entry is a `Utf8`.
    pub fn utf8(&self, i: u16) -> Option<&str> {
        match self.get(i)? {
            Constant::Utf8(s) => Some(s),
            _ => None,
        }
    }

    /// The class name at `i` (a `Class` entry → its `Utf8` name).
    pub fn class_name(&self, i: u16) -> Option<String> {
        match self.get(i)? {
            Constant::Class(n) => self.utf8(*n).map(str::to_string),
            _ => None,
        }
    }

    fn name_and_type(&self, i: u16) -> Option<(String, String)> {
        match self.get(i)? {
            Constant::NameAndType { name, desc } => {
                Some((self.utf8(*name)?.to_string(), self.utf8(*desc)?.to_string()))
            }
            _ => None,
        }
    }

    /// A human rendering of the entry at `i` — used for instruction-operand comments. References
    /// render as `Class.name:descriptor`, strings quoted, numbers as literals.
    pub fn resolve(&self, i: u16) -> String {
        match self.get(i) {
            None => format!("#{i}?"),
            Some(c) => match c {
                Constant::Utf8(s) => s.clone(),
                Constant::Integer(v) => v.to_string(),
                Constant::Float(v) => format!("{v}f"),
                Constant::Long(v) => format!("{v}L"),
                Constant::Double(v) => v.to_string(),
                Constant::Class(n) => self.utf8(*n).unwrap_or("?").to_string(),
                Constant::String(n) => format!("{:?}", self.utf8(*n).unwrap_or("?")),
                Constant::FieldRef { class, nat }
                | Constant::MethodRef { class, nat }
                | Constant::InterfaceMethodRef { class, nat } => {
                    let cls = self.class_name(*class).unwrap_or_else(|| "?".into());
                    match self.name_and_type(*nat) {
                        Some((n, d)) => format!("{cls}.{n}:{d}"),
                        None => format!("{cls}.#{nat}"),
                    }
                }
                Constant::NameAndType { name, desc } => format!(
                    "{}:{}",
                    self.utf8(*name).unwrap_or("?"),
                    self.utf8(*desc).unwrap_or("?")
                ),
                Constant::MethodHandle { kind, index } => format!("handle kind {kind} #{index}"),
                Constant::MethodType(d) => self.utf8(*d).unwrap_or("?").to_string(),
                Constant::Dynamic { nat, .. } | Constant::InvokeDynamic { nat, .. } => {
                    match self.name_and_type(*nat) {
                        Some((n, d)) => format!("{n}:{d}"),
                        None => format!("#{nat}"),
                    }
                }
                Constant::Module(n) | Constant::Package(n) => {
                    self.utf8(*n).unwrap_or("?").to_string()
                }
                Constant::Unusable => "(unusable)".to_string(),
            },
        }
    }
}

/// A caught-exception entry in a method's `Code`.
#[derive(Debug, Clone, PartialEq)]
pub struct Exception {
    pub start: u16,
    pub end: u16,
    pub handler: u16,
    /// Caught class name, or `None` for a `finally` (catch-all).
    pub catch_type: Option<String>,
}

/// A method's executable code.
#[derive(Debug, Clone)]
pub struct Code {
    pub max_stack: u16,
    pub max_locals: u16,
    pub bytecode: Vec<u8>,
    pub exceptions: Vec<Exception>,
}

/// A field or method.
#[derive(Debug, Clone)]
pub struct Member {
    pub access: u16,
    pub name: String,
    pub descriptor: String,
    /// Methods: the decoded `Code` attribute, if present (absent for abstract/native).
    pub code: Option<Code>,
    /// Fields: the constant-pool index of a `ConstantValue` attribute (compile-time constant).
    pub constant_value: Option<u16>,
}

/// A parsed Java class file.
#[derive(Debug, Clone)]
pub struct ClassFile {
    pub minor: u16,
    pub major: u16,
    pub access: u16,
    pub this_class: String,
    /// `None` only for `java/lang/Object`.
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<Member>,
    pub methods: Vec<Member>,
    pub source_file: Option<String>,
    pub cp: ConstantPool,
}

impl ClassFile {
    /// A readable Java platform version from the major version (`61` → `Java 17`).
    pub fn java_version(&self) -> String {
        match self.major {
            45 => "Java 1.1".into(),
            46 => "Java 1.2".into(),
            47 => "Java 1.3".into(),
            48 => "Java 1.4".into(),
            m if m >= 49 => format!("Java {}", m - 44),
            m => format!("class v{m}"),
        }
    }
}

/// True if `data` starts with the JVM class-file magic `0xCAFEBABE`.
pub fn is_class(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0xCA, 0xFE, 0xBA, 0xBE]
}

/// Decodes class/field/method access flags into readable names.
pub fn access_flag_names(access: u16) -> Vec<&'static str> {
    const FLAGS: &[(u16, &str)] = &[
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0020, "synchronized"), // also ACC_SUPER on classes
        (0x0040, "volatile"),     // also ACC_BRIDGE on methods
        (0x0080, "transient"),    // also ACC_VARARGS
        (0x0100, "native"),
        (0x0200, "interface"),
        (0x0400, "abstract"),
        (0x0800, "strictfp"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
    ];
    FLAGS
        .iter()
        .filter(|&&(bit, _)| access & bit != 0)
        .map(|&(_, n)| n)
        .collect()
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn u1(&mut self) -> Result<u8, String> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or("unexpected end of class file")?;
        self.pos += 1;
        Ok(b)
    }
    fn u2(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes([self.u1()?, self.u1()?]))
    }
    fn u4(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes([
            self.u1()?,
            self.u1()?,
            self.u1()?,
            self.u1()?,
        ]))
    }
    fn u8v(&mut self) -> Result<u64, String> {
        Ok((self.u4()? as u64) << 32 | self.u4()? as u64)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("length overflow")?;
        let s = self.data.get(self.pos..end).ok_or("truncated data")?;
        self.pos = end;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.bytes(n).map(|_| ())
    }
}

/// Parses a `.class` file.
pub fn parse(data: &[u8]) -> Result<ClassFile, String> {
    let mut r = Reader::new(data);
    if r.u4()? != 0xCAFE_BABE {
        return Err("not a Java class file (missing 0xCAFEBABE magic)".into());
    }
    let minor = r.u2()?;
    let major = r.u2()?;

    let cp = parse_constant_pool(&mut r)?;

    let access = r.u2()?;
    let this_idx = r.u2()?;
    let this_class = cp.class_name(this_idx).unwrap_or_else(|| "?".into());
    let super_idx = r.u2()?;
    let super_class = if super_idx == 0 {
        None
    } else {
        cp.class_name(super_idx)
    };

    let icount = r.u2()? as usize;
    let mut interfaces = Vec::with_capacity(icount.min(256));
    for _ in 0..icount {
        let idx = r.u2()?;
        interfaces.push(cp.class_name(idx).unwrap_or_else(|| "?".into()));
    }

    let fields = parse_members(&mut r, &cp, false)?;
    let methods = parse_members(&mut r, &cp, true)?;

    // Class-level attributes: pick up SourceFile; skip the rest.
    let mut source_file = None;
    let acount = r.u2()? as usize;
    for _ in 0..acount {
        let name = cp.utf8(r.u2()?).unwrap_or("").to_string();
        let len = r.u4()? as usize;
        if name == "SourceFile" && len == 2 {
            source_file = cp.utf8(r.u2()?).map(str::to_string);
        } else {
            r.skip(len)?;
        }
    }

    Ok(ClassFile {
        minor,
        major,
        access,
        this_class,
        super_class,
        interfaces,
        fields,
        methods,
        source_file,
        cp,
    })
}

fn parse_constant_pool(r: &mut Reader) -> Result<ConstantPool, String> {
    let count = r.u2()? as usize;
    if count == 0 {
        return Err("invalid constant pool count 0".into());
    }
    let mut pool = vec![Constant::Unusable]; // index 0 is unused
    let mut i = 1;
    while i < count {
        let tag = r.u1()?;
        let c = match tag {
            1 => {
                let len = r.u2()? as usize;
                Constant::Utf8(decode_mutf8(r.bytes(len)?))
            }
            3 => Constant::Integer(r.u4()? as i32),
            4 => Constant::Float(f32::from_bits(r.u4()?)),
            5 => Constant::Long(r.u8v()? as i64),
            6 => Constant::Double(f64::from_bits(r.u8v()?)),
            7 => Constant::Class(r.u2()?),
            8 => Constant::String(r.u2()?),
            9 => Constant::FieldRef {
                class: r.u2()?,
                nat: r.u2()?,
            },
            10 => Constant::MethodRef {
                class: r.u2()?,
                nat: r.u2()?,
            },
            11 => Constant::InterfaceMethodRef {
                class: r.u2()?,
                nat: r.u2()?,
            },
            12 => Constant::NameAndType {
                name: r.u2()?,
                desc: r.u2()?,
            },
            15 => Constant::MethodHandle {
                kind: r.u1()?,
                index: r.u2()?,
            },
            16 => Constant::MethodType(r.u2()?),
            17 => Constant::Dynamic {
                bootstrap: r.u2()?,
                nat: r.u2()?,
            },
            18 => Constant::InvokeDynamic {
                bootstrap: r.u2()?,
                nat: r.u2()?,
            },
            19 => Constant::Module(r.u2()?),
            20 => Constant::Package(r.u2()?),
            other => return Err(format!("unknown constant-pool tag {other}")),
        };
        let wide = matches!(c, Constant::Long(_) | Constant::Double(_));
        pool.push(c);
        i += 1;
        if wide {
            // Long/Double take two pool slots.
            pool.push(Constant::Unusable);
            i += 1;
        }
    }
    Ok(ConstantPool(pool))
}

fn parse_members(r: &mut Reader, cp: &ConstantPool, methods: bool) -> Result<Vec<Member>, String> {
    let count = r.u2()? as usize;
    if count > 65_535 {
        return Err("implausible member count".into());
    }
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let access = r.u2()?;
        let name = cp.utf8(r.u2()?).unwrap_or("?").to_string();
        let descriptor = cp.utf8(r.u2()?).unwrap_or("?").to_string();
        let mut code = None;
        let mut constant_value = None;
        let acount = r.u2()? as usize;
        for _ in 0..acount {
            let aname = cp.utf8(r.u2()?).unwrap_or("").to_string();
            let len = r.u4()? as usize;
            match aname.as_str() {
                "Code" if methods => code = Some(parse_code(r, cp, len)?),
                "ConstantValue" if !methods && len == 2 => constant_value = Some(r.u2()?),
                _ => r.skip(len)?,
            }
        }
        out.push(Member {
            access,
            name,
            descriptor,
            code,
            constant_value,
        });
    }
    Ok(out)
}

fn parse_code(r: &mut Reader, cp: &ConstantPool, attr_len: usize) -> Result<Code, String> {
    let end = r.pos + attr_len;
    let max_stack = r.u2()?;
    let max_locals = r.u2()?;
    let code_len = r.u4()? as usize;
    let bytecode = r.bytes(code_len)?.to_vec();
    let ecount = r.u2()? as usize;
    let mut exceptions = Vec::with_capacity(ecount.min(256));
    for _ in 0..ecount {
        let start = r.u2()?;
        let end_pc = r.u2()?;
        let handler = r.u2()?;
        let ct = r.u2()?;
        exceptions.push(Exception {
            start,
            end: end_pc,
            handler,
            catch_type: (ct != 0).then(|| cp.class_name(ct).unwrap_or_else(|| "?".into())),
        });
    }
    // Skip the Code attribute's own sub-attributes (LineNumberTable, etc.).
    if end >= r.pos {
        r.skip(end - r.pos)?;
    }
    Ok(Code {
        max_stack,
        max_locals,
        bytecode,
        exceptions,
    })
}

/// Decodes Java's "modified UTF-8" to a Rust `String` (best-effort; invalid sequences become
/// U+FFFD). Handles 1/2/3-byte forms and the 6-byte supplementary-pair encoding, and `C0 80` NUL.
fn decode_mutf8(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            out.push(b as char);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            if i + 1 < bytes.len() {
                let c = ((b as u32 & 0x1F) << 6) | (bytes[i + 1] as u32 & 0x3F);
                out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
            }
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            // Could be a normal 3-byte char or half of a 6-byte surrogate pair.
            if i + 5 < bytes.len()
                && b == 0xED
                && (bytes[i + 1] & 0xF0) == 0xA0
                && bytes[i + 3] == 0xED
            {
                let hi = ((bytes[i + 1] as u32 & 0x0F) << 6) | (bytes[i + 2] as u32 & 0x3F);
                let lo = ((bytes[i + 4] as u32 & 0x0F) << 6) | (bytes[i + 5] as u32 & 0x3F);
                let c = 0x10000 + (hi << 10) + lo;
                out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                i += 6;
            } else {
                if i + 2 < bytes.len() {
                    let c = ((b as u32 & 0x0F) << 12)
                        | ((bytes[i + 1] as u32 & 0x3F) << 6)
                        | (bytes[i + 2] as u32 & 0x3F);
                    out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                }
                i += 3;
            }
        } else {
            out.push('\u{FFFD}');
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests;
