//! Python compiled-bytecode (`.pyc`) loading for ORRESS.
//!
//! A `.pyc` is a short header (a version magic, flags, and a timestamp or source hash) followed by
//! a `marshal`-serialized module code object. [`parse`] recovers the whole code-object tree —
//! every function, comprehension and class body, with their names, constants and raw bytecode —
//! and [`disassemble`] turns a code object's bytecode into instructions. Pure `std`, no external
//! dependencies, and tolerant of hostile input.
//!
//! The marshal reader and the code-object field layout work across Python 3.x (the layout is
//! selected from the detected version). Named disassembly is currently bundled for the host's
//! CPython (3.14); other versions still yield the full structure, constants, strings and raw
//! bytecode — only the opcode *names* wait on their own bundled table.

mod dis;
mod marshal;
mod opcodes_314;

pub use dis::Insn;
pub use marshal::{CodeObject, Obj, Unmarshal};

/// How a code object is laid out in the marshal stream, which changed across Python versions.
#[derive(Debug, Clone, Copy)]
pub struct CodeLayout {
    /// 3.11+: `localsplusnames`/`localspluskinds`, `qualname`, exception table, no `nlocals`.
    pub modern: bool,
    /// 3.8+: a `posonlyargcount` field.
    pub has_posonly: bool,
    /// < 3.11: an `nlocals` field.
    pub has_nlocals: bool,
}

impl CodeLayout {
    fn for_version(v: Option<(u8, u8)>) -> Self {
        // Default to the modern layout when the version is unknown (most .pyc today are 3.11+).
        let (_maj, min) = v.unwrap_or((3, 11));
        let modern = min >= 11;
        Self {
            modern,
            has_posonly: min >= 8,
            has_nlocals: !modern,
        }
    }
}

/// A parsed `.pyc` file.
#[derive(Debug, Clone)]
pub struct Pyc {
    /// Detected `(major, minor)` Python version, if the magic is known.
    pub version: Option<(u8, u8)>,
    /// The raw 16-bit magic number.
    pub magic: u16,
    /// 3.7+ hash-based pyc (otherwise timestamp-based).
    pub hash_based: bool,
    /// Length of the header before the marshal body.
    pub header_len: usize,
    pub layout: CodeLayout,
    /// The module-level code object (its constants hold the nested functions/classes).
    pub top: CodeObject,
}

impl Pyc {
    /// A short version label such as `Python 3.14` or `Python (unknown magic 1234)`.
    pub fn version_label(&self) -> String {
        match self.version {
            Some((a, b)) => format!("Python {a}.{b}"),
            None => format!("Python (unknown magic {})", self.magic),
        }
    }

    /// Whether ORRESS can name this version's opcodes (so a disassembly is meaningful).
    pub fn can_disassemble(&self) -> bool {
        self.version == Some((3, 14))
    }
}

/// CPython 3.x magic-number ranges, inclusive. Each range runs from a minor version's first
/// development magic up to just before the next minor's, so alpha/beta/point-release bumps map to
/// the right version. Anything outside (Python 2's 62211-style magics, versions newer than the
/// last known one, garbage) is reported as unknown rather than guessed.
const MAGIC_RANGES: &[(u16, u16, u8, u8)] = &[
    (3000, 3140, 3, 0),
    (3141, 3159, 3, 1),
    (3160, 3189, 3, 2),
    (3190, 3249, 3, 3),
    (3250, 3319, 3, 4),
    (3320, 3359, 3, 5),
    (3360, 3389, 3, 6),
    (3390, 3399, 3, 7),
    (3400, 3419, 3, 8),
    (3420, 3429, 3, 9),
    (3430, 3449, 3, 10),
    (3450, 3499, 3, 11),
    (3500, 3549, 3, 12),
    (3550, 3599, 3, 13),
    (3600, 3649, 3, 14),
];

fn version_from_magic(magic: u16) -> Option<(u8, u8)> {
    MAGIC_RANGES
        .iter()
        .find(|&&(lo, hi, _, _)| (lo..=hi).contains(&magic))
        .map(|&(_, _, a, b)| (a, b))
}

/// A quick check: a `.pyc` carries `\r\n` at bytes 2–3 after the 2-byte magic.
pub fn looks_like_pyc(data: &[u8]) -> bool {
    data.len() >= 16 && data[2] == 0x0d && data[3] == 0x0a
}

/// Parses a `.pyc` file into its header and code-object tree.
pub fn parse(data: &[u8]) -> Result<Pyc, String> {
    if data.len() < 16 {
        return Err("file too small to be a .pyc".into());
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if data[2] != 0x0d || data[3] != 0x0a {
        return Err("not a .pyc file (missing \\r\\n after the magic number)".into());
    }
    let version = version_from_magic(magic);
    let layout = CodeLayout::for_version(version);
    // Unknown magics get the current (3.7+) 16-byte header as a best guess.
    let min = version.map(|v| v.1).unwrap_or(11);

    // Header length and flags by version: 3.7+ magic/flags/(mtime+size | hash) = 16 bytes,
    // 3.3–3.6 magic/mtime/size = 12 bytes, 3.0–3.2 magic/mtime = 8 bytes.
    let (header_len, hash_based) = if min >= 7 {
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        (16, flags & 1 != 0)
    } else if min >= 3 {
        (12, false)
    } else {
        (8, false)
    };

    let body = data
        .get(header_len..)
        .ok_or("file truncated before the marshal body")?;
    let obj = Unmarshal::new(body, layout).read()?;
    let top = match obj {
        Obj::Code(c) => *c,
        other => {
            return Err(format!(
                "top-level object is not a code object: {}",
                other.render()
            ));
        }
    };

    Ok(Pyc {
        version,
        magic,
        hash_based,
        header_len,
        layout,
        top,
    })
}

/// Disassembles a code object, if ORRESS has the opcode table for `version`.
pub fn disassemble(code: &CodeObject, version: Option<(u8, u8)>) -> Option<Vec<Insn>> {
    (version == Some((3, 14))).then(|| dis::disassemble_314(code))
}

/// Decodes the `co_flags` bitfield into readable flag names.
pub fn flag_names(flags: u32) -> Vec<&'static str> {
    const FLAGS: &[(u32, &str)] = &[
        (0x0001, "OPTIMIZED"),
        (0x0002, "NEWLOCALS"),
        (0x0004, "VARARGS"),
        (0x0008, "VARKEYWORDS"),
        (0x0010, "NESTED"),
        (0x0020, "GENERATOR"),
        (0x0040, "NOFREE"),
        (0x0080, "COROUTINE"),
        (0x0100, "ITERABLE_COROUTINE"),
        (0x0200, "ASYNC_GENERATOR"),
    ];
    FLAGS
        .iter()
        .filter(|&&(bit, _)| flags & bit != 0)
        .map(|&(_, name)| name)
        .collect()
}

#[cfg(test)]
mod tests;
