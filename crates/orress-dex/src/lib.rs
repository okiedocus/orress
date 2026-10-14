//! Android DEX (Dalvik Executable) loading for ORRESS.
//!
//! [`parse`] reads a `classes.dex` header and its **string pool** — the single most useful thing
//! in a DEX for triage, since every class name, method name, field name, type descriptor and
//! string constant lives there (URLs, commands and secrets included). It also resolves type and
//! method names from the id tables. Pure `std`, no dependencies, tolerant of hostile input.
//!
//! This is the DEX inside an APK (which is a ZIP — see `orress-archive`). [`Dex::classes`] lists
//! each class's methods and [`Dex::disassemble_method`] decodes a method's Dalvik bytecode, with
//! string/type/field/method references resolved.

mod dis;

use std::collections::HashSet;

/// Offsets of the `u32` fields in the 112-byte DEX header.
mod hdr {
    pub const STRING_IDS_SIZE: usize = 56;
    pub const STRING_IDS_OFF: usize = 60;
    pub const TYPE_IDS_SIZE: usize = 64;
    pub const TYPE_IDS_OFF: usize = 68;
    pub const PROTO_IDS_SIZE: usize = 72;
    pub const FIELD_IDS_SIZE: usize = 80;
    pub const FIELD_IDS_OFF: usize = 84;
    pub const METHOD_IDS_SIZE: usize = 88;
    pub const METHOD_IDS_OFF: usize = 92;
    pub const CLASS_DEFS_SIZE: usize = 96;
    pub const CLASS_DEFS_OFF: usize = 100;
}

/// A parsed DEX file (header counts, the string pool, and resolved type/method names).
#[derive(Debug, Clone)]
pub struct Dex {
    /// Version from the magic, e.g. `035`.
    pub version: String,
    pub string_count: u32,
    pub type_count: u32,
    pub proto_count: u32,
    pub field_count: u32,
    pub method_count: u32,
    pub class_def_count: u32,
    /// The decoded string pool, in index order.
    pub strings: Vec<String>,
    /// Type descriptors (`Lcom/example/Foo;`), resolved from the type-id table.
    pub types: Vec<String>,
    /// Fully-qualified method names (`Lcom/example/Foo;.bar`), resolved from the method-id table.
    pub methods: Vec<String>,
    /// Fully-qualified field names (`Lcom/example/Foo;.bar`), from the field-id table.
    pub fields: Vec<String>,
    /// Classes with their methods (name + code offset), for disassembly.
    pub classes: Vec<DexClass>,
}

/// A class and its methods.
#[derive(Debug, Clone)]
pub struct DexClass {
    pub name: String,
    pub methods: Vec<DexMethod>,
}

/// A method and the file offset of its `code_item` (0 if abstract/native).
#[derive(Debug, Clone)]
pub struct DexMethod {
    pub name: String,
    pub code_off: u32,
}

/// One decoded Dalvik instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct DalvikInsn {
    /// Offset in 16-bit code units from the start of the method's code (matches `dexdump`).
    pub offset: usize,
    pub opcode: u8,
    pub mnemonic: &'static str,
    /// Rendered operands (registers, literals, resolved references, branch targets).
    pub operand: String,
    pub branch_target: Option<usize>,
    pub is_branch_target: bool,
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// True if `data` starts with the DEX magic (`dex\n`).
pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..4] == b"dex\n"
}

/// Reads an unsigned LEB128 value at `*pos`, advancing it. `None` if the stream ends first.
fn read_uleb128(d: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let byte = *d.get(*pos)?;
        *pos += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 32 {
            return Some(result);
        }
    }
}

/// Decodes a MUTF-8 string_data item at `off` (a ULEB128 code-unit count, then UTF-8 bytes up to a
/// NUL terminator).
fn read_string_data(d: &[u8], off: usize) -> String {
    let mut pos = off;
    let _utf16_len = read_uleb128(d, &mut pos);
    let start = pos;
    while d.get(pos).is_some_and(|&b| b != 0) {
        pos += 1;
    }
    decode_mutf8(&d[start..pos.min(d.len())])
}

/// Decodes Java/Dalvik "modified UTF-8" (1/2/3-byte forms, `C0 80` NUL, 6-byte surrogate pairs).
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
            if i + 5 < bytes.len()
                && b == 0xED
                && (bytes[i + 1] & 0xF0) == 0xA0
                && bytes[i + 3] == 0xED
            {
                let hi = ((bytes[i + 1] as u32 & 0x0F) << 6) | (bytes[i + 2] as u32 & 0x3F);
                let lo = ((bytes[i + 4] as u32 & 0x0F) << 6) | (bytes[i + 5] as u32 & 0x3F);
                out.push(char::from_u32(0x10000 + (hi << 10) + lo).unwrap_or('\u{FFFD}'));
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

/// Cap on table sizes, so a crafted header can't make us allocate wildly.
const MAX_ITEMS: u32 = 20_000_000;

/// Parses a DEX file.
pub fn parse(data: &[u8]) -> Result<Dex, String> {
    if !is_dex(data) {
        return Err("not a DEX file (missing \"dex\\n\" magic)".into());
    }
    if data.len() < 112 {
        return Err("file too small for a DEX header".into());
    }
    let version = String::from_utf8_lossy(&data[4..7]).into_owned();

    let get = |off: usize| u32_at(data, off).ok_or("truncated header");
    let string_count = get(hdr::STRING_IDS_SIZE)?;
    let string_off = get(hdr::STRING_IDS_OFF)? as usize;
    let type_count = get(hdr::TYPE_IDS_SIZE)?;
    let type_off = get(hdr::TYPE_IDS_OFF)? as usize;
    let proto_count = get(hdr::PROTO_IDS_SIZE)?;
    let field_count = get(hdr::FIELD_IDS_SIZE)?;
    let field_off = get(hdr::FIELD_IDS_OFF)? as usize;
    let method_count = get(hdr::METHOD_IDS_SIZE)?;
    let method_off = get(hdr::METHOD_IDS_OFF)? as usize;
    let class_def_count = get(hdr::CLASS_DEFS_SIZE)?;
    let class_def_off = get(hdr::CLASS_DEFS_OFF)? as usize;

    if string_count
        .max(type_count)
        .max(field_count)
        .max(method_count)
        .max(class_def_count)
        > MAX_ITEMS
    {
        return Err("implausible table size".into());
    }
    // Never walk more entries than the file can actually hold from each table's offset.
    let fits = |count: u32, off: usize, item: usize| -> usize {
        (count as usize).min(data.len().saturating_sub(off) / item)
    };

    // String pool: string_ids[i] is a u32 offset to a string_data item.
    let mut strings = Vec::with_capacity(string_count.min(1 << 16) as usize);
    for i in 0..fits(string_count, string_off, 4) {
        match u32_at(data, string_off + i * 4) {
            Some(off) if (off as usize) < data.len() => {
                strings.push(read_string_data(data, off as usize))
            }
            _ => strings.push(String::new()),
        }
    }

    // Type descriptors: type_ids[i] is a u32 index into the string pool.
    let mut types = Vec::with_capacity(type_count.min(1 << 16) as usize);
    for i in 0..fits(type_count, type_off, 4) {
        let s = u32_at(data, type_off + i * 4)
            .and_then(|idx| strings.get(idx as usize))
            .cloned()
            .unwrap_or_default();
        types.push(s);
    }

    // Methods: method_id = { class_idx: u16, proto_idx: u16, name_idx: u32 }.
    let mut methods = Vec::with_capacity(method_count.min(1 << 16) as usize);
    for i in 0..fits(method_count, method_off, 8) {
        let base = method_off + i * 8;
        let class = u16_at(data, base)
            .and_then(|idx| types.get(idx as usize))
            .cloned();
        let name = u32_at(data, base + 4)
            .and_then(|idx| strings.get(idx as usize))
            .cloned();
        match (class, name) {
            (Some(c), Some(n)) => methods.push(format!("{c}.{n}")),
            (None, Some(n)) => methods.push(n),
            _ => methods.push(String::new()),
        }
    }

    // Fields: field_id = { class_idx: u16, type_idx: u16, name_idx: u32 }.
    let mut fields = Vec::with_capacity(field_count.min(1 << 16) as usize);
    for i in 0..fits(field_count, field_off, 8) {
        let base = field_off + i * 8;
        let class = u16_at(data, base)
            .and_then(|idx| types.get(idx as usize))
            .cloned();
        let name = u32_at(data, base + 4)
            .and_then(|idx| strings.get(idx as usize))
            .cloned();
        fields.push(match (class, name) {
            (Some(c), Some(n)) => format!("{c}.{n}"),
            (_, Some(n)) => n,
            _ => String::new(),
        });
    }

    // Classes and their methods (from class_defs -> class_data).
    let classes = parse_classes(
        data,
        class_def_off,
        fits(class_def_count, class_def_off, 32) as u32,
        &types,
        &methods,
    );

    Ok(Dex {
        version,
        string_count,
        type_count,
        proto_count,
        field_count,
        method_count,
        class_def_count,
        strings,
        types,
        methods,
        fields,
        classes,
    })
}

/// Walks the class_defs table and each present class_data to collect methods + their code offsets.
fn parse_classes(
    d: &[u8],
    off: usize,
    count: u32,
    types: &[String],
    methods: &[String],
) -> Vec<DexClass> {
    let count = (count as usize).min(1 << 20);
    let mut out = Vec::with_capacity(count.min(1 << 16));
    for i in 0..count {
        let base = off + i * 32; // class_def_item is 32 bytes
        let Some(class_idx) = u32_at(d, base) else {
            break;
        };
        let name = types.get(class_idx as usize).cloned().unwrap_or_default();
        let data_off = u32_at(d, base + 24).unwrap_or(0) as usize;
        let mut ms = Vec::new();
        if data_off != 0 {
            ms = parse_class_methods(d, data_off, methods);
        }
        out.push(DexClass { name, methods: ms });
    }
    out
}

/// Parses a class_data_item's method lists (fields are skipped). Method indices are delta-encoded.
fn parse_class_methods(d: &[u8], off: usize, methods: &[String]) -> Vec<DexMethod> {
    let mut p = off;
    let static_fields = read_uleb128(d, &mut p);
    let instance_fields = read_uleb128(d, &mut p);
    let direct_methods = read_uleb128(d, &mut p);
    let virtual_methods = read_uleb128(d, &mut p);
    let (Some(sf), Some(inf), Some(dm), Some(vm)) = (
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
    ) else {
        return Vec::new();
    };
    // Reject implausible counts (junk or hostile offsets) before looping on them.
    const CAP: u32 = 1 << 20;
    if sf > CAP || inf > CAP || dm > CAP || vm > CAP {
        return Vec::new();
    }
    // Skip encoded_field lists (each: field_idx_diff, access_flags).
    for _ in 0..(sf + inf) {
        read_uleb128(d, &mut p);
        read_uleb128(d, &mut p);
    }
    let mut out = Vec::new();
    for group in [dm, vm] {
        let mut method_idx: u32 = 0;
        let mut first = true;
        for _ in 0..group {
            let Some(diff) = read_uleb128(d, &mut p) else {
                return out;
            };
            let _access = read_uleb128(d, &mut p);
            let Some(code_off) = read_uleb128(d, &mut p) else {
                return out;
            };
            method_idx = if first {
                diff
            } else {
                method_idx.wrapping_add(diff)
            };
            first = false;
            let name = methods
                .get(method_idx as usize)
                .cloned()
                .unwrap_or_default();
            out.push(DexMethod { name, code_off });
        }
    }
    out
}

fn sign4(x: u16) -> i32 {
    let x = (x & 0xf) as i32;
    if x >= 8 { x - 16 } else { x }
}
fn sign8(x: u16) -> i32 {
    (x & 0xff) as u8 as i8 as i32
}
fn sign16(x: u16) -> i32 {
    x as i16 as i32
}

impl Dex {
    fn resolve_ref(&self, kind: dis::Ref, idx: usize) -> String {
        match kind {
            dis::Ref::Str => self.strings.get(idx).map(|s| format!("{s:?}")),
            dis::Ref::Type => self.types.get(idx).cloned(),
            dis::Ref::Method => self.methods.get(idx).cloned(),
            dis::Ref::Field => self.fields.get(idx).cloned(),
            dis::Ref::Other => Some(format!("@{idx}")),
            dis::Ref::None => None,
        }
        .unwrap_or_else(|| format!("@{idx}"))
    }

    /// Disassembles the Dalvik bytecode of the `code_item` at file offset `code_off`.
    pub fn disassemble_method(
        &self,
        data: &[u8],
        code_off: u32,
    ) -> Result<Vec<DalvikInsn>, String> {
        if code_off == 0 {
            return Err("method has no code (abstract or native)".into());
        }
        let base = code_off as usize;
        let insns_size = u32_at(data, base + 12).ok_or("truncated code_item")? as usize;
        if insns_size > 10_000_000 {
            return Err("implausible code size".into());
        }
        let start = base + 16;
        let mut units = Vec::with_capacity(insns_size.min(1 << 16));
        for k in 0..insns_size {
            units.push(u16_at(data, start + k * 2).ok_or("truncated instructions")?);
        }
        Ok(self.decode(&units))
    }

    fn decode(&self, units: &[u16]) -> Vec<DalvikInsn> {
        let mut out = Vec::new();
        let mut targets = HashSet::new();
        let mut i = 0;
        while i < units.len() {
            let op = (units[i] & 0xff) as u8;
            // A `nop` unit with a non-zero high byte may start switch/array payload data, which
            // sits inline in the code: skip it by its encoded size and keep decoding after it.
            if op == 0x00
                && let Some((mnemonic, size, operand)) = payload(units, i)
            {
                out.push(DalvikInsn {
                    offset: i,
                    opcode: op,
                    mnemonic,
                    operand,
                    branch_target: None,
                    is_branch_target: false,
                });
                i = i.saturating_add(size);
                continue;
            }
            let (mnemonic, fmt, refkind) = dis::info(op);
            let (operand, target) = self.decode_fmt(units, i, fmt, refkind);
            if let Some(t) = target {
                targets.insert(t);
            }
            out.push(DalvikInsn {
                offset: i,
                opcode: op,
                mnemonic,
                operand,
                branch_target: target,
                is_branch_target: false,
            });
            i += fmt.units().max(1);
        }
        for ins in &mut out {
            if targets.contains(&ins.offset) {
                ins.is_branch_target = true;
            }
        }
        out
    }

    fn decode_fmt(
        &self,
        units: &[u16],
        i: usize,
        fmt: dis::Fmt,
        refkind: dis::Ref,
    ) -> (String, Option<usize>) {
        use dis::Fmt::*;
        let u = |j: usize| units.get(i + j).copied().unwrap_or(0);
        let a8 = ((u(0) >> 8) & 0xff) as u32;
        let a4 = ((u(0) >> 8) & 0xf) as u32;
        let b4 = ((u(0) >> 12) & 0xf) as u32;
        let branch = |off: i32| {
            let t = (i as i64 + off as i64) as usize;
            (format!("{t:04x}"), Some(t))
        };
        let reff = |idx: u16| self.resolve_ref(refkind, idx as usize);

        match fmt {
            F10x | Unknown => (String::new(), None),
            F12x => (format!("v{a4}, v{b4}"), None),
            F11n => (format!("v{a4}, #{}", sign4(u(0) >> 12)), None),
            F11x => (format!("v{a8}"), None),
            F10t => branch(sign8(u(0) >> 8)),
            F20t => branch(sign16(u(1))),
            F22x => (format!("v{a8}, v{}", u(1)), None),
            F21t => {
                let (t, tgt) = branch(sign16(u(1)));
                (format!("v{a8}, {t}"), tgt)
            }
            F21s => (format!("v{a8}, #{}", sign16(u(1))), None),
            F21h => (format!("v{a8}, #{:#x}", (u(1) as u32) << 16), None),
            F21hw => (format!("v{a8}, #{:#x}", (u(1) as u64) << 48), None),
            F21c => (format!("v{a8}, {}", reff(u(1))), None),
            F23x => (format!("v{a8}, v{}, v{}", u(1) & 0xff, u(1) >> 8), None),
            F22b => (
                format!("v{a8}, v{}, #{}", u(1) & 0xff, sign8(u(1) >> 8)),
                None,
            ),
            F22t => {
                let (t, tgt) = branch(sign16(u(1)));
                (format!("v{a4}, v{b4}, {t}"), tgt)
            }
            F22s => (format!("v{a4}, v{b4}, #{}", sign16(u(1))), None),
            F22c => (format!("v{a4}, v{b4}, {}", reff(u(1))), None),
            F30t => branch((u(1) as u32 | ((u(2) as u32) << 16)) as i32),
            F31t => {
                let (t, tgt) = branch((u(1) as u32 | ((u(2) as u32) << 16)) as i32);
                (format!("v{a8}, {t}"), tgt)
            }
            F31i => (
                format!("v{a8}, #{}", (u(1) as u32 | ((u(2) as u32) << 16)) as i32),
                None,
            ),
            F31c => (
                format!(
                    "v{a8}, {}",
                    reff_wide(self, refkind, u(1) as u32 | ((u(2) as u32) << 16))
                ),
                None,
            ),
            F32x => (format!("v{}, v{}", u(1), u(2)), None),
            F35c => (
                format!("{{{}}}, {}", list_regs(u(0), u(2)), reff(u(1))),
                None,
            ),
            F3rc => {
                let count = (u(0) >> 8) & 0xff;
                let list = range_regs(u(2), count);
                (format!("{{{list}}}, {}", reff(u(1))), None)
            }
            F51l => {
                let v = (u(1) as u64)
                    | ((u(2) as u64) << 16)
                    | ((u(3) as u64) << 32)
                    | ((u(4) as u64) << 48);
                (format!("v{a8}, #{}", v as i64), None)
            }
            // invoke-polymorphic: like 35c/3rc plus a trailing proto index.
            F45cc => (
                format!(
                    "{{{}}}, {}, proto@{}",
                    list_regs(u(0), u(2)),
                    reff(u(1)),
                    u(3)
                ),
                None,
            ),
            F4rcc => (
                format!(
                    "{{{}}}, {}, proto@{}",
                    range_regs(u(2), (u(0) >> 8) & 0xff),
                    reff(u(1)),
                    u(3)
                ),
                None,
            ),
        }
    }
}

/// The register list of a 35c/45cc instruction (`A|G|op ... F|E|D|C`).
fn list_regs(u0: u16, u2: u16) -> String {
    let count = (u0 >> 12) & 0xf;
    let g = (u0 >> 8) & 0xf;
    let regs = [
        u2 & 0xf,
        (u2 >> 4) & 0xf,
        (u2 >> 8) & 0xf,
        (u2 >> 12) & 0xf,
        g,
    ];
    regs[..(count as usize).min(5)]
        .iter()
        .map(|r| format!("v{r}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The register range of a 3rc/4rcc instruction: `count` registers starting at `first`.
fn range_regs(first: u16, count: u16) -> String {
    (0..u32::from(count))
        .map(|k| format!("v{}", u32::from(first) + k))
        .collect::<Vec<_>>()
        .join(", ")
}

/// If the code unit at `i` starts a switch/array payload pseudo-instruction, returns its
/// mnemonic, total size in code units and a short description.
fn payload(units: &[u16], i: usize) -> Option<(&'static str, usize, String)> {
    let u = |j: usize| u64::from(units.get(i + j).copied().unwrap_or(0));
    let (mnemonic, size, desc) = match units[i] {
        0x0100 => {
            let n = u(1);
            ("packed-switch-payload", n * 2 + 4, format!("{n} entries"))
        }
        0x0200 => {
            let n = u(1);
            ("sparse-switch-payload", n * 4 + 2, format!("{n} entries"))
        }
        0x0300 => {
            let width = u(1);
            let n = u(2) | (u(3) << 16);
            (
                "fill-array-data-payload",
                (n * width).div_ceil(2) + 4,
                format!("{n} x {width}-byte elements"),
            )
        }
        _ => return None,
    };
    Some((mnemonic, usize::try_from(size).unwrap_or(usize::MAX), desc))
}

/// Resolves a 32-bit reference index (jumbo string / wide const).
fn reff_wide(dex: &Dex, kind: dis::Ref, idx: u32) -> String {
    dex.resolve_ref(kind, idx as usize)
}

#[cfg(test)]
mod tests;
