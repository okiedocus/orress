//! .NET (CLI) assembly loading for ORRESS.
//!
//! A .NET executable is a PE whose CLI header (data directory 14) points at a metadata region: a
//! root, a set of streams (`#~` tables, `#Strings`, `#US` user strings, `#GUID`, `#Blob`), and the
//! metadata tables themselves. [`parse`] walks all of that with no dependencies and recovers the
//! assembly/module names, the type and method names, and the **user-string heap** — the literal
//! strings in the IL, where .NET malware hides URLs, commands and keys.
//!
//! Row sizes are computed from the ECMA-335 schema in `tables` plus the heap-index and
//! table-row sizes, so it reads real assemblies, not just a fixed layout. Tolerant of hostile
//! input (bounded, errors instead of panics). [`DotNet::disassemble`] decodes a method's IL body
//! with tokens and user strings resolved.

mod il;
mod sig;
mod tables;

pub use il::Il;
use tables::{Coded, Col, columns, table_name};

/// A method: its name, decoded signature and the RVA of its body (0 if it has no body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method {
    pub name: String,
    /// `(params) : ret`, decoded from the signature blob (empty if unavailable).
    pub signature: String,
    pub rva: u32,
}

/// A type and the methods defined on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeInfo {
    pub namespace: String,
    pub name: String,
    pub methods: Vec<Method>,
}

impl TypeInfo {
    /// `Namespace.Name` (or just `Name` with no namespace).
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.namespace, self.name)
        }
    }
}

/// A parsed .NET assembly.
#[derive(Debug, Clone)]
pub struct DotNet {
    /// CLI runtime version string, e.g. `v4.0.30319`.
    pub runtime_version: String,
    pub module_name: String,
    pub assembly_name: Option<String>,
    pub types: Vec<TypeInfo>,
    /// `#US` user strings — the string literals in the code.
    pub user_strings: Vec<String>,
    /// `(table name, row count)` for present tables.
    pub table_rows: Vec<(&'static str, u32)>,
    /// Everything needed to resolve tokens and locate method bodies for IL disassembly.
    resolver: Resolver,
}

fn u16a(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32a(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// True if `data` is a PE with a CLI (.NET) header.
pub fn is_dotnet(data: &[u8]) -> bool {
    metadata_offset(data).is_ok()
}

/// A PE section mapping entry: `(virtual_address, size, raw_file_pointer)`.
type Section = (u32, u32, u32);

fn rva_to_off(sections: &[Section], rva: u32) -> Option<usize> {
    sections
        .iter()
        .find(|&&(va, size, _)| rva >= va && u64::from(rva) < u64::from(va) + u64::from(size))
        .and_then(|&(va, _, ptr)| usize::try_from(u64::from(ptr) + u64::from(rva - va)).ok())
}

/// Finds the metadata root's file offset and the PE section table (via the CLI header).
fn metadata_offset(d: &[u8]) -> Result<(usize, Vec<Section>), String> {
    if d.len() < 0x40 || &d[0..2] != b"MZ" {
        return Err("not a PE (no MZ)".into());
    }
    let pe = u32a(d, 0x3c).ok_or("truncated")? as usize;
    if d.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE (no PE signature)".into());
    }
    let nsec = u16a(d, pe + 6).ok_or("truncated")? as usize;
    let optsize = u16a(d, pe + 20).ok_or("truncated")? as usize;
    let opt = pe + 24;
    let magic = u16a(d, opt).ok_or("truncated")?;
    let dd = match magic {
        0x10b => opt + 96,  // PE32
        0x20b => opt + 112, // PE32+
        _ => return Err("unknown optional-header magic".into()),
    };
    let cor_rva = u32a(d, dd + 14 * 8).ok_or("truncated")?;
    if cor_rva == 0 {
        return Err("not a .NET assembly (no CLI header)".into());
    }

    let sec0 = opt + optsize;
    let mut sections = Vec::with_capacity(nsec.min(96));
    for i in 0..nsec {
        let s = sec0 + i * 40;
        let vsz = u32a(d, s + 8).ok_or("truncated section")?;
        let va = u32a(d, s + 12).ok_or("truncated section")?;
        let rsz = u32a(d, s + 16).ok_or("truncated section")?;
        let ptr = u32a(d, s + 20).ok_or("truncated section")?;
        sections.push((va, vsz.max(rsz), ptr));
    }

    let cor = rva_to_off(&sections, cor_rva).ok_or("CLI header RVA not in any section")?;
    let md_rva = u32a(d, cor + 8).ok_or("truncated CLI header")?;
    let md = rva_to_off(&sections, md_rva).ok_or("metadata RVA not in any section")?;
    if u32a(d, md) != Some(0x424a_5342) {
        return Err("bad metadata signature (expected BSJB)".into());
    }
    Ok((md, sections))
}

/// A located metadata stream: absolute file offset and size.
struct Stream {
    off: usize,
    size: usize,
}

/// Parses a .NET assembly.
pub fn parse(data: &[u8]) -> Result<DotNet, String> {
    let (md, sections) = metadata_offset(data)?;

    let ver_len = u32a(data, md + 12).ok_or("truncated metadata root")? as usize;
    let runtime_version = {
        let s = data
            .get(md + 16..md + 16 + ver_len)
            .ok_or("truncated version")?;
        String::from_utf8_lossy(s)
            .trim_end_matches('\0')
            .to_string()
    };
    let mut p = md + 16 + ((ver_len + 3) & !3);
    let nstreams = u16a(data, p + 2).ok_or("truncated stream count")?;
    p += 4;

    let mut streams: std::collections::HashMap<String, Stream> = std::collections::HashMap::new();
    for _ in 0..nstreams {
        let off = u32a(data, p).ok_or("truncated stream header")? as usize;
        let size = u32a(data, p + 4).ok_or("truncated stream header")? as usize;
        p += 8;
        let start = p;
        while data.get(p).is_some_and(|&b| b != 0) {
            p += 1;
        }
        let name = String::from_utf8_lossy(&data[start..p]).into_owned();
        p += 1;
        p = (p + 3) & !3; // pad to 4
        streams.insert(
            name,
            Stream {
                off: md + off,
                size,
            },
        );
    }

    let strings = streams.get("#Strings").ok_or("no #Strings heap")?;
    let tilde = streams
        .get("#~")
        .or_else(|| streams.get("#-"))
        .ok_or("no table stream")?;

    let md_tables = MdTables::parse(data, tilde.off, tilde.size)?;
    let string_at =
        |idx: u32| read_cstr(data, strings.off + idx as usize, strings.off + strings.size);

    // Module name (Module table, row 1, Name column = index 1).
    let module_name = md_tables
        .cell(data, 0x00, 1, 1)
        .map(|i| string_at(i as u32))
        .unwrap_or_default();

    // Assembly name (Assembly table, row 1, Name is column 7).
    let assembly_name = (md_tables.rows[0x20] > 0)
        .then(|| {
            md_tables
                .cell(data, 0x20, 1, 7)
                .map(|i| string_at(i as u32))
        })
        .flatten();

    // Types and their methods (with decoded signatures from the blob heap).
    let blob_off = streams.get("#Blob").map(|s| s.off);
    let types = collect_types(data, &md_tables, &string_at, blob_off);

    // User strings (#US).
    let user_strings = streams
        .get("#US")
        .map(|s| read_user_strings(data, s.off, s.size))
        .unwrap_or_default();

    let table_rows = (0u8..=0x2c)
        .filter(|&id| md_tables.rows[id as usize] > 0)
        .map(|id| (table_name(id), md_tables.rows[id as usize]))
        .collect();

    let resolver = Resolver {
        tables: md_tables,
        strings_off: strings.off,
        strings_size: strings.size,
        us_off: streams.get("#US").map(|s| s.off),
        sections,
    };

    Ok(DotNet {
        runtime_version,
        module_name,
        assembly_name,
        types,
        user_strings,
        table_rows,
        resolver,
    })
}

/// Walks TypeDef (name/namespace + its method range) and MethodDef (name, signature, RVA).
fn collect_types(
    data: &[u8],
    t: &MdTables,
    string_at: &impl Fn(u32) -> String,
    blob_off: Option<usize>,
) -> Vec<TypeInfo> {
    let n_types = t.rows[0x02];
    let n_methods = t.rows[0x06];
    // Resolve a type reference (TypeDef/TypeRef/TypeSpec) to a readable name, for signatures.
    let resolve_type = |table: u8, row: u32| type_full_name(t, data, string_at, table, row);

    // Row counts are validated against the stream size in `MdTables::parse`, but keep the
    // up-front reservation modest anyway.
    let mut out = Vec::with_capacity((n_types as usize).min(4096));
    // Method lists are monotonic (ECMA-335 II.22.37); clamping each type's start to the previous
    // type's end keeps hostile, overlapping lists linear instead of quadratic.
    let mut prev_end = 1u32;
    for r in 1..=n_types {
        let name = t
            .cell(data, 0x02, r, 1)
            .map(|i| string_at(i as u32))
            .unwrap_or_default();
        let ns = t
            .cell(data, 0x02, r, 2)
            .map(|i| string_at(i as u32))
            .unwrap_or_default();
        // MethodList (column 5) is the first method row; the type owns up to the next type's start.
        let end_of_table = n_methods.saturating_add(1);
        let first = (t.cell(data, 0x02, r, 5).unwrap_or(0) as u32)
            .max(prev_end)
            .min(end_of_table);
        let last = if r < n_types {
            t.cell(data, 0x02, r + 1, 5).unwrap_or(0) as u32
        } else {
            end_of_table
        }
        .clamp(first, end_of_table);
        prev_end = last;
        let mut methods = Vec::new();
        for m in first..last {
            if let Some(ni) = t.cell(data, 0x06, m, 3) {
                let rva = t.cell(data, 0x06, m, 0).unwrap_or(0) as u32;
                let signature = blob_off
                    .and_then(|bo| {
                        t.cell(data, 0x06, m, 4)
                            .and_then(|bi| blob_at(data, bo, bi as u32))
                    })
                    .and_then(|b| sig::decode_method(b, &resolve_type))
                    .map(|s| format!("({}) : {}", s.params.join(", "), s.ret))
                    .unwrap_or_default();
                methods.push(Method {
                    name: string_at(ni as u32),
                    signature,
                    rva,
                });
            }
        }
        out.push(TypeInfo {
            namespace: ns,
            name,
            methods,
        });
    }
    out
}

/// `Namespace.Name` of a TypeDef (0x02)/TypeRef (0x01) row (TypeSpec is shown as a placeholder).
fn type_full_name(
    t: &MdTables,
    d: &[u8],
    string_at: &impl Fn(u32) -> String,
    table: u8,
    row: u32,
) -> String {
    if table == 0x1b {
        return format!("TypeSpec#{row}");
    }
    let name = t
        .cell(d, table, row, 1)
        .map(|i| string_at(i as u32))
        .unwrap_or_default();
    let ns = t
        .cell(d, table, row, 2)
        .map(|i| string_at(i as u32))
        .unwrap_or_default();
    if ns.is_empty() {
        name
    } else {
        format!("{ns}.{name}")
    }
}

/// Reads a blob-heap entry (`compressed length` + bytes) at `blob_off + idx`.
fn blob_at(d: &[u8], blob_off: usize, idx: u32) -> Option<&[u8]> {
    let at = blob_off + idx as usize;
    let (len, hdr) = compressed_uint(d, at, d.len().saturating_sub(at))?;
    let start = at + hdr;
    d.get(start..start + len as usize)
}

/// The `#~` table stream: row counts and the geometry needed to address any cell.
#[derive(Clone, Debug)]
struct MdTables {
    rows: [u32; 64],
    /// Heap index sizes in bytes (Strings, GUID, Blob).
    str_sz: usize,
    guid_sz: usize,
    blob_sz: usize,
    /// Byte size of each table's row.
    row_size: [usize; 64],
    /// Absolute file offset of each present table's first row.
    base: [usize; 64],
}

impl MdTables {
    /// Parses the `#~` stream header at `off` (`size` bytes long) and checks that every table
    /// lies inside the stream, so hostile row counts can't drive huge allocations or loops.
    fn parse(d: &[u8], off: usize, size: usize) -> Result<Self, String> {
        let heapsizes = *d.get(off + 6).ok_or("truncated table header")?;
        let valid = u64::from_le_bytes(
            d.get(off + 8..off + 16)
                .ok_or("truncated")?
                .try_into()
                .unwrap(),
        );
        let str_sz = if heapsizes & 1 != 0 { 4 } else { 2 };
        let guid_sz = if heapsizes & 2 != 0 { 4 } else { 2 };
        let blob_sz = if heapsizes & 4 != 0 { 4 } else { 2 };

        let mut rows = [0u32; 64];
        let mut rc = off + 24;
        for (id, slot) in rows.iter_mut().enumerate() {
            if valid >> id & 1 == 1 {
                *slot = u32a(d, rc).ok_or("truncated row counts")?;
                rc += 4;
            }
        }
        // HeapSizes bit 0x40: four bytes of extra data follow the row counts.
        if heapsizes & 0x40 != 0 {
            rc += 4;
        }

        let mut t = MdTables {
            rows,
            str_sz,
            guid_sz,
            blob_sz,
            row_size: [0; 64],
            base: [0; 64],
        };

        // First pass: row sizes (needs row counts, already known).
        for id in 0u8..64 {
            if t.rows[id as usize] > 0 {
                t.row_size[id as usize] = columns(id).iter().map(|c| t.col_size(*c)).sum();
            }
        }
        // Second pass: table base offsets, in ascending id order.
        let end = off.saturating_add(size).min(d.len());
        let mut cur = rc;
        for id in 0u8..64 {
            if t.rows[id as usize] > 0 {
                t.base[id as usize] = cur;
                cur = (t.row_size[id as usize] as u64)
                    .checked_mul(u64::from(t.rows[id as usize]))
                    .and_then(|len| (cur as u64).checked_add(len))
                    .filter(|&e| e <= end as u64)
                    .ok_or_else(|| {
                        format!(
                            "table {} ({} rows) extends past the #~ stream",
                            table_name(id),
                            t.rows[id as usize]
                        )
                    })? as usize;
            }
        }
        Ok(t)
    }

    /// Size in bytes of a column, from heap and table sizes.
    fn col_size(&self, c: Col) -> usize {
        match c {
            Col::U16 => 2,
            Col::U32 => 4,
            Col::Str => self.str_sz,
            Col::Guid => self.guid_sz,
            Col::Blob => self.blob_sz,
            Col::Idx(table) => {
                if self.rows[table as usize] >= 0x1_0000 {
                    4
                } else {
                    2
                }
            }
            Col::CodedIdx(code) => self.coded_size(code),
        }
    }

    fn coded_size(&self, code: Coded) -> usize {
        let (tag_bits, tables) = code.info();
        let max = tables
            .iter()
            .filter(|&&t| t != 0xff)
            .map(|&t| self.rows[t as usize])
            .max()
            .unwrap_or(0);
        if (max as u64) < (1u64 << (16 - tag_bits)) {
            2
        } else {
            4
        }
    }

    /// Reads column `col` (0-based) of row `row` (1-based) in table `id` as an integer. `None` if
    /// out of range.
    fn cell(&self, d: &[u8], id: u8, row: u32, col: usize) -> Option<u64> {
        if row == 0 || row > self.rows[id as usize] {
            return None;
        }
        let cols = columns(id);
        let mut coloff = 0usize;
        for c in &cols[..col.min(cols.len())] {
            coloff += self.col_size(*c);
        }
        let size = self.col_size(*cols.get(col)?);
        let at = self.base[id as usize] + (row as usize - 1) * self.row_size[id as usize] + coloff;
        match size {
            2 => u16a(d, at).map(|v| v as u64),
            4 => u32a(d, at).map(|v| v as u64),
            _ => None,
        }
    }
}

/// Reads a NUL-terminated UTF-8 string at `start`, bounded by `end`.
fn read_cstr(d: &[u8], start: usize, end: usize) -> String {
    let mut p = start;
    while p < end && d.get(p).is_some_and(|&b| b != 0) {
        p += 1;
    }
    String::from_utf8_lossy(d.get(start..p).unwrap_or(&[])).into_owned()
}

/// Enumerates the `#US` heap: blob-style, each entry a compressed length then UTF-16LE + a flag.
fn read_user_strings(d: &[u8], off: usize, size: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 1; // the heap starts with a single 0 byte
    while i < size {
        let (len, hdr) = match compressed_uint(d, off + i, size - i) {
            Some(v) => v,
            None => break,
        };
        i += hdr;
        if len == 0 {
            continue;
        }
        let bytes = match d.get(off + i..off + i + len as usize) {
            Some(b) => b,
            None => break,
        };
        i += len as usize;
        // The last byte is a flag; the rest is UTF-16LE.
        let body = &bytes[..bytes.len().saturating_sub(1)];
        let mut units = Vec::with_capacity(body.len() / 2);
        let mut k = 0;
        while k + 1 < body.len() {
            units.push(u16::from_le_bytes([body[k], body[k + 1]]));
            k += 2;
        }
        let s = String::from_utf16_lossy(&units);
        if !s.is_empty() {
            out.push(s);
        }
    }
    out
}

/// Reads an ECMA-335 compressed unsigned integer. Returns `(value, bytes_read)`.
fn compressed_uint(d: &[u8], off: usize, avail: usize) -> Option<(u32, usize)> {
    let b0 = *d.get(off)? as u32;
    if avail == 0 {
        return None;
    }
    if b0 & 0x80 == 0 {
        Some((b0, 1))
    } else if b0 & 0xC0 == 0x80 {
        let b1 = *d.get(off + 1)? as u32;
        Some((((b0 & 0x3f) << 8) | b1, 2))
    } else {
        let b1 = *d.get(off + 1)? as u32;
        let b2 = *d.get(off + 2)? as u32;
        let b3 = *d.get(off + 3)? as u32;
        Some((((b0 & 0x1f) << 24) | (b1 << 16) | (b2 << 8) | b3, 4))
    }
}

/// Holds what IL disassembly needs: the tables, heap locations and section map.
#[derive(Clone, Debug)]
struct Resolver {
    tables: MdTables,
    strings_off: usize,
    strings_size: usize,
    us_off: Option<usize>,
    sections: Vec<Section>,
}

impl Resolver {
    fn string(&self, d: &[u8], idx: u32) -> String {
        read_cstr(
            d,
            self.strings_off + idx as usize,
            self.strings_off + self.strings_size,
        )
    }

    /// `Namespace.Name` for a TypeDef (0x02) or TypeRef (0x01) row.
    fn type_name(&self, d: &[u8], table: u8, row: u32) -> String {
        let (name_col, ns_col) = (1, 2);
        let name = self
            .tables
            .cell(d, table, row, name_col)
            .map(|i| self.string(d, i as u32))
            .unwrap_or_default();
        let ns = self
            .tables
            .cell(d, table, row, ns_col)
            .map(|i| self.string(d, i as u32))
            .unwrap_or_default();
        if ns.is_empty() {
            name
        } else {
            format!("{ns}.{name}")
        }
    }

    /// Decodes a coded index value into `(table_id, row)`.
    fn decode_coded(code: Coded, value: u64) -> Option<(u8, u32)> {
        let (bits, group) = code.info();
        let tag = (value & ((1 << bits) - 1)) as usize;
        let table = *group.get(tag)?;
        if table == 0xff {
            return None;
        }
        Some((table, (value >> bits) as u32))
    }
}

impl DotNet {
    /// Resolves a metadata token (`table << 24 | row`) to a readable name.
    fn resolve_token(&self, d: &[u8], tok: u32) -> String {
        let r = &self.resolver;
        let table = (tok >> 24) as u8;
        let row = tok & 0x00ff_ffff;
        match table {
            0x06 => r
                .tables
                .cell(d, 0x06, row, 3)
                .map(|i| r.string(d, i as u32))
                .unwrap_or_default(),
            0x04 => r
                .tables
                .cell(d, 0x04, row, 1)
                .map(|i| r.string(d, i as u32))
                .unwrap_or_default(),
            0x01 => r.type_name(d, 0x01, row),
            0x02 => r.type_name(d, 0x02, row),
            0x0a => {
                // MemberRef: Parent.Name
                let name = r
                    .tables
                    .cell(d, 0x0a, row, 1)
                    .map(|i| r.string(d, i as u32))
                    .unwrap_or_default();
                let parent = r
                    .tables
                    .cell(d, 0x0a, row, 0)
                    .and_then(|v| Resolver::decode_coded(Coded::MemberRefParent, v))
                    .map(|(t, rr)| match t {
                        0x01 | 0x02 => r.type_name(d, t, rr),
                        _ => String::new(),
                    })
                    .unwrap_or_default();
                if parent.is_empty() {
                    name
                } else {
                    format!("{parent}.{name}")
                }
            }
            0x1b => format!("TypeSpec#{row}"),
            0x11 => format!("StandAloneSig#{row}"),
            _ => format!("token 0x{tok:08x}"),
        }
    }

    /// Resolves a user-string token (`0x70 << 24 | heap_offset`) to the quoted literal.
    fn resolve_string(&self, d: &[u8], tok: u32) -> String {
        if (tok >> 24) != 0x70 {
            return format!("token 0x{tok:08x}");
        }
        let Some(base) = self.resolver.us_off else {
            return String::new();
        };
        let off = base + (tok & 0x00ff_ffff) as usize;
        let Some((len, hdr)) = compressed_uint(d, off, d.len().saturating_sub(off)) else {
            return String::new();
        };
        if len == 0 {
            return "\"\"".into();
        }
        let start = off + hdr;
        let bytes = d.get(start..start + len as usize).unwrap_or(&[]);
        let body = &bytes[..bytes.len().saturating_sub(1)];
        let mut units = Vec::with_capacity(body.len() / 2);
        let mut k = 0;
        while k + 1 < body.len() {
            units.push(u16::from_le_bytes([body[k], body[k + 1]]));
            k += 2;
        }
        format!("{:?}", String::from_utf16_lossy(&units))
    }

    /// Disassembles the IL of the method body at `rva`. `data` must be the same bytes `parse`
    /// received. Returns an error if the method has no body or the body is malformed.
    pub fn disassemble(&self, data: &[u8], rva: u32) -> Result<Vec<Il>, String> {
        if rva == 0 {
            return Err("method has no body (abstract, native or P/Invoke)".into());
        }
        let off =
            rva_to_off(&self.resolver.sections, rva).ok_or("method RVA not in any section")?;
        let b0 = *data.get(off).ok_or("truncated method header")?;
        let (code_off, code_size) = match b0 & 0x03 {
            0x02 => (off + 1, (b0 >> 2) as usize), // tiny header
            0x03 => {
                let code_size = u32a(data, off + 4).ok_or("truncated fat header")? as usize;
                (off + 12, code_size) // fat header is 12 bytes
            }
            _ => return Err("unknown method-header format".into()),
        };
        let code = data
            .get(code_off..code_off + code_size)
            .ok_or("method code out of bounds")?;
        Ok(il::disassemble(
            code,
            |t| self.resolve_token(data, t),
            |t| self.resolve_string(data, t),
        ))
    }
}

#[cfg(test)]
mod tests;
