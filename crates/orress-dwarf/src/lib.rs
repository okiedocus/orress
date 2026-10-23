//! Import DWARF debug info into the ORRESS type catalog.
//!
//! Reads the `.debug_*` sections of an ELF (or the `__debug_*` sections of a Mach-O) and
//! turns the type DIEs into [`UserType`]s (structs/unions/enums/typedefs) and the
//! `DW_TAG_subprogram` DIEs into [`FuncProto`]s keyed by their entry address. Pure Rust:
//! sections come from `object`, parsing from `gimli`; no C and no debugger.
//!
//! The mapping is best-effort — anything the catalog's type model cannot represent
//! (bitfields, packed/overlapping layouts, nameless-with-spaces C++ template types) is
//! skipped and counted, rather than failing the whole import. Struct layout is kept faithful
//! by inserting `_padN: [u8; k]` filler wherever DWARF's member offsets leave a gap the
//! catalog's natural C alignment would not produce on its own.
//!
//! The input is expected to be a **linked** binary (executable or shared object), which is
//! what reverse engineers analyse. In an unlinked relocatable object (`.o`), the references
//! from `.debug_info` into `.debug_str` and `.text` are stored as zero plus ELF relocations
//! the linker would apply, so names and `low_pc` addresses would read as zero; applying those
//! relocations is left as a future extension.

use std::borrow::Cow;
use std::collections::HashMap;

use object::{Object, ObjectSection};
use orress_project::{FieldDef, FuncProto, Prim, TypeRef, UserType};

#[cfg(test)]
mod tests;

/// The result of importing one binary's DWARF.
#[derive(Debug, Default, Clone)]
pub struct Imported {
    /// Recovered types, in DIE order, de-duplicated by name (first definition wins).
    pub types: Vec<UserType>,
    /// Function prototypes keyed by entry address (`DW_AT_low_pc`).
    pub protos: Vec<(u64, FuncProto)>,
    /// How many declarations were skipped as unrepresentable (bitfields, packed structs, …).
    pub skipped: usize,
}

/// Whether `bytes` is an object file that carries DWARF type/debug info.
pub fn has_debug_info(bytes: &[u8]) -> bool {
    let Ok(file) = object::File::parse(bytes) else {
        return false;
    };
    section_bytes(&file, ".debug_info").is_some_and(|d| !d.is_empty())
}

/// Imports the DWARF in `bytes`. Returns an empty result (not an error) when the file parses
/// but has no debug info, so a caller can treat "nothing to import" as a soft outcome.
pub fn import(bytes: &[u8]) -> Result<Imported, String> {
    let file =
        object::File::parse(bytes).map_err(|e| format!("not a recognised object file: {e}"))?;
    if section_bytes(&file, ".debug_info").is_none_or(|d| d.is_empty()) {
        return Ok(Imported::default());
    }

    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let ptr_width = if file.is_64() { 8 } else { 4 };

    // Load each DWARF section as borrowed bytes, then re-borrow as endian slices (the standard
    // gimli two-step that keeps all the readers pointing into `file`).
    let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        Ok(section_bytes(&file, id.name()).unwrap_or(Cow::Borrowed(&[][..])))
    };
    let sections =
        gimli::DwarfSections::load(load).map_err(|e| format!("DWARF load failed: {e}"))?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    let dies = collect_dies(&dwarf).map_err(|e| format!("DWARF parse failed: {e}"))?;
    let ctx = Ctx::new(dies, ptr_width);
    Ok(ctx.build())
}

/// Returns a section's bytes, trying the ELF/COFF name (`.debug_info`) and then the Mach-O
/// spelling (`__debug_info`) so both object layouts resolve.
fn section_bytes<'a>(file: &object::File<'a>, name: &str) -> Option<Cow<'a, [u8]>> {
    let mach = name.strip_prefix('.').map(|rest| format!("__{rest}"));
    file.section_by_name(name)
        .or_else(|| mach.as_deref().and_then(|m| file.section_by_name(m)))
        .and_then(|s| s.uncompressed_data().ok())
}

// ---------------------------------------------------------------------------- raw DIE model

/// A flattened debugging-information entry: just the attributes the importer needs, keyed by
/// its global `.debug_info` offset so `DW_AT_type` references resolve by lookup.
#[derive(Debug)]
struct RawDie {
    off: usize,
    tag: gimli::DwTag,
    parent: Option<usize>,
    name: Option<String>,
    /// `DW_AT_type` target, as a global offset.
    type_off: Option<usize>,
    byte_size: Option<u64>,
    encoding: Option<u16>,
    /// `DW_AT_data_member_location` as a constant byte offset (expression forms are dropped).
    member_loc: Option<u64>,
    const_value: Option<i64>,
    bit_size: Option<u64>,
    upper_bound: Option<i64>,
    count: Option<u64>,
    declaration: bool,
    low_pc: Option<u64>,
}

impl RawDie {
    fn new(off: usize, tag: gimli::DwTag, parent: Option<usize>) -> Self {
        RawDie {
            off,
            tag,
            parent,
            name: None,
            type_off: None,
            byte_size: None,
            encoding: None,
            member_loc: None,
            const_value: None,
            bit_size: None,
            upper_bound: None,
            count: None,
            declaration: false,
            low_pc: None,
        }
    }
}

type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// Walks every unit depth-first and records a [`RawDie`] per entry, tracking parent offsets.
fn collect_dies(dwarf: &gimli::Dwarf<Reader<'_>>) -> Result<Vec<RawDie>, gimli::Error> {
    let mut out = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        let mut depth: isize = 0;
        // parents[d] holds the global offset of the current ancestor at depth d.
        let mut parents: Vec<usize> = Vec::new();
        while let Some((delta, entry)) = entries.next_dfs()? {
            depth += delta;
            let d = depth.max(0) as usize;
            parents.truncate(d);
            let parent = parents.last().copied();

            let Some(off) = entry
                .offset()
                .to_debug_info_offset(&unit.header)
                .map(|o| o.0)
            else {
                parents.push(usize::MAX);
                continue;
            };

            let mut die = RawDie::new(off, entry.tag(), parent);
            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next()? {
                match attr.name() {
                    gimli::DW_AT_name => {
                        die.name = dwarf
                            .attr_string(&unit, attr.value())
                            .ok()
                            .and_then(|s| s.to_string().ok().map(str::to_owned));
                    }
                    gimli::DW_AT_type => die.type_off = ref_offset(attr.value(), &unit),
                    gimli::DW_AT_byte_size => die.byte_size = attr.value().udata_value(),
                    gimli::DW_AT_encoding => {
                        die.encoding = match attr.value() {
                            gimli::AttributeValue::Encoding(e) => Some(e.0 as u16),
                            other => other.udata_value().map(|v| v as u16),
                        }
                    }
                    gimli::DW_AT_data_member_location => {
                        die.member_loc = attr.value().udata_value()
                    }
                    gimli::DW_AT_const_value => {
                        die.const_value = attr
                            .value()
                            .sdata_value()
                            .or_else(|| attr.value().udata_value().map(|v| v as i64))
                    }
                    gimli::DW_AT_bit_size => die.bit_size = attr.value().udata_value(),
                    gimli::DW_AT_upper_bound => {
                        die.upper_bound = attr
                            .value()
                            .sdata_value()
                            .or_else(|| attr.value().udata_value().map(|v| v as i64))
                    }
                    gimli::DW_AT_count => die.count = attr.value().udata_value(),
                    gimli::DW_AT_declaration => {
                        die.declaration = matches!(attr.value(), gimli::AttributeValue::Flag(true))
                    }
                    gimli::DW_AT_low_pc => {
                        if let gimli::AttributeValue::Addr(a) = attr.value() {
                            die.low_pc = Some(a);
                        }
                    }
                    _ => {}
                }
            }
            out.push(die);
            parents.push(off);
        }
    }
    Ok(out)
}

/// A `DW_AT_type`-style reference as a global `.debug_info` offset.
fn ref_offset(
    value: gimli::AttributeValue<Reader<'_>>,
    unit: &gimli::Unit<Reader<'_>>,
) -> Option<usize> {
    match value {
        gimli::AttributeValue::UnitRef(o) => o.to_debug_info_offset(&unit.header).map(|x| x.0),
        gimli::AttributeValue::DebugInfoRef(o) => Some(o.0),
        _ => None,
    }
}

// ---------------------------------------------------------------------------- resolution

const MAX_DEPTH: u32 = 24;

struct Ctx {
    dies: Vec<RawDie>,
    /// Global offset → index into `dies`.
    index: HashMap<usize, usize>,
    /// Parent offset → child offsets, in order.
    children: HashMap<usize, Vec<usize>>,
    /// Canonical catalog name for each aggregate/typedef DIE (anonymous ones synthesised).
    names: HashMap<usize, String>,
    ptr_width: u64,
}

impl Ctx {
    fn new(dies: Vec<RawDie>, ptr_width: u64) -> Self {
        let mut index = HashMap::new();
        let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, d) in dies.iter().enumerate() {
            index.insert(d.off, i);
            if let Some(p) = d.parent {
                children.entry(p).or_default().push(d.off);
            }
        }
        let mut ctx = Ctx {
            dies,
            index,
            children,
            names: HashMap::new(),
            ptr_width,
        };
        ctx.assign_names();
        ctx
    }

    fn die(&self, off: usize) -> Option<&RawDie> {
        self.index.get(&off).map(|&i| &self.dies[i])
    }

    fn kids(&self, off: usize) -> &[usize] {
        self.children.get(&off).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Names every type DIE that can be referenced by name, synthesising `anon_<off>` for
    /// anonymous aggregates so a parent can still point at them.
    fn assign_names(&mut self) {
        for i in 0..self.dies.len() {
            let d = &self.dies[i];
            let named = matches!(
                d.tag,
                gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_union_type
                    | gimli::DW_TAG_enumeration_type
                    | gimli::DW_TAG_typedef
            );
            if !named {
                continue;
            }
            let name = match &d.name {
                Some(n) if is_catalog_name(n) => n.clone(),
                _ => format!("anon_{:x}", d.off),
            };
            self.names.insert(d.off, name);
        }
    }

    fn type_name(&self, off: usize) -> Option<&str> {
        self.names.get(&off).map(String::as_str)
    }

    /// A catalog [`TypeRef`] for the type at `off`. Pointers stop the recursion (they become
    /// `*T` regardless of whether `T` is complete), aggregates/typedefs become `Named`, and
    /// qualifiers (`const`/`volatile`/…) are transparent. Unknowns degrade to `void`.
    fn resolve(&self, off: Option<usize>, depth: u32) -> TypeRef {
        let void = || TypeRef::Prim(Prim::Void);
        let Some(off) = off else { return void() };
        if depth > MAX_DEPTH {
            return void();
        }
        let Some(d) = self.die(off) else {
            return void();
        };
        match d.tag {
            gimli::DW_TAG_base_type => base_prim(d).map(TypeRef::Prim).unwrap_or_else(void),
            gimli::DW_TAG_pointer_type => {
                TypeRef::Pointer(Box::new(self.resolve(d.type_off, depth + 1)))
            }
            gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => self.resolve(d.type_off, depth + 1),
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type => self
                .type_name(off)
                .map(|n| TypeRef::Named(n.to_owned()))
                .unwrap_or_else(void),
            gimli::DW_TAG_array_type => self.resolve(d.type_off, depth + 1),
            _ => void(),
        }
    }

    /// Byte size of the type at `off`, using `DW_AT_byte_size` where present and recursing for
    /// typedefs/qualifiers/arrays. Pointers fall back to the pointer width.
    fn size_of(&self, off: Option<usize>, depth: u32) -> u64 {
        let Some(off) = off else {
            return self.ptr_width;
        };
        if depth > MAX_DEPTH {
            return self.ptr_width;
        }
        let Some(d) = self.die(off) else {
            return self.ptr_width;
        };
        if d.tag != gimli::DW_TAG_array_type
            && let Some(bs) = d.byte_size
        {
            return bs;
        }
        match d.tag {
            gimli::DW_TAG_pointer_type => d.byte_size.unwrap_or(self.ptr_width),
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => self.size_of(d.type_off, depth + 1),
            gimli::DW_TAG_array_type => self
                .size_of(d.type_off, depth + 1)
                .saturating_mul(self.array_count(off).max(1)),
            _ => d.byte_size.unwrap_or(0),
        }
    }

    /// Element count of an array DIE (from its `DW_TAG_subrange_type` child), defaulting to 1.
    fn array_count(&self, off: usize) -> u64 {
        for &c in self.kids(off) {
            if let Some(sub) = self.die(c)
                && sub.tag == gimli::DW_TAG_subrange_type
            {
                if let Some(n) = sub.count {
                    return n;
                }
                if let Some(ub) = sub.upper_bound {
                    return (ub + 1).max(0) as u64;
                }
            }
        }
        1
    }

    // ---------------------------------------------------------------- building UserTypes

    fn build(&self) -> Imported {
        let mut out = Imported::default();
        let mut seen: HashMap<String, ()> = HashMap::new();

        for d in &self.dies {
            match d.tag {
                gimli::DW_TAG_typedef => {
                    if let Some(ty) = self.build_typedef(d) {
                        self.push_type(ty, &mut out, &mut seen);
                    }
                }
                gimli::DW_TAG_enumeration_type => match self.build_enum(d) {
                    Some(ty) => self.push_type(ty, &mut out, &mut seen),
                    None => out.skipped += 1,
                },
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                    // Forward declarations carry no members; ignore them silently.
                    if d.declaration || self.kids(d.off).is_empty() {
                        continue;
                    }
                    match self.build_record(d) {
                        Ok((ty, dropped)) => {
                            out.skipped += dropped;
                            self.push_type(ty, &mut out, &mut seen);
                        }
                        Err(()) => out.skipped += 1,
                    }
                }
                gimli::DW_TAG_subprogram => {
                    if let (Some(addr), false) = (d.low_pc, d.declaration) {
                        out.protos.push((addr, self.build_proto(d)));
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn push_type(&self, ty: UserType, out: &mut Imported, seen: &mut HashMap<String, ()>) {
        if seen.insert(ty.name().to_owned(), ()).is_none() {
            out.types.push(ty);
        }
    }

    fn build_typedef(&self, d: &RawDie) -> Option<UserType> {
        let name = self.type_name(d.off)?.to_owned();
        Some(UserType::Typedef {
            name,
            target: self.resolve(d.type_off, 0),
        })
    }

    fn build_enum(&self, d: &RawDie) -> Option<UserType> {
        let name = self.type_name(d.off)?.to_owned();
        let width = int_prim(d.byte_size.unwrap_or(4)).unwrap_or(Prim::I32);
        let mut variants = Vec::new();
        for &c in self.kids(d.off) {
            if let Some(e) = self.die(c)
                && e.tag == gimli::DW_TAG_enumerator
                && let Some(n) = e.name.as_deref().filter(|n| is_catalog_name(n))
            {
                variants.push((n.to_owned(), e.const_value.unwrap_or(0)));
            }
        }
        if variants.is_empty() {
            return None;
        }
        Some(UserType::Enum {
            name,
            width,
            variants,
        })
    }

    /// Builds a struct or union. Returns `Err` when the layout cannot be represented faithfully
    /// (a packed/overlapping struct) or no usable field survives; otherwise the type and the
    /// number of members dropped as unrepresentable (bitfields).
    fn build_record(&self, d: &RawDie) -> Result<(UserType, usize), ()> {
        let name = self.type_name(d.off).ok_or(())?.to_owned();
        let is_union = d.tag == gimli::DW_TAG_union_type;
        let mut fields: Vec<FieldDef> = Vec::new();
        let mut running = 0u64;
        let mut pad_n = 0u32;
        let mut dropped = 0usize;

        for &c in self.kids(d.off) {
            let Some(m) = self.die(c) else { continue };
            if m.tag != gimli::DW_TAG_member {
                continue;
            }
            if m.bit_size.is_some() {
                // Bitfields have no byte-granular field model; drop them.
                dropped += 1;
                continue;
            }
            let (elem_ty, count, total) = self.member_elem(m);
            let fname = m
                .name
                .as_deref()
                .filter(|n| is_catalog_name(n))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("field_{}", fields.len()));

            if is_union {
                fields.push(FieldDef {
                    name: fname,
                    ty: elem_ty,
                    count: count.max(1),
                });
                continue;
            }

            let off = m.member_loc.unwrap_or(running);
            if off < running {
                // A member lands before the cursor: a packed/overlapping layout the catalog's
                // additive model cannot reproduce.
                return Err(());
            }
            if off > running {
                fields.push(FieldDef {
                    name: format!("_pad{pad_n}"),
                    ty: TypeRef::Prim(Prim::U8),
                    count: off - running,
                });
                pad_n += 1;
            }
            fields.push(FieldDef {
                name: fname,
                ty: elem_ty,
                count: count.max(1),
            });
            running = off.saturating_add(total);
        }

        if fields.is_empty() {
            return Err(());
        }

        // Trailing padding so the recovered struct keeps DWARF's declared size.
        if !is_union
            && let Some(bs) = d.byte_size
            && bs > running
        {
            fields.push(FieldDef {
                name: format!("_pad{pad_n}"),
                ty: TypeRef::Prim(Prim::U8),
                count: bs - running,
            });
        }

        let ty = if is_union {
            UserType::Union { name, fields }
        } else {
            UserType::Struct { name, fields }
        };
        Ok((ty, dropped))
    }

    /// For one member: its element [`TypeRef`], element count, and total byte span (element
    /// size × count). Arrays contribute their element type plus the subrange count.
    fn member_elem(&self, m: &RawDie) -> (TypeRef, u64, u64) {
        if let Some(to) = m.type_off
            && let Some(td) = self.die(to)
            && td.tag == gimli::DW_TAG_array_type
        {
            let count = self.array_count(to);
            let elem = self.resolve(td.type_off, 0);
            let total = self.size_of(Some(to), 0);
            return (elem, count, total);
        }
        let elem = self.resolve(m.type_off, 0);
        let total = self.size_of(m.type_off, 0);
        (elem, 1, total)
    }

    fn build_proto(&self, d: &RawDie) -> FuncProto {
        let ret = d.type_off.map(|_| self.resolve(d.type_off, 0));
        let mut params = Vec::new();
        for &c in self.kids(d.off) {
            if let Some(p) = self.die(c)
                && p.tag == gimli::DW_TAG_formal_parameter
            {
                let name = p
                    .name
                    .as_deref()
                    .filter(|n| is_catalog_name(n))
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("arg{}", params.len()));
                params.push((name, self.resolve(p.type_off, 0)));
            }
        }
        FuncProto { ret, params }
    }
}

// ---------------------------------------------------------------------------- base types

/// Maps a `DW_TAG_base_type` to a catalog primitive by encoding + size.
fn base_prim(d: &RawDie) -> Option<Prim> {
    let size = d.byte_size.unwrap_or(0);
    match d.encoding.unwrap_or(0) {
        0x02 => Some(Prim::Bool), // boolean
        0x04 => match size {
            4 => Some(Prim::F32),
            _ => Some(Prim::F64), // double / long double → f64
        },
        0x05 => int_prim(size),   // signed
        0x06 => Some(Prim::Char), // signed char
        0x07 => uint_prim(size),  // unsigned
        0x08 => Some(Prim::U8),   // unsigned char
        0x01 => uint_prim(size),  // address → pointer-sized unsigned
        _ => uint_prim(size),     // numeric fallbacks (e.g. UTF, fixed) → by width
    }
}

fn int_prim(size: u64) -> Option<Prim> {
    Some(match size {
        1 => Prim::I8,
        2 => Prim::I16,
        4 => Prim::I32,
        8 => Prim::I64,
        _ => return None,
    })
}

fn uint_prim(size: u64) -> Option<Prim> {
    Some(match size {
        1 => Prim::U8,
        2 => Prim::U16,
        4 => Prim::U32,
        8 => Prim::U64,
        _ => return None,
    })
}

/// Whether a DWARF name is usable as a catalog identifier (the catalog forbids spaces and most
/// punctuation, so names like `unsigned int` or `std::vector<T, A>` are rejected).
fn is_catalog_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && !name.chars().next().is_some_and(|c| c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "_@$.:?<>~".contains(c))
}
