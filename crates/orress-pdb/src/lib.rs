//! Import Windows PDB debug info into the ORRESS type catalog.
//!
//! Reads a `.pdb`'s type stream (TPI) into [`UserType`]s (structs/unions/enums) and its
//! procedure symbols into [`FuncProto`]s keyed by entry address. Pure Rust via the `pdb`
//! crate; no `dbghelp` and no debugger.
//!
//! A PDB is a companion file to a PE and stores addresses as RVAs, so [`import`] takes the
//! PE's `image_base` (and pointer width) to turn procedure RVAs into the load addresses the
//! rest of ORRESS keys functions by.
//!
//! Best-effort, like the DWARF importer: struct layout is kept faithful with `_padN` filler
//! from CodeView member offsets; bitfields and packed/overlapping layouts are skipped and
//! counted. Prototypes recover the return type and parameter *types* with positional names
//! (`arg0`, `arg1`, …) — real parameter names live in the per-function local-symbol scopes and
//! are a future extension. Typedefs (CodeView `S_UDT`) are not imported yet.

use std::collections::HashMap;
use std::io::Cursor;

use orress_project::{FieldDef, FuncProto, Prim, TypeRef, UserType, is_catalog_name};
use pdb::FallibleIterator;

pub use orress_project::Imported;

#[cfg(test)]
mod tests;

/// Imports the types and procedure prototypes from a PDB's bytes. `image_base` and `ptr_width`
/// come from the companion PE (procedure addresses are `image_base + RVA`).
pub fn import(bytes: &[u8], image_base: u64, ptr_width: u64) -> Result<Imported, String> {
    run(bytes, image_base, ptr_width).map_err(|e| format!("could not read PDB: {e}"))
}

fn run(bytes: &[u8], image_base: u64, ptr_width: u64) -> Result<Imported, pdb::Error> {
    let mut pdb = pdb::PDB::open(Cursor::new(bytes))?;

    // Phase A — build the owned type model from the TPI. The `pdb` finder borrows the type
    // stream, so everything that needs it (type + signature resolution) happens in this scope
    // and lands in owned structures before we touch the symbol streams.
    let mut types: Vec<UserType> = Vec::new();
    let mut sig_by_index: HashMap<u32, (Option<TypeRef>, Vec<TypeRef>)> = HashMap::new();
    let mut skipped = 0usize;
    {
        let type_info = pdb.type_information()?;
        let mut finder = type_info.finder();

        // Pass 1: index every record so the finder can resolve forward references, note the
        // records we will turn into types or signatures, and map each aggregate name to its
        // *defining* record. CodeView members reference the forward declaration of a type
        // (whose size is 0), so sizing a by-value member needs the real definition's size.
        let mut aggregates: Vec<(u32, bool)> = Vec::new(); // (index, is_union)
        let mut enums: Vec<u32> = Vec::new();
        let mut procs: Vec<u32> = Vec::new();
        let mut defn: HashMap<String, u32> = HashMap::new();
        let mut iter = type_info.iter();
        while let Some(item) = iter.next()? {
            finder.update(&iter);
            let idx = item.index().0;
            let Ok(data) = item.parse() else { continue };
            match data {
                pdb::TypeData::Class(c)
                    if c.fields.is_some() && !c.properties.forward_reference() =>
                {
                    defn.insert(c.name.to_string().into_owned(), idx);
                    aggregates.push((idx, false));
                }
                pdb::TypeData::Union(u) if !u.properties.forward_reference() => {
                    defn.insert(u.name.to_string().into_owned(), idx);
                    aggregates.push((idx, true));
                }
                pdb::TypeData::Enumeration(e) if !e.properties.forward_reference() => {
                    defn.insert(e.name.to_string().into_owned(), idx);
                    enums.push(idx);
                }
                pdb::TypeData::Procedure(_) => procs.push(idx),
                _ => {}
            }
        }

        let rz = Resolver {
            finder: &finder,
            defn: &defn,
            ptr_width,
        };
        let mut seen: HashMap<String, ()> = HashMap::new();

        for idx in enums {
            if let Some(ty) = rz.build_enum(idx) {
                push_type(ty, &mut types, &mut seen);
            } else {
                skipped += 1;
            }
        }
        for (idx, is_union) in aggregates {
            match rz.build_record(idx, is_union) {
                Ok((ty, dropped)) => {
                    skipped += dropped;
                    push_type(ty, &mut types, &mut seen);
                }
                Err(()) => skipped += 1,
            }
        }
        for idx in procs {
            if let Some(sig) = rz.build_signature(idx) {
                sig_by_index.insert(idx, sig);
            }
        }
    }

    // Phase B — walk the module symbol streams for procedures and key each prototype by its
    // load address (image_base + RVA). The type stream is dropped, so signatures come from the
    // owned `sig_by_index` built above.
    let mut protos: Vec<(u64, FuncProto)> = Vec::new();
    let mut seen_addr: HashMap<u64, ()> = HashMap::new();
    let address_map = pdb.address_map()?;
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        let Some(info) = pdb.module_info(&module)? else {
            continue;
        };
        let mut symbols = info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            if let Ok(pdb::SymbolData::Procedure(proc)) = symbol.parse() {
                let Some(rva) = proc.offset.to_rva(&address_map) else {
                    continue;
                };
                let addr = image_base.wrapping_add(rva.0 as u64);
                if seen_addr.insert(addr, ()).is_none() {
                    protos.push((addr, proto_from_sig(sig_by_index.get(&proc.type_index.0))));
                }
            }
        }
    }

    Ok(Imported {
        types,
        protos,
        skipped,
    })
}

fn push_type(ty: UserType, types: &mut Vec<UserType>, seen: &mut HashMap<String, ()>) {
    if seen.insert(ty.name().to_owned(), ()).is_none() {
        types.push(ty);
    }
}

fn proto_from_sig(sig: Option<&(Option<TypeRef>, Vec<TypeRef>)>) -> FuncProto {
    match sig {
        Some((ret, args)) => FuncProto {
            ret: ret.clone(),
            params: args
                .iter()
                .enumerate()
                .map(|(i, t)| (format!("arg{i}"), t.clone()))
                .collect(),
        },
        None => FuncProto::default(),
    }
}

// ---------------------------------------------------------------------------- resolution

const MAX_DEPTH: u32 = 24;

struct Resolver<'a, 't> {
    finder: &'a pdb::TypeFinder<'t>,
    /// Aggregate name → its defining record index, to size members that reference a forward decl.
    defn: &'a HashMap<String, u32>,
    ptr_width: u64,
}

impl Resolver<'_, '_> {
    fn data(&self, idx: u32) -> Option<pdb::TypeData<'_>> {
        self.finder.find(pdb::TypeIndex(idx)).ok()?.parse().ok()
    }

    /// A catalog [`TypeRef`] for the type at `idx`. Pointers stop the recursion, aggregates and
    /// enums become `Named`, modifiers are transparent, and unknowns degrade to `void`.
    fn resolve(&self, idx: u32, depth: u32) -> TypeRef {
        let void = || TypeRef::Prim(Prim::Void);
        if depth > MAX_DEPTH {
            return void();
        }
        let Some(data) = self.data(idx) else {
            return void();
        };
        match data {
            pdb::TypeData::Primitive(p) => {
                let inner = prim_of(p.kind).map(TypeRef::Prim).unwrap_or_else(void);
                if p.indirection.is_some() {
                    TypeRef::Pointer(Box::new(inner))
                } else {
                    inner
                }
            }
            pdb::TypeData::Pointer(ptr) => {
                TypeRef::Pointer(Box::new(self.resolve(ptr.underlying_type.0, depth + 1)))
            }
            pdb::TypeData::Modifier(m) => self.resolve(m.underlying_type.0, depth + 1),
            pdb::TypeData::Array(a) => self.resolve(a.element_type.0, depth + 1),
            pdb::TypeData::Class(_) | pdb::TypeData::Union(_) | pdb::TypeData::Enumeration(_) => {
                named(&data).map(TypeRef::Named).unwrap_or_else(void)
            }
            _ => void(),
        }
    }

    /// Byte size of the type at `idx`.
    fn size_of(&self, idx: u32, depth: u32) -> u64 {
        if depth > MAX_DEPTH {
            return self.ptr_width;
        }
        let Some(data) = self.data(idx) else { return 0 };
        match data {
            pdb::TypeData::Primitive(p) => {
                if p.indirection.is_some() {
                    self.ptr_width
                } else {
                    prim_of(p.kind).map(|p| p.size()).unwrap_or(0)
                }
            }
            pdb::TypeData::Pointer(_) => self.ptr_width,
            pdb::TypeData::Modifier(m) => self.size_of(m.underlying_type.0, depth + 1),
            pdb::TypeData::Class(c) => self.aggregate_size(c.size, &c.name, depth),
            pdb::TypeData::Union(u) => self.aggregate_size(u.size, &u.name, depth),
            pdb::TypeData::Enumeration(e) => self.size_of(e.underlying_type.0, depth + 1),
            pdb::TypeData::Array(a) => a.dimensions.last().copied().unwrap_or(0) as u64,
            _ => 0,
        }
    }

    /// Size of an aggregate, resolving a forward declaration (size 0) to its defining record.
    fn aggregate_size(&self, size: u64, name: &pdb::RawString<'_>, depth: u32) -> u64 {
        if size > 0 {
            return size;
        }
        let key = name.to_string();
        self.defn
            .get(key.as_ref())
            .map(|&d| self.size_of(d, depth + 1))
            .unwrap_or(0)
    }

    /// Element type, element count and total byte span of a member (arrays contribute the
    /// element type plus the dimension count).
    fn member_elem(&self, field_type: u32) -> (TypeRef, u64, u64) {
        if let Some(pdb::TypeData::Array(a)) = self.data(field_type) {
            let total = a.dimensions.last().copied().unwrap_or(0) as u64;
            let elem = self.resolve(a.element_type.0, 0);
            let esize = self.size_of(a.element_type.0, 0);
            let count = total.checked_div(esize).unwrap_or(0).max(1);
            return (elem, count, total);
        }
        (self.resolve(field_type, 0), 1, self.size_of(field_type, 0))
    }

    fn is_bitfield(&self, idx: u32) -> bool {
        matches!(self.data(idx), Some(pdb::TypeData::Bitfield(_)))
    }

    /// Collects the `Member`/`Enumerate` entries of a field list, following continuations.
    fn field_list(&self, mut idx: Option<u32>) -> Vec<pdb::TypeData<'_>> {
        let mut out = Vec::new();
        let mut guard = 0;
        while let Some(i) = idx {
            guard += 1;
            if guard > 256 {
                break;
            }
            let Some(pdb::TypeData::FieldList(fl)) = self.data(i) else {
                break;
            };
            idx = fl.continuation.map(|c| c.0);
            out.extend(fl.fields);
        }
        out
    }

    fn build_enum(&self, idx: u32) -> Option<UserType> {
        let pdb::TypeData::Enumeration(e) = self.data(idx)? else {
            return None;
        };
        let name = e.name.to_string().into_owned();
        if !is_catalog_name(&name) {
            return None;
        }
        let width = int_prim(self.size_of(e.underlying_type.0, 0)).unwrap_or(Prim::I32);
        let mut variants = Vec::new();
        for entry in self.field_list(Some(e.fields.0)) {
            if let pdb::TypeData::Enumerate(en) = entry {
                let vname = en.name.to_string().into_owned();
                if is_catalog_name(&vname) {
                    variants.push((vname, variant_i64(&en.value)));
                }
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

    /// Builds a struct or union; `Err` when the layout is unrepresentable (packed/overlapping)
    /// or nothing usable survives. On success, also returns how many bitfield members were
    /// dropped.
    fn build_record(&self, idx: u32, is_union: bool) -> Result<(UserType, usize), ()> {
        let data = self.data(idx).ok_or(())?;
        let (name, fields_idx, size) = match &data {
            pdb::TypeData::Class(c) => (c.name, c.fields.map(|f| f.0), c.size),
            pdb::TypeData::Union(u) => (u.name, Some(u.fields.0), u.size),
            _ => return Err(()),
        };
        let name = name.to_string().into_owned();
        if !is_catalog_name(&name) {
            return Err(());
        }

        let mut fields: Vec<FieldDef> = Vec::new();
        let mut running = 0u64;
        let mut pad_n = 0u32;
        let mut dropped = 0usize;

        for entry in self.field_list(fields_idx) {
            let pdb::TypeData::Member(m) = entry else {
                continue; // base classes, methods, vftable pointers, …
            };
            if self.is_bitfield(m.field_type.0) {
                dropped += 1;
                continue;
            }
            let (elem_ty, count, total) = self.member_elem(m.field_type.0);
            let fname = {
                let n = m.name.to_string().into_owned();
                if is_catalog_name(&n) {
                    n
                } else {
                    format!("field_{}", fields.len())
                }
            };

            if is_union {
                fields.push(FieldDef {
                    name: fname,
                    ty: elem_ty,
                    count: count.max(1),
                });
                continue;
            }

            let off = m.offset;
            if off < running {
                return Err(()); // packed / overlapping: additive model can't reproduce it
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
        if !is_union && size > running {
            fields.push(FieldDef {
                name: format!("_pad{pad_n}"),
                ty: TypeRef::Prim(Prim::U8),
                count: size - running,
            });
        }

        let ty = if is_union {
            UserType::Union { name, fields }
        } else {
            UserType::Struct { name, fields }
        };
        Ok((ty, dropped))
    }

    /// The return type and ordered parameter types of a `Procedure` (`LF_PROCEDURE`) type.
    fn build_signature(&self, idx: u32) -> Option<(Option<TypeRef>, Vec<TypeRef>)> {
        let pdb::TypeData::Procedure(p) = self.data(idx)? else {
            return None;
        };
        let ret = p.return_type.map(|r| self.resolve(r.0, 0));
        let mut args = Vec::new();
        if let Some(pdb::TypeData::ArgumentList(list)) = self.data(p.argument_list.0) {
            for a in list.arguments {
                args.push(self.resolve(a.0, 0));
            }
        }
        Some((ret, args))
    }
}

/// The catalog name of a Class/Union/Enumeration `TypeData`, if usable.
fn named(data: &pdb::TypeData<'_>) -> Option<String> {
    let n = data.name()?.to_string().into_owned();
    is_catalog_name(&n).then_some(n)
}

// ---------------------------------------------------------------------------- primitives

/// Maps a CodeView primitive kind to a catalog primitive (ignoring indirection, handled apart).
fn prim_of(kind: pdb::PrimitiveKind) -> Option<Prim> {
    use pdb::PrimitiveKind as K;
    Some(match kind {
        K::Void => Prim::Void,
        K::Bool8 => Prim::Bool,
        K::Char | K::RChar => Prim::Char,
        K::UChar | K::U8 => Prim::U8,
        K::I8 => Prim::I8,
        K::Short | K::I16 => Prim::I16,
        K::UShort | K::U16 | K::WChar | K::RChar16 | K::Bool16 => Prim::U16,
        K::Long | K::I32 | K::HRESULT => Prim::I32,
        K::ULong | K::U32 | K::RChar32 | K::Bool32 => Prim::U32,
        K::Quad | K::I64 => Prim::I64,
        K::UQuad | K::U64 | K::Bool64 => Prim::U64,
        K::F32 => Prim::F32,
        K::F64 => Prim::F64,
        _ => return None,
    })
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

fn variant_i64(v: &pdb::Variant) -> i64 {
    use pdb::Variant::*;
    match v {
        U8(x) => *x as i64,
        U16(x) => *x as i64,
        U32(x) => *x as i64,
        U64(x) => *x as i64,
        I8(x) => *x as i64,
        I16(x) => *x as i64,
        I32(x) => *x as i64,
        I64(x) => *x,
    }
}
