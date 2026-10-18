//! User-defined types: structs, unions, enums and typedefs the analyst declares and
//! applies to data. Pure data plus C-style layout (size, alignment, field offsets); the
//! GUI (the Types view) and persistence ([`crate::Annotations`]) are built on top.
//!
//! Types are resolved through a [`TypeCatalog`], which also knows the binary's pointer
//! size so a `Pointer` (and a struct holding one) sizes correctly on 32- and 64-bit
//! targets.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::annotations::validate_name;

/// A built-in scalar type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prim {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    Bool,
    Char,
    /// A zero-sized placeholder; only meaningful behind a pointer (`void *`).
    Void,
}

impl Prim {
    /// Size in bytes (`Void` is 0).
    pub fn size(self) -> u64 {
        match self {
            Self::U8 | Self::I8 | Self::Bool | Self::Char => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
            Self::Void => 0,
        }
    }

    /// Natural alignment in bytes (`Void` aligns to 1).
    pub fn align(self) -> u64 {
        self.size().max(1)
    }

    /// The name shown in the UI and the layout preview.
    pub fn label(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::I8 => "i8",
            Self::U16 => "u16",
            Self::I16 => "i16",
            Self::U32 => "u32",
            Self::I32 => "i32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
            Self::Char => "char",
            Self::Void => "void",
        }
    }

    /// Every primitive, for building a dropdown.
    pub const ALL: [Prim; 13] = [
        Prim::U8,
        Prim::I8,
        Prim::U16,
        Prim::I16,
        Prim::U32,
        Prim::I32,
        Prim::U64,
        Prim::I64,
        Prim::F32,
        Prim::F64,
        Prim::Bool,
        Prim::Char,
        Prim::Void,
    ];
}

/// A reference to a type: a primitive, a pointer to another type, or a named user type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeRef {
    Prim(Prim),
    /// `*T`. Breaks recursion cycles, so a struct may point to itself.
    Pointer(Box<TypeRef>),
    /// Another user type, by name.
    Named(String),
}

impl TypeRef {
    /// A readable form for the layout preview (`u32`, `*Node`, `Packet`).
    pub fn label(&self) -> String {
        match self {
            Self::Prim(p) => p.label().to_owned(),
            Self::Pointer(inner) => format!("*{}", inner.label()),
            Self::Named(name) => name.clone(),
        }
    }
}

/// One field of a struct or union: a name, a type, and an array count (`1` = scalar).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub ty: TypeRef,
    /// Array length; always at least 1.
    pub count: u64,
}

/// A user-defined type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserType {
    Struct {
        name: String,
        fields: Vec<FieldDef>,
    },
    Union {
        name: String,
        fields: Vec<FieldDef>,
    },
    Enum {
        name: String,
        /// Underlying integer width (an integer primitive).
        width: Prim,
        variants: Vec<(String, i64)>,
    },
    Typedef {
        name: String,
        target: TypeRef,
    },
}

impl UserType {
    pub fn name(&self) -> &str {
        match self {
            Self::Struct { name, .. }
            | Self::Union { name, .. }
            | Self::Enum { name, .. }
            | Self::Typedef { name, .. } => name,
        }
    }

    /// The word shown in the UI for this kind of type.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Struct { .. } => "struct",
            Self::Union { .. } => "union",
            Self::Enum { .. } => "enum",
            Self::Typedef { .. } => "typedef",
        }
    }
}

/// An applied function prototype: the return type and named, typed parameters the user
/// has pinned to a function. Consumed by the decompiler (Phase B) to override its
/// recovered signature.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FuncProto {
    pub ret: Option<TypeRef>,
    pub params: Vec<(String, TypeRef)>,
}

/// One field placed in memory: its dotted path, element type, offset and total size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaidField {
    pub path: String,
    pub ty: TypeRef,
    /// Array length (`1` for a scalar), carried through so the UI can show `[N]`.
    pub count: u64,
    pub offset: u64,
    /// Total size of this field (element size × count).
    pub size: u64,
}

/// The catalog of user types for one binary, plus the pointer size to resolve `Pointer`.
#[derive(Clone, Debug)]
pub struct TypeCatalog {
    pub types: BTreeMap<String, UserType>,
    pub pointer_size: u64,
}

impl Default for TypeCatalog {
    fn default() -> Self {
        Self {
            types: BTreeMap::new(),
            pointer_size: 8,
        }
    }
}

impl TypeCatalog {
    /// Builds a catalog from a type map and a binary bitness (`Some(32)`/`Some(64)`).
    pub fn new(types: BTreeMap<String, UserType>, bits: Option<u8>) -> Self {
        Self {
            types,
            pointer_size: if bits == Some(32) { 4 } else { 8 },
        }
    }

    /// Size of a type reference, or `None` if a named type is missing or forms a
    /// by-value cycle.
    pub fn size_of(&self, ty: &TypeRef) -> Option<u64> {
        self.size_of_guarded(ty, &mut BTreeSet::new())
    }

    /// Alignment of a type reference.
    pub fn align_of(&self, ty: &TypeRef) -> Option<u64> {
        self.align_of_guarded(ty, &mut BTreeSet::new())
    }

    fn size_of_guarded(&self, ty: &TypeRef, seen: &mut BTreeSet<String>) -> Option<u64> {
        match ty {
            TypeRef::Prim(p) => Some(p.size()),
            TypeRef::Pointer(_) => Some(self.pointer_size),
            TypeRef::Named(name) => {
                if !seen.insert(name.clone()) {
                    return None; // by-value cycle
                }
                let out = self.named_size(name, seen);
                seen.remove(name);
                out
            }
        }
    }

    fn align_of_guarded(&self, ty: &TypeRef, seen: &mut BTreeSet<String>) -> Option<u64> {
        match ty {
            TypeRef::Prim(p) => Some(p.align()),
            TypeRef::Pointer(_) => Some(self.pointer_size),
            TypeRef::Named(name) => {
                if !seen.insert(name.clone()) {
                    return None;
                }
                let out = self.named_align(name, seen);
                seen.remove(name);
                out
            }
        }
    }

    fn named_size(&self, name: &str, seen: &mut BTreeSet<String>) -> Option<u64> {
        match self.types.get(name)? {
            UserType::Enum { width, .. } => Some(width.size()),
            UserType::Typedef { target, .. } => self.size_of_guarded(target, seen),
            UserType::Struct { fields, .. } => {
                let (size, _) = self.lay_fields(fields, seen)?;
                Some(size)
            }
            UserType::Union { fields, .. } => {
                let mut size = 0;
                let mut align = 1;
                for f in fields {
                    let fs = self.field_size(f, seen)?;
                    let fa = self.align_of_guarded(&f.ty, seen)?;
                    size = size.max(fs);
                    align = align.max(fa);
                }
                Some(round_up(size, align))
            }
        }
    }

    fn named_align(&self, name: &str, seen: &mut BTreeSet<String>) -> Option<u64> {
        match self.types.get(name)? {
            UserType::Enum { width, .. } => Some(width.align()),
            UserType::Typedef { target, .. } => self.align_of_guarded(target, seen),
            UserType::Struct { fields, .. } | UserType::Union { fields, .. } => {
                let mut align = 1;
                for f in fields {
                    align = align.max(self.align_of_guarded(&f.ty, seen)?);
                }
                Some(align)
            }
        }
    }

    /// Total size of a field (element size × count).
    fn field_size(&self, f: &FieldDef, seen: &mut BTreeSet<String>) -> Option<u64> {
        let elem = self.size_of_guarded(&f.ty, seen)?;
        Some(elem.saturating_mul(f.count.max(1)))
    }

    /// Lays struct fields out in order, returning (total size, placed fields).
    fn lay_fields(
        &self,
        fields: &[FieldDef],
        seen: &mut BTreeSet<String>,
    ) -> Option<(u64, Vec<LaidField>)> {
        let mut offset = 0u64;
        let mut max_align = 1u64;
        let mut out = Vec::with_capacity(fields.len());
        for f in fields {
            let align = self.align_of_guarded(&f.ty, seen)?.max(1);
            let size = self.field_size(f, seen)?;
            offset = round_up(offset, align);
            max_align = max_align.max(align);
            out.push(LaidField {
                path: f.name.clone(),
                ty: f.ty.clone(),
                count: f.count.max(1),
                offset,
                size,
            });
            offset = offset.saturating_add(size);
        }
        Some((round_up(offset, max_align), out))
    }

    /// Places every field of a struct or union in memory for the layout preview and the
    /// Inspector. `None` if the type cannot be laid out (missing or cyclic member).
    pub fn layout(&self, ty: &UserType) -> Option<Vec<LaidField>> {
        let mut seen = BTreeSet::new();
        seen.insert(ty.name().to_owned());
        match ty {
            UserType::Struct { fields, .. } => Some(self.lay_fields(fields, &mut seen)?.1),
            UserType::Union { fields, .. } => {
                let mut out = Vec::with_capacity(fields.len());
                for f in fields {
                    out.push(LaidField {
                        path: f.name.clone(),
                        ty: f.ty.clone(),
                        count: f.count.max(1),
                        offset: 0,
                        size: self.field_size(f, &mut seen)?,
                    });
                }
                Some(out)
            }
            UserType::Enum { .. } | UserType::Typedef { .. } => Some(Vec::new()),
        }
    }

    /// Checks a type is well formed: valid identifiers, unique non-empty field names,
    /// every referenced type resolves, and no by-value cycle.
    pub fn validate(&self, ty: &UserType) -> Result<(), String> {
        validate_name(ty.name()).map_err(|e| format!("type name: {e}"))?;
        if ty.name().trim().is_empty() {
            return Err("a type needs a name".into());
        }
        match ty {
            UserType::Struct { fields, .. } | UserType::Union { fields, .. } => {
                if fields.is_empty() {
                    return Err("add at least one field".into());
                }
                let mut names = BTreeSet::new();
                for f in fields {
                    let fname = f.name.trim();
                    validate_name(fname).map_err(|e| format!("field `{}`: {e}", f.name))?;
                    if fname.is_empty() {
                        return Err("every field needs a name".into());
                    }
                    if !names.insert(fname.to_owned()) {
                        return Err(format!("duplicate field name `{fname}`"));
                    }
                    self.resolve_ref(&f.ty)?;
                }
            }
            UserType::Enum { variants, width, .. } => {
                if !matches!(
                    width,
                    Prim::U8 | Prim::I8 | Prim::U16 | Prim::I16 | Prim::U32 | Prim::I32 | Prim::U64 | Prim::I64
                ) {
                    return Err("enum underlying type must be an integer".into());
                }
                if variants.is_empty() {
                    return Err("add at least one variant".into());
                }
                let mut names = BTreeSet::new();
                for (vname, _) in variants {
                    let vname = vname.trim();
                    validate_name(vname).map_err(|e| format!("variant `{vname}`: {e}"))?;
                    if vname.is_empty() {
                        return Err("every variant needs a name".into());
                    }
                    if !names.insert(vname.to_owned()) {
                        return Err(format!("duplicate variant name `{vname}`"));
                    }
                }
            }
            UserType::Typedef { target, .. } => self.resolve_ref(target)?,
        }
        // A by-value cycle makes the size unresolvable; catch it with the type in place.
        let mut probe = self.clone();
        probe.types.insert(ty.name().to_owned(), ty.clone());
        if probe.size_of(&TypeRef::Named(ty.name().to_owned())).is_none() {
            return Err("this type refers to itself by value (use a pointer instead)".into());
        }
        Ok(())
    }

    /// Checks a type reference names only things that exist. Pointers are not followed,
    /// so `*Missing` is still an error but `*SelfType` is fine.
    fn resolve_ref(&self, ty: &TypeRef) -> Result<(), String> {
        match ty {
            TypeRef::Prim(_) => Ok(()),
            TypeRef::Pointer(inner) => self.resolve_ref(inner),
            TypeRef::Named(name) => {
                if self.types.contains_key(name) {
                    Ok(())
                } else {
                    Err(format!("unknown type `{name}`"))
                }
            }
        }
    }
}

/// Whether a type reference mentions the named type (following pointers), used to drop
/// data applications when their type is deleted.
pub fn references(ty: &TypeRef, name: &str) -> bool {
    match ty {
        TypeRef::Prim(_) => false,
        TypeRef::Pointer(inner) => references(inner, name),
        TypeRef::Named(n) => n == name,
    }
}

/// Rounds `value` up to the next multiple of `align` (a power of two or any non-zero).
fn round_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align).saturating_mul(align)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(types: Vec<UserType>, bits: Option<u8>) -> TypeCatalog {
        let map = types.into_iter().map(|t| (t.name().to_owned(), t)).collect();
        TypeCatalog::new(map, bits)
    }

    fn field(name: &str, ty: TypeRef, count: u64) -> FieldDef {
        FieldDef { name: name.into(), ty, count }
    }

    #[test]
    fn struct_layout_has_c_padding() {
        // struct { u8 a; u32 b; u16 c; } -> a@0, pad, b@4, c@8, size 12 (align 4).
        let s = UserType::Struct {
            name: "S".into(),
            fields: vec![
                field("a", TypeRef::Prim(Prim::U8), 1),
                field("b", TypeRef::Prim(Prim::U32), 1),
                field("c", TypeRef::Prim(Prim::U16), 1),
            ],
        };
        let c = cat(vec![s.clone()], Some(64));
        let laid = c.layout(&s).unwrap();
        assert_eq!(laid[0].offset, 0);
        assert_eq!(laid[1].offset, 4);
        assert_eq!(laid[2].offset, 8);
        assert_eq!(c.size_of(&TypeRef::Named("S".into())).unwrap(), 12);
    }

    #[test]
    fn array_field_size_and_union_size() {
        let s = UserType::Struct {
            name: "Buf".into(),
            fields: vec![
                field("magic", TypeRef::Prim(Prim::U32), 1),
                field("body", TypeRef::Prim(Prim::Char), 64),
            ],
        };
        let c = cat(vec![s.clone()], Some(64));
        let laid = c.layout(&s).unwrap();
        assert_eq!(laid[1].offset, 4);
        assert_eq!(laid[1].size, 64);
        assert_eq!(c.size_of(&TypeRef::Named("Buf".into())).unwrap(), 68);

        let u = UserType::Union {
            name: "U".into(),
            fields: vec![
                field("w", TypeRef::Prim(Prim::U32), 1),
                field("q", TypeRef::Prim(Prim::U64), 1),
            ],
        };
        let c = cat(vec![u.clone()], Some(64));
        assert_eq!(c.size_of(&TypeRef::Named("U".into())).unwrap(), 8);
    }

    #[test]
    fn pointer_size_follows_bitness() {
        let p = TypeRef::Pointer(Box::new(TypeRef::Prim(Prim::Char)));
        assert_eq!(cat(vec![], Some(64)).size_of(&p).unwrap(), 8);
        assert_eq!(cat(vec![], Some(32)).size_of(&p).unwrap(), 4);
    }

    #[test]
    fn self_pointer_ok_but_by_value_cycle_rejected() {
        // A linked-list node: pointer to self is fine.
        let node = UserType::Struct {
            name: "Node".into(),
            fields: vec![
                field("val", TypeRef::Prim(Prim::I32), 1),
                field("next", TypeRef::Pointer(Box::new(TypeRef::Named("Node".into()))), 1),
            ],
        };
        let c = cat(vec![node.clone()], Some(64));
        assert!(c.validate(&node).is_ok());
        assert_eq!(c.size_of(&TypeRef::Named("Node".into())).unwrap(), 16);

        // A struct containing itself by value has no finite size.
        let bad = UserType::Struct {
            name: "Bad".into(),
            fields: vec![field("me", TypeRef::Named("Bad".into()), 1)],
        };
        let c = cat(vec![], Some(64));
        assert!(c.validate(&bad).is_err());
    }

    #[test]
    fn validate_catches_missing_type_and_dupes() {
        let c = cat(vec![], Some(64));
        let missing = UserType::Struct {
            name: "X".into(),
            fields: vec![field("f", TypeRef::Named("Nope".into()), 1)],
        };
        assert!(c.validate(&missing).is_err());

        let dupe = UserType::Struct {
            name: "Y".into(),
            fields: vec![
                field("f", TypeRef::Prim(Prim::U8), 1),
                field("f", TypeRef::Prim(Prim::U8), 1),
            ],
        };
        assert!(c.validate(&dupe).is_err());
    }

    #[test]
    fn typedef_and_enum_sizes() {
        let td = UserType::Typedef {
            name: "Word".into(),
            target: TypeRef::Prim(Prim::U16),
        };
        let en = UserType::Enum {
            name: "Cmd".into(),
            width: Prim::U32,
            variants: vec![("Read".into(), 1), ("Write".into(), 2)],
        };
        let c = cat(vec![td, en], Some(64));
        assert_eq!(c.size_of(&TypeRef::Named("Word".into())).unwrap(), 2);
        assert_eq!(c.size_of(&TypeRef::Named("Cmd".into())).unwrap(), 4);
    }
}
