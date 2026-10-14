//! ECMA-335 metadata table schema: the column layout of every `#~` table, used to compute row
//! sizes and locate a column within a row. This is data, transcribed from the spec.

/// A coded index: a table reference tagged with a few low bits selecting which table.
#[derive(Clone, Copy)]
pub enum Coded {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl Coded {
    /// `(tag_bits, member_tables)`. A `0xff` entry is an unused tag slot.
    pub fn info(self) -> (u32, &'static [u8]) {
        match self {
            Coded::TypeDefOrRef => (2, &[0x02, 0x01, 0x1b]),
            Coded::HasConstant => (2, &[0x04, 0x08, 0x17]),
            Coded::HasCustomAttribute => (
                5,
                &[
                    0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a,
                    0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2b, 0x2c,
                ],
            ),
            Coded::HasFieldMarshal => (1, &[0x04, 0x08]),
            Coded::HasDeclSecurity => (2, &[0x02, 0x06, 0x20]),
            Coded::MemberRefParent => (3, &[0x02, 0x01, 0x1a, 0x06, 0x1b]),
            Coded::HasSemantics => (1, &[0x14, 0x17]),
            Coded::MethodDefOrRef => (1, &[0x06, 0x0a]),
            Coded::MemberForwarded => (1, &[0x04, 0x06]),
            Coded::Implementation => (2, &[0x26, 0x23, 0x27]),
            Coded::CustomAttributeType => (3, &[0xff, 0xff, 0x06, 0x0a, 0xff]),
            Coded::ResolutionScope => (2, &[0x00, 0x1a, 0x23, 0x01]),
            Coded::TypeOrMethodDef => (1, &[0x02, 0x06]),
        }
    }
}

/// A column's type.
#[derive(Clone, Copy)]
pub enum Col {
    U16,
    U32,
    /// `#Strings` heap index.
    Str,
    /// `#GUID` heap index.
    Guid,
    /// `#Blob` heap index.
    Blob,
    /// Simple index into a single table.
    Idx(u8),
    /// A coded index (table reference tagged in its low bits).
    CodedIdx(Coded),
}

/// The columns of table `id`, in order. An empty slice means an unknown/absent table.
pub fn columns(id: u8) -> &'static [Col] {
    use Coded::*;
    use Col::CodedIdx as C;
    use Col::{Blob, Guid, Idx, Str, U16, U32};
    match id {
        0x00 => &[U16, Str, Guid, Guid, Guid],   // Module
        0x01 => &[C(ResolutionScope), Str, Str], // TypeRef
        0x02 => &[U32, Str, Str, C(TypeDefOrRef), Idx(0x04), Idx(0x06)], // TypeDef
        0x03 => &[Idx(0x04)],                    // FieldPtr
        0x04 => &[U16, Str, Blob],               // Field
        0x05 => &[Idx(0x06)],                    // MethodPtr
        0x06 => &[U32, U16, U16, Str, Blob, Idx(0x08)], // MethodDef
        0x07 => &[Idx(0x08)],                    // ParamPtr
        0x08 => &[U16, U16, Str],                // Param
        0x09 => &[Idx(0x02), C(TypeDefOrRef)],   // InterfaceImpl
        0x0a => &[C(MemberRefParent), Str, Blob], // MemberRef
        0x0b => &[U16, C(HasConstant), Blob],    // Constant
        0x0c => &[C(HasCustomAttribute), C(CustomAttributeType), Blob], // CustomAttribute
        0x0d => &[C(HasFieldMarshal), Blob],     // FieldMarshal
        0x0e => &[U16, C(HasDeclSecurity), Blob], // DeclSecurity
        0x0f => &[U16, U32, Idx(0x02)],          // ClassLayout
        0x10 => &[U32, Idx(0x04)],               // FieldLayout
        0x11 => &[Blob],                         // StandAloneSig
        0x12 => &[Idx(0x02), Idx(0x14)],         // EventMap
        0x13 => &[Idx(0x14)],                    // EventPtr
        0x14 => &[U16, Str, C(TypeDefOrRef)],    // Event
        0x15 => &[Idx(0x02), Idx(0x17)],         // PropertyMap
        0x16 => &[Idx(0x17)],                    // PropertyPtr
        0x17 => &[U16, Str, Blob],               // Property
        0x18 => &[U16, Idx(0x06), C(HasSemantics)], // MethodSemantics
        0x19 => &[Idx(0x02), C(MethodDefOrRef), C(MethodDefOrRef)], // MethodImpl
        0x1a => &[Str],                          // ModuleRef
        0x1b => &[Blob],                         // TypeSpec
        0x1c => &[U16, C(MemberForwarded), Str, Idx(0x1a)], // ImplMap
        0x1d => &[U32, Idx(0x04)],               // FieldRVA
        0x1e => &[U32, U32],                     // EncLog
        0x1f => &[U32],                          // EncMap
        0x20 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str], // Assembly
        0x21 => &[U32],                          // AssemblyProcessor
        0x22 => &[U32, U32, U32],                // AssemblyOS
        0x23 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob], // AssemblyRef
        0x24 => &[U32, Idx(0x23)],               // AssemblyRefProcessor
        0x25 => &[U32, U32, U32, Idx(0x23)],     // AssemblyRefOS
        0x26 => &[U32, Str, Blob],               // File
        0x27 => &[U32, U32, Str, Str, C(Implementation)], // ExportedType
        0x28 => &[U32, U32, Str, C(Implementation)], // ManifestResource
        0x29 => &[Idx(0x02), Idx(0x02)],         // NestedClass
        0x2a => &[U16, U16, C(TypeOrMethodDef), Str], // GenericParam
        0x2b => &[C(MethodDefOrRef), Blob],      // MethodSpec
        0x2c => &[Idx(0x2a), C(TypeDefOrRef)],   // GenericParamConstraint
        _ => &[],
    }
}

/// The readable name of a table id (for the overview).
pub fn table_name(id: u8) -> &'static str {
    match id {
        0x00 => "Module",
        0x01 => "TypeRef",
        0x02 => "TypeDef",
        0x04 => "Field",
        0x06 => "MethodDef",
        0x08 => "Param",
        0x0a => "MemberRef",
        0x0b => "Constant",
        0x0c => "CustomAttribute",
        0x11 => "StandAloneSig",
        0x14 => "Event",
        0x17 => "Property",
        0x1a => "ModuleRef",
        0x1b => "TypeSpec",
        0x20 => "Assembly",
        0x23 => "AssemblyRef",
        0x26 => "File",
        0x27 => "ExportedType",
        0x28 => "ManifestResource",
        0x2a => "GenericParam",
        0x2b => "MethodSpec",
        _ => "Table",
    }
}
