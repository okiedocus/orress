//! Deterministic, compiler-free tests: synthesize a tiny DWARF program with `gimli::write`,
//! wrap it in an ELF with `object::write`, then round-trip it through [`import`].

use gimli::write::{AttributeValue, EndianVec, LineProgram, Sections, Unit};
use gimli::{Encoding, Format};
use object::write::{Object, SectionKind};
use object::{Architecture, BinaryFormat, Endianness};

use super::*;

/// Handle onto the unit being built, so helpers stay terse.
struct Builder {
    dwarf: gimli::write::Dwarf,
    unit: gimli::write::UnitId,
}

impl Builder {
    fn new() -> Self {
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = gimli::write::Dwarf::new();
        let unit = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        Builder { dwarf, unit }
    }

    fn root(&mut self) -> gimli::write::UnitEntryId {
        self.dwarf.units.get_mut(self.unit).root()
    }

    fn add(
        &mut self,
        parent: gimli::write::UnitEntryId,
        tag: gimli::DwTag,
    ) -> gimli::write::UnitEntryId {
        self.dwarf.units.get_mut(self.unit).add(parent, tag)
    }

    fn set(&mut self, id: gimli::write::UnitEntryId, attr: gimli::DwAt, value: AttributeValue) {
        self.dwarf
            .units
            .get_mut(self.unit)
            .get_mut(id)
            .set(attr, value);
    }

    fn name(&mut self, id: gimli::write::UnitEntryId, name: &str) {
        self.set(id, gimli::DW_AT_name, AttributeValue::String(name.into()));
    }

    /// A base type with a name, DWARF encoding, and byte size.
    fn base(&mut self, name: &str, enc: gimli::DwAte, size: u64) -> gimli::write::UnitEntryId {
        let root = self.root();
        let id = self.add(root, gimli::DW_TAG_base_type);
        self.name(id, name);
        self.set(id, gimli::DW_AT_encoding, AttributeValue::Encoding(enc));
        self.set(id, gimli::DW_AT_byte_size, AttributeValue::Udata(size));
        id
    }

    fn member(
        &mut self,
        parent: gimli::write::UnitEntryId,
        name: &str,
        ty: gimli::write::UnitEntryId,
        offset: u64,
    ) -> gimli::write::UnitEntryId {
        let id = self.add(parent, gimli::DW_TAG_member);
        self.name(id, name);
        self.set(id, gimli::DW_AT_type, AttributeValue::UnitRef(ty));
        self.set(
            id,
            gimli::DW_AT_data_member_location,
            AttributeValue::Udata(offset),
        );
        id
    }

    /// Serialize the units and wrap them in a minimal little-endian x86-64 ELF.
    fn elf(mut self) -> Vec<u8> {
        let mut sections = Sections::new(EndianVec::new(gimli::RunTimeEndian::Little));
        self.dwarf.write(&mut sections).unwrap();

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        sections
            .for_each(|id, data| {
                if !data.slice().is_empty() {
                    let sec = obj.add_section(
                        Vec::new(),
                        id.name().as_bytes().to_vec(),
                        SectionKind::Debug,
                    );
                    obj.set_section_data(sec, data.slice().to_vec(), 1);
                }
                Ok::<(), ()>(())
            })
            .unwrap();
        obj.write().unwrap()
    }
}

/// Builds the shared fixture ELF and returns the import result.
fn import_fixture() -> Imported {
    let mut b = Builder::new();
    let int = b.base("int", gimli::DW_ATE_signed, 4);
    let ch = b.base("char", gimli::DW_ATE_signed_char, 1);
    let uchar = b.base("uchar", gimli::DW_ATE_unsigned_char, 1);
    let root = b.root();

    // typedef byte_t = unsigned char.
    let td = b.add(root, gimli::DW_TAG_typedef);
    b.name(td, "byte_t");
    b.set(td, gimli::DW_AT_type, AttributeValue::UnitRef(uchar));

    // enum Color { RED=0, GREEN=1, BLUE=2 } : 4 bytes.
    let col = b.add(root, gimli::DW_TAG_enumeration_type);
    b.name(col, "Color");
    b.set(col, gimli::DW_AT_byte_size, AttributeValue::Udata(4));
    for (n, v) in [("RED", 0), ("GREEN", 1), ("BLUE", 2)] {
        let e = b.add(col, gimli::DW_TAG_enumerator);
        b.name(e, n);
        b.set(e, gimli::DW_AT_const_value, AttributeValue::Sdata(v));
    }

    // struct Packet { int id @0; char flag @8; } size 16  -> gap pad + trailing pad.
    let packet = b.add(root, gimli::DW_TAG_structure_type);
    b.name(packet, "Packet");
    b.set(packet, gimli::DW_AT_byte_size, AttributeValue::Udata(16));
    b.member(packet, "id", int, 0);
    b.member(packet, "flag", ch, 8);

    // struct Buf { char data[4] @0; int len @4; } size 8 -> array member.
    let arr = b.add(root, gimli::DW_TAG_array_type);
    b.set(arr, gimli::DW_AT_type, AttributeValue::UnitRef(ch));
    let sub = b.add(arr, gimli::DW_TAG_subrange_type);
    b.set(sub, gimli::DW_AT_upper_bound, AttributeValue::Sdata(3)); // count = 4
    let buf = b.add(root, gimli::DW_TAG_structure_type);
    b.name(buf, "Buf");
    b.set(buf, gimli::DW_AT_byte_size, AttributeValue::Udata(8));
    b.member(buf, "data", arr, 0);
    b.member(buf, "len", int, 4);

    // struct Node { int value @0; Node *next @8; } size 16 -> self-referential pointer.
    let node = b.add(root, gimli::DW_TAG_structure_type);
    b.name(node, "Node");
    b.set(node, gimli::DW_AT_byte_size, AttributeValue::Udata(16));
    let node_ptr = b.add(root, gimli::DW_TAG_pointer_type);
    b.set(node_ptr, gimli::DW_AT_type, AttributeValue::UnitRef(node));
    b.set(node_ptr, gimli::DW_AT_byte_size, AttributeValue::Udata(8));
    b.member(node, "value", int, 0);
    b.member(node, "next", node_ptr, 8);

    // struct Flags { int b @0; <1-bit bitfield a>; } size 4 -> one member skipped.
    let flags = b.add(root, gimli::DW_TAG_structure_type);
    b.name(flags, "Flags");
    b.set(flags, gimli::DW_AT_byte_size, AttributeValue::Udata(4));
    b.member(flags, "b", int, 0);
    let bit = b.add(flags, gimli::DW_TAG_member);
    b.name(bit, "a");
    b.set(bit, gimli::DW_AT_type, AttributeValue::UnitRef(int));
    b.set(bit, gimli::DW_AT_bit_size, AttributeValue::Udata(1));

    // int add(int a, int b) @ 0x1000.
    let func = b.add(root, gimli::DW_TAG_subprogram);
    b.name(func, "add");
    b.set(func, gimli::DW_AT_type, AttributeValue::UnitRef(int));
    b.set(
        func,
        gimli::DW_AT_low_pc,
        AttributeValue::Address(gimli::write::Address::Constant(0x1000)),
    );
    for pn in ["a", "b"] {
        let p = b.add(func, gimli::DW_TAG_formal_parameter);
        b.name(p, pn);
        b.set(p, gimli::DW_AT_type, AttributeValue::UnitRef(int));
    }

    let elf = b.elf();
    assert!(has_debug_info(&elf), "fixture should carry debug info");
    import(&elf).expect("import should succeed")
}

fn find<'a>(imp: &'a Imported, name: &str) -> &'a UserType {
    imp.types
        .iter()
        .find(|t| t.name() == name)
        .unwrap_or_else(|| panic!("type `{name}` not imported; got {:?}", names(imp)))
}

fn names(imp: &Imported) -> Vec<&str> {
    imp.types.iter().map(UserType::name).collect()
}

#[test]
fn typedef_maps_to_underlying_primitive() {
    let imp = import_fixture();
    match find(&imp, "byte_t") {
        UserType::Typedef { target, .. } => assert_eq!(*target, TypeRef::Prim(Prim::U8)),
        other => panic!("expected typedef, got {other:?}"),
    }
}

#[test]
fn enum_recovers_width_and_variants() {
    let imp = import_fixture();
    match find(&imp, "Color") {
        UserType::Enum {
            width, variants, ..
        } => {
            assert_eq!(*width, Prim::I32);
            assert_eq!(
                variants,
                &[
                    ("RED".to_owned(), 0),
                    ("GREEN".to_owned(), 1),
                    ("BLUE".to_owned(), 2)
                ]
            );
        }
        other => panic!("expected enum, got {other:?}"),
    }
}

#[test]
fn struct_gets_interior_and_trailing_padding() {
    let imp = import_fixture();
    let UserType::Struct { fields, .. } = find(&imp, "Packet") else {
        panic!("Packet should be a struct");
    };
    // id:i32@0, _pad0:[u8;4]@4, flag:char@8, _pad1:[u8;7]@9  => 16 bytes.
    let got: Vec<(&str, &TypeRef, u64)> = fields
        .iter()
        .map(|f| (f.name.as_str(), &f.ty, f.count))
        .collect();
    assert_eq!(
        got,
        vec![
            ("id", &TypeRef::Prim(Prim::I32), 1),
            ("_pad0", &TypeRef::Prim(Prim::U8), 4),
            ("flag", &TypeRef::Prim(Prim::Char), 1),
            ("_pad1", &TypeRef::Prim(Prim::U8), 7),
        ]
    );
}

#[test]
fn array_member_keeps_element_type_and_count() {
    let imp = import_fixture();
    let UserType::Struct { fields, .. } = find(&imp, "Buf") else {
        panic!("Buf should be a struct");
    };
    assert_eq!(fields.len(), 2, "no padding expected: {fields:?}");
    assert_eq!(fields[0].name, "data");
    assert_eq!(fields[0].ty, TypeRef::Prim(Prim::Char));
    assert_eq!(fields[0].count, 4);
    assert_eq!(fields[1].name, "len");
    assert_eq!(fields[1].ty, TypeRef::Prim(Prim::I32));
    assert_eq!(fields[1].count, 1);
}

#[test]
fn self_referential_pointer_resolves_to_named() {
    let imp = import_fixture();
    let UserType::Struct { fields, .. } = find(&imp, "Node") else {
        panic!("Node should be a struct");
    };
    let next = fields
        .iter()
        .find(|f| f.name == "next")
        .expect("next field");
    assert_eq!(
        next.ty,
        TypeRef::Pointer(Box::new(TypeRef::Named("Node".into())))
    );
}

#[test]
fn bitfield_member_is_skipped_and_counted() {
    let imp = import_fixture();
    let UserType::Struct { fields, .. } = find(&imp, "Flags") else {
        panic!("Flags should be a struct");
    };
    assert_eq!(fields.len(), 1, "bitfield should be dropped: {fields:?}");
    assert_eq!(fields[0].name, "b");
    assert!(
        imp.skipped >= 1,
        "the dropped bitfield is not reflected in skipped count"
    );
}

#[test]
fn subprogram_becomes_prototype_keyed_by_low_pc() {
    let imp = import_fixture();
    let (addr, proto) = imp
        .protos
        .iter()
        .find(|(a, _)| *a == 0x1000)
        .expect("add() prototype at 0x1000");
    assert_eq!(*addr, 0x1000);
    assert_eq!(proto.ret, Some(TypeRef::Prim(Prim::I32)));
    assert_eq!(
        proto.params,
        vec![
            ("a".to_owned(), TypeRef::Prim(Prim::I32)),
            ("b".to_owned(), TypeRef::Prim(Prim::I32)),
        ]
    );
}

#[test]
fn no_debug_info_is_a_soft_empty_result() {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let sec = obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    obj.set_section_data(sec, b"\x90\x90\x90\x90".to_vec(), 1);
    let bytes = obj.write().unwrap();
    assert!(!has_debug_info(&bytes));
    let imp = import(&bytes).expect("import on a debug-free ELF is ok");
    assert!(imp.types.is_empty() && imp.protos.is_empty());
}
