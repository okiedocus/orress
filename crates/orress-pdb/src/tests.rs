//! Round-trips a committed PDB fixture through [`import`].
//!
//! `testdata/pdbtest.pdb` was built from a small C file (a struct with interior/trailing
//! padding, a nested struct by value, a `char[16]` array, an enum, a self-referential pointer,
//! and four functions) with the LLVM toolchain:
//!
//! ```text
//! clang --target=x86_64-pc-windows-msvc -gcodeview -g -O0 -c pdbtest.c -o pdbtest.obj
//! lld-link -debug -nodefaultlib -entry:startup -subsystem:console pdbtest.obj \
//!          -out:pdbtest.exe -pdb:pdbtest.pdb
//! ```
//!
//! The linked image uses the default x64 base `0x1_4000_0000`, which the test passes to
//! `import` so procedure RVAs become load addresses.

use super::*;

const FIXTURE: &[u8] = include_bytes!("testdata/pdbtest.pdb");
const IMAGE_BASE: u64 = 0x1_4000_0000;

fn imported() -> Imported {
    import(FIXTURE, IMAGE_BASE, 8).expect("import should succeed")
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
fn enum_recovers_width_and_variants() {
    let imp = imported();
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
                    ("BLUE".to_owned(), 7)
                ]
            );
        }
        other => panic!("expected enum, got {other:?}"),
    }
}

#[test]
fn struct_gets_interior_and_trailing_padding() {
    let imp = imported();
    let UserType::Struct { fields, .. } = find(&imp, "Padded") else {
        panic!("Padded should be a struct");
    };
    let got: Vec<(&str, &TypeRef, u64)> = fields
        .iter()
        .map(|f| (f.name.as_str(), &f.ty, f.count))
        .collect();
    assert_eq!(
        got,
        vec![
            ("tag", &TypeRef::Prim(Prim::Char), 1),
            ("_pad0", &TypeRef::Prim(Prim::U8), 7),
            ("value", &TypeRef::Prim(Prim::F64), 1),
            ("n", &TypeRef::Prim(Prim::I32), 1),
            ("_pad1", &TypeRef::Prim(Prim::U8), 4),
        ]
    );
}

#[test]
fn nested_struct_and_array_members_have_no_spurious_padding() {
    let imp = imported();
    let UserType::Struct { fields, .. } = find(&imp, "Record") else {
        panic!("Record should be a struct");
    };
    // Forward-declared `Point` is sized from its definition, so there is no filler between it
    // and `color`.
    let got: Vec<(&str, &TypeRef, u64)> = fields
        .iter()
        .map(|f| (f.name.as_str(), &f.ty, f.count))
        .collect();
    assert_eq!(
        got,
        vec![
            ("name", &TypeRef::Prim(Prim::Char), 16),
            ("origin", &TypeRef::Named("Point".into()), 1),
            ("color", &TypeRef::Named("Color".into()), 1),
            ("flags", &TypeRef::Prim(Prim::U32), 1),
        ]
    );
}

#[test]
fn self_referential_pointer_resolves_to_named() {
    let imp = imported();
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
fn procedures_recover_signatures_keyed_by_load_address() {
    let imp = imported();
    assert_eq!(imp.protos.len(), 4, "add/scale/advance/startup");

    // All procedure addresses are in the image (base + RVA).
    assert!(imp.protos.iter().all(|(a, _)| *a >= IMAGE_BASE));

    // `add(int, int) -> int`
    assert!(imp.protos.iter().any(|(_, p)| {
        p.ret == Some(TypeRef::Prim(Prim::I32))
            && p.params.len() == 2
            && p.params.iter().all(|(_, t)| *t == TypeRef::Prim(Prim::I32))
    }));
    // `advance(Node*) -> Node*`
    let node_ptr = TypeRef::Pointer(Box::new(TypeRef::Named("Node".into())));
    assert!(imp.protos.iter().any(|(_, p)| {
        p.ret.as_ref() == Some(&node_ptr) && p.params.len() == 1 && p.params[0].1 == node_ptr
    }));
    // `scale(Point*, double) -> double`
    assert!(imp.protos.iter().any(|(_, p)| {
        p.ret == Some(TypeRef::Prim(Prim::F64))
            && p.params.len() == 2
            && p.params[1].1 == TypeRef::Prim(Prim::F64)
    }));
}
