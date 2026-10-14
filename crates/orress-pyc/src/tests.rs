use super::*;

/// A real `.pyc` compiled by CPython 3.14 from `tests/fixtures/sample_src.py`.
const PYC: &[u8] = include_bytes!("../tests/fixtures/sample.pyc");

fn check_fn(p: &Pyc) -> &CodeObject {
    p.top
        .nested()
        .into_iter()
        .find(|c| c.name == "check")
        .expect("check function")
}

#[test]
fn detects_and_parses_header() {
    assert!(looks_like_pyc(PYC));
    assert!(!looks_like_pyc(b"MZ\x90\x00 not a pyc at all........"));

    let p = parse(PYC).unwrap();
    assert_eq!(p.magic, 3627);
    assert_eq!(p.version, Some((3, 14)));
    assert_eq!(p.version_label(), "Python 3.14");
    assert!(!p.hash_based);
    assert_eq!(p.header_len, 16);
    assert!(p.can_disassemble());
}

#[test]
fn recovers_the_code_tree() {
    let p = parse(PYC).unwrap();
    assert_eq!(p.top.name, "<module>");
    assert_eq!(p.top.names, ["SECRET", "check", "main"]);
    // The module's first constant is the flag string.
    assert!(matches!(&p.top.consts[0], Obj::Str(s) if s == "flag{n0t_a_r3al_flag}"));
    // Nested functions, in definition order.
    let nested: Vec<&str> = p.top.nested().iter().map(|c| c.name.as_str()).collect();
    assert_eq!(nested, ["check", "main"]);
}

#[test]
fn check_function_metadata() {
    let p = parse(PYC).unwrap();
    let check = check_fn(&p);
    assert_eq!(check.argcount, 1);
    assert_eq!(check.names, ["enumerate", "ord"]);
    assert_eq!(check.qualname, "check");
    assert!(check.consts.iter().any(|c| matches!(c, Obj::Int(1337))));
    // flags 3 = OPTIMIZED | NEWLOCALS
    assert_eq!(flag_names(check.flags), ["OPTIMIZED", "NEWLOCALS"]);
    // `pw` is the single argument, so it's the first fast local.
    assert_eq!(check.localsplus.first().map(String::as_str), Some("pw"));
}

#[test]
fn disassembly_matches_cpython_dis() {
    let p = parse(PYC).unwrap();
    let check = check_fn(&p);
    let ins = disassemble(check, p.version).unwrap();

    // Offsets + opcodes must match `dis.get_instructions` exactly (including cache skipping).
    let got: Vec<(usize, &str, Option<u32>)> = ins
        .iter()
        .map(|i| (i.offset, i.opname.as_str(), i.arg))
        .collect();
    let expect: Vec<(usize, &str, Option<u32>)> = vec![
        (0, "RESUME", Some(0)),
        (2, "LOAD_SMALL_INT", Some(0)),
        (4, "STORE_FAST", Some(1)),
        (6, "LOAD_GLOBAL", Some(1)),
        (16, "LOAD_FAST_BORROW", Some(0)),
        (18, "CALL", Some(1)),
        (26, "GET_ITER", None),
        (28, "FOR_ITER", Some(37)),
        (32, "UNPACK_SEQUENCE", Some(2)),
        (36, "STORE_FAST_STORE_FAST", Some(35)),
        (38, "LOAD_FAST_BORROW", Some(1)),
        (40, "LOAD_GLOBAL", Some(3)),
        (50, "LOAD_FAST_BORROW", Some(3)),
        (52, "CALL", Some(1)),
        (60, "LOAD_FAST_BORROW", Some(2)),
        (62, "LOAD_SMALL_INT", Some(7)),
        (64, "BINARY_OP", Some(0)),
        (76, "BINARY_OP", Some(12)),
        (88, "BINARY_OP", Some(13)),
        (100, "STORE_FAST", Some(1)),
        (102, "JUMP_BACKWARD", Some(39)),
        (106, "END_FOR", None),
        (108, "POP_ITER", None),
        (110, "LOAD_FAST_BORROW", Some(1)),
        (112, "LOAD_CONST", Some(1)),
        (114, "COMPARE_OP", Some(72)),
        (118, "RETURN_VALUE", None),
    ];
    assert_eq!(got, expect);
}

#[test]
fn resolves_operands_and_jump_targets() {
    let p = parse(PYC).unwrap();
    let check = check_fn(&p);
    let ins = disassemble(check, p.version).unwrap();
    let at = |off: usize| ins.iter().find(|i| i.offset == off).unwrap();

    assert_eq!(at(4).argval.as_deref(), Some("total")); // STORE_FAST 1
    assert_eq!(at(6).argval.as_deref(), Some("enumerate + NULL")); // LOAD_GLOBAL 1
    assert_eq!(at(40).argval.as_deref(), Some("ord + NULL")); // LOAD_GLOBAL 3
    assert_eq!(at(112).argval.as_deref(), Some("1337")); // LOAD_CONST 1
    assert_eq!(at(62).argval.as_deref(), Some("7")); // LOAD_SMALL_INT 7

    // FOR_ITER @28 jumps forward to 106; JUMP_BACKWARD @102 jumps back to 28.
    assert_eq!(at(28).argval.as_deref(), Some("to 106"));
    assert_eq!(at(102).argval.as_deref(), Some("to 28"));
    assert!(at(28).is_jump_target); // JUMP_BACKWARD lands here
    assert!(at(106).is_jump_target); // FOR_ITER lands here
    assert!(!at(4).is_jump_target);
}

#[test]
fn resolves_operators() {
    let p = parse(PYC).unwrap();
    let check = check_fn(&p);
    let ins = disassemble(check, p.version).unwrap();
    let at = |off: usize| ins.iter().find(|i| i.offset == off).unwrap();
    // BINARY_OP and COMPARE_OP operands resolve to their symbols (matching CPython dis).
    assert_eq!(at(64).argval.as_deref(), Some("+")); // i + 7
    assert_eq!(at(76).argval.as_deref(), Some("^")); // ord(c) ^ ...
    assert_eq!(at(88).argval.as_deref(), Some("+=")); // total += ...
    assert_eq!(at(114).argval.as_deref(), Some("==")); // total == 1337
}

#[test]
fn reconstructs_signatures() {
    let p = parse(PYC).unwrap();
    assert_eq!(p.top.signature(), "<module>");
    assert_eq!(check_fn(&p).signature(), "def check(pw)");
    let main = p
        .top
        .nested()
        .into_iter()
        .find(|c| c.name == "main")
        .unwrap();
    assert_eq!(main.signature(), "def main()");
}

#[test]
fn rejects_non_pyc() {
    assert!(parse(b"not a pyc").is_err());
    let mut bad = PYC.to_vec();
    bad[2] = 0; // break the \r\n signature
    assert!(parse(&bad).is_err());
}

#[test]
fn version_from_older_magics() {
    // The range table maps a magic to the right (major, minor).
    assert_eq!(version_from_magic(3627), Some((3, 14)));
    assert_eq!(version_from_magic(3495), Some((3, 11)));
    assert_eq!(version_from_magic(3500), Some((3, 12))); // 3.12a1's first magic
    assert_eq!(version_from_magic(3379), Some((3, 6)));
    assert_eq!(version_from_magic(3230), Some((3, 3)));
    assert_eq!(version_from_magic(3131), Some((3, 0)));
    assert_eq!(version_from_magic(1000), None);
    // Python 2 magics and future versions are unknown, not "3.14".
    assert_eq!(version_from_magic(62211), None);
    assert_eq!(version_from_magic(3700), None);
}

/// A minimal pre-3.8 code object body (`'c'` + fields) whose name is `name`.
fn legacy_code_object(name: &str) -> Vec<u8> {
    let mut b = vec![b'c'];
    for _ in 0..5 {
        b.extend(0u32.to_le_bytes()); // argcount kwonly nlocals stacksize flags
    }
    b.extend([b's', 0, 0, 0, 0]); // co_code
    for _ in 0..5 {
        b.extend([b')', 0]); // consts names varnames freevars cellvars
    }
    b.extend([b'z', 1, b'f']); // filename
    b.push(b'z');
    b.push(name.len() as u8);
    b.extend(name.as_bytes());
    b.extend(1u32.to_le_bytes()); // firstlineno
    b.extend([b's', 0, 0, 0, 0]); // lnotab
    b
}

#[test]
fn header_sizes_follow_the_version() {
    // 3.6 (magic 3379): 12-byte header.
    let mut py36 = vec![0x33, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0];
    py36.extend(legacy_code_object("m36"));
    let p = parse(&py36).unwrap();
    assert_eq!(p.version, Some((3, 6)));
    assert_eq!(p.header_len, 12);
    assert_eq!(p.top.name, "m36");
    assert!(!p.can_disassemble());

    // 3.2 (magic 3180): 8-byte header.
    let mut py32 = vec![0x6c, 0x0c, 0x0d, 0x0a, 0, 0, 0, 0];
    py32.extend(legacy_code_object("m32"));
    py32.extend([0; 8]); // pad past the 16-byte minimum
    let p = parse(&py32).unwrap();
    assert_eq!(p.version, Some((3, 2)));
    assert_eq!(p.header_len, 8);
    assert_eq!(p.top.name, "m32");

    // A Python 2 magic is unknown and can't be disassembled.
    let mut py2 = PYC.to_vec();
    py2[..2].copy_from_slice(&62211u16.to_le_bytes());
    if let Ok(p) = parse(&py2) {
        assert_eq!(p.version, None);
        assert!(!p.can_disassemble());
    }
}

#[test]
fn reference_bombs_are_bounded() {
    // A list whose element i is a FLAG_REF tuple holding two refs to element i-1: the tree it
    // describes has 2^60 nodes, from under a kilobyte of input. Must fail fast, not OOM.
    let levels: u32 = 60;
    let mut b = vec![b'['];
    b.extend(levels.to_le_bytes());
    b.extend([b'(' | 0x80, 2, 0, 0, 0, b'N', b'N']);
    for i in 1..levels {
        b.extend([b'(' | 0x80, 2, 0, 0, 0]);
        for _ in 0..2 {
            b.push(b'r');
            b.extend((i - 1).to_le_bytes());
        }
    }
    let layout = CodeLayout::for_version(Some((3, 14)));
    let err = Unmarshal::new(&b, layout).read().unwrap_err();
    assert!(err.contains("expands"), "{err}");

    // Ordinary sharing still works.
    let ok = [b'(', 2, 0, 0, 0, b'z' | 0x80, 1, b'x', b'r', 0, 0, 0, 0];
    let obj = Unmarshal::new(&ok, layout).read().unwrap();
    assert_eq!(obj.render(), "(\"x\", \"x\")");
}

#[test]
fn decodes_slices_and_big_ints() {
    let layout = CodeLayout::for_version(Some((3, 14)));
    // TYPE_SLICE: slice(1, None, 2)
    let s = [b':', b'i', 1, 0, 0, 0, b'N', b'i', 2, 0, 0, 0];
    let obj = Unmarshal::new(&s, layout).read().unwrap();
    assert_eq!(obj.render(), "slice(1, None, 2)");

    // 2^120 as 9 15-bit digits: fits i128 exactly.
    let mut l = vec![b'l'];
    l.extend(9i32.to_le_bytes());
    for d in 0..9 {
        let digit: u16 = if d == 8 { 1 } else { 0 };
        l.extend(digit.to_le_bytes());
    }
    let obj = Unmarshal::new(&l, layout).read().unwrap();
    assert_eq!(obj, Obj::BigInt((1i128 << 120).to_string()));

    // 0x7fff << 120 needs 135 bits: must be reported as too big, not silently wrapped.
    let mut l = vec![b'l'];
    l.extend(9i32.to_le_bytes());
    for d in 0..9 {
        let digit: u16 = if d == 8 { 0x7fff } else { 0 };
        l.extend(digit.to_le_bytes());
    }
    let obj = Unmarshal::new(&l, layout).read().unwrap();
    assert!(
        matches!(obj, Obj::BigInt(ref s) if s.starts_with("<big int")),
        "{obj:?}"
    );
}

#[test]
fn load_super_attr_name_index() {
    // LOAD_SUPER_ATTR (96) with oparg 0b1011: name index 2, two-arg form, method load.
    let code = CodeObject {
        argcount: 0,
        posonlyargcount: 0,
        kwonlyargcount: 0,
        stacksize: 0,
        flags: 0,
        code: vec![96, 0b1011],
        consts: vec![],
        names: vec!["a".into(), "b".into(), "meth".into(), "zzz".into()],
        localsplus: vec![],
        filename: String::new(),
        name: "f".into(),
        qualname: "f".into(),
        firstlineno: 1,
    };
    let ins = disassemble(&code, Some((3, 14))).unwrap();
    assert_eq!(ins[0].argval.as_deref(), Some("meth + NULL|self"));
}
