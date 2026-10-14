use super::*;

fn uleb(mut v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

fn string_data(s: &str) -> Vec<u8> {
    let mut d = uleb(s.chars().count() as u32);
    d.extend_from_slice(s.as_bytes());
    d.push(0);
    d
}

fn put(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Hand-builds a minimal but structurally valid DEX: a 4-string pool, one type and one method.
/// (Checksum/signature are left zero — the parser reads structure, not integrity fields.)
fn build_dex() -> Vec<u8> {
    let strings = ["Hello", "Lcom/evil/Main;", "http://c2.example", "doEvil"];
    let (n, t, m) = (strings.len(), 1usize, 1usize);
    let string_ids_off = 112;
    let type_ids_off = string_ids_off + n * 4;
    let method_ids_off = type_ids_off + t * 4;
    let data_off = method_ids_off + m * 8;

    let mut blocks = Vec::new();
    let mut offsets = Vec::new();
    let mut cur = data_off;
    for s in strings {
        let b = string_data(s);
        offsets.push(cur as u32);
        cur += b.len();
        blocks.push(b);
    }
    let file_size = cur;

    let mut out = vec![0u8; data_off];
    out[0..8].copy_from_slice(b"dex\n035\0");
    put(&mut out, 32, file_size as u32);
    put(&mut out, 36, 112); // header_size
    put(&mut out, 40, 0x1234_5678); // endian tag
    put(&mut out, 56, n as u32);
    put(&mut out, 60, string_ids_off as u32);
    put(&mut out, 64, t as u32);
    put(&mut out, 68, type_ids_off as u32);
    put(&mut out, 88, m as u32);
    put(&mut out, 92, method_ids_off as u32);
    put(&mut out, 96, 2); // class_defs_size (fictional, for display)

    for (i, off) in offsets.iter().enumerate() {
        put(&mut out, string_ids_off + i * 4, *off);
    }
    put(&mut out, type_ids_off, 1); // type[0] -> string[1] "Lcom/evil/Main;"
    // method[0] = { class_idx: 0 (u16), proto_idx: 0 (u16), name_idx: 3 (u32) }
    put(&mut out, method_ids_off + 4, 3);

    for b in blocks {
        out.extend_from_slice(&b);
    }
    out
}

#[test]
fn detects_dex_magic() {
    let dex = build_dex();
    assert!(is_dex(&dex));
    assert!(!is_dex(b"PK\x03\x04"));
}

#[test]
fn parses_header_and_string_pool() {
    let d = parse(&build_dex()).unwrap();
    assert_eq!(d.version, "035");
    assert_eq!(d.string_count, 4);
    assert_eq!(d.class_def_count, 2);
    assert_eq!(
        d.strings,
        ["Hello", "Lcom/evil/Main;", "http://c2.example", "doEvil"]
    );
}

#[test]
fn resolves_types_and_methods() {
    let d = parse(&build_dex()).unwrap();
    assert_eq!(d.types, ["Lcom/evil/Main;"]);
    assert_eq!(d.methods, ["Lcom/evil/Main;.doEvil"]);
}

/// Builds a DEX with one class whose one method has a real `code_item`:
///   const/4 v0, #1 ; const-string v0, "http://c2.example" ; return-void
fn build_dex_with_code() -> Vec<u8> {
    let strings = ["Hello", "Lcom/evil/Main;", "http://c2.example", "doEvil"];
    let (n, t, m, c) = (strings.len(), 1usize, 1usize, 1usize);
    let sio = 112;
    let tio = sio + n * 4;
    let mio = tio + t * 4;
    let cio = mio + m * 8;
    let data_off = cio + c * 32;

    // Data section: string blocks, then (4-aligned) the code_item, then the class_data.
    let mut data: Vec<u8> = Vec::new();
    let mut cur = data_off;
    let mut soff = Vec::new();
    for s in strings {
        let b = string_data(s);
        soff.push(cur as u32);
        cur += b.len();
        data.extend(b);
    }
    while cur % 4 != 0 {
        data.push(0);
        cur += 1;
    }
    let code_item_off = cur;
    let mut ci = Vec::new();
    ci.extend(1u16.to_le_bytes()); // registers_size
    ci.extend(0u16.to_le_bytes()); // ins_size
    ci.extend(0u16.to_le_bytes()); // outs_size
    ci.extend(0u16.to_le_bytes()); // tries_size
    ci.extend(0u32.to_le_bytes()); // debug_info_off
    ci.extend(4u32.to_le_bytes()); // insns_size (units)
    for inst in [0x1012u16, 0x001a, 0x0002, 0x000e] {
        ci.extend(inst.to_le_bytes());
    }
    data.extend(&ci);
    cur += ci.len();

    let class_data_off = cur;
    let mut cd = Vec::new();
    for v in [0u32, 0, 1, 0] {
        cd.extend(uleb(v)); // static/instance fields, direct(1)/virtual methods
    }
    cd.extend(uleb(0)); // method_idx_diff (-> method 0)
    cd.extend(uleb(0x9)); // access_flags
    cd.extend(uleb(code_item_off as u32)); // code_off
    data.extend(&cd);

    let file_size = data_off + data.len();
    let mut out = vec![0u8; data_off];
    out[0..8].copy_from_slice(b"dex\n035\0");
    put(&mut out, 32, file_size as u32);
    put(&mut out, 36, 112);
    put(&mut out, 40, 0x1234_5678);
    put(&mut out, 56, n as u32);
    put(&mut out, 60, sio as u32);
    put(&mut out, 64, t as u32);
    put(&mut out, 68, tio as u32);
    put(&mut out, 88, m as u32);
    put(&mut out, 92, mio as u32);
    put(&mut out, 96, c as u32);
    put(&mut out, 100, cio as u32);
    for (i, o) in soff.iter().enumerate() {
        put(&mut out, sio + i * 4, *o);
    }
    put(&mut out, tio, 1); // type[0] -> string[1]
    put(&mut out, mio + 4, 3); // method[0] name_idx -> "doEvil"
    put(&mut out, cio, 0); // class_def class_idx -> type[0]
    put(&mut out, cio + 24, class_data_off as u32);
    out.extend(data);
    out
}

#[test]
fn disassembles_method() {
    let dex = build_dex_with_code();
    let d = parse(&dex).unwrap();

    // The class and its method were recovered from class_defs -> class_data.
    let class = d
        .classes
        .iter()
        .find(|c| c.name == "Lcom/evil/Main;")
        .expect("class");
    let method = class
        .methods
        .iter()
        .find(|m| m.name.ends_with("doEvil"))
        .expect("method");

    let il = d.disassemble_method(&dex, method.code_off).unwrap();
    let got: Vec<(usize, &str)> = il.iter().map(|i| (i.offset, i.mnemonic)).collect();
    assert_eq!(
        got,
        [(0, "const/4"), (1, "const-string"), (3, "return-void")]
    );

    assert_eq!(il[0].operand, "v0, #1");
    // const-string resolves the referenced string from the pool.
    assert_eq!(il[1].operand, "v0, \"http://c2.example\"");
    assert_eq!(il[2].operand, "");
}

#[test]
fn rejects_non_dex() {
    assert!(parse(b"not a dex file at all, padding padding padding").is_err());
}

#[test]
fn hostile_table_counts_are_bounded() {
    // A field count above the cap is rejected outright (it used to be missing from the check).
    let mut dex = build_dex();
    put(&mut dex, 80, 0xFFFF_FFFF);
    assert!(parse(&dex).is_err());

    // Large-but-under-cap counts only walk what the file can actually hold.
    let mut dex = build_dex();
    put(&mut dex, 80, 19_000_000); // field_ids_size
    put(&mut dex, 84, 112); // field_ids_off
    put(&mut dex, 88, 19_000_000); // method_ids_size
    let d = parse(&dex).unwrap();
    assert!(d.fields.len() <= dex.len() / 8);
    assert!(d.methods.len() <= dex.len() / 8);
    assert_eq!(d.field_count, 19_000_000);
}

#[test]
fn class_data_method_index_wraps_instead_of_panicking() {
    let mut cd = Vec::new();
    for v in [0, 0, 2, 0] {
        cd.extend(uleb(v)); // static/instance fields, direct/virtual methods
    }
    for diff in [0xFFFF_FFFF, 5] {
        cd.extend(uleb(diff));
        cd.extend(uleb(1)); // access flags
        cd.extend(uleb(0)); // code_off
    }
    let ms = parse_class_methods(&cd, 0, &[]);
    assert_eq!(ms.len(), 2);
}

fn decode_units(units: &[u16]) -> Vec<DalvikInsn> {
    let d = parse(&build_dex()).unwrap();
    d.decode(units)
}

#[test]
fn payloads_are_skipped_and_decoding_continues() {
    let units = [
        0x0000, // nop
        0x0100, 1, 0, 0, 0, 0, // packed-switch-payload: 1 entry → 6 units
        0x0300, 1, 3, 0, 0x4241, 0x0043, // fill-array-data-payload: 3 x 1 byte → 6 units
        0x0200, 1, 0, 0, 0, 0,      // sparse-switch-payload: 1 entry → 6 units
        0x000e, // return-void
    ];
    let got: Vec<(usize, &str)> = decode_units(&units)
        .iter()
        .map(|i| (i.offset, i.mnemonic))
        .collect();
    assert_eq!(
        got,
        [
            (0, "nop"),
            (1, "packed-switch-payload"),
            (7, "fill-array-data-payload"),
            (13, "sparse-switch-payload"),
            (19, "return-void"),
        ]
    );
    // A payload with an absurd size just ends decoding, without panicking.
    let got = decode_units(&[0x0300, 0xFFFF, 0xFFFF, 0xFFFF, 0x000e]);
    assert_eq!(got.len(), 1);
}

#[test]
fn wide_and_range_operands() {
    // const-wide/high16 v1, #0x4000 << 48
    let il = decode_units(&[0x0119, 0x4000]);
    assert_eq!(il[0].mnemonic, "const-wide/high16");
    assert_eq!(il[0].operand, "v1, #0x4000000000000000");
    // const/high16 keeps its 16-bit shift.
    let il = decode_units(&[0x0115, 0x4000]);
    assert_eq!(il[0].operand, "v1, #0x40000000");

    // invoke-static/range with a first register near u16::MAX must not overflow.
    let il = decode_units(&[0x0377, 0, 0xFFFF]);
    assert_eq!(
        il[0].operand,
        "{v65535, v65536, v65537}, Lcom/evil/Main;.doEvil"
    );

    // invoke-polymorphic {v0, v1}, meth@0, proto@5
    let il = decode_units(&[0x20fa, 0, 0x0010, 5]);
    assert_eq!(il[0].operand, "{v0, v1}, Lcom/evil/Main;.doEvil, proto@5");
    // invoke-polymorphic/range {v7, v8}, meth@0, proto@2
    let il = decode_units(&[0x02fb, 0, 7, 2]);
    assert_eq!(il[0].operand, "{v7, v8}, Lcom/evil/Main;.doEvil, proto@2");
}
