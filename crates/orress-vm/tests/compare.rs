//! The compare-hook key recovery: a hand-built keygen whose serial is *computed* from the input
//! (`serial[i] = name[i] ^ 0x10`) and then `strcmp`'d — the shape per-byte symbolic branching
//! misses cheaply. Seeding a known name and reading back the compared value recovers the serial.

use std::sync::Arc;

use iced_x86::code_asm::*;
use orress_analysis::Program;
use orress_emu::Abi;
use orress_loaders::{BinaryInfo, Format, Kind, NamedAddress, Perms, Section};

const BASE: u64 = 0x40_1000;
const DATA: u64 = 0x40_2000;
const BUF: u64 = DATA + 0x10; // gets() writes the seeded name here
const SCRATCH: u64 = DATA + 0x40; // the computed expected serial (zeroed .data, so NUL-terminated)
const GETS_SLOT: u64 = DATA + 0x100;
const STRCMP_SLOT: u64 = DATA + 0x108;

/// `check() { gets(buf); for i in 0..4 { serial[i] = buf[i] ^ 0x10 } return strcmp(buf, serial)==0 }`
/// — a keygen: the accepting serial is derived from the entered name, never stored in the binary.
fn keygen() -> Program {
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, BUF).unwrap(); // gets(buf)
    a.call(qword_ptr(GETS_SLOT)).unwrap();
    for i in 0..4u64 {
        a.mov(al, byte_ptr(BUF + i)).unwrap();
        a.xor(al, 0x10).unwrap();
        a.mov(byte_ptr(SCRATCH + i), al).unwrap();
    }
    a.mov(rdi, BUF).unwrap(); // strcmp(buf, serial)
    a.mov(rsi, SCRATCH).unwrap();
    a.call(qword_ptr(STRCMP_SLOT)).unwrap();
    a.test(eax, eax).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    let mut code = a.assemble(BASE).unwrap();
    code.resize(0x100, 0xcc);

    let data = vec![0u8; 0x200]; // buf/scratch/slots all start zeroed
    let mut file = vec![0u8; 0x200]; // headers
    file.extend(&code); // 0x200 -> BASE
    file.extend(&data); // 0x300 -> DATA

    let section = |name: &str, offset, size, address, execute: bool| Section {
        name: name.into(),
        offset,
        file_size: size,
        address,
        virtual_size: size,
        perms: Perms { read: true, write: !execute, execute },
        entropy: None,
    };
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "x86-64".into(),
        bits: Some(64),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![
            section(".text", 0x200, 0x100, BASE, true),
            section(".data", 0x300, 0x200, DATA, false),
        ],
        import_slots: vec![
            NamedAddress { address: GETS_SLOT, name: "gets".into() },
            NamedAddress { address: STRCMP_SLOT, name: "strcmp".into() },
        ],
        function_symbols: vec![NamedAddress { address: BASE, name: "check".into() }],
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("supported architecture")
}

/// `check() { gets(buf); for i in 0..5 { if buf[i] != KEY[i] return 0 } return 1 }` — an INLINE
/// per-byte comparison loop against a hardcoded key, with NO strcmp/memcmp call (the shape of
/// statically-linked crackmes like EasyCrackMe). The key is recovered by taint-tracking the input
/// byte into a register and reading what each `cmp` checks it against.
fn inline_keycheck() -> Program {
    const KEY: u64 = DATA + 0x60; // "WXYZ!" lives here
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, BUF).unwrap();
    a.call(qword_ptr(GETS_SLOT)).unwrap();
    a.mov(rsi, BUF).unwrap(); // input base
    a.mov(rdi, KEY).unwrap(); // key base
    a.xor(rax, rax).unwrap();
    let mut loop_lbl = a.create_label();
    let mut fail = a.create_label();
    a.set_label(&mut loop_lbl).unwrap();
    a.movzx(ecx, byte_ptr(rsi + rax)).unwrap(); // cl = input[i]
    a.cmp(cl, byte_ptr(rdi + rax)).unwrap(); // vs key[i]
    a.jne(fail).unwrap();
    a.inc(rax).unwrap();
    a.cmp(rax, 5i32).unwrap();
    a.jne(loop_lbl).unwrap();
    a.mov(eax, 1u32).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    let mut code = a.assemble(BASE).unwrap();
    code.resize(0x100, 0xcc);

    let mut data = vec![0u8; 0x200];
    data[0x60..0x65].copy_from_slice(b"WXYZ!"); // KEY at DATA+0x60
    let mut file = vec![0u8; 0x200];
    file.extend(&code);
    file.extend(&data);

    let section = |name: &str, offset, size, address, execute: bool| Section {
        name: name.into(),
        offset,
        file_size: size,
        address,
        virtual_size: size,
        perms: Perms { read: true, write: !execute, execute },
        entropy: None,
    };
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "x86-64".into(),
        bits: Some(64),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![
            section(".text", 0x200, 0x100, BASE, true),
            section(".data", 0x300, 0x200, DATA, false),
        ],
        import_slots: vec![NamedAddress { address: GETS_SLOT, name: "gets".into() }],
        function_symbols: vec![NamedAddress { address: BASE, name: "check".into() }],
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("supported architecture")
}

#[test]
fn compare_hook_recovers_an_inline_byte_loop_key() {
    let p = inline_keycheck();
    let recoveries = orress_vm::recover_by_compare(&p, BASE, Abi::SysV);
    assert!(!recoveries.is_empty(), "no inline comparison observed");
    assert!(
        recoveries.iter().any(|r| r.keys.iter().any(|k| k == b"WXYZ!")),
        "expected inline key WXYZ! among {:?}",
        recoveries
            .iter()
            .flat_map(|r| &r.keys)
            .map(|k| String::from_utf8_lossy(k).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn compare_hook_recovers_a_computed_serial() {
    let p = keygen();
    let recoveries = orress_vm::recover_by_compare(&p, BASE, Abi::SysV);
    assert!(!recoveries.is_empty(), "the compare-hook saw no comparison");

    // Every seed is all 'A' (0x41); the serial the binary compares against is 'A' ^ 0x10 = 'Q'.
    for rec in &recoveries {
        assert!(
            rec.keys.iter().any(|k| k == b"QQQQ"),
            "expected the computed serial QQQQ among {:?} (seed {:?})",
            rec.keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect::<Vec<_>>(),
            String::from_utf8_lossy(&rec.seed),
        );
        // The seed itself is never offered as the key.
        assert!(!rec.keys.iter().any(|k| k == &rec.seed));
    }
}
