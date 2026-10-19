use std::sync::Arc;

use orress_loaders::{BinaryInfo, Format, Kind, NamedAddress, Perms, Section};

use crate::*;

const BASE: u64 = 0x40_1000;
const DATA: u64 = 0x40_2000;

/// A tiny hand-assembled x86-64 crackme:
///
/// ```text
/// 401000 main:  push rbp
///               mov rbp, rsp
///               lea rdi, [rip -> 402000 "Wrong password"]
///               call check
///               test eax, eax
///               jz fail
///               call [rip -> 402100 (import slot: puts)]
///               xor eax, eax
///               pop rbp
///               ret
///        fail:  mov eax, 1
///               pop rbp
///               ret
///        check: xor eax, eax
///               ret
/// ```
fn crackme() -> (BinaryInfo, Arc<Vec<u8>>) {
    let mut code: Vec<u8> = Vec::new();
    code.push(0x55); // push rbp
    code.extend([0x48, 0x89, 0xe5]); // mov rbp, rsp
    let lea_at = BASE + code.len() as u64;
    let rel = (DATA as i64 - (lea_at as i64 + 7)) as i32;
    code.extend([0x48, 0x8d, 0x3d]);
    code.extend(rel.to_le_bytes()); // lea rdi, [rip+rel]
    let call_at = code.len();
    code.extend([0xe8, 0, 0, 0, 0]); // call check (patched below)
    code.extend([0x85, 0xc0]); // test eax, eax
    let jz_at = code.len();
    code.extend([0x74, 0]); // jz fail (patched below)
    let icall_at = BASE + code.len() as u64;
    let rel = (DATA as i64 + 0x100 - (icall_at as i64 + 6)) as i32;
    code.extend([0xff, 0x15]);
    code.extend(rel.to_le_bytes()); // call [rip+rel]
    code.extend([0x31, 0xc0, 0x5d, 0xc3]); // xor eax,eax; pop rbp; ret
    let fail = code.len();
    code.extend([0xb8, 1, 0, 0, 0, 0x5d, 0xc3]); // mov eax,1; pop rbp; ret
    let check = code.len();
    code.extend([0x31, 0xc0, 0xc3]); // xor eax,eax; ret
    code[jz_at + 1] = (fail - (jz_at + 2)) as u8;
    let rel = (check as i32) - (call_at as i32 + 5);
    code[call_at + 1..call_at + 5].copy_from_slice(&rel.to_le_bytes());
    code.resize(0x100, 0xcc);

    let mut data = vec![0u8; 0x200];
    data[..15].copy_from_slice(b"Wrong password\0");

    let mut file = vec![0u8; 0x200]; // headers
    file.extend(&code); // offset 0x200 -> 0x401000
    file.extend(&data); // offset 0x300 -> 0x402000

    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "x86-64".into(),
        bits: Some(64),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![
            Section {
                name: ".text".into(),
                offset: 0x200,
                file_size: 0x100,
                address: BASE,
                virtual_size: 0x100,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                entropy: None,
            },
            Section {
                name: ".rodata".into(),
                offset: 0x300,
                file_size: 0x200,
                address: DATA,
                virtual_size: 0x200,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: false,
                },
                entropy: None,
            },
        ],
        import_slots: vec![NamedAddress {
            address: DATA + 0x100,
            name: "puts".into(),
        }],
        function_symbols: vec![NamedAddress {
            address: BASE,
            name: "main".into(),
        }],
        ..BinaryInfo::default()
    };
    (info, Arc::new(file))
}

fn analyzed() -> Program {
    let (info, data) = crackme();
    let strings = orress_bytes::strings::extract(&data, 4, 1000);
    Program::analyze(&info, data, &strings).expect("x86-64 is supported")
}

#[test]
fn finds_functions_and_blocks() {
    let p = analyzed();
    assert_eq!(p.functions.len(), 2, "main and check");
    let main = &p.functions[&BASE];
    assert_eq!(main.blocks.len(), 3, "entry, success path, fail path");
    let entry = main.block_at(BASE).unwrap();
    let kinds: Vec<EdgeKind> = entry.succs.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EdgeKind::Taken, EdgeKind::NotTaken]);
    assert_eq!(main.calls.len(), 1);
    let check = main.calls[0];
    assert_eq!(p.name(check).unwrap().text, format!("sub_{check:x}"));
    assert_eq!(p.main, Some(BASE));
    assert_eq!(p.name(BASE).unwrap().text, "main");
}

#[test]
fn cross_references() {
    let p = analyzed();
    // The string is referenced by the lea, and shows up as a string comment.
    let refs = p.xrefs(DATA);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].kind, XrefKind::Data);
    assert_eq!(p.string_refs[&DATA], "Wrong password");
    // The import slot is called.
    let slot_refs = p.xrefs(DATA + 0x100);
    assert_eq!(slot_refs.len(), 1);
    assert_eq!(slot_refs[0].kind, XrefKind::Call);
    assert_eq!(p.name(DATA + 0x100).unwrap().text, "puts");
    // check() is called once.
    let check = p.functions[&BASE].calls[0];
    assert_eq!(p.xrefs(check)[0].kind, XrefKind::Call);
}

#[test]
fn listing_covers_code_and_padding() {
    let p = analyzed();
    assert_eq!(p.lines[0].kind, LineKind::Region);
    assert_eq!(
        p.lines[1],
        Line {
            addr: BASE,
            kind: LineKind::Function
        }
    );
    assert_eq!(
        p.lines[2],
        Line {
            addr: BASE,
            kind: LineKind::Insn
        }
    );
    assert!(p.lines.iter().any(|l| l.kind == LineKind::Label));
    assert!(
        matches!(p.lines.last().unwrap().kind, LineKind::Data(_)),
        "int3 padding is data"
    );
    // Lookup lands on the instruction line, not the header.
    let i = p.line_index(BASE).unwrap();
    assert_eq!(p.lines[i].kind, LineKind::Insn);
    // Lines are sorted and cover the region without gaps.
    assert!(p.lines.windows(2).all(|w| w[0].addr <= w[1].addr));
    assert_eq!(
        p.insn_start(BASE + 2),
        Some(BASE + 1),
        "inside mov rbp, rsp"
    );
}

#[test]
fn listing_shows_data_section_strings() {
    let p = analyzed();
    // The non-executable `.rodata` region is now part of the linear listing.
    assert!(
        p.lines
            .iter()
            .any(|l| l.addr == DATA && l.kind == LineKind::Region),
        "data region header present"
    );
    // "Wrong password\0" (15 bytes incl. NUL) shows as one string line at DATA.
    let str_line = p
        .lines
        .iter()
        .find(|l| l.addr == DATA && matches!(l.kind, LineKind::Str(_)));
    assert_eq!(str_line.map(|l| l.kind), Some(LineKind::Str(15)));
    // The rest of the data region renders as bounded `db` runs, not one giant line.
    assert!(
        p.lines
            .iter()
            .any(|l| l.addr > DATA && matches!(l.kind, LineKind::Data(_))),
        "trailing data shown as db"
    );
}

#[test]
fn unsupported_arch_is_none() {
    let (mut info, data) = crackme();
    info.arch = "PowerPC (32-bit)".into();
    assert!(Program::analyze(&info, data, &[]).is_none());
}

/// The test binary itself is a large real program.
#[test]
fn analyzes_host_executable() {
    let data = Arc::new(std::fs::read(std::env::current_exe().unwrap()).unwrap());
    let info = orress_loaders::triage(&data);
    let start = std::time::Instant::now();
    let p = Program::analyze(&info, Arc::clone(&data), &[]).expect("host arch supported");
    assert!(
        p.functions.len() > 200,
        "found {} functions",
        p.functions.len()
    );
    assert!(p.functions.contains_key(&info.entry.unwrap()));
    assert!(!p.lines.is_empty());
    // Import slots are called from code.
    let called_imports = info
        .import_slots
        .iter()
        .filter(|s| !p.xrefs(s.address).is_empty())
        .count();
    assert!(called_imports > 5, "{called_imports} imports have xrefs");
    eprintln!(
        "analyzed {} functions, {} instructions in {:?}",
        p.functions.len(),
        p.insns.len(),
        start.elapsed()
    );
}

#[test]
fn calls_clobber_caller_saved_registers() {
    let p = analyzed();
    let main = &p.functions[&BASE];
    // `lea rdi, [rip->DATA]` is rdi's only explicit definition, but `call check` follows and may
    // overwrite rdi, so it is not a function-wide constant.
    assert_eq!(p.register_const(main, 7), None);
    // The use right after the lea (the call itself) is in the same block as the call, so the
    // call's clobber reaches it too: still not provably constant at any point after the call.
    let after_call = main.blocks[0].insns[4]; // test eax, eax
    assert_eq!(p.register_const_at(main, after_call, 7), None);
}

/// An x86-64 or ARM64 program with one executable section of `code` at `addr`.
fn tiny(arch: &str, addr: u64, code: &[u8], symbols: &[(u64, &str)]) -> Program {
    let mut file = vec![0u8; 0x200];
    file.extend(code);
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: arch.into(),
        bits: Some(64),
        entry: Some(addr),
        image_base: 0x40_0000,
        sections: vec![Section {
            name: ".text".into(),
            offset: 0x200,
            file_size: code.len() as u64,
            address: addr,
            virtual_size: code.len() as u64,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            entropy: None,
        }],
        function_symbols: symbols
            .iter()
            .map(|&(address, name)| NamedAddress {
                address,
                name: name.into(),
            })
            .collect(),
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("supported arch")
}

#[test]
fn syscall_does_not_end_the_function() {
    // mov eax, 60; syscall; mov eax, 1; ret
    let code = [0xb8, 60, 0, 0, 0, 0x0f, 0x05, 0xb8, 1, 0, 0, 0, 0xc3];
    let p = tiny("x86-64", BASE, &code, &[(BASE, "f")]);
    assert_eq!(p.functions[&BASE].insn_count(), 4);
}

#[test]
fn arm64_main_from_adrp_add_with_unmapped_page() {
    // .text starts mid-page at 0x401800, so `adrp x0`'s page base 0x401000 is not mapped.
    const TEXT: u64 = 0x40_1800;
    let words: [u32; 20] = [
        0x9000_0000, // adrp x0, 0x401000
        0x9121_0000, // add x0, x0, #0x840
        0x9400_0006, // bl __libc_start_main (0x401820)
        0xd65f_03c0, // ret
        0,
        0,
        0,
        0,
        0xd65f_03c0, // 0x401820: __libc_start_main: ret
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xd280_0000, // 0x401840: main: mov x0, #0
        0xd65f_03c0, // ret
        0,
        0,
    ];
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let p = tiny(
        "ARM64 (AArch64)",
        TEXT,
        &code,
        &[(0x40_1820, "__libc_start_main")],
    );
    assert_eq!(p.main, Some(0x40_1840));
}

#[test]
fn arm64_main_from_literal_pool() {
    const TEXT: u64 = 0x40_1000;
    let mut words = [0u32; 32];
    words[0] = 0x5800_0300; // ldr x0, 0x401060 (literal)
    words[1] = 0x9400_0007; // bl __libc_start_main (0x401020)
    words[2] = 0xd65f_03c0; // ret
    words[8] = 0xd65f_03c0; // 0x401020: __libc_start_main
    words[16] = 0xd280_0000; // 0x401040: main
    words[17] = 0xd65f_03c0;
    words[24] = 0x0040_1040; // 0x401060: literal = main
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let p = tiny(
        "ARM64 (AArch64)",
        TEXT,
        &code,
        &[(0x40_1020, "__libc_start_main")],
    );
    assert_eq!(p.main, Some(0x40_1040));
}

#[test]
fn region_length_honours_virtual_size() {
    let (mut info, data) = crackme();
    // PE-style: raw data padded past the virtual size; only the virtual part is mapped.
    info.sections[1].virtual_size = 0x20;
    let m = Memory::new(&info, Arc::clone(&data));
    assert!(m.contains(DATA + 0x1f) && !m.contains(DATA + 0x20));
    // Zero virtual size: the file size stands.
    info.sections[1].virtual_size = 0;
    assert!(Memory::new(&info, Arc::clone(&data)).contains(DATA + 0x1ff));
    // A section whose address range wraps the address space is rejected.
    info.sections[1].address = u64::MAX - 0x10;
    assert!(!Memory::new(&info, data).contains(u64::MAX - 0x8));
}

/// The Academy's Rust crackmes: real-world Rust start-up code and string layout.
#[test]
fn rust_crackmes() {
    for (bytes, check_fn_cmp) in [
        (
            &include_bytes!("../../../academy/crackmes/bin/crackme01.exe")[..],
            None,
        ),
        (
            &include_bytes!("../../../academy/crackmes/bin/crackme02.exe")[..],
            Some(0x52u64),
        ),
    ] {
        let data = Arc::new(bytes.to_vec());
        let info = orress_loaders::triage(&data);
        let strings = orress_bytes::strings::extract(&data, 4, 100_000);
        let p = Program::analyze(&info, Arc::clone(&data), &strings).unwrap();
        let main = p.main.expect("main found");
        assert_eq!(p.name(main).unwrap().text, "main");
        assert!(
            p.names.values().any(|n| n.text == "rust_runtime_main"),
            "the C-level shim is named"
        );
        // main references "Wrong password", which sits in the middle of merged strings.
        let f = &p.functions[&main];
        let texts: Vec<&String> = f
            .blocks
            .iter()
            .flat_map(|b| &b.insns)
            .filter_map(|&a| p.decode(a))
            .flat_map(|i| i.data_refs)
            .filter_map(|r| p.string_refs.get(&r))
            .collect();
        assert!(
            texts.iter().any(|t| t.starts_with("Wrong password")),
            "{texts:?}"
        );
        // crackme02: the check function compares the first byte with 'R' (0x52).
        if let Some(byte) = check_fn_cmp {
            let found = p.insns.keys().any(|&a| {
                p.decode(a).is_some_and(|i| {
                    i.mnemonic == "cmp"
                        && i.operands.iter().any(|t| t.text == format!("0x{byte:x}"))
                })
            });
            assert!(found, "cmp with 'R' present");
        }
    }
}
