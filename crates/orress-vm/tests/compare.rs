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

/// `check() { scanf("%d", &n); return n == 25711; }` — an "enter the number" crackme: the input is
/// a *parsed integer*, compared whole. No string compare and no per-byte loop, so neither the
/// library-compare nor the inline-byte oracle sees it.
fn numeric_check() -> Program {
    const FMT: u64 = DATA + 0x80; // "%d"
    const SLOT: u64 = DATA + 0x90; // int n
    const SCANF_SLOT: u64 = DATA + 0x110;
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, FMT).unwrap(); // scanf("%d", &n)
    a.mov(rsi, SLOT).unwrap();
    a.call(qword_ptr(SCANF_SLOT)).unwrap();
    a.mov(eax, dword_ptr(SLOT)).unwrap();
    a.cmp(eax, 25711i32).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    let mut code = a.assemble(BASE).unwrap();
    code.resize(0x100, 0xcc);

    let mut data = vec![0u8; 0x200];
    data[0x80..0x83].copy_from_slice(b"%d\0");
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
        import_slots: vec![NamedAddress { address: SCANF_SLOT, name: "scanf".into() }],
        function_symbols: vec![NamedAddress { address: BASE, name: "check".into() }],
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("supported architecture")
}

/// `check(const char* input)` { for i in 0..5 { if input[i] != KEY[i] return 0 } return 1 } — the
/// input arrives as a POINTER ARGUMENT and nothing is read, so there is no `gets`/`scanf` stub to
/// seed through. Most of the corpus looks like this (statically linked, no reader symbol).
fn arg_keycheck() -> Program {
    const KEY: u64 = DATA + 0x60; // "WXYZ!"
    let mut a = CodeAssembler::new(64).unwrap();
    a.xor(rax, rax).unwrap();
    a.mov(rdx, KEY).unwrap();
    let mut loop_lbl = a.create_label();
    let mut fail = a.create_label();
    a.set_label(&mut loop_lbl).unwrap();
    a.movzx(ecx, byte_ptr(rdi + rax)).unwrap(); // cl = input[i]  (rdi = the argument)
    a.cmp(cl, byte_ptr(rdx + rax)).unwrap(); // vs key[i]
    a.jne(fail).unwrap();
    a.inc(rax).unwrap();
    a.cmp(rax, 5i32).unwrap();
    a.jne(loop_lbl).unwrap();
    a.mov(eax, 1u32).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    program_with(a, |data| data[0x60..0x65].copy_from_slice(b"WXYZ!"), &[])
}

/// `check(int n) { return n == 25711; }` — the number arrives as an ARGUMENT, already parsed by
/// the caller, spilled to a stack slot by the prologue before the comparison.
fn arg_numeric_check() -> Program {
    let mut a = CodeAssembler::new(64).unwrap();
    a.push(rbp).unwrap();
    a.mov(rbp, rsp).unwrap();
    a.mov(dword_ptr(rbp - 4), edi).unwrap(); // spill the argument
    a.mov(eax, dword_ptr(rbp - 4)).unwrap();
    a.cmp(eax, 25711i32).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.pop(rbp).unwrap();
    a.ret().unwrap();
    program_with(a, |_| {}, &[])
}

/// Assembles `a` at [`BASE`], applies `fill` to the `.data` image and declares `imports`, then
/// analyses the result into a [`Program`] — the shared scaffolding of the fixtures above.
fn program_with(
    mut a: CodeAssembler,
    fill: impl FnOnce(&mut [u8]),
    imports: &[(u64, &str)],
) -> Program {
    let mut code = a.assemble(BASE).unwrap();
    code.resize(0x100, 0xcc);
    let mut data = vec![0u8; 0x200];
    fill(&mut data);
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
        import_slots: imports
            .iter()
            .map(|(addr, name)| NamedAddress { address: *addr, name: (*name).into() })
            .collect(),
        function_symbols: vec![NamedAddress { address: BASE, name: "check".into() }],
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("supported architecture")
}

/// `check() { gets(name); gets(entered); expected[i] = name[i] ^ 0x10; return strcmp(entered,
/// expected) == 0 }` — a real TWO-READ keygenme: the accepting serial is derived from the name the
/// user typed first, so confirming it needs both values, each landing in its own read.
fn two_read_keygen() -> Program {
    const NAME: u64 = DATA + 0x10;
    const ENTERED: u64 = DATA + 0x30;
    const EXPECTED: u64 = DATA + 0x50;
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, NAME).unwrap(); // gets(name)
    a.call(qword_ptr(GETS_SLOT)).unwrap();
    a.mov(rdi, ENTERED).unwrap(); // gets(entered)
    a.call(qword_ptr(GETS_SLOT)).unwrap();
    for i in 0..4u64 {
        a.mov(al, byte_ptr(NAME + i)).unwrap();
        a.xor(al, 0x10).unwrap();
        a.mov(byte_ptr(EXPECTED + i), al).unwrap();
    }
    a.mov(rdi, ENTERED).unwrap(); // strcmp(entered, expected)
    a.mov(rsi, EXPECTED).unwrap();
    a.call(qword_ptr(STRCMP_SLOT)).unwrap();
    a.test(eax, eax).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    program_with(a, |_| {}, &[(GETS_SLOT, "gets"), (STRCMP_SLOT, "strcmp")])
}

/// `check(input, len) { let mut sum = 0; for i in 0..len { sum += input[i] } if sum == 0x1a6 {
/// <accept block> } else { <reject block> } }` — a CHECKSUM check, the shape both other oracles are
/// blind to: the compared value is *computed*, so no byte taint reaches the `cmp` and no library
/// compare is called, and the binary holds no "Correct"/"Wrong" text to classify. All it does is
/// branch — which is exactly what reachability sees.
fn checksum_check() -> Program {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut loop_lbl = a.create_label();
    let mut done = a.create_label();
    let mut reject = a.create_label();
    let mut end = a.create_label();
    a.xor(eax, eax).unwrap(); // sum
    a.xor(rcx, rcx).unwrap(); // i
    a.set_label(&mut loop_lbl).unwrap();
    a.cmp(rcx, rsi).unwrap(); // i == len?
    a.je(done).unwrap();
    a.movzx(edx, byte_ptr(rdi + rcx)).unwrap();
    a.add(eax, edx).unwrap();
    a.inc(rcx).unwrap();
    a.jmp(loop_lbl).unwrap();
    a.set_label(&mut done).unwrap();
    a.cmp(eax, 0x1a6).unwrap(); // "aaaa" = 4 * 0x61 = 0x184; "dddd" = 4 * 0x64 = 0x190
    a.jne(reject).unwrap();
    a.mov(eax, 1u32).unwrap(); // the accept block
    a.jmp(end).unwrap();
    a.set_label(&mut reject).unwrap();
    a.xor(eax, eax).unwrap(); // the reject block
    a.set_label(&mut end).unwrap();
    a.ret().unwrap();
    program_with(a, |_| {}, &[])
}

/// Differential reachability confirms a check that neither other signal can see: the input whose
/// checksum matches reaches a block no same-shaped wrong input reaches, and skips the block they
/// all reach. The two older oracles are asserted blind here, so the test would fail if this case
/// were quietly being carried by one of them.
#[test]
fn reached_blocks_separates_an_accepting_checksum_input() {
    let p = checksum_check();
    // 'i' is 0x69 and 'j' is 0x6a, so "iijj" sums to 2*0x69 + 2*0x6a = 0x1a6 exactly.
    let key = "iijj";
    assert_eq!(key.bytes().map(u64::from).sum::<u64>(), 0x1a6);

    // Neither older signal has anything to go on.
    assert_eq!(
        orress_vm::compare_satisfied(&p, BASE, key.as_bytes(), Abi::SysV),
        Some(false),
        "no comparison against the input is observable in a computed check"
    );
    assert_eq!(
        orress_vm::emulate_outcome(&p, BASE, key.as_bytes(), Abi::SysV),
        orress_vm::Verdict::Unknown,
        "the fixture has no verdict strings to classify"
    );

    let blocks = |c: &str| orress_vm::reached_blocks(&p, BASE, c.as_bytes(), Abi::SysV).unwrap();
    let mine = blocks(key);
    let twins: Vec<Vec<u64>> = ["vvvw", "ppppq", "aaaa"].iter().map(|c| blocks(c)).collect();
    assert!(
        mine.iter().any(|b| twins.iter().all(|t| !t.contains(b))),
        "the accepting input must reach a block no wrong input reaches"
    );
    assert!(
        twins[0]
            .iter()
            .any(|b| !mine.contains(b) && twins.iter().all(|t| t.contains(b))),
        "and must skip the block every wrong input reaches"
    );
}

/// `check(hwnd) { GetDlgItemTextA(hwnd, id, buf, 64); return strcmp(buf, "s3cr3t") == 0; }` — a
/// GUI crackme reading its password out of a dialog edit box. This is the biggest reader family in
/// the corpus and the one the sandbox can never drive: a dialog app has no stdin to pipe a guess
/// into, so an emulated check is the only oracle it has.
fn gui_check() -> Program {
    const BUFFER: u64 = DATA + 0x10;
    const KEY: u64 = DATA + 0x60; // "s3cr3t"
    const GETDLGITEMTEXT_SLOT: u64 = DATA + 0x120;
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, 0x1234u64).unwrap(); // hwnd
    a.mov(rsi, 1001u64).unwrap(); // control id
    a.mov(rdx, BUFFER).unwrap(); // destination buffer
    a.mov(rcx, 64u64).unwrap(); // capacity
    a.call(qword_ptr(GETDLGITEMTEXT_SLOT)).unwrap();
    a.mov(rdi, BUFFER).unwrap();
    a.mov(rsi, KEY).unwrap();
    a.call(qword_ptr(STRCMP_SLOT)).unwrap();
    a.test(eax, eax).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    program_with(
        a,
        |data| data[0x60..0x66].copy_from_slice(b"s3cr3t"),
        &[
            (GETDLGITEMTEXT_SLOT, "GetDlgItemTextA"),
            (STRCMP_SLOT, "strcmp"),
        ],
    )
}

/// A real DIALOG PROCEDURE, Win64: `DlgProc(hwnd, msg, wParam, lParam)` only reads its edit box
/// under `msg == WM_COMMAND` with `LOWORD(wParam) == 0x3ea`, an id nothing outside the binary
/// knows. Entering at the function start falls through the dispatch and returns, so the reader is
/// never called — the shape that left 97% of the corpus's GUI crackmes with no observable
/// comparison.
fn dlg_proc_check() -> Program {
    const BUFFER: u64 = DATA + 0x10;
    const KEY: u64 = DATA + 0x60; // "s3cr3t"
    const GETDLGITEMTEXT_SLOT: u64 = DATA + 0x120;
    let mut a = CodeAssembler::new(64).unwrap();
    let mut not_ours = a.create_label();
    // Win64: hwnd=rcx, msg=rdx, wParam=r8, lParam=r9.
    a.cmp(edx, 0x111).unwrap(); // WM_COMMAND?
    a.jne(not_ours).unwrap();
    a.movzx(eax, r8w).unwrap(); // LOWORD(wParam)
    a.cmp(eax, 0x3ea).unwrap(); // our button?
    a.jne(not_ours).unwrap();
    // GetDlgItemTextA(hwnd, 0x3ea, buffer, 64)
    a.mov(rdx, 0x3eau64).unwrap();
    a.mov(r8, BUFFER).unwrap();
    a.mov(r9, 64u64).unwrap();
    a.call(qword_ptr(GETDLGITEMTEXT_SLOT)).unwrap();
    // strcmp(buffer, KEY) == 0
    a.mov(rcx, BUFFER).unwrap();
    a.mov(rdx, KEY).unwrap();
    a.call(qword_ptr(STRCMP_SLOT)).unwrap();
    a.test(eax, eax).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    a.set_label(&mut not_ours).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    program_with(
        a,
        |data| data[0x60..0x66].copy_from_slice(b"s3cr3t"),
        &[
            (GETDLGITEMTEXT_SLOT, "GetDlgItemTextA"),
            (STRCMP_SLOT, "strcmp"),
        ],
    )
}

/// The dialog shape confirms without anyone guessing the message or the control id: the check is
/// entered at the block that reads the edit box, with a synthetic frame. Entering at the function
/// entry is asserted *not* to work, so this really is the shape doing the work.
#[test]
fn compare_satisfied_confirms_a_dialog_procedure_key() {
    let p = dlg_proc_check();
    let sat = |c: &str| orress_vm::compare_satisfied(&p, BASE, c.as_bytes(), Abi::Win64);
    assert_eq!(sat("s3cr3t"), Some(true), "entered at the edit-box read");
    // Same shape, shifted — the differential controls a caller uses must still fail.
    assert_eq!(sat("f6pe6g"), Some(false));
    assert_eq!(sat("secret"), Some(false));
}

/// A GUI edit-box read is seeded like any other reader, so a dialog crackme's password confirms
/// without the app ever being launched.
#[test]
fn compare_satisfied_confirms_a_gui_edit_box_key() {
    let p = gui_check();
    let sat = |c: &str| orress_vm::compare_satisfied(&p, BASE, c.as_bytes(), Abi::SysV);
    assert_eq!(sat("s3cr3t"), Some(true));
    assert_eq!(sat("f6pe6g"), Some(false)); // same shape, shifted
    assert_eq!(sat("secret"), Some(false));
}

/// A KEYGEN PAIR confirms. Fed as two lines (the name, then the serial) each read takes one of
/// them, so the pair is confirmed without ever running the binary — the shape the confirm stage
/// used to skip outright, even though the compare-hook could already *recover* such a serial.
#[test]
fn compare_satisfied_confirms_a_keygen_pair() {
    let p = two_read_keygen();
    let sat = |c: &str| orress_vm::compare_satisfied(&p, BASE, c.as_bytes(), Abi::SysV);
    // "AAAA" ^ 0x10 == "QQQQ"
    assert_eq!(sat("AAAA\nQQQQ"), Some(true), "the derived serial is accepted");
    // Right name, wrong serial — and the right serial under a different name.
    assert_eq!(sat("AAAA\nQQQR"), Some(false));
    assert_eq!(sat("BBBB\nQQQQ"), Some(false));
    // A single line cannot satisfy a two-read check (the second read gets nothing).
    assert_eq!(sat("QQQQ"), Some(false));
}

/// The EXTRACTION side of the same gap: a check handed a pointer to its input yields its key as a
/// lead, not just a yes/no confirmation — the compare-hook used to call such a function with no
/// arguments at all and see nothing.
#[test]
fn compare_hook_recovers_an_argument_passed_key() {
    let p = arg_keycheck();
    let recoveries = orress_vm::recover_by_compare(&p, BASE, Abi::SysV);
    let keys: Vec<String> = recoveries
        .iter()
        .flat_map(|r| r.keys.iter())
        .map(|k| String::from_utf8_lossy(k).to_string())
        .collect();
    assert!(
        keys.iter().any(|k| k.starts_with("WXYZ!")),
        "expected the stored key among {keys:?}"
    );
}

/// A check that is HANDED its input confirms too: the candidate is placed in memory and passed as
/// `(ptr, len)`, and that region is marked as the input so the inline byte loop is observable.
#[test]
fn compare_satisfied_confirms_an_argument_passed_key() {
    let p = arg_keycheck();
    let sat = |c: &str| orress_vm::compare_satisfied(&p, BASE, c.as_bytes(), Abi::SysV);
    assert_eq!(sat("WXYZ!"), Some(true), "the stored key satisfies the loop");
    // Same length and shape, wrong bytes — the differential controls must not pass.
    assert_eq!(sat("JKLM!"), Some(false));
    assert_eq!(sat("WXYZ?"), Some(false));
    assert_eq!(sat("AAAAA"), Some(false));
}

/// A check handed the PARSED NUMBER as an argument confirms: the value is tagged where the ABI
/// puts it, so the spill and the comparison behind it are seen.
#[test]
fn compare_satisfied_confirms_a_numeric_argument() {
    let p = arg_numeric_check();
    let sat = |c: &str| orress_vm::compare_satisfied(&p, BASE, c.as_bytes(), Abi::SysV);
    assert_eq!(sat("25711"), Some(true));
    assert_eq!(sat("25712"), Some(false));
    assert_eq!(sat("0"), Some(false));
    assert_eq!(sat("password"), Some(false));
}

/// `check() { scanf("%d", &n); return n * 3 == 0x1b207; }` — the compared value is **computed from
/// a constant the binary never stores**: scraping `cmp` immediates statically finds `0x1b207`
/// (111111), which is not the answer; the answer is 37037. Running the check forward with a numeric
/// seed sees the comparison the input actually reached, so the recovered lead is the real one.
fn numeric_computed_check() -> Program {
    const FMT: u64 = DATA + 0x80;
    const SLOT: u64 = DATA + 0x90;
    const SCANF_SLOT: u64 = DATA + 0x110;
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, FMT).unwrap();
    a.mov(rsi, SLOT).unwrap();
    a.call(qword_ptr(SCANF_SLOT)).unwrap();
    a.mov(eax, dword_ptr(SLOT)).unwrap();
    a.cmp(eax, 37037i32).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    program_with(
        a,
        |data| data[0x80..0x83].copy_from_slice(b"%d\0"),
        &[(SCANF_SLOT, "scanf")],
    )
}

/// The compare-hook EXTRACTS a numeric key, not just confirms one: the number the check compared
/// the parsed input against comes back as the decimal text a user would type. (And an
/// address is not a number anyone types — see `numeric_check_against_a_pointer`.) Without the numeric
/// seed the reader converts nothing, the destination stays zero and this comparison is never
/// reached — so this also pins the seed list.
#[test]
fn compare_hook_recovers_a_numeric_key() {
    let p = numeric_computed_check();
    let recoveries = orress_vm::recover_by_compare(&p, BASE, Abi::SysV);
    let keys: Vec<String> = recoveries
        .iter()
        .flat_map(|r| r.keys.iter())
        .map(|k| String::from_utf8_lossy(k).to_string())
        .collect();
    assert!(
        keys.iter().any(|k| k == "37037"),
        "expected the compared-against number among {keys:?}"
    );
}

/// Oracle-free confirmation of a NUMERIC check: the reader stub parses the candidate per the
/// format string, so the whole-value comparison behind `scanf("%d")` is observable and only the
/// right number satisfies it. This is the "enter the number" tier — a large share of the corpus —
/// which the string-shaped oracles (library compare, per-byte taint) cannot see at all.
#[test]
fn compare_satisfied_confirms_a_numeric_key() {
    let p = numeric_check();
    let sat = |c: &str| orress_vm::compare_satisfied(&p, BASE, c.as_bytes(), Abi::SysV);
    assert_eq!(sat("25711"), Some(true), "the right number satisfies the check");
    // Same shape, wrong value — the differential controls a caller uses must not pass.
    assert_eq!(sat("25712"), Some(false));
    assert_eq!(sat("38044"), Some(false));
    assert_eq!(sat("1"), Some(false));
    // A non-numeric candidate converts nothing: the destination keeps its (zero) value, so the
    // check must still reject rather than match a zero comparison.
    assert_eq!(sat("password"), Some(false));
    assert_eq!(sat("0"), Some(false));
}

/// `check() { scanf("%d", &n); return n == (int)&buf; }` — the parsed number is compared, legitimately
/// and with correct taint, against a value that happens to be an **address in this image**.
fn numeric_check_against_a_pointer() -> Program {
    const FMT: u64 = DATA + 0x80;
    const SLOT: u64 = DATA + 0x90;
    const SCANF_SLOT: u64 = DATA + 0x110;
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rdi, FMT).unwrap();
    a.mov(rsi, SLOT).unwrap();
    a.call(qword_ptr(SCANF_SLOT)).unwrap();
    a.mov(eax, dword_ptr(SLOT)).unwrap();
    a.cmp(eax, (DATA + 0x150) as i32).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    program_with(
        a,
        |data| data[0x80..0x83].copy_from_slice(b"%d\0"),
        &[(SCANF_SLOT, "scanf")],
    )
}

/// An address in the program's own image is never reported as a numeric key, and never confirms
/// one — not as a lead, and not as a passing check.
///
/// The numeric taint follows values through registers and slots, and a pointer that reaches a
/// comparison is indistinguishable *by value* from a passing numeric check: the two sides are
/// equal, so the candidate "the pointer, in decimal" both extracts and then confirms itself. That
/// is how three corpus binaries came back solved with the address of their own input buffer. The
/// value here is a real mapped `.data` address, exactly as those were.
#[test]
fn an_address_is_not_a_numeric_key() {
    let p = numeric_check_against_a_pointer();
    let pointer = (DATA + 0x150).to_string();

    let keys: Vec<String> = orress_vm::recover_by_compare(&p, BASE, Abi::SysV)
        .iter()
        .flat_map(|r| r.keys.iter())
        .map(|k| String::from_utf8_lossy(k).to_string())
        .collect();
    assert!(
        !keys.contains(&pointer),
        "{pointer} is a mapped address, not a key: {keys:?}"
    );

    // And the confirmation refuses it even when handed it directly, so a lead reaching this from
    // any other stage (a scraped `cmp` immediate, say) cannot be laundered into a solve.
    assert_eq!(
        orress_vm::compare_satisfied(&p, BASE, pointer.as_bytes(), Abi::SysV),
        Some(false),
        "a satisfied comparison on an image address is not a confirmation"
    );
}


/// Check functions named by **what they call** — a reader, a comparer, or both.
///
/// This exists alongside the size and call-graph heuristics because those rank by shape and
/// position, and fall back to address order on the (very common) binary whose `main` cannot be
/// identified. A function that calls neither a reader nor a comparer cannot produce an observable
/// comparison against the input, so a budget slot spent on it is wasted; one that calls both is
/// the check itself far more often than one that calls either.
#[test]
fn input_handling_functions_are_named_by_what_they_call() {
    // `gets` twice and `strcmp` once, all in the one function: the both-of-them shape.
    let p = two_read_keygen();
    assert_eq!(orress_vm::input_check_functions(&p), vec![BASE]);

    // A function that neither reads nor compares is not a target.
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    let quiet = program_with(a, |_| {}, &[]);
    assert!(
        orress_vm::input_check_functions(&quiet).is_empty(),
        "nothing to observe in a function that touches no input"
    );

    // The name is matched through the decoration a linker adds (`_scanf`), not just the bare form.
    let numeric = numeric_check();
    assert_eq!(orress_vm::input_check_functions(&numeric), vec![BASE]);
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

    // The fixture derives its serial as `name[i] ^ 0x10` over the first four bytes, so the key to
    // expect follows from whichever seed produced that recovery (the seeds are not all alike: one
    // is numeric, so a `scanf("%d")` reader has something it can convert).
    for rec in &recoveries {
        let expected: Vec<u8> = rec.seed.iter().take(4).map(|b| b ^ 0x10).collect();
        assert!(
            rec.keys.contains(&expected),
            "expected the computed serial {:?} among {:?} (seed {:?})",
            String::from_utf8_lossy(&expected),
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

/// The two flavours of compare-pass are **not** equally good evidence, so they are reported apart.
///
/// A `Bytes` pass means the comparison spelled out a whole byte sequence that agreed with the
/// candidate at every position — a wrong input cannot do that by coincidence. A `Number` pass means
/// one integer equality held, which is far weaker: when the candidate was itself read out of that
/// same comparison by the decompiler, re-running it can only pass, and no wrong twin can make it
/// fail, so the differential test proves nothing. Three unrelated corpus binaries "confirmed" the
/// key `252` that way. CRACKEN's confirm stage relies on this distinction to decide which passes
/// need corroborating, so the kinds must not be collapsed back together.
#[test]
fn a_compare_pass_reports_which_comparison_accepted_the_input() {
    use orress_vm::{ComparePass, ComparePassOutcome};

    // A string key, matched byte by byte.
    let p = inline_keycheck();
    assert_eq!(
        orress_vm::compare_pass(&p, BASE, b"WXYZ!", Abi::SysV),
        ComparePassOutcome::Passed(ComparePass::Bytes),
        "a per-byte key check is a Bytes pass"
    );
    assert_eq!(
        orress_vm::compare_pass(&p, BASE, b"ABCD?", Abi::SysV),
        ComparePassOutcome::No,
        "and a wrong input of the same length does not pass at all"
    );

    // A whole-value numeric gate: the weak flavour.
    let p = numeric_check();
    assert_eq!(
        orress_vm::compare_pass(&p, BASE, b"25711", Abi::SysV),
        ComparePassOutcome::Passed(ComparePass::Number),
        "an integer gate is only a Number pass"
    );
    assert_eq!(
        orress_vm::compare_pass(&p, BASE, b"25712", Abi::SysV),
        ComparePassOutcome::No
    );

    // `compare_satisfied` stays the boolean view over the same answer.
    assert_eq!(orress_vm::compare_satisfied(&p, BASE, b"25711", Abi::SysV), Some(true));
    assert_eq!(orress_vm::compare_satisfied(&p, BASE, b"25712", Abi::SysV), Some(false));
}
