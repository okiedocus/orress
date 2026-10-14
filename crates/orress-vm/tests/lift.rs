//! Program-level seeding and lifting: a hand-built x86-64 binary, analysed by `orress-analysis`,
//! run through the shared `emu_image` / `import_hooks` seeding.

use std::sync::Arc;

use iced_x86::code_asm::*;
use orress_analysis::Program;
use orress_emu::{Abi, Emulator};
use orress_loaders::{BinaryInfo, Format, Kind, NamedAddress, Perms, Section};

const BASE: u64 = 0x40_1000;
const DATA: u64 = 0x40_2000;
/// The import slot for `strcmp`. In the file image it holds 0 (like an unbound GOT/IAT entry).
const SLOT: u64 = DATA + 0x100;
const INPUT: u64 = 0x50_0000;

/// `check(s) { return strcmp(s, "hunter2") == 0 }` calling strcmp through its import slot
/// (`call [slot]`, as PE and `-fno-plt` ELF code does), in an analysable binary.
fn program(arch: &str, bits: u8) -> Program {
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rsi, DATA).unwrap();
    a.call(qword_ptr(SLOT)).unwrap();
    a.test(eax, eax).unwrap();
    a.sete(al).unwrap();
    a.movzx(eax, al).unwrap();
    a.ret().unwrap();
    let mut code = a.assemble(BASE).unwrap();
    code.resize(0x100, 0xcc);

    let mut data = vec![0u8; 0x200];
    data[..8].copy_from_slice(b"hunter2\0");

    let mut file = vec![0u8; 0x200]; // headers
    file.extend(&code); // offset 0x200 -> BASE
    file.extend(&data); // offset 0x300 -> DATA

    let section = |name: &str, offset, size, address, execute: bool| Section {
        name: name.into(),
        offset,
        file_size: size,
        address,
        virtual_size: size,
        perms: Perms {
            read: true,
            write: !execute,
            execute,
        },
        entropy: None,
    };
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: arch.into(),
        bits: Some(bits),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![
            section(".text", 0x200, 0x100, BASE, true),
            section(".data", 0x300, 0x200, DATA, false),
        ],
        import_slots: vec![NamedAddress {
            address: SLOT,
            name: "strcmp".into(),
        }],
        function_symbols: vec![NamedAddress {
            address: BASE,
            name: "check".into(),
        }],
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("supported architecture")
}

/// The hook is keyed by the import *slot*; `call [slot]` loads the slot's file contents (0 here),
/// so before the fix execution jumped to address 0 instead of running the strcmp stub.
#[test]
fn a_call_through_an_import_slot_runs_the_stub() {
    let p = program("x86-64", 64);
    let hooks = orress_vm::import_hooks(&p);
    assert_eq!(hooks.get(&SLOT), Some(&orress_emu::Stub::Strcmp));

    let run = |input: &[u8]| {
        let mut emu = Emulator::new();
        emu.mem = orress_vm::emu_image(&p);
        for (&addr, stub) in &hooks {
            emu.hook(addr, stub.clone());
        }
        emu.map(INPUT, input);
        emu.call(BASE, &[INPUT], Abi::SysV).unwrap()
    };
    assert_eq!(run(b"hunter2\0"), 1);
    assert_eq!(run(b"letmein\0"), 0);
}

/// The image maps a zeroed tail after each file-backed region (`.bss`), so guest writes there
/// work now that writes to unmapped memory fault.
#[test]
fn the_image_maps_a_zeroed_bss_tail() {
    let p = program("x86-64", 64);
    let mut mem = orress_vm::emu_image(&p);
    assert_eq!(
        mem.read(DATA, 8).unwrap(),
        u64::from_le_bytes(*b"hunter2\0")
    );
    mem.write(DATA + 0x200, 0x1234, 8).unwrap();
    assert_eq!(mem.read(DATA + 0x200, 8).unwrap(), 0x1234);
    assert!(mem.write(0, 1, 1).is_err(), "null stays unmapped");
}

/// VM lifting decodes and executes x86-64 only; any other ISA is refused with a reason rather
/// than mis-decoded.
#[test]
fn try_solve_rejects_non_x64_programs() {
    let p = program("x86 (32-bit)", 32);
    let report = orress_vm::VmReport {
        entry: BASE,
        dispatcher: BASE,
        blocks: 0,
        handlers: 0,
        max_fan_in: 0,
        confidence: 1.0,
    };
    match orress_vm::try_solve(&p, &report) {
        Err(orress_sym::SymError::Unsupported { what, .. }) => {
            assert!(what.contains("x86-64"), "{what}");
        }
        other => panic!("expected Unsupported, got {:?}", other.map(|s| s.key)),
    }
    assert!(orress_vm::solve(&p, &report).is_none());
}
