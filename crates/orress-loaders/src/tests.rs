//! Format tests. Fixtures are generated with `object::write`, so the tests need no
//! binary files and run on every platform.

use object::write::{Object as WObject, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

use crate::*;

fn object_file(format: BinaryFormat, arch: Architecture) -> Vec<u8> {
    let mut obj = WObject::new(format, arch, Endianness::Little);
    let text = obj.section_id(StandardSection::Text);
    obj.append_section_data(text, &[0x55, 0x48, 0x89, 0xe5, 0xc3], 16);
    let rodata = obj.section_id(StandardSection::ReadOnlyData);
    obj.append_section_data(rodata, b"flag{generated_fixture}\0Wrong password\0", 1);
    obj.add_symbol(Symbol {
        name: b"main".to_vec(),
        value: 0,
        size: 5,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.add_symbol(Symbol {
        name: b"strcmp".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Unknown,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    obj.write().unwrap()
}

#[test]
fn elf_object_is_recognized() {
    let data = object_file(BinaryFormat::Elf, Architecture::X86_64);
    let info = triage(&data);
    assert_eq!(info.format, Format::Elf);
    assert_eq!(info.kind, Kind::Object);
    assert_eq!(info.arch, "x86-64");
    assert_eq!(info.bits, Some(64));
    let text = info.sections.iter().find(|s| s.name == ".text").unwrap();
    assert!(text.perms.execute && !text.perms.write);
    assert_eq!(text.file_size, 5);
    assert!(info.parse_error.is_none());
    assert_eq!(info.hashes.sha256.len(), 64);
    assert!(info.protections.iter().any(|p| p.name == "PIE"));
}

#[test]
fn coff_and_macho_objects_parse() {
    let coff = triage(&object_file(BinaryFormat::Coff, Architecture::I386));
    assert_eq!(coff.format, Format::Coff);
    assert_eq!(coff.arch, "x86 (32-bit)");
    let macho = triage(&object_file(BinaryFormat::MachO, Architecture::Aarch64));
    assert_eq!(macho.format, Format::MachO);
    assert_eq!(macho.arch, "ARM64 (AArch64)");
}

#[test]
fn unknown_data_still_gets_triage() {
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend([0u8; 100]);
    let info = triage(&zip);
    assert_eq!(info.format, Format::Unknown);
    assert!(info.parse_error.is_some());
    assert!(info.detections.iter().any(|d| d.name == "ZIP archive"));
    assert!(info.insights.iter().any(|i| i.title == "Not an executable"));
    assert_eq!(info.size, 104);
}

#[test]
fn garbage_does_not_panic() {
    for len in [0usize, 1, 2, 4, 64, 4096] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let _ = triage(&data);
    }
    // Truncated headers of every supported format.
    for format in [BinaryFormat::Elf, BinaryFormat::Coff, BinaryFormat::MachO] {
        let data = object_file(format, Architecture::X86_64);
        for cut in [4, 16, 52, 64, 100, data.len() / 2] {
            let _ = triage(&data[..cut.min(data.len())]);
        }
    }
}

#[test]
fn upx_and_markers_are_detected() {
    let mut data = object_file(BinaryFormat::Elf, Architecture::X86_64);
    data.extend_from_slice(b"....UPX!....GCC: (Ubuntu 13.2.0) 13.2.0");
    let info = triage(&data);
    let names: Vec<_> = info.detections.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"UPX"), "{names:?}");
    assert!(names.contains(&"GCC"), "{names:?}");
    assert!(
        info.insights
            .iter()
            .any(|i| i.title == "The program is packed")
    );
}

#[test]
fn address_mapping_round_trips() {
    let info = BinaryInfo {
        sections: vec![Section {
            name: ".text".into(),
            offset: 0x400,
            file_size: 0x200,
            address: 0x40_1000,
            virtual_size: 0x200,
            perms: Perms::default(),
            entropy: None,
        }],
        ..BinaryInfo::default()
    };
    assert_eq!(info.offset_to_address(0x410), Some(0x40_1010));
    assert_eq!(info.address_to_offset(0x40_1010), Some(0x410));
    assert_eq!(info.offset_to_address(0x10), None);
    assert_eq!(info.address_to_offset(0x40_1200), None);
    assert_eq!(
        info.section_at_offset(0x5ff).map(|s| s.name.as_str()),
        Some(".text")
    );
}

#[test]
fn address_mapping_does_not_overflow() {
    // A hostile section mapped at the very top of the address space.
    let info = BinaryInfo {
        sections: vec![Section {
            name: ".evil".into(),
            offset: u64::MAX - 0x10,
            file_size: 0x100,
            address: u64::MAX - 0x10,
            virtual_size: 0x100,
            perms: Perms::default(),
            entropy: None,
        }],
        ..BinaryInfo::default()
    };
    assert_eq!(info.offset_to_address(u64::MAX - 0x8), Some(u64::MAX - 0x8));
    let info = BinaryInfo {
        sections: vec![Section {
            offset: 0,
            address: u64::MAX - 0x10,
            ..info.sections[0].clone()
        }],
        ..BinaryInfo::default()
    };
    assert_eq!(info.offset_to_address(0x80), None);
    let info = BinaryInfo {
        sections: vec![Section {
            offset: u64::MAX - 0x10,
            address: 0x1000,
            ..info.sections[0].clone()
        }],
        ..BinaryInfo::default()
    };
    assert_eq!(info.address_to_offset(0x1080), None);
}

/// The test binary itself is a real linked executable for the host platform
/// (PE on Windows, ELF on Linux, Mach-O on macOS).
#[test]
fn host_executable_parses() {
    let exe = std::env::current_exe().unwrap();
    let data = std::fs::read(exe).unwrap();
    let info = triage(&data);
    let expected = if cfg!(windows) {
        Format::Pe
    } else if cfg!(target_os = "macos") {
        Format::MachO
    } else {
        Format::Elf
    };
    assert_eq!(info.format, expected);
    assert_eq!(info.kind, Kind::Executable);
    assert!(info.entry.is_some());
    assert!(
        info.entry_offset().is_some(),
        "entry point maps to a file offset"
    );
    assert!(!info.imports.is_empty());
    assert!(info.detections.iter().any(|d| d.name == "Rust"));
    if cfg!(windows) {
        assert!(info.pe.is_some());
        assert!(
            info.protections
                .iter()
                .any(|p| p.name == "ASLR" && p.state == ProtectionState::On)
        );
        assert!(info.hashes.imphash.is_some());
        assert!(
            info.import_slots.len() >= info.imports.len() / 2,
            "IAT slots found for imports"
        );
        assert!(
            info.function_starts.len() > 100,
            "x64 .pdata lists functions"
        );
    }
}
