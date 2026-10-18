//! Turns bytes into the format-independent model using the `object` crate.

use object::read::elf::{ElfFile, FileHeader};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::{
    Architecture, BinaryFormat, ExportTarget, NameOrOrdinal, Object, ObjectKind, ObjectSection,
    ObjectSegment, SectionFlags, SectionKind,
};

use crate::model::*;
use crate::{code_hints, protections};

pub fn parse(data: &[u8]) -> BinaryInfo {
    let file = match object::File::parse(data) {
        Ok(file) => file,
        Err(e) => {
            return BinaryInfo {
                parse_error: Some(e.to_string()),
                ..BinaryInfo::default()
            };
        }
    };

    let format = match file.format() {
        BinaryFormat::Pe => Format::Pe,
        BinaryFormat::Elf => Format::Elf,
        BinaryFormat::MachO => Format::MachO,
        BinaryFormat::Coff => Format::Coff,
        BinaryFormat::Wasm => Format::Wasm,
        BinaryFormat::Xcoff => Format::Xcoff,
        _ => Format::Unknown,
    };

    let mut info = BinaryInfo {
        format,
        kind: match file.kind() {
            ObjectKind::Executable => Kind::Executable,
            ObjectKind::Dynamic => Kind::Library,
            ObjectKind::Relocatable => Kind::Object,
            ObjectKind::Core => Kind::Core,
            _ => Kind::Unknown,
        },
        arch: arch_name(file.architecture()).to_owned(),
        bits: Some(if file.is_64() { 64 } else { 32 }),
        endian: if file.is_little_endian() {
            Endian::Little
        } else {
            Endian::Big
        },
        entry: Some(file.entry()).filter(|&e| e != 0),
        image_base: file.relative_address_base(),
        has_debug_info: file.has_debug_symbols(),
        symbol_count: file.symbols().count() + file.dynamic_symbols().count(),
        ..BinaryInfo::default()
    };

    // Mach-O's LC_MAIN stores the entry point as a *file offset* (`entryoff`), and `object`
    // reports it as-is; turn it into a virtual address through the segment that maps it.
    if format == Format::MachO
        && let Some(off) = info.entry
    {
        info.entry = file.segments().find_map(|seg| {
            let (start, size) = seg.file_range();
            (size > 0 && off >= start && off - start < size).then(|| seg.address() + (off - start))
        });
    }

    for section in file.sections() {
        let name = section.name().unwrap_or("").to_owned();
        let (offset, file_size) = section.file_range().unwrap_or((0, 0));
        info.sections.push(Section {
            perms: section_perms(section.flags(), section.kind()),
            name,
            offset,
            file_size,
            address: section.address(),
            virtual_size: section.size(),
            entropy: None,
        });
    }

    for segment in file.segments() {
        let (offset, file_size) = segment.file_range();
        let p = segment.permissions();
        info.segments.push(Segment {
            name: segment.name().ok().flatten().map(str::to_owned),
            offset,
            file_size,
            address: segment.address(),
            virtual_size: segment.size(),
            perms: Perms {
                read: p.readable(),
                write: p.writable(),
                execute: p.executable(),
            },
        });
    }
    if info.format == Format::Elf
        && let Some(lowest) = info
            .segments
            .iter()
            .filter(|s| s.file_size > 0)
            .map(|s| s.address)
            .min()
    {
        info.image_base = lowest;
    }

    if let Ok(imports) = file.imports() {
        // Malformed entries are skipped; the rest of the table is still useful.
        info.imports = imports
            .filter_map(Result::ok)
            .map(|i| Import {
                library: String::from_utf8_lossy(i.library()).into_owned(),
                name: match i.name() {
                    NameOrOrdinal::Name(n) => {
                        let raw = String::from_utf8_lossy(n);
                        orress_demangle::demangle(&raw).unwrap_or_else(|| raw.into_owned())
                    }
                    NameOrOrdinal::Ordinal(o) => format!("#{o}"),
                },
            })
            .collect();
    }
    if let Ok(exports) = file.exports() {
        info.exports = exports
            .filter_map(Result::ok)
            .map(|e| Export {
                name: match e.name() {
                    NameOrOrdinal::Name(n) => {
                        let raw = String::from_utf8_lossy(n);
                        orress_demangle::demangle(&raw).unwrap_or_else(|| raw.into_owned())
                    }
                    NameOrOrdinal::Ordinal(o) => format!("#{o}"),
                },
                // Forwarded exports (to another DLL) have no address in this file.
                address: match e.target() {
                    ExportTarget::Address { address } => address,
                    ExportTarget::Absolute { value } => value,
                    _ => 0,
                },
            })
            .collect();
    }

    info.function_symbols = code_hints::function_symbols(&file);
    match &file {
        object::File::Pe32(pe) => {
            info.import_slots = code_hints::pe_import_slots(pe, info.image_base);
            pe_details(pe, &mut info);
        }
        object::File::Pe64(pe) => {
            info.import_slots = code_hints::pe_import_slots(pe, info.image_base);
            let exception = pe.data_directory(3).map(|d| {
                (
                    d.virtual_address.get(object::LittleEndian),
                    d.size.get(object::LittleEndian),
                )
            });
            info.function_starts = code_hints::pe_pdata_starts(&info, data, exception);
            pe_details(pe, &mut info);
        }
        object::File::Elf32(elf) => {
            info.import_slots = code_hints::elf_import_slots(&file);
            protections::elf(elf, data, &mut info);
        }
        object::File::Elf64(elf) => {
            info.import_slots = code_hints::elf_import_slots(&file);
            protections::elf(elf, data, &mut info);
        }
        object::File::MachO32(macho) => {
            info.import_slots = code_hints::macho_import_slots(macho);
            protections::macho(&file, &mut info);
        }
        object::File::MachO64(macho) => {
            info.import_slots = code_hints::macho_import_slots(macho);
            protections::macho(&file, &mut info);
        }
        _ => {}
    }
    info
}

fn section_perms(flags: SectionFlags, kind: SectionKind) -> Perms {
    match flags {
        SectionFlags::Coff { characteristics } => {
            let c = characteristics.0;
            Perms {
                read: c & 0x4000_0000 != 0,
                write: c & 0x8000_0000 != 0,
                execute: c & 0x2000_0000 != 0,
            }
        }
        SectionFlags::Elf { sh_flags, .. } => {
            let f = sh_flags.0;
            Perms {
                read: f & 0x2 != 0, // SHF_ALLOC: loaded into memory, so readable
                write: f & 0x1 != 0,
                execute: f & 0x4 != 0,
            }
        }
        _ => Perms {
            read: true,
            write: matches!(kind, SectionKind::Data | SectionKind::UninitializedData),
            execute: kind == SectionKind::Text,
        },
    }
}

fn pe_details<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, info: &mut BinaryInfo) {
    let nt = pe.nt_headers();
    let opt = nt.optional_header();
    let dir_present = |index: usize| {
        pe.data_directory(index)
            .is_some_and(|d| d.virtual_address.get(object::LittleEndian) != 0)
    };
    let rich = pe
        .rich_header_info()
        .map(|r| {
            r.unmasked_entries()
                .map(|e| {
                    (
                        (e.comp_id >> 16) as u16,
                        (e.comp_id & 0xffff) as u16,
                        e.count,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let details = PeDetails {
        timestamp: nt.file_header().time_date_stamp.get(object::LittleEndian),
        subsystem: subsystem_name(opt.subsystem().0).to_owned(),
        linker_version: (opt.major_linker_version(), opt.minor_linker_version()),
        is_dotnet: dir_present(14),
        has_signature: dir_present(4),
        has_tls: dir_present(9),
        rich,
    };
    protections::pe(
        opt.dll_characteristics().0,
        info.bits == Some(64),
        &details,
        info,
    );
    info.pe = Some(details);
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "Native (driver or boot program)",
        2 => "Windows GUI",
        3 => "Windows console",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot driver",
        12 => "EFI runtime driver",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "Other",
    }
}

fn arch_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::I386 => "x86 (32-bit)",
        Architecture::X86_64 => "x86-64",
        Architecture::X86_64_X32 => "x86-64 (x32 ABI)",
        Architecture::Arm => "ARM (32-bit)",
        Architecture::Aarch64 => "ARM64 (AArch64)",
        Architecture::Aarch64_Ilp32 => "ARM64 (ILP32)",
        Architecture::Mips => "MIPS (32-bit)",
        Architecture::Mips64 => "MIPS64",
        Architecture::PowerPc => "PowerPC (32-bit)",
        Architecture::PowerPc64 => "PowerPC64",
        Architecture::Riscv32 => "RISC-V (32-bit)",
        Architecture::Riscv64 => "RISC-V (64-bit)",
        Architecture::Avr => "AVR (microcontroller)",
        Architecture::Wasm32 => "WebAssembly (32-bit)",
        Architecture::Wasm64 => "WebAssembly (64-bit)",
        Architecture::S390x => "IBM Z (s390x)",
        Architecture::Sparc | Architecture::Sparc32Plus => "SPARC",
        Architecture::Sparc64 => "SPARC64",
        Architecture::LoongArch64 => "LoongArch64",
        Architecture::Msp430 => "MSP430 (microcontroller)",
        Architecture::Bpf => "eBPF",
        _ => "Unknown architecture",
    }
}

// Used by protections.rs for ELF.
pub(crate) fn elf_type<Elf: FileHeader>(elf: &ElfFile<'_, Elf>) -> u16 {
    elf.elf_header().e_type(elf.endian()).0
}
