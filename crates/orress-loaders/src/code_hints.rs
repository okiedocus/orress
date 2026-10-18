//! Facts the code analysis needs from the file format: where imported function pointers
//! live, named function symbols, and function starts from exception tables.

use object::macho;
use object::read::macho::{MachHeader, MachOFile, Nlist, Section as _};
use object::read::pe::{ImageNtHeaders, ImageThunkData, PeFile};
use object::{
    LittleEndian as LE, Object, ObjectSymbol, ObjectSymbolTable, ReadRef, RelocationTarget,
    SymbolIndex, SymbolKind, U32,
};

use crate::model::*;

/// PE: one slot per imported function in the Import Address Table. The program calls
/// imports indirectly through these slots: `call [IAT slot]`.
pub fn pe_import_slots<Pe: ImageNtHeaders>(
    pe: &PeFile<'_, Pe>,
    image_base: u64,
) -> Vec<NamedAddress> {
    let mut out = Vec::new();
    let Ok(Some(table)) = pe.import_table() else {
        return out;
    };
    let Ok(mut descriptors) = table.descriptors() else {
        return out;
    };
    let slot_size: u64 = if pe.is_64() { 8 } else { 4 };
    while let Ok(Some(desc)) = descriptors.next() {
        let library = table
            .name(desc.name.get(LE))
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .unwrap_or_default();
        let first_thunk = desc.first_thunk.get(LE);
        // Names come from the original thunks; the IAT itself may be pre-bound.
        let names_at = match desc.original_first_thunk.get(LE) {
            0 => first_thunk,
            oft => oft,
        };
        let Ok(mut thunks) = table.thunks(names_at) else {
            continue;
        };
        let mut index = 0u64;
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            let name = match table.import::<Pe>(thunk) {
                Ok(object::read::pe::Import::Name(_, name)) => {
                    String::from_utf8_lossy(name).into_owned()
                }
                Ok(object::read::pe::Import::Ordinal(o)) => format!("{library}#{o}"),
                Err(_) => format!("import_{:x}", thunk.raw()),
            };
            out.push(NamedAddress {
                address: image_base + u64::from(first_thunk) + index * slot_size,
                name,
            });
            index += 1;
        }
    }
    out
}

/// ELF: GOT slots filled in by the dynamic linker (JUMP_SLOT / GLOB_DAT relocations).
/// PLT stubs jump through these: `jmp [GOT slot]`.
pub fn elf_import_slots(file: &object::File<'_>) -> Vec<NamedAddress> {
    let Some(relocations) = file.dynamic_relocations() else {
        return Vec::new();
    };
    let Some(symbols) = file.dynamic_symbol_table() else {
        return Vec::new();
    };
    relocations
        .filter_map(|(offset, reloc)| match reloc.target() {
            RelocationTarget::Symbol(index) => {
                let symbol = symbols.symbol_by_index(index).ok()?;
                let name = symbol.name().ok()?;
                (!name.is_empty() && symbol.is_undefined()).then(|| NamedAddress {
                    address: offset,
                    name: name.to_owned(),
                })
            }
            _ => None,
        })
        .collect()
}

/// Mach-O: the indirect symbol table names every entry of the symbol-stub (`__stubs`) and
/// symbol-pointer (`__got`, `__la_symbol_ptr`) sections. Code calls an import with
/// `bl`/`call <stub>` or loads its pointer from the GOT, so those entries are the import slots.
pub fn macho_import_slots<'data, Mach: MachHeader, R: ReadRef<'data>>(
    file: &MachOFile<'data, Mach, R>,
) -> Vec<NamedAddress> {
    let endian = file.endian();
    let Ok(mut commands) = file.macho_load_commands() else {
        return Vec::new();
    };
    let mut dysymtab = None;
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(d)) = command.dysymtab() {
            dysymtab = Some(d);
            break;
        }
    }
    let Some(dysymtab) = dysymtab else {
        return Vec::new();
    };
    let Ok(indirect) = file.data().read_slice_at::<U32<Mach::Endian>>(
        u64::from(dysymtab.indirectsymoff.get(endian)),
        dysymtab.nindirectsyms.get(endian) as usize,
    ) else {
        return Vec::new();
    };
    let symbols = file.macho_symbol_table();
    let pointer_size = if file.is_64() { 8 } else { 4 };
    let mut out = Vec::new();
    for section in file.sections() {
        let section = section.macho_section();
        let entry_size = match section.flags(endian).typ() {
            macho::S_SYMBOL_STUBS => u64::from(section.reserved2(endian)),
            macho::S_NON_LAZY_SYMBOL_POINTERS | macho::S_LAZY_SYMBOL_POINTERS => pointer_size,
            _ => continue,
        };
        if entry_size == 0 {
            continue;
        }
        let address: u64 = section.addr(endian).into();
        let size: u64 = section.size(endian).into();
        let first = section.reserved1(endian) as usize;
        // Bounded by the indirect table: a hostile section size cannot make this loop long.
        for i in 0..size / entry_size {
            let Some(entry) = first
                .checked_add(i as usize)
                .and_then(|index| indirect.get(index))
            else {
                break;
            };
            let index = entry.get(endian);
            // INDIRECT_SYMBOL_LOCAL / INDIRECT_SYMBOL_ABS: not an import.
            if index & 0xc000_0000 != 0 {
                continue;
            }
            let Ok(nlist) = symbols.symbol(SymbolIndex(index as usize)) else {
                continue;
            };
            let Ok(name) = nlist.name(endian, symbols.strings()) else {
                continue;
            };
            if !name.is_empty() {
                out.push(NamedAddress {
                    address: address + i * entry_size,
                    name: String::from_utf8_lossy(name).into_owned(),
                });
            }
        }
    }
    out
}

/// Defined function symbols (static and dynamic), one name per address.
pub fn function_symbols(file: &object::File<'_>) -> Vec<NamedAddress> {
    let mut out: Vec<NamedAddress> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter(|s| s.is_definition() && s.kind() == SymbolKind::Text && s.address() != 0)
        .filter_map(|s| {
            let name = s.name().ok()?;
            (!name.is_empty()).then(|| NamedAddress {
                address: s.address(),
                name: orress_demangle::demangle(name).unwrap_or_else(|| name.to_owned()),
            })
        })
        .collect();
    out.sort_by_key(|n| n.address);
    out.dedup_by_key(|n| n.address);
    out
}

/// x64 PE: every non-leaf function has a RUNTIME_FUNCTION entry in the exception
/// directory (.pdata), so this lists function starts even in stripped binaries.
pub fn pe_pdata_starts(
    info: &BinaryInfo,
    data: &[u8],
    exception_dir: Option<(u32, u32)>,
) -> Vec<u64> {
    let Some((rva, size)) = exception_dir else {
        return Vec::new();
    };
    let Some(offset) = info.address_to_offset(info.image_base + u64::from(rva)) else {
        return Vec::new();
    };
    let start = offset as usize;
    let Some(bytes) = data.get(start..start.saturating_add(size as usize)) else {
        return Vec::new();
    };
    let mut out: Vec<u64> = bytes
        // RUNTIME_FUNCTION: begin RVA, end RVA, unwind info RVA (3 x u32).
        .as_chunks::<12>()
        .0
        .iter()
        .map(|entry| u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]))
        .filter(|&begin| begin != 0)
        .map(|begin| info.image_base + u64::from(begin))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}
