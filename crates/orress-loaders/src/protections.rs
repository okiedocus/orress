//! Security protections ("checksec"). Each one changes what a reverse engineer or
//! exploit writer sees, so each comes with an explanation of why it matters.

use object::read::elf::{ElfFile, FileHeader, ProgramHeader};
use object::{FileFlags, Object};

use crate::model::*;

const ASLR: &str = "Address Space Layout Randomization: the program is loaded at a random \
    address each run. Addresses you see in a debugger change between runs; ORRESS shows \
    addresses relative to the image base so they stay comparable.";
const DEP: &str = "Data Execution Prevention / NX: memory is either writable or executable, \
    never both. Injected code (shellcode) on the stack or heap cannot run directly.";
const CFG: &str = "Control Flow Guard: indirect calls are checked against a list of valid \
    targets, which makes hijacking function pointers harder.";
const SIGNED: &str = "Authenticode signature: the file carries a code-signing certificate. \
    A valid signature says who published it; malware sometimes uses stolen certificates.";
const SAFESEH: &str = "SafeSEH: 32-bit Windows programs list their valid exception handlers, \
    so an overwritten handler pointer on the stack cannot be used to take control.";
const PIE: &str = "Position Independent Executable: the program can be loaded at any \
    address, so ASLR randomizes it. In the file you see small addresses (from 0); at run \
    time a random base is added.";
const RELRO: &str = "RELocation Read-Only: after loading, the dynamic linker makes the \
    Global Offset Table read-only (Full RELRO), so overwriting GOT entries is impossible. \
    Partial RELRO protects only part of it.";
const CANARY: &str = "Stack canary: a secret value placed before the return address and \
    checked before the function returns. A buffer overflow that changes it crashes the \
    program (__stack_chk_fail) instead of being exploitable.";
const FORTIFY: &str = "FORTIFY_SOURCE: the compiler replaced risky functions like memcpy \
    and sprintf with checked versions (__memcpy_chk ...) that stop on overflows.";
const STRIPPED: &str = "Symbols are the names of functions and variables. A stripped binary \
    has them removed, so you must work out and name functions yourself. Most CTF \
    challenges and almost all malware are stripped.";

fn add(
    info: &mut BinaryInfo,
    name: &'static str,
    state: ProtectionState,
    detail: impl Into<String>,
    explain: &'static str,
) {
    info.protections.push(Protection {
        name,
        state,
        detail: detail.into(),
        explain,
    });
}

fn on_off(on: bool) -> ProtectionState {
    if on {
        ProtectionState::On
    } else {
        ProtectionState::Off
    }
}

pub fn pe(dll_flags: u16, is_64: bool, details: &PeDetails, info: &mut BinaryInfo) {
    const DYNAMIC_BASE: u16 = 0x0040;
    const HIGH_ENTROPY_VA: u16 = 0x0020;
    const NX_COMPAT: u16 = 0x0100;
    const NO_SEH: u16 = 0x0400;
    const GUARD_CF: u16 = 0x4000;

    let aslr = dll_flags & DYNAMIC_BASE != 0;
    let high = dll_flags & HIGH_ENTROPY_VA != 0;
    let (state, detail) = match (aslr, is_64 && high) {
        (true, true) => (ProtectionState::On, "DYNAMIC_BASE + HIGH_ENTROPY_VA"),
        (true, false) => (ProtectionState::On, "DYNAMIC_BASE"),
        _ => (ProtectionState::Off, "fixed load address"),
    };
    add(info, "ASLR", state, detail, ASLR);
    add(
        info,
        "DEP / NX",
        on_off(dll_flags & NX_COMPAT != 0),
        "NX_COMPAT flag",
        DEP,
    );
    add(
        info,
        "Control Flow Guard",
        on_off(dll_flags & GUARD_CF != 0),
        "GUARD_CF flag",
        CFG,
    );
    if !is_64 {
        let no_seh = dll_flags & NO_SEH != 0;
        add(
            info,
            "SafeSEH / no SEH",
            on_off(no_seh),
            if no_seh {
                "NO_SEH flag"
            } else {
                "not marked (needs load config to confirm)"
            },
            SAFESEH,
        );
    }
    add(
        info,
        "Signed",
        on_off(details.has_signature),
        if details.has_signature {
            "has a certificate table (not verified)"
        } else {
            "no embedded certificate (system files may be catalog-signed)"
        },
        SIGNED,
    );
    stripped(info);
}

pub fn elf<Elf: FileHeader>(elf: &ElfFile<'_, Elf>, data: &[u8], info: &mut BinaryInfo) {
    const ET_DYN: u16 = 3;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const PT_GNU_STACK: u32 = 0x6474_e551;
    const PT_GNU_RELRO: u32 = 0x6474_e552;
    const PF_X: u32 = 1;
    const DT_NULL: u64 = 0;
    const DT_BIND_NOW: u64 = 24;
    const DT_FLAGS: u64 = 30;
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    const DF_1_PIE: u64 = 0x0800_0000;

    let endian = elf.endian();
    let headers = elf.elf_program_headers();
    let find = |kind: u32| headers.iter().find(|h| h.p_type(endian).0 == kind);

    // Dynamic section entries, read straight from the PT_DYNAMIC segment.
    let mut dynamic = Vec::new();
    if let Some(h) = find(PT_DYNAMIC) {
        let offset: u64 = h.p_offset(endian).into();
        let size: u64 = h.p_filesz(endian).into();
        let entry = if elf.is_64() { 16 } else { 8 };
        let bytes = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(size).ok())
            .and_then(|(o, s)| data.get(o..o.checked_add(s)?));
        for chunk in bytes.unwrap_or(&[]).chunks_exact(entry) {
            let read = |b: &[u8]| -> u64 {
                let mut buf = [0u8; 8];
                let n = b.len();
                if info.endian == Endian::Little {
                    buf[..n].copy_from_slice(b);
                    u64::from_le_bytes(buf)
                } else {
                    buf[8 - n..].copy_from_slice(b);
                    u64::from_be_bytes(buf)
                }
            };
            let half = entry / 2;
            let (tag, val) = (read(&chunk[..half]), read(&chunk[half..]));
            if tag == DT_NULL {
                break;
            }
            dynamic.push((tag, val));
        }
    }
    let dyn_val = |tag: u64| dynamic.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v);
    let flags_1 = dyn_val(DT_FLAGS_1).unwrap_or(0);

    let is_dyn = crate::parse::elf_type(elf) == ET_DYN;
    // A PIE executable is ET_DYN just like a shared library, so `object` reports it as
    // `Dynamic`. It is a program if it asks for a dynamic loader (PT_INTERP) or is flagged PIE.
    if is_dyn
        && info.kind == Kind::Library
        && (find(PT_INTERP).is_some() || flags_1 & DF_1_PIE != 0)
    {
        info.kind = Kind::Executable;
    }
    let pie = is_dyn && (flags_1 & DF_1_PIE != 0 || elf.entry() != 0);
    add(
        info,
        "PIE",
        on_off(pie),
        if pie {
            "ET_DYN with entry point"
        } else {
            "fixed load address (ET_EXEC)"
        },
        PIE,
    );

    let nx = find(PT_GNU_STACK).is_none_or(|h| h.p_flags(endian).0 & PF_X == 0);
    add(
        info,
        "NX (non-executable stack)",
        on_off(nx),
        if nx {
            "stack is not executable"
        } else {
            "PT_GNU_STACK is executable"
        },
        DEP,
    );

    let bind_now = dyn_val(DT_BIND_NOW).is_some()
        || dyn_val(DT_FLAGS).is_some_and(|f| f & DF_BIND_NOW != 0)
        || flags_1 & DF_1_NOW != 0;
    let (state, detail) = match (find(PT_GNU_RELRO).is_some(), bind_now) {
        (true, true) => (ProtectionState::On, "Full RELRO"),
        (true, false) => (ProtectionState::Partial, "Partial RELRO"),
        _ => (ProtectionState::Off, "No RELRO"),
    };
    add(info, "RELRO", state, detail, RELRO);

    let names = symbol_names(elf);
    let canary = names
        .iter()
        .any(|n| n == "__stack_chk_fail" || n == "__stack_chk_guard");
    add(
        info,
        "Stack canary",
        on_off(canary),
        if canary {
            "uses __stack_chk_fail"
        } else {
            "no __stack_chk_fail"
        },
        CANARY,
    );
    let fortified = names
        .iter()
        .filter(|n| n.starts_with("__") && n.ends_with("_chk"))
        .count();
    add(
        info,
        "FORTIFY_SOURCE",
        on_off(fortified > 0),
        format!("{fortified} checked function(s)"),
        FORTIFY,
    );
    stripped(info);
}

pub fn macho(file: &object::File<'_>, info: &mut BinaryInfo) {
    const MH_PIE: u32 = 0x0020_0000;
    const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;
    if let FileFlags::MachO { flags } = file.flags() {
        let pie = flags.0 & MH_PIE != 0;
        add(info, "PIE", on_off(pie), "MH_PIE flag", PIE);
        let nx_heap = flags.0 & MH_NO_HEAP_EXECUTION != 0;
        add(
            info,
            "Non-executable heap",
            on_off(nx_heap),
            "MH_NO_HEAP_EXECUTION flag",
            DEP,
        );
    }
    stripped(info);
}

fn symbol_names<Elf: FileHeader>(elf: &ElfFile<'_, Elf>) -> Vec<String> {
    use object::ObjectSymbol;
    elf.symbols()
        .chain(elf.dynamic_symbols())
        .filter_map(|s| s.name().ok().map(str::to_owned))
        .collect()
}

fn stripped(info: &mut BinaryInfo) {
    let has_symbols =
        info.symbol_count > info.imports.len() + info.exports.len() || info.has_debug_info;
    add(
        info,
        "Stripped",
        on_off(!has_symbols),
        if info.has_debug_info {
            "debug info present"
        } else if has_symbols {
            "function names present"
        } else {
            "stripped: only imports/exports are named"
        },
        STRIPPED,
    );
}
