//! Finding `main`. The entry point of a C program is runtime start-up code, not the
//! programmer's main function. Recognizing the start-up pattern saves beginners from
//! getting lost in it.

use orress_loaders::BinaryInfo;

use crate::{Flow, NameKind, Program};

pub fn find_main(p: &Program, info: &BinaryInfo) -> Option<u64> {
    // A symbol named main wins.
    if let Some((&addr, _)) = p
        .names
        .iter()
        .find(|(_, n)| n.kind == NameKind::Symbol && (n.text == "main" || n.text == "_main"))
    {
        return Some(addr);
    }
    info.entry
        .and_then(|entry| libc_start_main(p, entry))
        .or_else(|| msvc_main(p).map(|(addr, _)| addr))
}

/// Rust programs have a small C-level `main` that passes the address of the real
/// `main` to the standard library's start-up code (`std::rt::lang_start`). Returns
/// that address when `c_main` looks like this shim.
pub fn rust_user_main(p: &Program, info: &BinaryInfo, c_main: u64) -> Option<u64> {
    let is_rust = info.detections.iter().any(|d| d.name == "Rust");
    if !is_rust {
        return None;
    }
    let mut addr = c_main;
    for _ in 0..24 {
        let insn = p.decode(addr)?;
        if matches!(
            insn.mnemonic.as_str(),
            "lea" | "mov" | "adrp" | "adr" | "add"
        ) && let Some(&target) = insn
            .data_refs
            .iter()
            .find(|&&r| p.memory.is_code(r) && r != c_main)
        {
            return Some(target);
        }
        if !insn.flow.falls_through() {
            return None;
        }
        addr = insn.end();
    }
    None
}

fn is_thunk(p: &Program, addr: u64) -> bool {
    p.functions
        .get(&addr)
        .is_some_and(|f| f.kind == crate::FunctionKind::Thunk)
}

/// Instructions that call an import, directly through its slot or through a stub
/// (`jmp [slot]`) that the compiler placed in between.
fn call_sites(p: &Program, slot: u64) -> Vec<u64> {
    let mut out = Vec::new();
    for xref in p.xrefs(slot) {
        if is_thunk(p, xref.from) {
            out.extend(p.xrefs(xref.from).iter().map(|x| x.from));
        } else {
            out.push(xref.from);
        }
    }
    out
}

/// Name for the detected main: `WinMain` for GUI programs, `main` otherwise.
pub fn main_name(p: &Program) -> &'static str {
    match msvc_main(p) {
        Some((_, true)) => "WinMain",
        _ => "main",
    }
}

/// MSVC C runtime: `invoke_main` fetches argc/argv (or the WinMain command line) from
/// the CRT DLL right before calling main, so the first direct call after those
/// imports is main. Returns the address and whether it is WinMain.
fn msvc_main(p: &Program) -> Option<(u64, bool)> {
    const ARGS: [&str; 4] = [
        "__p___argc",
        "__p___argv",
        "__p___wargv",
        "_get_initial_narrow_environment",
    ];
    const WINMAIN: [&str; 2] = [
        "_get_wide_winmain_command_line",
        "_get_narrow_winmain_command_line",
    ];
    for (&slot, name) in p.names.iter().filter(|(_, n)| n.kind == NameKind::Import) {
        let crt = crt_name(&name.text);
        let winmain = WINMAIN.contains(&crt);
        if !winmain && !ARGS.contains(&crt) {
            continue;
        }
        for from in call_sites(p, slot) {
            let Some(mut addr) = p.decode(from).map(|i| i.end()) else {
                continue;
            };
            for _ in 0..16 {
                let Some(insn) = p.decode(addr) else {
                    break;
                };
                match insn.flow {
                    Flow::Call(target) if p.memory.is_code(target) && !is_thunk(p, target) => {
                        return Some((target, winmain));
                    }
                    f if !f.falls_through() => break,
                    _ => {}
                }
                addr = insn.end();
            }
        }
    }
    exit_after_main(p).map(|addr| (addr, false))
}

/// Older and other C runtimes: `exit(main(argc, argv, envp))`. The last direct call
/// shortly before the call to `exit` is main.
fn exit_after_main(p: &Program) -> Option<u64> {
    for (&slot, _) in p.names.iter().filter(|(_, n)| {
        n.kind == NameKind::Import && matches!(crt_name(&n.text), "exit" | "_exit" | "_cexit")
    }) {
        for from in call_sites(p, slot) {
            let Some(function) = p.function_containing(from) else {
                continue;
            };
            let mut insns: Vec<u64> = function
                .blocks
                .iter()
                .flat_map(|b| b.insns.iter().copied())
                .collect();
            insns.sort_unstable();
            let Some(at) = insns.iter().position(|&a| a == from) else {
                continue;
            };
            let found = insns[at.saturating_sub(8)..at].iter().rev().find_map(|&a| {
                match p.decode(a)?.flow {
                    Flow::Call(t)
                        if p.memory.is_code(t)
                            && p.functions.get(&t).is_some_and(|f| f.insn_count() > 3) =>
                    {
                        Some(t)
                    }
                    _ => None,
                }
            });
            if found.is_some() {
                return found;
            }
        }
    }
    None
}

/// glibc start-up: `_start` loads the address of main into the first argument register
/// (rdi on x86-64, a push on 32-bit x86, x0 on ARM64) and calls __libc_start_main.
fn libc_start_main(p: &Program, entry: u64) -> Option<u64> {
    let mut candidate = None;
    // ARM64 `adrp x0, page`: the page base itself need not be code (it can lie below `.text`);
    // only the full address after the following `add` is validated.
    let mut page = None;
    let mut addr = entry;
    for _ in 0..40 {
        let insn = p.decode(addr)?;
        let ops = insn.text();
        let to_x0 = ops.contains(" x0,");
        // Track the last address-like value placed where main's address goes.
        let first_arg = matches!(insn.mnemonic.as_str(), "lea" | "mov")
            && (ops.contains(" rdi,") || ops.contains(" edi,"))
            || insn.mnemonic == "push"
            || (insn.mnemonic == "adr" && to_x0);
        if first_arg && let Some(&r) = insn.data_refs.first().filter(|&&r| p.memory.is_code(r)) {
            candidate = Some(r);
        }
        if insn.mnemonic == "adrp" && to_x0 {
            page = insn.data_refs.first().copied();
        }
        if insn.mnemonic == "add" && to_x0 {
            // ARM64: adrp x0, page; add x0, x0, #off
            if let (Some(pg), Some(off)) = (
                page.take(),
                insn.operands.last().and_then(|t| parse_imm(&t.text)),
            ) {
                candidate = pg.checked_add(off).filter(|&c| p.memory.is_code(c));
            }
        }
        // ARM64 `ldr x0, =main`: a PC-relative load of main's address from a literal pool.
        if insn.mnemonic == "ldr"
            && to_x0
            && let Some(&lit) = insn.data_refs.first()
            && let Some(bytes) = p.memory.read(lit, 8)
            && let Ok(bytes) = <[u8; 8]>::try_from(bytes)
        {
            let value = u64::from_le_bytes(bytes);
            if p.memory.is_code(value) {
                candidate = Some(value);
            }
        }
        let calls_start_main = match insn.flow {
            Flow::Call(t) => p
                .name(t)
                .is_some_and(|n| n.text.contains("__libc_start_main")),
            Flow::IndirectCall { slot: Some(s) } => p
                .name(s)
                .is_some_and(|n| n.text.contains("__libc_start_main")),
            _ => false,
        };
        if calls_start_main {
            return candidate.filter(|&c| p.memory.is_code(c));
        }
        if !insn.flow.falls_through() {
            return None;
        }
        addr = insn.end();
    }
    None
}

/// Windows' own programs import the C runtime from a private DLL whose functions carry
/// an `_o_` prefix (`_o_exit`, `_o__get_wide_winmain_command_line`).
fn crt_name(name: &str) -> &str {
    name.strip_prefix("_o_").unwrap_or(name)
}

fn parse_imm(text: &str) -> Option<u64> {
    let t = text.trim_start_matches('#');
    match t.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse().ok(),
    }
}
