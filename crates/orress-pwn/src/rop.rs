//! A ROP gadget finder: scan a binary's executable bytes for short instruction sequences that end
//! in a `ret` (or `syscall`), the building blocks of a return-oriented-programming chain.

use orress_arch::{Flow, Isa, decode};

/// One gadget: its virtual address and its instructions as text (`"pop rdi ; ret"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gadget {
    pub addr: u64,
    pub text: String,
}

/// How far back (in bytes) from a terminator to look for a gadget start.
fn max_back(max_insns: usize) -> usize {
    max_insns * 10
}

/// A gadget terminator and its byte length.
struct Terminator {
    offset: usize,
    len: usize,
}

/// Finds every gadget in `sections` (each `(virtual base, bytes)`), up to `max_insns` instructions
/// before the terminator. Results are unique by address and sorted.
pub fn find_gadgets(sections: &[(u64, &[u8])], isa: Isa, max_insns: usize) -> Vec<Gadget> {
    let mut out = Vec::new();
    for &(base, bytes) in sections {
        for term in terminators(bytes) {
            let back = term.offset.saturating_sub(max_back(max_insns));
            for start in back..=term.offset {
                if let Some(text) = gadget_at(bytes, base, isa, start, &term, max_insns) {
                    out.push(Gadget {
                        addr: base + start as u64,
                        text,
                    });
                }
            }
        }
    }
    out.sort_by_key(|g| g.addr);
    out.dedup_by_key(|g| g.addr);
    out
}

/// The offsets of gadget terminators in `bytes`: `ret` (0xc3), `ret imm16` (0xc2) and `syscall`
/// (0f 05). A given start can only reach the first terminator it hits (a `ret` in the middle breaks
/// the chain), so terminators never produce duplicate gadget addresses.
fn terminators(bytes: &[u8]) -> Vec<Terminator> {
    let mut t: Vec<Terminator> = Vec::new();
    for off in memchr::memchr_iter(0xc3, bytes) {
        t.push(Terminator {
            offset: off,
            len: 1,
        });
    }
    for off in memchr::memchr_iter(0xc2, bytes) {
        t.push(Terminator {
            offset: off,
            len: 3,
        });
    }
    for off in memchr::memmem::find_iter(bytes, &[0x0f, 0x05]) {
        t.push(Terminator {
            offset: off,
            len: 2,
        });
    }
    t
}

/// A window of up to 15 bytes starting at `pos` (enough for any x86 instruction).
fn window(bytes: &[u8], pos: usize) -> &[u8] {
    &bytes[pos..(pos + 15).min(bytes.len())]
}

/// Tries to read a gadget from `start` up to and including the terminator at `term.offset`:
/// every instruction before the terminator must be a plain (non-branching) instruction, the chain
/// must land exactly on the terminator, and there must be at most `max_insns` of them.
fn gadget_at(
    bytes: &[u8],
    base: u64,
    isa: Isa,
    start: usize,
    term: &Terminator,
    max_insns: usize,
) -> Option<String> {
    let mut pos = start;
    let mut parts: Vec<String> = Vec::new();
    while pos < term.offset {
        if parts.len() >= max_insns {
            return None;
        }
        let insn = decode(isa, window(bytes, pos), base + pos as u64)?;
        if insn.len == 0 || !matches!(insn.flow, Flow::Next) {
            return None; // zero-length, or a branch/stop before the terminator
        }
        parts.push(insn.text());
        pos += usize::from(insn.len);
    }
    if pos != term.offset {
        return None; // the last instruction overran the terminator
    }
    let term_insn = decode(isa, window(bytes, term.offset), base + term.offset as u64)?;
    if usize::from(term_insn.len) != term.len {
        return None;
    }
    parts.push(term_insn.text());
    Some(parts.join(" ; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assembles x86-64 and returns the bytes.
    fn asm(src: &str) -> Vec<u8> {
        orress_asm::assemble(src, orress_asm::Arch::X64, 0)
            .expect("assemble")
            .bytes
    }

    #[test]
    fn finds_pop_rdi_ret_and_syscall() {
        // A blob with a classic `pop rdi ; ret` and a `syscall` gadget.
        let bytes = asm("pop rdi\nret\nsyscall\nret\nnop");
        let gadgets = find_gadgets(&[(0x400000, &bytes)], Isa::X64, 6);
        assert!(
            gadgets.iter().any(|g| g.text == "pop rdi ; ret"),
            "gadgets: {:?}",
            gadgets.iter().map(|g| &g.text).collect::<Vec<_>>()
        );
        assert!(gadgets.iter().any(|g| g.text == "ret"));
        assert!(gadgets.iter().any(|g| g.text.starts_with("syscall")));
        // Addresses are real (base-relative) and unique.
        let addrs: std::collections::HashSet<u64> = gadgets.iter().map(|g| g.addr).collect();
        assert_eq!(addrs.len(), gadgets.len());
    }
}
