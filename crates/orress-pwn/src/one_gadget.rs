//! A pragmatic "one_gadget" finder: scan a libc's executable bytes for a single address that, when
//! jumped to, runs `execve("/bin/sh", …)` — the magic gadgets used to pop a shell from a single
//! control-flow hijack. This is a heuristic scanner (match the common shapes), not a full
//! constraint solver like the `one_gadget` tool, so it reports candidate addresses and the register
//! preconditions it could not already see satisfied.

use orress_arch::{Flow, Isa, decode};

/// A candidate one-shot execve gadget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneGadget {
    pub addr: u64,
    /// Register preconditions still to satisfy (e.g. argv/envp must be NULL).
    pub constraints: Vec<String>,
}

/// Finds candidate one_gadgets in `exec` (each `(virtual base, bytes)`). `binsh` is the address of
/// the `"/bin/sh"` string; `execve` lists the addresses of `execve` (direct call targets) to match.
pub fn find_one_gadgets(exec: &[(u64, &[u8])], binsh: u64, execve: &[u64], isa: Isa) -> Vec<OneGadget> {
    let mut out = Vec::new();
    for &(base, bytes) in exec {
        let mut off = 0usize;
        let mut gadget: Option<u64> = None; // address that sets rdi = &"/bin/sh"
        let mut rsi_null = false;
        let mut rdx_null = false;
        while off < bytes.len() {
            let Some(insn) = decode(isa, &bytes[off..(off + 15).min(bytes.len())], base + off as u64)
            else {
                off += 1;
                continue;
            };
            if insn.len == 0 {
                off += 1;
                continue;
            }
            let addr = base + off as u64;
            let text = insn.text();

            if writes_reg(&text, "di") && insn.data_refs.contains(&binsh) {
                // rdi <- &"/bin/sh"
                gadget = Some(addr);
                rsi_null = false;
                rdx_null = false;
            } else if is_zeroed(&text, "si") {
                rsi_null = true;
            } else if is_zeroed(&text, "dx") {
                rdx_null = true;
            } else if writes_reg(&text, "di") {
                gadget = None; // rdi clobbered with something else
            } else if matches!(insn.flow, Flow::Return | Flow::Jump(_)) {
                gadget = None;
                rsi_null = false;
                rdx_null = false;
            }

            let reaches_execve = match insn.flow {
                Flow::Call(t) => execve.contains(&t),
                _ => insn.mnemonic == "syscall",
            };
            if reaches_execve
                && let Some(g) = gadget.take()
            {
                let mut constraints = Vec::new();
                if !rsi_null {
                    constraints.push("rsi (argv) == NULL".into());
                }
                if !rdx_null {
                    constraints.push("rdx (envp) == NULL".into());
                }
                out.push(OneGadget {
                    addr: g,
                    constraints,
                });
            }
            off += usize::from(insn.len);
        }
    }
    out.sort_by_key(|g| g.addr);
    out.dedup_by_key(|g| g.addr);
    out
}

/// Whether `text` writes register `r{suffix}`/`e{suffix}` as its destination (a `mov`/`lea`/`pop`).
fn writes_reg(text: &str, suffix: &str) -> bool {
    let (r, e) = (format!("r{suffix}"), format!("e{suffix}"));
    for m in ["mov", "lea", "pop", "xor", "add", "sub"] {
        if text.starts_with(&format!("{m} {r},")) || text.starts_with(&format!("{m} {e},")) {
            return true;
        }
        if m == "pop" && (text == format!("pop {r}") || text == format!("pop {e}")) {
            return true;
        }
    }
    false
}

/// Whether `text` zeroes register `{suffix}` (`xor esi, esi` / `xor rsi, rsi` / `mov esi, 0`).
fn is_zeroed(text: &str, suffix: &str) -> bool {
    let (r, e) = (format!("r{suffix}"), format!("e{suffix}"));
    // The disassembler formats operands with no space after the comma ("xor esi,esi").
    text == format!("xor {e},{e}")
        || text == format!("xor {r},{r}")
        || text == format!("mov {e},0")
        || text == format!("mov {r},0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_an_execve_gadget_with_no_outstanding_constraints() {
        // lea rdi, [rip+0] resolves to the next instruction's address; point "/bin/sh" there,
        // then null argv/envp and syscall.
        let base = 0x1000u64;
        let bytes = orress_asm::assemble(
            "lea rdi, [rip+0]\nxor esi, esi\nxor edx, edx\nsyscall",
            orress_asm::Arch::X64,
            base,
        )
        .unwrap()
        .bytes;
        // The lea is 7 bytes, so rip+0 resolves to base+7.
        let binsh = base + 7;
        let gadgets = find_one_gadgets(&[(base, &bytes)], binsh, &[], Isa::X64);
        assert_eq!(gadgets.len(), 1, "gadgets: {gadgets:?}");
        assert_eq!(gadgets[0].addr, base);
        assert!(gadgets[0].constraints.is_empty(), "{:?}", gadgets[0].constraints);
    }

    #[test]
    fn reports_outstanding_null_constraints() {
        let base = 0x2000u64;
        let bytes = orress_asm::assemble("lea rdi, [rip+0]\nsyscall", orress_asm::Arch::X64, base)
            .unwrap()
            .bytes;
        let binsh = base + 7;
        let gadgets = find_one_gadgets(&[(base, &bytes)], binsh, &[], Isa::X64);
        assert_eq!(gadgets.len(), 1);
        assert_eq!(gadgets[0].constraints.len(), 2); // rsi and rdx must be NULL
    }
}
