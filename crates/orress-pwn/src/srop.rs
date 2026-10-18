//! Sigreturn-oriented-programming frames (x86-64): build the `rt_sigframe` that `rt_sigreturn`
//! restores, so a single `sigreturn` call sets every register at once. Byte offsets follow the
//! Linux `struct sigcontext` inside the frame, as pwntools' `SigreturnFrame` uses them.

use std::collections::BTreeMap;

/// Total frame length we emit (through the signal mask).
const FRAME_LEN: usize = 248;
/// `csgsfs` default: `cs = 0x33` (64-bit user code segment), required for a valid return.
const CSGSFS_OFFSET: usize = 184;
const DEFAULT_CSGSFS: u64 = 0x33;

/// Byte offset of each saved register within the frame.
fn reg_offset(name: &str) -> Option<usize> {
    Some(match name {
        "r8" => 40,
        "r9" => 48,
        "r10" => 56,
        "r11" => 64,
        "r12" => 72,
        "r13" => 80,
        "r14" => 88,
        "r15" => 96,
        "rdi" => 104,
        "rsi" => 112,
        "rbp" => 120,
        "rbx" => 128,
        "rdx" => 136,
        "rax" => 144,
        "rcx" => 152,
        "rsp" => 160,
        "rip" => 168,
        "eflags" => 176,
        "csgsfs" => CSGSFS_OFFSET,
        _ => return None,
    })
}

/// Builds a sigreturn frame with the given registers set (names as in [`reg_offset`]); unset
/// registers are zero, except `csgsfs` which defaults to `0x33`.
pub fn sigreturn_frame(regs: &BTreeMap<String, u64>) -> Vec<u8> {
    let mut frame = vec![0u8; FRAME_LEN];
    frame[CSGSFS_OFFSET..CSGSFS_OFFSET + 8].copy_from_slice(&DEFAULT_CSGSFS.to_le_bytes());
    for (name, &value) in regs {
        if let Some(off) = reg_offset(name) {
            frame[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(frame: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(frame[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn registers_land_at_their_offsets() {
        let mut regs = BTreeMap::new();
        regs.insert("rip".into(), 0x401000);
        regs.insert("rsp".into(), 0x7fff_0000);
        regs.insert("rdi".into(), 0xdead);
        let frame = sigreturn_frame(&regs);
        assert_eq!(frame.len(), FRAME_LEN);
        assert_eq!(rd(&frame, 168), 0x401000); // rip
        assert_eq!(rd(&frame, 160), 0x7fff_0000); // rsp
        assert_eq!(rd(&frame, 104), 0xdead); // rdi
        assert_eq!(rd(&frame, CSGSFS_OFFSET), DEFAULT_CSGSFS); // cs defaulted
        assert_eq!(rd(&frame, 144), 0); // rax untouched
    }

    #[test]
    fn csgsfs_is_overridable() {
        let mut regs = BTreeMap::new();
        regs.insert("csgsfs".into(), 0x0);
        let frame = sigreturn_frame(&regs);
        assert_eq!(rd(&frame, CSGSFS_OFFSET), 0);
    }
}
