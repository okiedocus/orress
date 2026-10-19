//! Byte patches for common edits: remove an instruction, invert a condition, or make a
//! conditional jump unconditional. These are the classic crackme patches.

use crate::Isa;

/// Bytes that replace an instruction of `len` bytes with "do nothing".
///
/// ARM64 instructions are 4 bytes each: a `len` that is not a multiple of 4 cannot be
/// filled with NOPs, so this returns an empty patch (no change) rather than covering only
/// part of the range. Use [`try_nop`] to detect that case.
pub fn nop(isa: Isa, len: usize) -> Vec<u8> {
    try_nop(isa, len).unwrap_or_default()
}

/// Like [`nop`], but `None` when `len` cannot be covered exactly by NOPs (ARM64 with a
/// length that is not a multiple of 4).
pub fn try_nop(isa: Isa, len: usize) -> Option<Vec<u8>> {
    match isa {
        Isa::X86 | Isa::X64 => Some(vec![0x90; len]),
        // ARM64 instructions are 4 bytes; NOP is d503201f.
        Isa::Arm64 => len
            .is_multiple_of(4)
            .then(|| 0xd503_201fu32.to_le_bytes().repeat(len / 4)),
        // RISC-V base instructions are 4 bytes; NOP is `addi x0,x0,0` = 0x00000013.
        Isa::Riscv64 => len
            .is_multiple_of(4)
            .then(|| 0x0000_0013u32.to_le_bytes().repeat(len / 4)),
        // MIPS NOP is all-zero (sll $zero,$zero,0).
        Isa::Mips32 | Isa::Mips32El | Isa::Mips64 | Isa::Mips64El => {
            len.is_multiple_of(4).then(|| vec![0u8; len])
        }
    }
}

/// `b.cond` (B.cond: `0101_0100 imm19 0 cond`).
fn is_bcond(word: u32) -> bool {
    word & 0xff00_0010 == 0x5400_0000
}

/// `cbz`/`cbnz` (32- or 64-bit).
fn is_cbz(word: u32) -> bool {
    word & 0x7e00_0000 == 0x3400_0000
}

/// `tbz`/`tbnz`.
fn is_tbz(word: u32) -> bool {
    word & 0x7e00_0000 == 0x3600_0000
}

/// Sign-extends the `bits`-wide field of `word` starting at bit 5 (the branch offset in
/// instruction units).
fn branch_field(word: u32, bits: u32) -> i32 {
    let raw = (word >> 5) & ((1 << bits) - 1);
    ((raw << (32 - bits)) as i32) >> (32 - bits)
}

/// Inverts a conditional jump (je <-> jne, jl <-> jge, ...). `None` if the instruction
/// is not a conditional jump this function knows.
pub fn invert(isa: Isa, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = bytes.to_vec();
    match isa {
        Isa::X86 | Isa::X64 => match bytes {
            // Short jcc: 70..7F rel8. Opcodes come in pairs that differ in the low bit.
            [op @ 0x70..=0x7f, _] => out[0] = op ^ 1,
            // Near jcc: 0F 80..8F rel32.
            [0x0f, op @ 0x80..=0x8f, _, _, _, _] => out[1] = op ^ 1,
            _ => return None,
        },
        Isa::Arm64 => {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            let new = if is_bcond(word) {
                // b.al / b.nv (condition 111x) always branch: there is no inverse.
                if word & 0xe == 0xe {
                    return None;
                }
                // b.cond: the lowest condition bit flips the condition.
                word ^ 1
            } else if is_cbz(word) || is_tbz(word) {
                // cbz <-> cbnz, tbz <-> tbnz: bit 24.
                word ^ (1 << 24)
            } else {
                return None;
            };
            out[..4].copy_from_slice(&new.to_le_bytes());
        }
        // Branch patching for RISC-V is not implemented yet.
        Isa::Riscv64 | Isa::Mips32 | Isa::Mips32El | Isa::Mips64 | Isa::Mips64El => return None,
    }
    Some(out)
}

/// Turns a conditional jump into an unconditional one with the same target.
pub fn force(isa: Isa, bytes: &[u8]) -> Option<Vec<u8>> {
    match isa {
        Isa::X86 | Isa::X64 => match bytes {
            [0x70..=0x7f, rel] => Some(vec![0xeb, *rel]),
            // jcc rel32 is 6 bytes, jmp rel32 is 5: a NOP first keeps the same end address,
            // so the relative offset stays valid.
            [0x0f, 0x80..=0x8f, r0, r1, r2, r3] => Some(vec![0x90, 0xe9, *r0, *r1, *r2, *r3]),
            _ => None,
        },
        Isa::Arm64 => {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            let new = if is_bcond(word) {
                // b.cond with condition AL (0b1110) always branches.
                (word & !0xf) | 0xe
            } else if is_cbz(word) || is_tbz(word) {
                // cbz/cbnz (imm19) and tbz/tbnz (imm14) become `b` (imm26) with the same
                // PC-relative offset: same address, same target.
                let off = if is_cbz(word) {
                    branch_field(word, 19)
                } else {
                    branch_field(word, 14)
                };
                0x1400_0000 | (off as u32 & 0x03ff_ffff)
            } else {
                return None;
            };
            Some(new.to_le_bytes().to_vec())
        }
        Isa::Riscv64 | Isa::Mips32 | Isa::Mips32El | Isa::Mips64 | Isa::Mips64El => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Flow, decode};

    #[test]
    fn x86_jump_patches_keep_targets() {
        // je +0x10 at 0x1000 (short) and jne +0x100 (near).
        let short = [0x74, 0x10];
        let near = [0x0f, 0x85, 0x00, 0x01, 0x00, 0x00];
        let inv = invert(Isa::X64, &short).unwrap();
        assert_eq!(decode(Isa::X64, &inv, 0x1000).unwrap().mnemonic, "jne");
        let forced = force(Isa::X64, &short).unwrap();
        assert_eq!(
            decode(Isa::X64, &forced, 0x1000).unwrap().flow,
            Flow::Jump(0x1012)
        );

        let inv = invert(Isa::X64, &near).unwrap();
        assert_eq!(decode(Isa::X64, &inv, 0x1000).unwrap().mnemonic, "je");
        // Forced near jump: NOP then jmp, landing on the original target 0x1106.
        let forced = force(Isa::X64, &near).unwrap();
        assert_eq!(decode(Isa::X64, &forced, 0x1000).unwrap().mnemonic, "nop");
        assert_eq!(
            decode(Isa::X64, &forced[1..], 0x1001).unwrap().flow,
            Flow::Jump(0x1106)
        );

        assert_eq!(invert(Isa::X64, &[0x90]), None);
        assert_eq!(nop(Isa::X64, 3), vec![0x90; 3]);
    }

    #[test]
    fn arm64_patches() {
        // b.eq +8 -> b.ne +8
        let beq = 0x5400_0040u32.to_le_bytes();
        let bne = invert(Isa::Arm64, &beq).unwrap();
        assert_eq!(decode(Isa::Arm64, &bne, 0).unwrap().mnemonic, "b.ne");
        // cbz -> cbnz
        let cbz = 0xb400_0080u32.to_le_bytes();
        assert_eq!(
            decode(Isa::Arm64, &invert(Isa::Arm64, &cbz).unwrap(), 0)
                .unwrap()
                .mnemonic,
            "cbnz"
        );
        let forced = force(Isa::Arm64, &beq).unwrap();
        assert!(matches!(
            decode(Isa::Arm64, &forced, 0).unwrap().flow,
            Flow::Jump(8) | Flow::CondJump(8)
        ));
        assert_eq!(
            decode(Isa::Arm64, &nop(Isa::Arm64, 4), 0).unwrap().mnemonic,
            "nop"
        );
    }

    #[test]
    fn arm64_always_branches_do_not_invert() {
        // b.al +8 and b.nv +8 always branch; flipping the low bit would not invert them.
        assert_eq!(invert(Isa::Arm64, &0x5400_004eu32.to_le_bytes()), None);
        assert_eq!(invert(Isa::Arm64, &0x5400_004fu32.to_le_bytes()), None);
    }

    #[test]
    fn arm64_force_compare_branches() {
        // cbz x0, +0x10 at 0x1000 -> b 0x1010
        let cbz = 0xb400_0080u32.to_le_bytes();
        let forced = force(Isa::Arm64, &cbz).unwrap();
        assert_eq!(
            decode(Isa::Arm64, &forced, 0x1000).unwrap().flow,
            Flow::Jump(0x1010)
        );
        // cbnz w1, -0x8 at 0x1000 -> b 0xff8
        let cbnz = (0x3500_0001u32 | ((0x7fffe & 0x7ffff) << 5)).to_le_bytes();
        let forced = force(Isa::Arm64, &cbnz).unwrap();
        assert_eq!(
            decode(Isa::Arm64, &forced, 0x1000).unwrap().flow,
            Flow::Jump(0xff8)
        );
        // tbnz x2, #3, +0x20 at 0x2000 -> b 0x2020
        let tbnz = (0x3718_0002u32 | (8 << 5)).to_le_bytes();
        assert_eq!(decode(Isa::Arm64, &tbnz, 0x2000).unwrap().mnemonic, "tbnz");
        let forced = force(Isa::Arm64, &tbnz).unwrap();
        assert_eq!(
            decode(Isa::Arm64, &forced, 0x2000).unwrap().flow,
            Flow::Jump(0x2020)
        );
        // Not a conditional branch.
        assert_eq!(force(Isa::Arm64, &0xd503_201fu32.to_le_bytes()), None);
    }

    #[test]
    fn arm64_nop_requires_whole_instructions() {
        assert_eq!(try_nop(Isa::Arm64, 6), None);
        assert!(nop(Isa::Arm64, 6).is_empty());
        assert_eq!(try_nop(Isa::Arm64, 8).map(|b| b.len()), Some(8));
        assert_eq!(try_nop(Isa::X64, 3), Some(vec![0x90; 3]));
    }
}
