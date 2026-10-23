//! ARM 32-bit (AArch32) disassembly — ARM and Thumb instruction states — via `yaxpeax-arm`'s
//! `armv7` decoder (the same crate ARM64 uses, so no new dependency). The two states share this
//! decoder and the same `Instruction` type; `thumb` only selects how bytes are read (ARM is a
//! fixed 4 bytes, Thumb is 2 or 4).

use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand};

use crate::{Flow, Insn, Token, TokenKind};

/// The absolute target of a direct `B`/`BL`/`BLX(imm)` branch, decoded straight from the raw
/// bytes. We don't use yaxpeax's branch operand here: its Thumb offsets are off by a halfword or
/// two in places, and Thumb is a first-class target (Cortex-M firmware), so correctness matters.
/// The ARM PC reads as `address + 8`, the Thumb PC as `address + 4`; the standard encodings fold
/// those pipeline biases. Returns `None` for register-form (`BX`/`BLX reg`) and non-branches.
fn branch_target(bytes: &[u8], address: u64, thumb: bool, len: u8) -> Option<u64> {
    let sext = |v: u32, bits: u32| -> i64 { i64::from((v << (32 - bits)) as i32 >> (32 - bits)) };
    let at = |off: i64| address.wrapping_add(4).wrapping_add_signed(off);

    if !thumb {
        let w = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
        // B/BL: `cond 101L imm24`, with cond != 0b1111 (that encoding is BLX).
        if (w >> 25) & 0b111 == 0b101 {
            let imm = sext(w & 0x00ff_ffff, 24) * 4;
            let cond_f = (w >> 28) & 0xf == 0xf;
            // ARM PC = address + 8.
            let t = address.wrapping_add(8).wrapping_add_signed(imm);
            // BLX(imm) adds the H bit as a halfword and targets a word-aligned ARM/Thumb address.
            return Some(if cond_f {
                t.wrapping_add(((w >> 24) & 1) as u64 * 2)
            } else {
                t
            });
        }
        return None;
    }

    let hw0 = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    if len == 2 {
        // B<cond> T1: `1101 cccc imm8` (cond 0b111x is SVC/undefined, not a branch).
        if hw0 & 0xf000 == 0xd000 && (hw0 >> 9) & 0b111 != 0b111 {
            return Some(at(i64::from(hw0 as u8 as i8) * 2));
        }
        // B T2: `11100 imm11`.
        if hw0 & 0xf800 == 0xe000 {
            return Some(at(sext(u32::from(hw0 & 0x7ff), 11) * 2));
        }
        return None;
    }

    // 32-bit Thumb branches: `11110 … | 1 … imm11`.
    let hw1 = u16::from_le_bytes([*bytes.get(2)?, *bytes.get(3)?]);
    if hw0 & 0xf800 != 0xf000 || hw1 & 0x8000 == 0 {
        return None;
    }
    let s = u32::from((hw0 >> 10) & 1);
    let imm10 = u32::from(hw0 & 0x3ff);
    let imm11 = u32::from(hw1 & 0x7ff);
    let j1 = u32::from((hw1 >> 13) & 1);
    let j2 = u32::from((hw1 >> 11) & 1);
    let link_class = (hw1 >> 14) & 1 == 1; // 1 => BL/BLX, 0 => B.W (T3/T4)
    let hi_bit = (hw1 >> 12) & 1 == 1;

    if link_class || hi_bit {
        // BL/BLX and the unconditional B.W (T4) share the I1/I2 25-bit form.
        let i1 = 1 - (j1 ^ s);
        let i2 = 1 - (j2 ^ s);
        let imm = sext(
            (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1),
            25,
        );
        let t = at(imm);
        // BLX(imm): link_class set, hi_bit clear — target is word-aligned (ARM state).
        return Some(if link_class && !hi_bit { t & !3 } else { t });
    }
    // B<cond>.W T3: `11110 S cond imm6 | 10 J1 0 J2 imm11`.
    let imm6 = u32::from(hw0 & 0x3f);
    let imm = sext(
        (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1),
        21,
    );
    Some(at(imm))
}

/// The number of the register written by a `pc`-targeting data-processing / move instruction, or
/// whether a load/pop restores `pc` (bit 15 of a register list).
fn writes_pc(ins: &Instruction) -> bool {
    matches!(ins.operands[0], Operand::Reg(r) if r.number() == 15)
        || ins
            .operands
            .iter()
            .any(|op| matches!(op, Operand::RegList(list) if list & (1 << 15) != 0))
}

/// Whether the only (first) operand is register `lr` — `bx lr` / `mov pc, lr` returns.
fn reads_lr(ins: &Instruction) -> bool {
    ins.operands
        .iter()
        .any(|op| matches!(op, Operand::Reg(r) if r.number() == 14))
}

/// The absolute address a `ldr rX, [pc, #imm]` literal-pool load reads from.
fn literal_ref(ins: &Instruction, address: u64, thumb: bool) -> Option<u64> {
    if ins.opcode != Opcode::LDR {
        return None;
    }
    ins.operands.iter().find_map(|op| {
        let (base, off, add) = match op {
            Operand::RegDerefPreindexOffset(r, off, add, _) => (r.number(), u64::from(*off), *add),
            _ => return None,
        };
        if base != 15 {
            return None;
        }
        // The ARM PC reads as address+8; the Thumb PC as (address+4) word-aligned.
        let pc = if thumb {
            (address + 4) & !3
        } else {
            address + 8
        };
        Some(if add { pc + off } else { pc.wrapping_sub(off) })
    })
}

pub fn decode(bytes: &[u8], address: u64, thumb: bool) -> Option<Insn> {
    let min = if thumb { 2 } else { 4 };
    if bytes.len() < min {
        return None;
    }
    let mut reader = U8Reader::new(bytes);
    let ins = InstDecoder::default()
        .with_thumb_mode(thumb)
        .decode(&mut reader)
        .ok()?;
    let len: u8 = if ins.thumb && !ins.wide { 2 } else { 4 };

    let target = branch_target(bytes, address, thumb, len);
    let pc_write = writes_pc(&ins);

    let flow = match ins.opcode {
        Opcode::B => match target {
            Some(t) if ins.condition == ConditionCode::AL => Flow::Jump(t),
            Some(t) => Flow::CondJump(t),
            None => Flow::Stop,
        },
        Opcode::BL => target.map_or(Flow::Stop, Flow::Call),
        // BLX with an immediate is a call; BLX to a register is an indirect call.
        Opcode::BLX => target.map_or(Flow::IndirectCall { slot: None }, Flow::Call),
        // `bx lr` returns; `bx reg` is a computed jump.
        Opcode::BX | Opcode::BXJ => {
            if reads_lr(&ins) {
                Flow::Return
            } else {
                Flow::IndirectJump {
                    slot: None,
                    table: None,
                }
            }
        }
        // `pop {…, pc}` / `ldm sp!, {…, pc}` restores the saved return address.
        Opcode::POP | Opcode::LDM(..) if pc_write => Flow::Return,
        // `mov pc, lr` returns; any other write to pc is a computed jump.
        _ if pc_write && reads_lr(&ins) => Flow::Return,
        _ if pc_write => Flow::IndirectJump {
            slot: None,
            table: None,
        },
        Opcode::BKPT | Opcode::UDF => Flow::Stop,
        _ => Flow::Next,
    };
    // A predicated (non-`AL`) return or computed jump falls through when its condition is false —
    // e.g. `bxlt lr` (an early-return guard). Treat it as fall-through so the rest of the function
    // is still discovered; its conditional effect is recovered by the decompiler.
    let flow = if ins.condition != ConditionCode::AL
        && matches!(flow, Flow::Return | Flow::IndirectJump { .. })
    {
        Flow::Next
    } else {
        flow
    };

    let mut data_refs = Vec::new();
    if let Some(addr) = literal_ref(&ins, address, thumb) {
        data_refs.push(addr);
    }

    let text = ins.to_string();
    let (mnemonic, rest) = text.split_once(' ').unwrap_or((text.as_str(), ""));
    let operands = tokenize(rest, target);

    Some(Insn {
        address,
        len,
        mnemonic: mnemonic.to_owned(),
        operands,
        flow,
        data_refs,
    })
}

/// Splits the operand text at top-level commas (ignoring commas inside `{…}` register lists and
/// `[…]` memory operands) and classifies each piece. A `$`-relative branch becomes the absolute
/// target so the UI can make it clickable.
fn tokenize(text: &str, pc_target: Option<u64>) -> Vec<Token> {
    let mut parts: Vec<&str> = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in text.char_indices() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);

    let mut out = Vec::new();
    for (i, part) in parts.into_iter().enumerate() {
        if i > 0 {
            out.push(Token {
                kind: TokenKind::Punct,
                text: ",".into(),
            });
        }
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (kind, shown) = if part.starts_with('$') || part.starts_with("#$") {
            match pc_target {
                Some(t) => (TokenKind::Address(t), format!("0x{t:x}")),
                None => (TokenKind::Number, part.to_owned()),
            }
        } else if part.starts_with('#') || part.starts_with("0x") {
            (TokenKind::Number, part.to_owned())
        } else if is_register(part) {
            (TokenKind::Register, part.to_owned())
        } else {
            (TokenKind::Text, part.to_owned())
        };
        out.push(Token { kind, text: shown });
    }
    out
}

/// Whether `s` names an ARM general-purpose register (`r0`–`r15` and the usual aliases).
fn is_register(s: &str) -> bool {
    matches!(s, "sp" | "lr" | "pc" | "fp" | "ip" | "sl" | "sb")
        || (s.starts_with('r') && s.len() >= 2 && s[1..].parse::<u8>().is_ok_and(|n| n <= 15))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode one ARM instruction from a 32-bit word.
    fn arm(word: u32, addr: u64) -> Insn {
        decode(&word.to_le_bytes(), addr, false).expect("arm decode")
    }
    /// Decode one Thumb instruction (`word` holds up to 4 little-endian bytes; a 16-bit
    /// instruction uses the low two).
    fn thumb(word: u32, addr: u64) -> Insn {
        decode(&word.to_le_bytes(), addr, true).expect("thumb decode")
    }

    #[test]
    fn arm_data_processing_and_return() {
        let add = arm(0xe081_0000, 0x1000); // add r0, r1, r0
        assert_eq!(add.mnemonic, "add");
        assert_eq!(add.flow, Flow::Next);
        assert_eq!(add.len, 4);
        assert_eq!(arm(0xe12f_ff1e, 0x1004).flow, Flow::Return); // bx lr
        assert_eq!(arm(0xe8bd_8830, 0x1008).flow, Flow::Return); // pop {r4,r5,fp,pc}
    }

    #[test]
    fn arm_branches_resolve_targets() {
        // blt 0x10234 (forward conditional), from 0x10210.
        assert_eq!(arm(0xba00_0007, 0x10210).flow, Flow::CondJump(0x10234));
        // b 0x10238, from 0x10230.
        assert_eq!(arm(0xea00_0000, 0x10230).flow, Flow::Jump(0x10238));
        // bl shifted @ 0x101f4, from 0x10234 (negative displacement).
        assert_eq!(arm(0xebff_ffee, 0x10234).flow, Flow::Call(0x101f4));
    }

    #[test]
    fn arm_pc_relative_literal_load() {
        // ldr r0, [pc, #8] at 0x1000 reads from (0x1000 + 8) + 8 = 0x1010.
        let ldr = arm(0xe59f_0008, 0x1000);
        assert_eq!(ldr.mnemonic, "ldr");
        assert_eq!(ldr.data_refs, vec![0x1010]);
    }

    #[test]
    fn thumb_lengths_and_returns() {
        assert_eq!(thumb(0x0000_4770, 0x1000).flow, Flow::Return); // bx lr (16-bit)
        assert_eq!(thumb(0x0000_4770, 0x1000).len, 2);
        assert_eq!(thumb(0x0000_bdb0, 0x1004).flow, Flow::Return); // pop {..,pc} (16-bit)
        // umull.w is a 32-bit Thumb instruction.
        assert_eq!(thumb(0x1301_fba2, 0x1008).len, 4);
    }

    #[test]
    fn thumb_branches_resolve_targets() {
        assert_eq!(thumb(0x0000_db0b, 0x101fa).flow, Flow::CondJump(0x10214)); // blt (T1)
        assert_eq!(thumb(0x0000_e000, 0x10212).flow, Flow::Jump(0x10216)); // b (T2)
        // bl.w loop/shifted @ 0x101f0, from 0x1021c (32-bit, J1/J2 encoding).
        let bl = thumb(0xffe8_f7ff, 0x1021c);
        assert_eq!(bl.flow, Flow::Call(0x101f0));
        assert_eq!(bl.len, 4);
    }
}
