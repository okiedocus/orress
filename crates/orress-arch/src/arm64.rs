use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

use crate::{Flow, Insn, Token, TokenKind};

fn pc_offset(ins: &Instruction) -> Option<i64> {
    ins.operands.iter().find_map(|op| match op {
        Operand::PCOffset(off) => Some(*off),
        _ => None,
    })
}

pub fn decode(bytes: &[u8], address: u64) -> Option<Insn> {
    let word = bytes.get(..4)?;
    let mut reader = U8Reader::new(word);
    let ins = InstDecoder::default().decode(&mut reader).ok()?;
    let target = pc_offset(&ins).map(|off| address.wrapping_add_signed(off));

    let flow = match ins.opcode {
        Opcode::B => target.map_or(Flow::Stop, Flow::Jump),
        Opcode::BL => target.map_or(Flow::Stop, Flow::Call),
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            target.map_or(Flow::Next, Flow::CondJump)
        }
        // Pointer-authenticated (PAC) variants branch exactly like their plain forms.
        Opcode::BR | Opcode::BRAA | Opcode::BRAAZ | Opcode::BRAB | Opcode::BRABZ => {
            Flow::IndirectJump {
                slot: None,
                table: None,
            }
        }
        Opcode::BLR | Opcode::BLRAA | Opcode::BLRAAZ | Opcode::BLRAB | Opcode::BLRABZ => {
            Flow::IndirectCall { slot: None }
        }
        Opcode::RET
        | Opcode::RETAA
        | Opcode::RETAB
        | Opcode::RETAASPPC
        | Opcode::RETABSPPC
        | Opcode::RETAASPPCR
        | Opcode::RETABSPPCR
        | Opcode::ERET
        | Opcode::ERETAA
        | Opcode::ERETAB => Flow::Return,
        Opcode::BRK | Opcode::HLT | Opcode::UDF => Flow::Stop,
        _ => Flow::Next,
    };

    let mut data_refs = Vec::new();
    match ins.opcode {
        // ADRP forms the address of a 4 KiB page; the next instruction adds the offset.
        Opcode::ADRP => {
            if let Some(off) = pc_offset(&ins) {
                data_refs.push((address & !0xfff).wrapping_add_signed(off));
            }
        }
        Opcode::ADR | Opcode::LDR => {
            if let Some(t) = target {
                data_refs.push(t);
            }
        }
        _ => {}
    }

    // yaxpeax prints PC-relative operands as `$+0x10`; show absolute addresses instead.
    let text = ins.to_string();
    let (mnemonic, rest) = text.split_once(' ').unwrap_or((text.as_str(), ""));
    let shown = match ins.opcode {
        Opcode::ADRP => data_refs.first().copied(),
        _ => target,
    };
    let operands = tokenize(rest, shown);

    Some(Insn {
        address,
        len: 4,
        mnemonic: mnemonic.to_owned(),
        operands,
        flow,
        data_refs,
    })
}

fn tokenize(text: &str, pc_target: Option<u64>) -> Vec<Token> {
    let mut out = Vec::new();
    for (i, part) in text.split(", ").enumerate() {
        if i > 0 {
            out.push(Token {
                kind: TokenKind::Punct,
                text: ",".into(),
            });
        }
        let part = part.trim();
        let (kind, text) = if part.starts_with('$') || part.starts_with("#$") {
            match pc_target {
                Some(t) => (TokenKind::Address(t), format!("0x{t:x}")),
                None => (TokenKind::Number, part.to_owned()),
            }
        } else if part.starts_with('#')
            || part.starts_with("0x")
            || part.chars().all(|c| c.is_ascii_digit())
        {
            (TokenKind::Number, part.to_owned())
        } else if is_register(part) {
            (TokenKind::Register, part.to_owned())
        } else {
            (TokenKind::Text, part.to_owned())
        };
        out.push(Token { kind, text });
    }
    out.retain(|t| !t.text.is_empty());
    out
}

fn is_register(s: &str) -> bool {
    matches!(s, "sp" | "wsp" | "xzr" | "wzr" | "lr" | "fp")
        || (s.len() >= 2
            && matches!(
                s.as_bytes()[0],
                b'x' | b'w' | b'v' | b'q' | b'd' | b's' | b'h' | b'b'
            )
            && s[1..].chars().take_while(char::is_ascii_digit).count() > 0)
}
