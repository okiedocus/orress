//! A hand-rolled MIPS32 disassembler (big- and little-endian). MIPS instructions are a fixed
//! 32 bits in three simple formats (R/I/J), so decoding is field extraction plus a couple of
//! opcode tables. Branches and jumps have a delay slot (the next instruction runs before the
//! transfer); conditional branches and calls fall through to it naturally, so it is decoded.
//! The delay slot after an *unconditional* `j`/`jr` is not a control-flow successor, so it may
//! show as data — a documented limitation. Floating-point, COP and the rarer ops are shown
//! generically. Pure Rust, no decoder dependency.

use crate::{Flow, Insn, Token, TokenKind};

const REG: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp",
    "ra",
];

pub fn decode(bytes: &[u8], address: u64, big_endian: bool) -> Option<Insn> {
    let raw: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let w = if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    };
    decode_word(w, address)
}

fn reg(n: u32) -> Token {
    Token {
        kind: TokenKind::Register,
        text: REG[(n & 31) as usize].to_owned(),
    }
}

fn num(text: impl Into<String>) -> Token {
    Token {
        kind: TokenKind::Number,
        text: text.into(),
    }
}

fn punct(text: &str) -> Token {
    Token {
        kind: TokenKind::Punct,
        text: text.into(),
    }
}

fn addr_tok(a: u64) -> Token {
    Token {
        kind: TokenKind::Address(a),
        text: format!("0x{a:x}"),
    }
}

fn imm(v: i64) -> Token {
    if v < 0 {
        num(format!("-0x{:x}", -v))
    } else {
        num(format!("0x{v:x}"))
    }
}

fn insn(address: u64, mnemonic: &str, operands: Vec<Token>, flow: Flow) -> Insn {
    Insn {
        address,
        len: 4,
        mnemonic: mnemonic.to_owned(),
        operands,
        flow,
        data_refs: Vec::new(),
    }
}

fn decode_word(w: u32, address: u64) -> Option<Insn> {
    let opcode = w >> 26;
    let rs = (w >> 21) & 0x1f;
    let rt = (w >> 16) & 0x1f;
    let rd = (w >> 11) & 0x1f;
    let shamt = (w >> 6) & 0x1f;
    let imm16 = (w & 0xffff) as i16 as i64;
    // Branch target: relative to the delay slot (address + 4), in instruction units.
    let branch_target = (address + 4).wrapping_add_signed(imm16 << 2);
    // Jump target: the 26-bit index shifted into the current 256 MiB region.
    let jump_target = ((address + 4) & 0xffff_ffff_f000_0000) | u64::from((w & 0x03ff_ffff) << 2);

    Some(match opcode {
        0x00 => return decode_special(w, address, rs, rt, rd, shamt),
        0x01 => {
            // REGIMM: bltz/bgez (and link variants).
            let (m, link) = match rt {
                0x00 => ("bltz", false),
                0x01 => ("bgez", false),
                0x10 => ("bltzal", true),
                0x11 => ("bgezal", true),
                _ => return None,
            };
            let flow = if link {
                Flow::Call(branch_target)
            } else {
                Flow::CondJump(branch_target)
            };
            insn(
                address,
                m,
                vec![reg(rs), punct(","), addr_tok(branch_target)],
                flow,
            )
        }
        0x02 => insn(
            address,
            "j",
            vec![addr_tok(jump_target)],
            Flow::Jump(jump_target),
        ),
        0x03 => insn(
            address,
            "jal",
            vec![addr_tok(jump_target)],
            Flow::Call(jump_target),
        ),
        0x04 | 0x05 => {
            let m = if opcode == 0x04 { "beq" } else { "bne" };
            insn(
                address,
                m,
                vec![
                    reg(rs),
                    punct(","),
                    reg(rt),
                    punct(","),
                    addr_tok(branch_target),
                ],
                Flow::CondJump(branch_target),
            )
        }
        0x06 | 0x07 => {
            let m = if opcode == 0x06 { "blez" } else { "bgtz" };
            insn(
                address,
                m,
                vec![reg(rs), punct(","), addr_tok(branch_target)],
                Flow::CondJump(branch_target),
            )
        }
        0x08..=0x0e => {
            let m =
                ["addi", "addiu", "slti", "sltiu", "andi", "ori", "xori"][(opcode - 0x08) as usize];
            insn(
                address,
                m,
                vec![reg(rt), punct(","), reg(rs), punct(","), imm(imm16)],
                Flow::Next,
            )
        }
        0x0f => insn(
            address,
            "lui",
            vec![reg(rt), punct(","), imm(imm16 & 0xffff)],
            Flow::Next,
        ),
        // Loads and stores: `op rt, imm(rs)`.
        0x20 | 0x21 | 0x23 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2b => {
            let m = match opcode {
                0x20 => "lb",
                0x21 => "lh",
                0x23 => "lw",
                0x24 => "lbu",
                0x25 => "lhu",
                0x28 => "sb",
                0x29 => "sh",
                0x2b => "sw",
                _ => unreachable!(),
            };
            insn(
                address,
                m,
                vec![
                    reg(rt),
                    punct(","),
                    imm(imm16),
                    punct("("),
                    reg(rs),
                    punct(")"),
                ],
                Flow::Next,
            )
        }
        // SPECIAL2: MIPS32 multiply-accumulate and count-leading-bits.
        0x1c => return decode_special2(w, address, rs, rt, rd),
        // Coprocessor / float / rarer ops: shown generically so they are not mistaken for data.
        0x10..=0x13 | 0x30..=0x3f => insn(address, &format!("cop0x{opcode:x}"), vec![], Flow::Next),
        _ => return None,
    })
}

/// SPECIAL2 (opcode 0x1c): the MIPS32 `mul`/`madd`/`msub` family and `clz`/`clo`.
fn decode_special2(w: u32, address: u64, rs: u32, rt: u32, rd: u32) -> Option<Insn> {
    let funct = w & 0x3f;
    let two = |m| insn(address, m, vec![reg(rs), punct(","), reg(rt)], Flow::Next);
    Some(match funct {
        0x00 => two("madd"),
        0x01 => two("maddu"),
        // `mul rd, rs, rt` — the MIPS32 three-operand multiply compilers emit instead of
        // `mult`+`mflo`, so it is common in real code.
        0x02 => insn(
            address,
            "mul",
            vec![reg(rd), punct(","), reg(rs), punct(","), reg(rt)],
            Flow::Next,
        ),
        0x04 => two("msub"),
        0x05 => two("msubu"),
        0x20 => insn(
            address,
            "clz",
            vec![reg(rd), punct(","), reg(rs)],
            Flow::Next,
        ),
        0x21 => insn(
            address,
            "clo",
            vec![reg(rd), punct(","), reg(rs)],
            Flow::Next,
        ),
        _ => return None,
    })
}

/// SPECIAL (opcode 0): R-type instructions selected by the `funct` field.
fn decode_special(w: u32, address: u64, rs: u32, rt: u32, rd: u32, shamt: u32) -> Option<Insn> {
    let funct = w & 0x3f;
    Some(match funct {
        0x00 if w == 0 => insn(address, "nop", vec![], Flow::Next),
        0x00 | 0x02 | 0x03 => {
            let m = ["sll", "", "srl", "sra"][funct as usize];
            insn(
                address,
                m,
                vec![reg(rd), punct(","), reg(rt), punct(","), imm(shamt as i64)],
                Flow::Next,
            )
        }
        0x04 | 0x06 | 0x07 => {
            let m = ["sllv", "", "srlv", "srav"][funct as usize];
            insn(
                address,
                m,
                vec![reg(rd), punct(","), reg(rt), punct(","), reg(rs)],
                Flow::Next,
            )
        }
        0x08 => {
            // jr: return when jumping through $ra, else an indirect jump.
            let flow = if rs == 31 {
                Flow::Return
            } else {
                Flow::IndirectJump {
                    slot: None,
                    table: None,
                }
            };
            insn(address, "jr", vec![reg(rs)], flow)
        }
        0x09 => insn(
            address,
            "jalr",
            vec![reg(rd), punct(","), reg(rs)],
            Flow::IndirectCall { slot: None },
        ),
        0x0a | 0x0b => {
            // Conditional moves: movz/movn rd, rs, rt.
            let m = if funct == 0x0a { "movz" } else { "movn" };
            insn(
                address,
                m,
                vec![reg(rd), punct(","), reg(rs), punct(","), reg(rt)],
                Flow::Next,
            )
        }
        0x0c => insn(address, "syscall", vec![], Flow::Next),
        0x0d => insn(address, "break", vec![], Flow::Stop),
        0x0f => insn(address, "sync", vec![], Flow::Next),
        0x10 => insn(address, "mfhi", vec![reg(rd)], Flow::Next),
        0x11 => insn(address, "mthi", vec![reg(rs)], Flow::Next),
        0x12 => insn(address, "mflo", vec![reg(rd)], Flow::Next),
        0x13 => insn(address, "mtlo", vec![reg(rs)], Flow::Next),
        0x18..=0x1b => {
            let m = ["mult", "multu", "div", "divu"][(funct - 0x18) as usize];
            insn(address, m, vec![reg(rs), punct(","), reg(rt)], Flow::Next)
        }
        // add/addu/sub/subu/and/or/xor/nor/slt/sltu (funct 0x20..0x2b).
        0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x2a | 0x2b => {
            let m = match funct {
                0x20 => "add",
                0x21 => "addu",
                0x22 => "sub",
                0x23 => "subu",
                0x24 => "and",
                0x25 => "or",
                0x26 => "xor",
                0x27 => "nor",
                0x2a => "slt",
                0x2b => "sltu",
                _ => unreachable!(),
            };
            insn(
                address,
                m,
                vec![reg(rd), punct(","), reg(rs), punct(","), reg(rt)],
                Flow::Next,
            )
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(w: u32, addr: u64) -> Insn {
        decode(&w.to_be_bytes(), addr, true).expect("decodes")
    }

    #[test]
    fn r_type_and_nop() {
        // add t0, t1, t2 : rd=t0(8) rs=t1(9) rt=t2(10) funct=0x20 -> 0x012A4020
        let i = be(0x012A_4020, 0x1000);
        assert_eq!(i.mnemonic, "add");
        assert_eq!(i.operands[0].text, "t0");
        assert_eq!(i.operands[2].text, "t1");
        assert_eq!(i.operands[4].text, "t2");
        // nop = 0x00000000
        assert_eq!(be(0x0000_0000, 0).mnemonic, "nop");
    }

    #[test]
    fn jumps_branches_jr() {
        // jal 0x100 -> index = 0x40 : 0x0C000040, target = 0x100
        let jal = be(0x0C00_0040, 0x2000);
        assert_eq!(jal.mnemonic, "jal");
        assert_eq!(jal.flow, Flow::Call(0x100));
        // jr ra = 0x03E00008 -> Return
        assert_eq!(be(0x03E0_0008, 0).flow, Flow::Return);
        // beq t0,t1,off : rs=t0(8) rt=t1(9) imm=2 -> 0x11090002, target = addr+4+8
        let beq = be(0x1109_0002, 0x3000);
        assert_eq!(beq.mnemonic, "beq");
        assert_eq!(beq.flow, Flow::CondJump(0x3000 + 4 + 8));
    }

    #[test]
    fn special2_and_moves() {
        // mul v0, a0, a1 : SPECIAL2 rd=v0(2) rs=a0(4) rt=a1(5) funct=0x02 -> 0x70851002
        let i = be(0x7085_1002, 0);
        assert_eq!(i.mnemonic, "mul");
        assert_eq!(i.operands[0].text, "v0");
        assert_eq!(i.operands[2].text, "a0");
        assert_eq!(i.operands[4].text, "a1");
        // clz v0, a0 : SPECIAL2 funct=0x20 -> 0x70801020
        let i = be(0x7080_1020, 0);
        assert_eq!(i.mnemonic, "clz");
        assert_eq!(i.operands[0].text, "v0");
        assert_eq!(i.operands[2].text, "a0");
        // movn v0, a0, a1 : SPECIAL funct=0x0b -> 0x0085100B
        let i = be(0x0085_100B, 0);
        assert_eq!(i.mnemonic, "movn");
        assert_eq!(i.operands[0].text, "v0");
        // mthi a0 : SPECIAL funct=0x11, rs=a0(4) -> 0x00800011
        assert_eq!(be(0x0080_0011, 0).mnemonic, "mthi");
    }

    #[test]
    fn immediate_and_memory() {
        // addiu sp, sp, -32 : rt=sp(29) rs=sp(29) imm=-32 -> 0x27BDFFE0
        let i = be(0x27BD_FFE0, 0);
        assert_eq!(i.mnemonic, "addiu");
        assert_eq!(i.operands[0].text, "sp");
        // lw ra, 28(sp) : rt=ra(31) rs=sp(29) imm=28 -> 0x8FBF001C
        assert_eq!(be(0x8FBF_001C, 0).mnemonic, "lw");
    }

    #[test]
    fn endianness_is_respected() {
        // The big-endian word 0x00000000 and its little-endian bytes decode differently from
        // the raw byte order: feeding LE bytes as BE would misdecode. `addu` BE 0x012A4021.
        let be_bytes = 0x012A_4021u32.to_be_bytes();
        assert_eq!(decode(&be_bytes, 0, true).unwrap().mnemonic, "addu");
        // The same bytes read little-endian are a different word, not necessarily `addu`.
        let le = decode(&be_bytes, 0, false);
        assert!(le.is_none() || le.unwrap().mnemonic != "addu");
    }
}
