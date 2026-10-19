//! A hand-rolled RISC-V (RV64I + M) disassembler. The base ISA is fixed 32-bit and very
//! regular, so decoding is a handful of field extractions per format. Compressed (`C`)
//! instructions are 16-bit; the flow-relevant ones are decoded and the rest are length-aware
//! (shown as `c.*`) so the linear sweep stays aligned. Floating-point, vector and CSR details
//! beyond the basics are shown generically. Pure Rust, no decoder dependency.

use crate::{Flow, Insn, Token, TokenKind};

/// Register ABI names, x0..x31.
const REG: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

pub fn decode(bytes: &[u8], address: u64) -> Option<Insn> {
    let half = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?);
    if half & 0b11 != 0b11 {
        return decode_compressed(half, address);
    }
    let w = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    decode_base(w, address)
}

/// Builds a register token.
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

fn insn(address: u64, len: u8, mnemonic: &str, operands: Vec<Token>, flow: Flow) -> Insn {
    Insn {
        address,
        len,
        mnemonic: mnemonic.to_owned(),
        operands,
        flow,
        data_refs: Vec::new(),
    }
}

fn sext(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((value << shift) as i32 >> shift) as i64
}

fn decode_base(w: u32, address: u64) -> Option<Insn> {
    let opcode = w & 0x7f;
    let rd = (w >> 7) & 0x1f;
    let rs1 = (w >> 15) & 0x1f;
    let rs2 = (w >> 20) & 0x1f;
    let f3 = (w >> 12) & 0x7;
    let f7 = (w >> 25) & 0x7f;
    let i_imm = sext(w >> 20, 12);
    let s_imm = sext(((w >> 25) << 5) | ((w >> 7) & 0x1f), 12);
    let b_imm = sext(
        ((w >> 31) << 12)
            | (((w >> 7) & 1) << 11)
            | (((w >> 25) & 0x3f) << 5)
            | (((w >> 8) & 0xf) << 1),
        13,
    );
    let u_imm = (w & 0xffff_f000) as i64;
    let j_imm = sext(
        ((w >> 31) << 20)
            | (((w >> 12) & 0xff) << 12)
            | (((w >> 20) & 1) << 11)
            | (((w >> 21) & 0x3ff) << 1),
        21,
    );

    // `op reg, off(base)` — the operand layout is the same for loads and stores.
    let mem = |data: u32, base: u32, off: i64| {
        vec![
            reg(data),
            punct(","),
            imm(off),
            punct("("),
            reg(base),
            punct(")"),
        ]
    };

    Some(match opcode {
        0x37 => insn(
            address,
            4,
            "lui",
            vec![reg(rd), punct(","), imm(u_imm >> 12)],
            Flow::Next,
        ),
        0x17 => {
            // auipc: form a PC-relative address; record the hint.
            let target = address.wrapping_add_signed(u_imm);
            let mut i = insn(
                address,
                4,
                "auipc",
                vec![reg(rd), punct(","), imm(u_imm >> 12)],
                Flow::Next,
            );
            i.data_refs.push(target);
            i
        }
        0x6f => {
            let target = address.wrapping_add_signed(j_imm);
            let (m, flow) = if rd == 0 {
                ("j", Flow::Jump(target))
            } else if rd == 1 {
                ("jal", Flow::Call(target))
            } else {
                ("jal", Flow::Jump(target))
            };
            let ops = if rd == 0 {
                vec![addr_tok(target)]
            } else {
                vec![reg(rd), punct(","), addr_tok(target)]
            };
            insn(address, 4, m, ops, flow)
        }
        0x67 => {
            // jalr: ret / indirect call / indirect jump.
            let flow = if rd == 0 && rs1 == 1 && i_imm == 0 {
                Flow::Return
            } else if rd == 1 {
                Flow::IndirectCall { slot: None }
            } else {
                Flow::IndirectJump {
                    slot: None,
                    table: None,
                }
            };
            if rd == 0 && rs1 == 1 && i_imm == 0 {
                insn(address, 4, "ret", vec![], flow)
            } else {
                insn(
                    address,
                    4,
                    "jalr",
                    vec![
                        reg(rd),
                        punct(","),
                        imm(i_imm),
                        punct("("),
                        reg(rs1),
                        punct(")"),
                    ],
                    flow,
                )
            }
        }
        0x63 => {
            let m = ["beq", "bne", "", "", "blt", "bge", "bltu", "bgeu"][f3 as usize];
            if m.is_empty() {
                return None;
            }
            let target = address.wrapping_add_signed(b_imm);
            insn(
                address,
                4,
                m,
                vec![reg(rs1), punct(","), reg(rs2), punct(","), addr_tok(target)],
                Flow::CondJump(target),
            )
        }
        0x03 => {
            let m = ["lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", ""][f3 as usize];
            if m.is_empty() {
                return None;
            }
            insn(address, 4, m, mem(rd, rs1, i_imm), Flow::Next)
        }
        0x23 => {
            let m = ["sb", "sh", "sw", "sd", "", "", "", ""][f3 as usize];
            if m.is_empty() {
                return None;
            }
            insn(address, 4, m, mem(rs2, rs1, s_imm), Flow::Next)
        }
        0x13 | 0x1b => op_imm(w, address, opcode == 0x1b, rd, rs1, f3, i_imm),
        0x33 | 0x3b => op_reg(address, opcode == 0x3b, rd, rs1, rs2, f3, f7)?,
        0x73 => {
            if w == 0x0000_0073 {
                insn(address, 4, "ecall", vec![], Flow::Next)
            } else if w == 0x0010_0073 {
                insn(address, 4, "ebreak", vec![], Flow::Stop)
            } else {
                // CSR instructions: shown generically.
                let m = [
                    "", "csrrw", "csrrs", "csrrc", "", "csrrwi", "csrrsi", "csrrci",
                ][f3 as usize];
                if m.is_empty() {
                    return None;
                }
                insn(
                    address,
                    4,
                    m,
                    vec![reg(rd), punct(","), reg(rs1)],
                    Flow::Next,
                )
            }
        }
        0x0f => insn(address, 4, "fence", vec![], Flow::Next),
        _ => return None,
    })
}

fn op_imm(w: u32, address: u64, word32: bool, rd: u32, rs1: u32, f3: u32, i_imm: i64) -> Insn {
    let suffix = if word32 { "w" } else { "" };
    // addi x0,x0,0 is the canonical NOP.
    if !word32 && w == 0x0000_0013 {
        return insn(address, 4, "nop", vec![], Flow::Next);
    }
    let (m, is_shift) = match f3 {
        0 => ("addi", false),
        1 => ("slli", true),
        2 => ("slti", false),
        3 => ("sltiu", false),
        4 => ("xori", false),
        5 => (if (w >> 30) & 1 == 1 { "srai" } else { "srli" }, true),
        6 => ("ori", false),
        7 => ("andi", false),
        _ => unreachable!(),
    };
    let name = format!("{m}{suffix}");
    let third = if is_shift {
        imm((i_imm as u64 & if word32 { 0x1f } else { 0x3f }) as i64)
    } else {
        imm(i_imm)
    };
    insn(
        address,
        4,
        &name,
        vec![reg(rd), punct(","), reg(rs1), punct(","), third],
        Flow::Next,
    )
}

fn op_reg(
    address: u64,
    word32: bool,
    rd: u32,
    rs1: u32,
    rs2: u32,
    f3: u32,
    f7: u32,
) -> Option<Insn> {
    let suffix = if word32 { "w" } else { "" };
    let base = if f7 == 0x01 {
        // M extension.
        match f3 {
            0 => "mul",
            1 => "mulh",
            2 => "mulhsu",
            3 => "mulhu",
            4 => "div",
            5 => "divu",
            6 => "rem",
            7 => "remu",
            _ => return None,
        }
    } else {
        match (f3, f7) {
            (0, 0x00) => "add",
            (0, 0x20) => "sub",
            (1, 0x00) => "sll",
            (2, 0x00) => "slt",
            (3, 0x00) => "sltu",
            (4, 0x00) => "xor",
            (5, 0x00) => "srl",
            (5, 0x20) => "sra",
            (6, 0x00) => "or",
            (7, 0x00) => "and",
            _ => return None,
        }
    };
    let name = format!("{base}{suffix}");
    Some(insn(
        address,
        4,
        &name,
        vec![reg(rd), punct(","), reg(rs1), punct(","), reg(rs2)],
        Flow::Next,
    ))
}

/// Compressed registers encode x8..x15 in 3 bits.
fn creg(n: u32) -> Token {
    reg(8 + (n & 7))
}

fn decode_compressed(h: u16, address: u64) -> Option<Insn> {
    let w = u32::from(h);
    let op = w & 0b11;
    let f3 = (w >> 13) & 0b111;
    // The flow-relevant and common compressed forms; everything else stays length-aware.
    match (op, f3) {
        // C.J: jump.
        (0b01, 0b101) => {
            let off = cj_imm(w);
            let target = address.wrapping_add_signed(off);
            Some(insn(
                address,
                2,
                "c.j",
                vec![addr_tok(target)],
                Flow::Jump(target),
            ))
        }
        // C.BEQZ / C.BNEZ.
        (0b01, 0b110) | (0b01, 0b111) => {
            let off = cb_imm(w);
            let target = address.wrapping_add_signed(off);
            let rs1 = creg((w >> 7) & 7);
            let m = if f3 == 0b110 { "c.beqz" } else { "c.bnez" };
            Some(insn(
                address,
                2,
                m,
                vec![rs1, punct(","), addr_tok(target)],
                Flow::CondJump(target),
            ))
        }
        // C.JR / C.MV / C.EBREAK / C.JALR / C.ADD (quadrant 2, funct3=100).
        (0b10, 0b100) => {
            let rs1 = (w >> 7) & 0x1f;
            let rs2 = (w >> 2) & 0x1f;
            let bit12 = (w >> 12) & 1;
            Some(match (bit12, rs1, rs2) {
                (0, r, 0) if r != 0 => {
                    // C.JR: ret if it jumps through ra, else an indirect jump.
                    if r == 1 {
                        insn(address, 2, "ret", vec![], Flow::Return)
                    } else {
                        insn(
                            address,
                            2,
                            "c.jr",
                            vec![reg(r)],
                            Flow::IndirectJump {
                                slot: None,
                                table: None,
                            },
                        )
                    }
                }
                (0, r, s) if s != 0 => insn(
                    address,
                    2,
                    "c.mv",
                    vec![reg(r), punct(","), reg(s)],
                    Flow::Next,
                ),
                (1, 0, 0) => insn(address, 2, "c.ebreak", vec![], Flow::Stop),
                (1, r, 0) if r != 0 => insn(
                    address,
                    2,
                    "c.jalr",
                    vec![reg(r)],
                    Flow::IndirectCall { slot: None },
                ),
                (1, r, s) if s != 0 => insn(
                    address,
                    2,
                    "c.add",
                    vec![reg(r), punct(","), reg(s)],
                    Flow::Next,
                ),
                _ => insn(address, 2, "c.unknown", vec![], Flow::Next),
            })
        }
        // C.NOP / C.ADDI.
        (0b01, 0b000) => {
            let rd = (w >> 7) & 0x1f;
            if rd == 0 {
                Some(insn(address, 2, "c.nop", vec![], Flow::Next))
            } else {
                Some(insn(
                    address,
                    2,
                    "c.addi",
                    vec![reg(rd), punct(","), imm(ci_imm(w))],
                    Flow::Next,
                ))
            }
        }
        // C.LI / C.LUI-or-ADDI16SP (shown generically, flow is Next).
        (0b01, 0b010) => {
            let rd = (w >> 7) & 0x1f;
            Some(insn(
                address,
                2,
                "c.li",
                vec![reg(rd), punct(","), imm(ci_imm(w))],
                Flow::Next,
            ))
        }
        // Any other compressed form: keep it length-aware so the sweep stays aligned.
        _ => Some(insn(address, 2, "c.insn", vec![], Flow::Next)),
    }
}

/// CI-format immediate (`c.addi`, `c.li`): imm[5] at bit 12, imm[4:0] at bits 6:2, sign-extended.
fn ci_imm(w: u32) -> i64 {
    sext(((w >> 12) & 1) << 5 | ((w >> 2) & 0x1f), 6)
}

/// CJ-format jump offset (`c.j`).
fn cj_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 11)
        | (((w >> 11) & 1) << 4)
        | (((w >> 9) & 3) << 8)
        | (((w >> 8) & 1) << 10)
        | (((w >> 7) & 1) << 6)
        | (((w >> 6) & 1) << 7)
        | (((w >> 3) & 7) << 1)
        | (((w >> 2) & 1) << 5);
    sext(v, 12)
}

/// CB-format branch offset (`c.beqz`/`c.bnez`).
fn cb_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 8)
        | (((w >> 10) & 3) << 3)
        | (((w >> 5) & 3) << 6)
        | (((w >> 3) & 3) << 1)
        | (((w >> 2) & 1) << 5);
    sext(v, 9)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(w: u32, addr: u64) -> Insn {
        decode(&w.to_le_bytes(), addr).expect("decodes")
    }

    #[test]
    fn base_arithmetic() {
        // addi a0, a1, 1  -> 0x00158513
        let i = d(0x0015_8513, 0x1000);
        assert_eq!(i.mnemonic, "addi");
        assert_eq!(i.len, 4);
        assert_eq!(i.operands[0].text, "a0");
        assert_eq!(i.operands[2].text, "a1");
        // add a0, a1, a2 -> 0x00c58533
        assert_eq!(d(0x00c5_8533, 0).mnemonic, "add");
        // mul a0, a1, a2 (M ext) -> 0x02c58533
        assert_eq!(d(0x02c5_8533, 0).mnemonic, "mul");
        // nop = addi x0,x0,0
        assert_eq!(d(0x0000_0013, 0).mnemonic, "nop");
    }

    #[test]
    fn jumps_and_branches() {
        // jal ra, +0x10  -> rd=ra, jimm=0x10 : 0x010000ef
        let jal = d(0x0100_00ef, 0x2000);
        assert_eq!(jal.mnemonic, "jal");
        assert_eq!(jal.flow, Flow::Call(0x2010));
        // ret = jalr x0, 0(ra) -> 0x00008067
        assert_eq!(d(0x0000_8067, 0).flow, Flow::Return);
        // beq a0, a1, +8 -> 0x00b50463
        let beq = d(0x00b5_0463, 0x3000);
        assert_eq!(beq.mnemonic, "beq");
        assert_eq!(beq.flow, Flow::CondJump(0x3008));
    }

    #[test]
    fn loads_stores_and_lui() {
        // ld a0, 8(sp) -> 0x00813503
        assert_eq!(d(0x0081_3503, 0).mnemonic, "ld");
        // sd ra, 8(sp) -> 0x00113423
        assert_eq!(d(0x0011_3423, 0).mnemonic, "sd");
        // lui a0, 0x1 -> 0x000015b7 ... use lui a1,0x1 = 0x000015b7
        assert_eq!(d(0x0000_15b7, 0).mnemonic, "lui");
    }

    #[test]
    fn compressed_is_length_aware_and_flows() {
        // c.ret (c.jr ra) = 0x8082 -> 2 bytes, Return
        let ret = decode(&0x8082u16.to_le_bytes(), 0).unwrap();
        assert_eq!(ret.len, 2);
        assert_eq!(ret.flow, Flow::Return);
        // An unknown compressed half still decodes as a 2-byte c.insn (keeps the sweep aligned).
        let other = decode(&0x0001u16.to_le_bytes(), 0).unwrap();
        assert_eq!(other.len, 2);
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x13], 0).is_none());
    }
}
