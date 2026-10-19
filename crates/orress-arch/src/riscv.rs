//! A hand-rolled RISC-V (RV64I + M + F/D) disassembler. The base ISA is fixed 32-bit and very
//! regular, so decoding is a handful of field extractions per format. Compressed (`C`)
//! instructions are 16-bit; the full RV64 *integer* compressed set is decoded with operands, and
//! the floating-point / reserved halves stay length-aware (shown as a generic `c.insn`) so the
//! linear sweep stays aligned. Single- and double-precision floating-point (loads/stores, OP-FP
//! arithmetic/compares/conversions/moves and the fused multiply-adds) is decoded; the vector
//! extension and CSR details beyond the basics are shown generically. Pure Rust, no decoder
//! dependency.

use crate::{Flow, Insn, Token, TokenKind};

/// Register ABI names, x0..x31.
const REG: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// Floating-point register ABI names, f0..f31.
const FREG: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
    "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
    "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

pub fn decode(bytes: &[u8], address: u64, bits64: bool) -> Option<Insn> {
    let half = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?);
    if half & 0b11 != 0b11 {
        return decode_compressed(half, address, bits64);
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

/// Builds a floating-point register token.
fn freg(n: u32) -> Token {
    Token {
        kind: TokenKind::Register,
        text: FREG[(n & 31) as usize].to_owned(),
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
                // CSR instructions: `csrrw rd, csr, rs1` / `csrrwi rd, csr, zimm`. The CSR number
                // is the unsigned 12-bit immediate; the `*i` forms (f3 bit 2 set) take a 5-bit
                // zero-extended immediate in place of the source register.
                let m = [
                    "", "csrrw", "csrrs", "csrrc", "", "csrrwi", "csrrsi", "csrrci",
                ][f3 as usize];
                if m.is_empty() {
                    return None;
                }
                let csr = (w >> 20) & 0xfff;
                let src = if f3 & 0b100 != 0 {
                    imm(i64::from(rs1))
                } else {
                    reg(rs1)
                };
                insn(
                    address,
                    4,
                    m,
                    vec![
                        reg(rd),
                        punct(","),
                        num(format!("0x{csr:x}")),
                        punct(","),
                        src,
                    ],
                    Flow::Next,
                )
            }
        }
        0x0f => insn(address, 4, "fence", vec![], Flow::Next),
        // Floating-point loads/stores: `flw fd, imm(rs1)` / `fsw fs2, imm(rs1)`.
        0x07 => {
            let m = match f3 {
                2 => "flw",
                3 => "fld",
                _ => return None,
            };
            insn(
                address,
                4,
                m,
                vec![
                    freg(rd),
                    punct(","),
                    imm(i_imm),
                    punct("("),
                    reg(rs1),
                    punct(")"),
                ],
                Flow::Next,
            )
        }
        0x27 => {
            let m = match f3 {
                2 => "fsw",
                3 => "fsd",
                _ => return None,
            };
            insn(
                address,
                4,
                m,
                vec![
                    freg(rs2),
                    punct(","),
                    imm(s_imm),
                    punct("("),
                    reg(rs1),
                    punct(")"),
                ],
                Flow::Next,
            )
        }
        // OP-FP and fused multiply-add.
        0x53 => return decode_fp(address, rd, rs1, rs2, f3, f7),
        0x43 | 0x47 | 0x4b | 0x4f => return Some(decode_fma(w, address, opcode, rd, rs1, rs2)),
        _ => return None,
    })
}

/// A `.s`/`.d` suffix from the OP-FP format field (`fmt`, bits 26:25).
fn fp_suffix(fmt: u32) -> &'static str {
    if fmt == 0 { ".s" } else { ".d" }
}

/// OP-FP (opcode 0x53): the single- and double-precision arithmetic, sign-inject, min/max,
/// compares, conversions and moves, selected by `funct7`.
fn decode_fp(address: u64, rd: u32, rs1: u32, rs2: u32, f3: u32, f7: u32) -> Option<Insn> {
    let s = fp_suffix(f7 & 1);
    // `fd, fs1, fs2` — the common three-register float form.
    let fff = |m: &str| {
        insn(
            address,
            4,
            m,
            vec![freg(rd), punct(","), freg(rs1), punct(","), freg(rs2)],
            Flow::Next,
        )
    };
    let name = |base: &str| format!("{base}{s}");
    Some(match f7 >> 1 {
        // Arithmetic.
        0x00 => fff(&name("fadd")),
        0x02 => fff(&name("fsub")),
        0x04 => fff(&name("fmul")),
        0x06 => fff(&name("fdiv")),
        // fsqrt fd, fs1.
        0x16 => insn(
            address,
            4,
            &name("fsqrt"),
            vec![freg(rd), punct(","), freg(rs1)],
            Flow::Next,
        ),
        // Sign-injection: fsgnj / fsgnjn / fsgnjx (fmv/fneg/fabs pseudo-ops).
        0x08 => fff(&name(
            ["fsgnj", "fsgnjn", "fsgnjx"].get(f3 as usize).copied()?,
        )),
        // Min / max.
        0x0a => fff(&name(if f3 == 0 { "fmin" } else { "fmax" })),
        // Compares (integer destination): feq / flt / fle.
        0x28 => {
            let m = match f3 {
                0 => "fle",
                1 => "flt",
                2 => "feq",
                _ => return None,
            };
            insn(
                address,
                4,
                &name(m),
                vec![reg(rd), punct(","), freg(rs1), punct(","), freg(rs2)],
                Flow::Next,
            )
        }
        // fcvt between single and double: fcvt.s.d (f7=0x20, rs2=1) / fcvt.d.s (f7=0x21, rs2=0).
        0x10 => {
            let (dst, src) = if f7 & 1 == 0 { ("s", "d") } else { ("d", "s") };
            insn(
                address,
                4,
                &format!("fcvt.{dst}.{src}"),
                vec![freg(rd), punct(","), freg(rs1)],
                Flow::Next,
            )
        }
        // Float → integer: fcvt.w/wu/l/lu.{s,d} (int dest, float src).
        0x30 => insn(
            address,
            4,
            &format!(
                "fcvt.{}{s}",
                ["w", "wu", "l", "lu"].get(rs2 as usize).copied()?
            ),
            vec![reg(rd), punct(","), freg(rs1)],
            Flow::Next,
        ),
        // Integer → float: fcvt.{s,d}.w/wu/l/lu (float dest, int src).
        0x34 => insn(
            address,
            4,
            &format!(
                "fcvt{s}.{}",
                ["w", "wu", "l", "lu"].get(rs2 as usize).copied()?
            ),
            vec![freg(rd), punct(","), reg(rs1)],
            Flow::Next,
        ),
        // fmv.x.w / fclass (int dest, float src).
        0x38 => {
            let m = if f3 == 0 {
                format!("fmv.x.{}", if f7 & 1 == 0 { "w" } else { "d" })
            } else {
                name("fclass")
            };
            insn(
                address,
                4,
                &m,
                vec![reg(rd), punct(","), freg(rs1)],
                Flow::Next,
            )
        }
        // fmv.w.x / fmv.d.x (float dest, int src).
        0x3c => insn(
            address,
            4,
            &format!("fmv.{}.x", if f7 & 1 == 0 { "w" } else { "d" }),
            vec![freg(rd), punct(","), reg(rs1)],
            Flow::Next,
        ),
        _ => return None,
    })
}

/// Fused multiply-add (opcodes 0x43/0x47/0x4b/0x4f): `op fd, fs1, fs2, fs3`, the extra source in
/// `rs3` (bits 31:27). Format comes from bits 26:25.
fn decode_fma(w: u32, address: u64, opcode: u32, rd: u32, rs1: u32, rs2: u32) -> Insn {
    let base = match opcode {
        0x43 => "fmadd",
        0x47 => "fmsub",
        0x4b => "fnmsub",
        _ => "fnmadd",
    };
    let rs3 = (w >> 27) & 0x1f;
    let s = fp_suffix((w >> 25) & 3);
    insn(
        address,
        4,
        &format!("{base}{s}"),
        vec![
            freg(rd),
            punct(","),
            freg(rs1),
            punct(","),
            freg(rs2),
            punct(","),
            freg(rs3),
        ],
        Flow::Next,
    )
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

/// `off(base)` memory operand layout, shared by compressed loads and stores.
fn cmem(data: Token, off: i64, base: Token) -> Vec<Token> {
    vec![data, punct(","), imm(off), punct("("), base, punct(")")]
}

fn decode_compressed(h: u16, address: u64, bits64: bool) -> Option<Insn> {
    let w = u32::from(h);
    let op = w & 0b11;
    let f3 = (w >> 13) & 0b111;
    // The integer compressed set (quadrants 0/1/2); floating-point and reserved encodings stay
    // length-aware (shown as `c.insn`) so the linear sweep stays aligned. `sp` is x2. Five slots
    // differ by width: on RV32 they are `c.jal`/`c.flw`/`c.fsw`/`c.flwsp`/`c.fswsp` where RV64 has
    // `c.addiw`/`c.ld`/`c.sd`/`c.ldsp`/`c.sdsp`.
    Some(match (op, f3) {
        // ---- Quadrant 0: reg+imm and stack loads/stores (`rs1'`/`rd'` are x8..x15) ----
        // C.ADDI4SPN: `addi rd', sp, nzuimm`. An all-zero immediate is the reserved/illegal form.
        (0b00, 0b000) => {
            let nz = ciw_imm(w);
            if nz == 0 {
                insn(address, 2, "c.unimp", vec![], Flow::Next)
            } else {
                insn(
                    address,
                    2,
                    "c.addi4spn",
                    vec![creg((w >> 2) & 7), punct(","), reg(2), punct(","), imm(nz)],
                    Flow::Next,
                )
            }
        }
        (0b00, 0b010) => insn(
            address,
            2,
            "c.lw",
            cmem(creg((w >> 2) & 7), clw_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        // RV64 C.LD / RV32 C.FLW.
        (0b00, 0b011) if bits64 => insn(
            address,
            2,
            "c.ld",
            cmem(creg((w >> 2) & 7), cld_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        (0b00, 0b011) => insn(
            address,
            2,
            "c.flw",
            cmem(freg(8 + ((w >> 2) & 7)), clw_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        (0b00, 0b110) => insn(
            address,
            2,
            "c.sw",
            cmem(creg((w >> 2) & 7), clw_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        // RV64 C.SD / RV32 C.FSW.
        (0b00, 0b111) if bits64 => insn(
            address,
            2,
            "c.sd",
            cmem(creg((w >> 2) & 7), cld_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        (0b00, 0b111) => insn(
            address,
            2,
            "c.fsw",
            cmem(freg(8 + ((w >> 2) & 7)), clw_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),

        // ---- Quadrant 1 ----
        // C.NOP / C.ADDI.
        (0b01, 0b000) => {
            let rd = (w >> 7) & 0x1f;
            if rd == 0 {
                insn(address, 2, "c.nop", vec![], Flow::Next)
            } else {
                insn(
                    address,
                    2,
                    "c.addi",
                    vec![reg(rd), punct(","), imm(ci_imm(w))],
                    Flow::Next,
                )
            }
        }
        // RV64 C.ADDIW (`addiw rd, rd, imm`) / RV32 C.JAL (a call to pc-relative target).
        (0b01, 0b001) if bits64 => insn(
            address,
            2,
            "c.addiw",
            vec![reg((w >> 7) & 0x1f), punct(","), imm(ci_imm(w))],
            Flow::Next,
        ),
        (0b01, 0b001) => {
            let target = address.wrapping_add_signed(cj_imm(w));
            insn(
                address,
                2,
                "c.jal",
                vec![addr_tok(target)],
                Flow::Call(target),
            )
        }
        // C.LI.
        (0b01, 0b010) => insn(
            address,
            2,
            "c.li",
            vec![reg((w >> 7) & 0x1f), punct(","), imm(ci_imm(w))],
            Flow::Next,
        ),
        // C.ADDI16SP (rd == sp) / C.LUI (any other rd).
        (0b01, 0b011) => {
            let rd = (w >> 7) & 0x1f;
            if rd == 2 {
                insn(
                    address,
                    2,
                    "c.addi16sp",
                    vec![reg(2), punct(","), imm(addi16sp_imm(w))],
                    Flow::Next,
                )
            } else {
                insn(
                    address,
                    2,
                    "c.lui",
                    vec![reg(rd), punct(","), imm(clui_imm(w) >> 12)],
                    Flow::Next,
                )
            }
        }
        // C.SRLI / C.SRAI / C.ANDI / C.SUB / C.XOR / C.OR / C.AND / C.SUBW / C.ADDW.
        (0b01, 0b100) => decode_c_arith(w, address),
        // C.J.
        (0b01, 0b101) => {
            let target = address.wrapping_add_signed(cj_imm(w));
            insn(
                address,
                2,
                "c.j",
                vec![addr_tok(target)],
                Flow::Jump(target),
            )
        }
        // C.BEQZ / C.BNEZ.
        (0b01, 0b110) | (0b01, 0b111) => {
            let target = address.wrapping_add_signed(cb_imm(w));
            let m = if f3 == 0b110 { "c.beqz" } else { "c.bnez" };
            insn(
                address,
                2,
                m,
                vec![creg((w >> 7) & 7), punct(","), addr_tok(target)],
                Flow::CondJump(target),
            )
        }

        // ---- Quadrant 2 ----
        // C.SLLI.
        (0b10, 0b000) => insn(
            address,
            2,
            "c.slli",
            vec![reg((w >> 7) & 0x1f), punct(","), imm(cshamt(w))],
            Flow::Next,
        ),
        // C.LWSP / C.LDSP.
        (0b10, 0b010) => insn(
            address,
            2,
            "c.lwsp",
            cmem(reg((w >> 7) & 0x1f), lwsp_imm(w), reg(2)),
            Flow::Next,
        ),
        // RV64 C.LDSP / RV32 C.FLWSP.
        (0b10, 0b011) if bits64 => insn(
            address,
            2,
            "c.ldsp",
            cmem(reg((w >> 7) & 0x1f), ldsp_imm(w), reg(2)),
            Flow::Next,
        ),
        (0b10, 0b011) => insn(
            address,
            2,
            "c.flwsp",
            cmem(freg((w >> 7) & 0x1f), lwsp_imm(w), reg(2)),
            Flow::Next,
        ),
        // C.JR / C.MV / C.EBREAK / C.JALR / C.ADD.
        (0b10, 0b100) => {
            let rs1 = (w >> 7) & 0x1f;
            let rs2 = (w >> 2) & 0x1f;
            let bit12 = (w >> 12) & 1;
            match (bit12, rs1, rs2) {
                (0, r, 0) if r != 0 => {
                    // C.JR: `ret` if it jumps through ra, else an indirect jump.
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
            }
        }
        // C.SWSP / C.SDSP.
        (0b10, 0b110) => insn(
            address,
            2,
            "c.swsp",
            cmem(reg((w >> 2) & 0x1f), swsp_imm(w), reg(2)),
            Flow::Next,
        ),
        // RV64 C.SDSP / RV32 C.FSWSP.
        (0b10, 0b111) if bits64 => insn(
            address,
            2,
            "c.sdsp",
            cmem(reg((w >> 2) & 0x1f), sdsp_imm(w), reg(2)),
            Flow::Next,
        ),
        (0b10, 0b111) => insn(
            address,
            2,
            "c.fswsp",
            cmem(freg((w >> 2) & 0x1f), swsp_imm(w), reg(2)),
            Flow::Next,
        ),

        // Compressed double-precision loads/stores (RV64: C.FLD/C.FSD and their SP forms).
        (0b00, 0b001) => insn(
            address,
            2,
            "c.fld",
            cmem(freg(8 + ((w >> 2) & 7)), cld_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        (0b00, 0b101) => insn(
            address,
            2,
            "c.fsd",
            cmem(freg(8 + ((w >> 2) & 7)), cld_imm(w), creg((w >> 7) & 7)),
            Flow::Next,
        ),
        (0b10, 0b001) => insn(
            address,
            2,
            "c.fldsp",
            cmem(freg((w >> 7) & 0x1f), ldsp_imm(w), reg(2)),
            Flow::Next,
        ),
        (0b10, 0b101) => insn(
            address,
            2,
            "c.fsdsp",
            cmem(freg((w >> 2) & 0x1f), sdsp_imm(w), reg(2)),
            Flow::Next,
        ),
        // Reserved / vector encodings: length-aware only.
        _ => insn(address, 2, "c.insn", vec![], Flow::Next),
    })
}

/// The quadrant-1 `funct3=100` arithmetic group: shift/mask immediates and the register-register
/// forms, selected by bits 11:10 (and bits 6:5 plus bit 12 for the register forms).
fn decode_c_arith(w: u32, address: u64) -> Insn {
    let rd = creg((w >> 7) & 7);
    match (w >> 10) & 0b11 {
        0b00 => insn(
            address,
            2,
            "c.srli",
            vec![rd, punct(","), imm(cshamt(w))],
            Flow::Next,
        ),
        0b01 => insn(
            address,
            2,
            "c.srai",
            vec![rd, punct(","), imm(cshamt(w))],
            Flow::Next,
        ),
        0b10 => insn(
            address,
            2,
            "c.andi",
            vec![rd, punct(","), imm(ci_imm(w))],
            Flow::Next,
        ),
        _ => {
            let rs2 = creg((w >> 2) & 7);
            let m = match ((w >> 12) & 1, (w >> 5) & 0b11) {
                (0, 0b00) => "c.sub",
                (0, 0b01) => "c.xor",
                (0, 0b10) => "c.or",
                (0, 0b11) => "c.and",
                (1, 0b00) => "c.subw",
                (1, 0b01) => "c.addw",
                _ => "c.unknown", // (bit12=1, 0b10/0b11) are reserved.
            };
            insn(address, 2, m, vec![rd, punct(","), rs2], Flow::Next)
        }
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

/// CIW immediate (`c.addi4spn`): a zero-extended, 4-scaled `nzuimm`.
fn ciw_imm(w: u32) -> i64 {
    i64::from(
        (((w >> 11) & 0b11) << 4)
            | (((w >> 7) & 0b1111) << 6)
            | (((w >> 6) & 1) << 2)
            | (((w >> 5) & 1) << 3),
    )
}

/// CL/CS word offset (`c.lw`/`c.sw`): zero-extended, 4-scaled.
fn clw_imm(w: u32) -> i64 {
    i64::from((((w >> 10) & 0b111) << 3) | (((w >> 6) & 1) << 2) | (((w >> 5) & 1) << 6))
}

/// CL/CS double offset (`c.ld`/`c.sd`): zero-extended, 8-scaled.
fn cld_imm(w: u32) -> i64 {
    i64::from((((w >> 10) & 0b111) << 3) | (((w >> 5) & 0b11) << 6))
}

/// C.LWSP offset: zero-extended, 4-scaled.
fn lwsp_imm(w: u32) -> i64 {
    i64::from((((w >> 12) & 1) << 5) | (((w >> 4) & 0b111) << 2) | (((w >> 2) & 0b11) << 6))
}

/// C.LDSP offset: zero-extended, 8-scaled.
fn ldsp_imm(w: u32) -> i64 {
    i64::from((((w >> 12) & 1) << 5) | (((w >> 5) & 0b11) << 3) | (((w >> 2) & 0b111) << 6))
}

/// C.SWSP offset: zero-extended, 4-scaled.
fn swsp_imm(w: u32) -> i64 {
    i64::from((((w >> 9) & 0b1111) << 2) | (((w >> 7) & 0b11) << 6))
}

/// C.SDSP offset: zero-extended, 8-scaled.
fn sdsp_imm(w: u32) -> i64 {
    i64::from((((w >> 10) & 0b111) << 3) | (((w >> 7) & 0b111) << 6))
}

/// A 6-bit shift amount (`c.slli`/`c.srli`/`c.srai`): shamt[5] at bit 12, shamt[4:0] at bits 6:2.
fn cshamt(w: u32) -> i64 {
    i64::from((((w >> 12) & 1) << 5) | ((w >> 2) & 0x1f))
}

/// C.ADDI16SP immediate: a sign-extended, 16-scaled `nzimm`.
fn addi16sp_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 9)
        | (((w >> 6) & 1) << 4)
        | (((w >> 5) & 1) << 6)
        | (((w >> 3) & 0b11) << 7)
        | (((w >> 2) & 1) << 5);
    sext(v, 10)
}

/// C.LUI immediate: `nzimm[17]` at bit 12, `nzimm[16:12]` at bits 6:2, sign-extended into bit 17 so
/// the printed value (`clui_imm >> 12`) matches the base `lui` operand.
fn clui_imm(w: u32) -> i64 {
    let v = (((w >> 12) & 1) << 17) | (((w >> 2) & 0x1f) << 12);
    sext(v, 18)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(w: u32, addr: u64) -> Insn {
        decode(&w.to_le_bytes(), addr, true).expect("decodes")
    }

    /// Decode a 16-bit compressed half-word as RV32 (`bits64 = false`).
    fn c32(h: u16, addr: u64) -> Insn {
        decode(&h.to_le_bytes(), addr, false).expect("decodes")
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
        let ret = decode(&0x8082u16.to_le_bytes(), 0, true).unwrap();
        assert_eq!(ret.len, 2);
        assert_eq!(ret.flow, Flow::Return);
        // A reserved compressed half (quadrant 0, funct3=100) still decodes as a 2-byte generic
        // c.insn (keeps the sweep aligned without claiming to know the operands).
        let other = decode(&0x8000u16.to_le_bytes(), 0, true).unwrap();
        assert_eq!(other.len, 2);
        assert_eq!(other.mnemonic, "c.insn");
    }

    #[test]
    fn compressed_integer_set() {
        // Each operand check also pins the immediate decoder for that format.
        let ops = |w: u32| {
            d(w, 0)
                .operands
                .iter()
                .map(|t| t.text.clone())
                .collect::<Vec<_>>()
        };

        // c.addi4spn a0, sp, 0x10
        let i = d(0x0808, 0);
        assert_eq!(i.mnemonic, "c.addi4spn");
        assert_eq!(ops(0x0808), ["a0", ",", "sp", ",", "0x10"]);
        // c.lw a0, 0x0(a1)
        assert_eq!(d(0x4188, 0).mnemonic, "c.lw");
        assert_eq!(ops(0x4188), ["a0", ",", "0x0", "(", "a1", ")"]);
        // c.ldsp ra, 0x8(sp)
        assert_eq!(d(0x60a2, 0).mnemonic, "c.ldsp");
        assert_eq!(ops(0x60a2), ["ra", ",", "0x8", "(", "sp", ")"]);
        // c.sdsp ra, 0x8(sp)
        assert_eq!(d(0xe406, 0).mnemonic, "c.sdsp");
        assert_eq!(ops(0xe406), ["ra", ",", "0x8", "(", "sp", ")"]);
        // c.swsp ra, 0x0(sp)
        assert_eq!(d(0xc006, 0).mnemonic, "c.swsp");
        // c.lui a0, 0x1
        assert_eq!(d(0x6505, 0).mnemonic, "c.lui");
        assert_eq!(ops(0x6505), ["a0", ",", "0x1"]);
        // c.sub a0, a1
        assert_eq!(d(0x8d0d, 0).mnemonic, "c.sub");
        assert_eq!(ops(0x8d0d), ["a0", ",", "a1"]);
        // c.slli a0, 0x1
        assert_eq!(d(0x0506, 0).mnemonic, "c.slli");
        assert_eq!(ops(0x0506), ["a0", ",", "0x1"]);
    }

    #[test]
    fn floating_point() {
        let ops = |w: u32| {
            d(w, 0)
                .operands
                .iter()
                .map(|t| t.text.clone())
                .collect::<Vec<_>>()
        };
        // fadd.s fa0, fa1, fa2
        assert_eq!(d(0x00c5_8553, 0).mnemonic, "fadd.s");
        assert_eq!(ops(0x00c5_8553), ["fa0", ",", "fa1", ",", "fa2"]);
        // fld fa0, 0x8(sp)
        assert_eq!(d(0x0081_3507, 0).mnemonic, "fld");
        assert_eq!(ops(0x0081_3507), ["fa0", ",", "0x8", "(", "sp", ")"]);
        // fsw fa0, 0x0(sp)
        assert_eq!(d(0x00a1_2027, 0).mnemonic, "fsw");
        assert_eq!(ops(0x00a1_2027), ["fa0", ",", "0x0", "(", "sp", ")"]);
        // fcvt.w.s a0, fa0 — float to int, integer destination.
        assert_eq!(d(0xc005_7553, 0).mnemonic, "fcvt.w.s");
        assert_eq!(ops(0xc005_7553), ["a0", ",", "fa0"]);
        // fmadd.s fa0, fa1, fa2, fa3 — fused multiply-add, four float registers.
        assert_eq!(d(0x68c5_8543, 0).mnemonic, "fmadd.s");
        assert_eq!(
            ops(0x68c5_8543),
            ["fa0", ",", "fa1", ",", "fa2", ",", "fa3"]
        );
        // c.fldsp fa0, 0x8(sp) — compressed double load from the stack.
        assert_eq!(d(0x2522, 0).mnemonic, "c.fldsp");
        assert_eq!(ops(0x2522), ["fa0", ",", "0x8", "(", "sp", ")"]);
    }

    #[test]
    fn csr_instructions() {
        let ops = |w: u32| {
            d(w, 0)
                .operands
                .iter()
                .map(|t| t.text.clone())
                .collect::<Vec<_>>()
        };
        // csrrw a0, 0x300, a1 — register source.
        let i = d(0x3005_9573, 0);
        assert_eq!(i.mnemonic, "csrrw");
        assert_eq!(ops(0x3005_9573), ["a0", ",", "0x300", ",", "a1"]);
        // csrrwi a0, 0x300, 0x5 — the `*i` form takes a 5-bit zero-extended immediate.
        let i = d(0x3002_d573, 0);
        assert_eq!(i.mnemonic, "csrrwi");
        assert_eq!(ops(0x3002_d573), ["a0", ",", "0x300", ",", "0x5"]);
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x13], 0, true).is_none());
    }

    #[test]
    fn rv32_compressed_collisions() {
        // The five slots that differ by XLEN. c.addiw (0x0001 | f3=001 | op=01 => 0x2001) is
        // c.addiw on RV64 but c.jal (a call) on RV32.
        let w = 0x2001u16;
        assert_eq!(d(u32::from(w), 0).mnemonic, "c.addiw");
        let jal = c32(w, 0x1000);
        assert_eq!(jal.mnemonic, "c.jal");
        assert!(
            matches!(jal.flow, Flow::Call(_)),
            "c.jal is a call: {:?}",
            jal.flow
        );

        // Quadrant 0 funct3=011: c.ld (RV64) vs c.flw (RV32).
        let ld = 0x4000u16 | (1 << 13); // op=00, f3=011
        assert_eq!(d(u32::from(ld), 0).mnemonic, "c.ld");
        assert_eq!(c32(ld, 0).mnemonic, "c.flw");
        // funct3=111: c.sd (RV64) vs c.fsw (RV32).
        let sd = 0xc000u16 | (1 << 13);
        assert_eq!(d(u32::from(sd), 0).mnemonic, "c.sd");
        assert_eq!(c32(sd, 0).mnemonic, "c.fsw");
        // Quadrant 2 funct3=011/111: c.ldsp/c.sdsp (RV64) vs c.flwsp/c.fswsp (RV32).
        let ldsp = 0x6002u16;
        assert_eq!(d(u32::from(ldsp), 0).mnemonic, "c.ldsp");
        assert_eq!(c32(ldsp, 0).mnemonic, "c.flwsp");
        let sdsp = 0xe002u16;
        assert_eq!(d(u32::from(sdsp), 0).mnemonic, "c.sdsp");
        assert_eq!(c32(sdsp, 0).mnemonic, "c.fswsp");
    }
}
