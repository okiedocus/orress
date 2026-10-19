//! A hand-rolled PowerPC disassembler (PPC32 and PPC64, big- and little-endian). PowerPC
//! instructions are a fixed 32 bits in a handful of fixed forms (D/DS/X/XL/I/B/M), so decoding is
//! field extraction plus an opcode table and, for the big primary opcode 31, an extended-opcode
//! table. PowerPC has no delay slots. The common integer, load/store, branch and
//! floating-point-memory instructions are decoded with operands and correct control flow;
//! rarer encodings are shown generically so they are not mistaken for data. Pure Rust, no decoder
//! dependency.
//!
//! Bit numbering: PowerPC documents bits MSB-first (bit 0 is the most significant), but once the
//! four instruction bytes are read as one integer (big-endian for PPC/PPC64, little-endian for
//! `ppc64le`), the usual `(w >> shift) & mask` extraction applies. `little` selects only the byte
//! order of that read.

use crate::{Flow, Insn, Token, TokenKind};

fn reg(n: u32) -> Token {
    Token {
        kind: TokenKind::Register,
        text: format!("r{}", n & 31),
    }
}

/// A floating-point register token, `f0`..`f31`.
fn freg(n: u32) -> Token {
    Token {
        kind: TokenKind::Register,
        text: format!("f{}", n & 31),
    }
}

/// A special-purpose / condition register token (`lr`, `ctr`, `cr0` …).
fn sreg(text: &str) -> Token {
    Token {
        kind: TokenKind::Register,
        text: text.to_owned(),
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

pub fn decode(bytes: &[u8], address: u64, little: bool, bits64: bool) -> Option<Insn> {
    let raw: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let w = if little {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    };
    decode_word(w, address, bits64)
}

/// `op rt, imm(ra)` — the D-form load/store operand shape.
fn mem(address: u64, m: &str, rt: Token, d: i64, ra: u32, flow: Flow) -> Insn {
    insn(
        address,
        m,
        vec![rt, punct(","), imm(d), punct("("), reg(ra), punct(")")],
        flow,
    )
}

fn decode_word(w: u32, address: u64, bits64: bool) -> Option<Insn> {
    let op = w >> 26;
    // RT/RS and RA share the two 5-bit fields after the opcode in most forms.
    let rt = (w >> 21) & 0x1f;
    let ra = (w >> 16) & 0x1f;
    let d = (w & 0xffff) as i16 as i64;
    let ud = u64::from(w & 0xffff);

    // D-form `rt, ra, simm` (arithmetic): destination RT, source RA.
    let arith = |m: &str| {
        insn(
            address,
            m,
            vec![reg(rt), punct(","), reg(ra), punct(","), imm(d)],
            Flow::Next,
        )
    };
    // D-form `ra, rs, uimm` (logical): destination RA, source RS (= the RT field).
    let logic = |m: &str| {
        insn(
            address,
            m,
            vec![
                reg(ra),
                punct(","),
                reg(rt),
                punct(","),
                num(format!("0x{ud:x}")),
            ],
            Flow::Next,
        )
    };

    Some(match op {
        7 => arith("mulli"),
        8 => arith("subfic"),
        10 | 11 => {
            // cmpli/cmpi: a 16-bit immediate compare. L (bit 10 of the instruction, i.e. (w>>21)&1)
            // selects 64-bit; crfD is bits 6-8.
            let crf = (w >> 23) & 7;
            let l = (rt & 1) != 0;
            let m = match (op, l) {
                (10, false) => "cmplwi",
                (10, true) => "cmpldi",
                (11, false) => "cmpwi",
                _ => "cmpdi",
            };
            let v = if op == 10 {
                num(format!("0x{ud:x}"))
            } else {
                imm(d)
            };
            let mut ops = Vec::new();
            if crf != 0 {
                ops.push(sreg(&format!("cr{crf}")));
                ops.push(punct(","));
            }
            ops.extend([reg(ra), punct(","), v]);
            insn(address, m, ops, Flow::Next)
        }
        12 => arith("addic"),
        13 => arith("addic."),
        14 => {
            if ra == 0 {
                // li rt, simm
                insn(address, "li", vec![reg(rt), punct(","), imm(d)], Flow::Next)
            } else {
                arith("addi")
            }
        }
        15 => {
            if ra == 0 {
                // lis rt, uimm
                insn(
                    address,
                    "lis",
                    vec![reg(rt), punct(","), num(format!("0x{ud:x}"))],
                    Flow::Next,
                )
            } else {
                arith("addis")
            }
        }
        16 => decode_bc(w, address),
        17 => insn(address, "sc", vec![], Flow::Next),
        18 => decode_b(w, address),
        19 => return decode_xl(w, address),
        20 => insn(address, "rlwimi", rot_ops(w), Flow::Next),
        21 => insn(address, "rlwinm", rot_ops(w), Flow::Next),
        23 => insn(address, "rlwnm", rot_ops(w), Flow::Next),
        24 => {
            if w == 0x6000_0000 {
                insn(address, "nop", vec![], Flow::Next)
            } else {
                logic("ori")
            }
        }
        25 => logic("oris"),
        26 => logic("xori"),
        27 => logic("xoris"),
        28 => logic("andi."),
        29 => logic("andis."),
        30 if bits64 => {
            // MD-form 64-bit rotate: the 2-bit sub-opcode in bits 27-28 selects the variant.
            let m = ["rldicl", "rldicr", "rldic", "rldimi"][((w >> 2) & 3) as usize];
            insn(address, m, rotd_ops(w), Flow::Next)
        }
        31 => return decode_x(w, address, bits64),
        // D-form loads and stores.
        32 => mem(address, "lwz", reg(rt), d, ra, Flow::Next),
        33 => mem(address, "lwzu", reg(rt), d, ra, Flow::Next),
        34 => mem(address, "lbz", reg(rt), d, ra, Flow::Next),
        35 => mem(address, "lbzu", reg(rt), d, ra, Flow::Next),
        36 => mem(address, "stw", reg(rt), d, ra, Flow::Next),
        37 => mem(address, "stwu", reg(rt), d, ra, Flow::Next),
        38 => mem(address, "stb", reg(rt), d, ra, Flow::Next),
        39 => mem(address, "stbu", reg(rt), d, ra, Flow::Next),
        40 => mem(address, "lhz", reg(rt), d, ra, Flow::Next),
        41 => mem(address, "lhzu", reg(rt), d, ra, Flow::Next),
        42 => mem(address, "lha", reg(rt), d, ra, Flow::Next),
        43 => mem(address, "lhau", reg(rt), d, ra, Flow::Next),
        44 => mem(address, "sth", reg(rt), d, ra, Flow::Next),
        45 => mem(address, "sthu", reg(rt), d, ra, Flow::Next),
        46 => mem(address, "lmw", reg(rt), d, ra, Flow::Next),
        47 => mem(address, "stmw", reg(rt), d, ra, Flow::Next),
        48 => mem(address, "lfs", freg(rt), d, ra, Flow::Next),
        49 => mem(address, "lfsu", freg(rt), d, ra, Flow::Next),
        50 => mem(address, "lfd", freg(rt), d, ra, Flow::Next),
        51 => mem(address, "lfdu", freg(rt), d, ra, Flow::Next),
        52 => mem(address, "stfs", freg(rt), d, ra, Flow::Next),
        53 => mem(address, "stfsu", freg(rt), d, ra, Flow::Next),
        54 => mem(address, "stfd", freg(rt), d, ra, Flow::Next),
        55 => mem(address, "stfdu", freg(rt), d, ra, Flow::Next),
        58 if bits64 => {
            // DS-form: the low two bits of the displacement are the extended opcode.
            let ds = (w & 0xfffc) as i16 as i64;
            let m = match w & 3 {
                0 => "ld",
                1 => "ldu",
                _ => "lwa",
            };
            mem(address, m, reg(rt), ds, ra, Flow::Next)
        }
        59 => decode_fp_a(w, address, true),
        62 if bits64 => {
            let ds = (w & 0xfffc) as i16 as i64;
            let m = if w & 3 == 0 { "std" } else { "stdu" };
            mem(address, m, reg(rt), ds, ra, Flow::Next)
        }
        63 => decode_fp_a(w, address, false),
        _ => return None,
    })
}

/// The rotate-and-mask operand shape `rA, rS, SH, MB, ME` (rlwinm/rlwimi/rlwnm).
fn rot_ops(w: u32) -> Vec<Token> {
    let rs = (w >> 21) & 0x1f;
    let ra = (w >> 16) & 0x1f;
    let sh = (w >> 11) & 0x1f;
    let mb = (w >> 6) & 0x1f;
    let me = (w >> 1) & 0x1f;
    vec![
        reg(ra),
        punct(","),
        reg(rs),
        punct(","),
        imm(i64::from(sh)),
        punct(","),
        imm(i64::from(mb)),
        punct(","),
        imm(i64::from(me)),
    ]
}

/// The 64-bit rotate operand shape `rA, rS, SH, MB` (rldic family); SH and MB are 6-bit.
fn rotd_ops(w: u32) -> Vec<Token> {
    let rs = (w >> 21) & 0x1f;
    let ra = (w >> 16) & 0x1f;
    let sh = ((w >> 11) & 0x1f) | (((w >> 1) & 1) << 5);
    let mb = ((w >> 6) & 0x1f) | (((w >> 5) & 1) << 5);
    vec![
        reg(ra),
        punct(","),
        reg(rs),
        punct(","),
        imm(i64::from(sh)),
        punct(","),
        imm(i64::from(mb)),
    ]
}

/// I-form branch (opcode 18): `b`/`bl`/`ba`/`bla`.
fn decode_b(w: u32, address: u64) -> Insn {
    let li = ((w & 0x03ff_fffc) as i32) << 6 >> 6; // sign-extend the 26-bit field
    let aa = (w >> 1) & 1 != 0;
    let lk = w & 1 != 0;
    let target = if aa {
        li as i64 as u64
    } else {
        address.wrapping_add_signed(i64::from(li))
    };
    let m = match (aa, lk) {
        (false, false) => "b",
        (false, true) => "bl",
        (true, false) => "ba",
        (true, true) => "bla",
    };
    let flow = if lk {
        Flow::Call(target)
    } else {
        Flow::Jump(target)
    };
    insn(address, m, vec![addr_tok(target)], flow)
}

/// B-form conditional branch (opcode 16): `bc`/`bcl`/`bca`/`bcla`.
fn decode_bc(w: u32, address: u64) -> Insn {
    let bo = (w >> 21) & 0x1f;
    let bi = (w >> 16) & 0x1f;
    // BD is the signed 14-bit displacement in bits 16-29; masking off AA/LK (the low two bits)
    // and reading as i16 sign-extends it.
    let bd = (w & 0xfffc) as i16 as i64;
    let aa = (w >> 1) & 1 != 0;
    let lk = w & 1 != 0;
    let target = if aa {
        bd as u64
    } else {
        address.wrapping_add_signed(bd)
    };
    let m = match (aa, lk) {
        (false, false) => "bc",
        (false, true) => "bcl",
        (true, false) => "bca",
        _ => "bcla",
    };
    insn(
        address,
        m,
        vec![
            imm(i64::from(bo)),
            punct(","),
            imm(i64::from(bi)),
            punct(","),
            addr_tok(target),
        ],
        Flow::CondJump(target),
    )
}

/// XL-form (opcode 19): branches through LR/CTR and the condition-register logical ops.
fn decode_xl(w: u32, address: u64) -> Option<Insn> {
    let xo = (w >> 1) & 0x3ff;
    let lk = w & 1 != 0;
    Some(match xo {
        16 => {
            // bclr: return through LR. Unconditional when BO = 20 (`blr`).
            let m = if lk { "blrl" } else { "blr" };
            insn(address, m, vec![], Flow::Return)
        }
        528 => {
            // bcctr: branch through CTR, a computed jump/call.
            let m = if lk { "bctrl" } else { "bctr" };
            let flow = if lk {
                Flow::IndirectCall { slot: None }
            } else {
                Flow::IndirectJump {
                    slot: None,
                    table: None,
                }
            };
            insn(address, m, vec![], flow)
        }
        150 => insn(address, "isync", vec![], Flow::Next),
        257 => insn(address, "crand", vec![], Flow::Next),
        193 => insn(address, "crxor", vec![], Flow::Next),
        449 => insn(address, "cror", vec![], Flow::Next),
        _ => insn(address, "xl", vec![], Flow::Next),
    })
}

/// A-form floating-point arithmetic (opcodes 59 single / 63 double, plus the 63 X-form compares
/// and moves). `single` selects the `s`-suffixed single-precision mnemonics.
fn decode_fp_a(w: u32, address: u64, single: bool) -> Insn {
    let frt = (w >> 21) & 0x1f;
    let fra = (w >> 16) & 0x1f;
    let frb = (w >> 11) & 0x1f;
    let frc = (w >> 6) & 0x1f;
    let xo5 = (w >> 1) & 0x1f;
    let s = if single { "s" } else { "" };
    let fff = |m: &str, a: u32, b: u32| {
        insn(
            address,
            m,
            vec![freg(frt), punct(","), freg(a), punct(","), freg(b)],
            Flow::Next,
        )
    };
    match xo5 {
        18 => fff(&format!("fdiv{s}"), fra, frb),
        20 => fff(&format!("fsub{s}"), fra, frb),
        21 => fff(&format!("fadd{s}"), fra, frb),
        25 => fff(&format!("fmul{s}"), fra, frc),
        22 if !single => insn(
            address,
            "fsqrt",
            vec![freg(frt), punct(","), freg(frb)],
            Flow::Next,
        ),
        // Opcode 63 also hosts X-form moves/compares in the full 10-bit extended opcode.
        _ if !single => decode_fp_x(w, address),
        _ => insn(address, &format!("fp{s}"), vec![], Flow::Next),
    }
}

/// X-form floating-point moves and compares living under opcode 63.
fn decode_fp_x(w: u32, address: u64) -> Insn {
    let frt = (w >> 21) & 0x1f;
    let fra = (w >> 16) & 0x1f;
    let frb = (w >> 11) & 0x1f;
    let xo = (w >> 1) & 0x3ff;
    let ff = |m: &str| {
        insn(
            address,
            m,
            vec![freg(frt), punct(","), freg(frb)],
            Flow::Next,
        )
    };
    match xo {
        0 => insn(
            address,
            "fcmpu",
            vec![
                sreg(&format!("cr{}", (w >> 23) & 7)),
                punct(","),
                freg(fra),
                punct(","),
                freg(frb),
            ],
            Flow::Next,
        ),
        72 => ff("fmr"),
        40 => ff("fneg"),
        264 => ff("fabs"),
        12 => ff("frsp"),
        _ => insn(address, "fp", vec![], Flow::Next),
    }
}

/// X-form and related (opcode 31): the integer register-register instructions, indexed
/// loads/stores and the special-register moves.
fn decode_x(w: u32, address: u64, bits64: bool) -> Option<Insn> {
    let rt = (w >> 21) & 0x1f; // RT or RS
    let ra = (w >> 16) & 0x1f;
    let rb = (w >> 11) & 0x1f;
    let xo = (w >> 1) & 0x3ff;
    let rc = w & 1 != 0;
    let dot = |m: &str| if rc { format!("{m}.") } else { m.to_owned() };

    // `rD, rA, rB` (arithmetic: destination is RT).
    let arith = |m: String| {
        insn(
            address,
            &m,
            vec![reg(rt), punct(","), reg(ra), punct(","), reg(rb)],
            Flow::Next,
        )
    };
    // `rA, rS, rB` (logical/shift: destination is RA, source is RS = the RT field).
    let logic = |m: String| {
        insn(
            address,
            &m,
            vec![reg(ra), punct(","), reg(rt), punct(","), reg(rb)],
            Flow::Next,
        )
    };
    // `rD, rA, rB` indexed memory.
    let memx = |m: &str| {
        insn(
            address,
            m,
            vec![reg(rt), punct(","), reg(ra), punct(","), reg(rb)],
            Flow::Next,
        )
    };

    Some(match xo {
        // Compares.
        0 | 32 => {
            let crf = (w >> 23) & 7;
            let l = (rt & 1) != 0;
            let m = match (xo, l, bits64) {
                (0, false, _) => "cmpw",
                (0, true, _) => "cmpd",
                (32, false, _) => "cmplw",
                _ => "cmpld",
            };
            let mut ops = Vec::new();
            if crf != 0 {
                ops.push(sreg(&format!("cr{crf}")));
                ops.push(punct(","));
            }
            ops.extend([reg(ra), punct(","), reg(rb)]);
            insn(address, m, ops, Flow::Next)
        }
        8 => arith(dot("subfc")),
        10 => arith(dot("addc")),
        40 => arith(dot("subf")),
        104 => insn(
            address,
            &dot("neg"),
            vec![reg(rt), punct(","), reg(ra)],
            Flow::Next,
        ),
        136 => arith(dot("subfe")),
        138 => arith(dot("adde")),
        235 => arith(dot("mullw")),
        75 => arith(dot("mulhw")),
        11 => arith(dot("mulhwu")),
        233 if bits64 => arith(dot("mulld")),
        266 => arith(dot("add")),
        457 if bits64 => arith(dot("divdu")),
        459 => arith(dot("divwu")),
        489 if bits64 => arith(dot("divd")),
        491 => arith(dot("divw")),
        // Logical register-register.
        28 => logic(dot("and")),
        60 => logic(dot("andc")),
        124 => logic(dot("nor")),
        284 => logic(dot("eqv")),
        316 => logic(dot("xor")),
        412 => logic(dot("orc")),
        444 => {
            // `or rA,rS,rB`; `or rA,rS,rS` is the `mr` register move.
            if rt == rb {
                insn(
                    address,
                    &dot("mr"),
                    vec![reg(ra), punct(","), reg(rt)],
                    Flow::Next,
                )
            } else {
                logic(dot("or"))
            }
        }
        476 => logic(dot("nand")),
        // Shifts.
        24 => logic(dot("slw")),
        536 => logic(dot("srw")),
        792 => logic(dot("sraw")),
        27 if bits64 => logic(dot("sld")),
        539 if bits64 => logic(dot("srd")),
        794 if bits64 => logic(dot("srad")),
        824 => insn(
            address,
            &dot("srawi"),
            vec![reg(ra), punct(","), reg(rt), punct(","), imm(i64::from(rb))],
            Flow::Next,
        ),
        // Sign/zero extension and bit counts (`rA, rS`).
        922 => insn(
            address,
            &dot("extsh"),
            vec![reg(ra), punct(","), reg(rt)],
            Flow::Next,
        ),
        954 => insn(
            address,
            &dot("extsb"),
            vec![reg(ra), punct(","), reg(rt)],
            Flow::Next,
        ),
        986 if bits64 => insn(
            address,
            &dot("extsw"),
            vec![reg(ra), punct(","), reg(rt)],
            Flow::Next,
        ),
        26 => insn(
            address,
            &dot("cntlzw"),
            vec![reg(ra), punct(","), reg(rt)],
            Flow::Next,
        ),
        // Condition-register and special-register moves.
        19 => insn(address, "mfcr", vec![reg(rt)], Flow::Next),
        339 => decode_mfspr(w, address, rt),
        467 => decode_mtspr(w, address, rt),
        // Indexed loads and stores.
        23 => memx("lwzx"),
        55 => memx("lwzux"),
        87 => memx("lbzx"),
        119 => memx("lbzux"),
        279 => memx("lhzx"),
        343 => memx("lhax"),
        151 => memx("stwx"),
        183 => memx("stwux"),
        215 => memx("stbx"),
        407 => memx("sthx"),
        21 if bits64 => memx("ldx"),
        53 if bits64 => memx("ldux"),
        149 if bits64 => memx("stdx"),
        181 if bits64 => memx("stdux"),
        // Traps.
        4 => {
            let to = rt;
            if to == 31 && ra == rb {
                insn(address, "trap", vec![], Flow::Stop)
            } else {
                insn(
                    address,
                    "tw",
                    vec![imm(i64::from(to)), punct(","), reg(ra), punct(","), reg(rb)],
                    Flow::Next,
                )
            }
        }
        // Atomics / cache ops left generic but named so they are not read as data.
        20 => memx("lwarx"),
        150 => insn(
            address,
            "stwcx.",
            vec![reg(rt), punct(","), reg(ra), punct(","), reg(rb)],
            Flow::Next,
        ),
        _ => insn(address, &format!("op31.{xo}"), vec![], Flow::Next),
    })
}

/// A special-purpose register name for the common SPR numbers.
fn spr_name(spr: u32) -> Option<&'static str> {
    match spr {
        1 => Some("xer"),
        8 => Some("lr"),
        9 => Some("ctr"),
        _ => None,
    }
}

/// The SPR number is the two 5-bit halves of bits 11-20, swapped.
fn spr_of(w: u32) -> u32 {
    let field = (w >> 11) & 0x3ff;
    ((field & 0x1f) << 5) | ((field >> 5) & 0x1f)
}

fn decode_mfspr(w: u32, address: u64, rt: u32) -> Insn {
    let spr = spr_of(w);
    match spr_name(spr) {
        Some("lr") => insn(address, "mflr", vec![reg(rt)], Flow::Next),
        Some("ctr") => insn(address, "mfctr", vec![reg(rt)], Flow::Next),
        Some(name) => insn(
            address,
            "mfspr",
            vec![reg(rt), punct(","), sreg(name)],
            Flow::Next,
        ),
        None => insn(
            address,
            "mfspr",
            vec![reg(rt), punct(","), num(format!("0x{spr:x}"))],
            Flow::Next,
        ),
    }
}

fn decode_mtspr(w: u32, address: u64, rt: u32) -> Insn {
    let spr = spr_of(w);
    match spr_name(spr) {
        Some("lr") => insn(address, "mtlr", vec![reg(rt)], Flow::Next),
        Some("ctr") => insn(address, "mtctr", vec![reg(rt)], Flow::Next),
        Some(name) => insn(
            address,
            "mtspr",
            vec![sreg(name), punct(","), reg(rt)],
            Flow::Next,
        ),
        None => insn(
            address,
            "mtspr",
            vec![num(format!("0x{spr:x}")), punct(","), reg(rt)],
            Flow::Next,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(w: u32, addr: u64) -> Insn {
        decode(&w.to_be_bytes(), addr, false, false).expect("decodes")
    }
    fn be64(w: u32, addr: u64) -> Insn {
        decode(&w.to_be_bytes(), addr, false, true).expect("decodes")
    }
    fn ops(i: &Insn) -> Vec<String> {
        i.operands.iter().map(|t| t.text.clone()).collect()
    }

    #[test]
    fn arithmetic_and_aliases() {
        // addi r3, r4, 0x10 -> opcode 14, RT=3, RA=4, SIMM=0x10 : 0x38640010
        let i = be(0x3864_0010, 0x1000);
        assert_eq!(i.mnemonic, "addi");
        assert_eq!(ops(&i), ["r3", ",", "r4", ",", "0x10"]);
        // li r3, 1 : addi with RA=0 -> 0x38600001
        assert_eq!(be(0x3860_0001, 0).mnemonic, "li");
        // lis r3, 0x1234 : opcode 15 RA=0 -> 0x3C601234
        let lis = be(0x3C60_1234, 0);
        assert_eq!(lis.mnemonic, "lis");
        assert_eq!(ops(&lis), ["r3", ",", "0x1234"]);
        // nop = ori r0,r0,0 = 0x60000000
        assert_eq!(be(0x6000_0000, 0).mnemonic, "nop");
    }

    #[test]
    fn register_register_and_mr() {
        // add r3, r4, r5 -> opcode 31 xo=266 RT=3 RA=4 RB=5 : 0x7C642A14
        let i = be(0x7C64_2A14, 0);
        assert_eq!(i.mnemonic, "add");
        assert_eq!(ops(&i), ["r3", ",", "r4", ",", "r5"]);
        // or r3, r4, r4 -> mr r3, r4 : xo=444, RS=4 RA=3 RB=4 : 0x7C832378
        let mr = be(0x7C83_2378, 0);
        assert_eq!(mr.mnemonic, "mr");
        assert_eq!(ops(&mr), ["r3", ",", "r4"]);
        // mullw r3, r4, r5 : xo=235 -> 0x7C6429D6
        assert_eq!(be(0x7C64_29D6, 0).mnemonic, "mullw");
    }

    #[test]
    fn loads_stores() {
        // lwz r3, 0x10(r4) -> opcode 32 : 0x80640010
        let i = be(0x8064_0010, 0);
        assert_eq!(i.mnemonic, "lwz");
        assert_eq!(ops(&i), ["r3", ",", "0x10", "(", "r4", ")"]);
        // stwu r1, -0x20(r1) : opcode 37, RS=1 RA=1 D=-32 -> 0x9421FFE0
        let stwu = be(0x9421_FFE0, 0);
        assert_eq!(stwu.mnemonic, "stwu");
        assert_eq!(stwu.operands[2].text, "-0x20");
        // std r3, 0x8(r1) : opcode 62 DS-form (64-bit) -> 0xF8610008
        assert_eq!(be64(0xF861_0008, 0).mnemonic, "std");
        // ld r3, 0x8(r1) : opcode 58 -> 0xE8610008
        assert_eq!(be64(0xE861_0008, 0).mnemonic, "ld");
    }

    #[test]
    fn branches_and_control_flow() {
        // bl +0x100 : opcode 18, LI=0x100, LK=1 -> 0x48000101
        let bl = be(0x4800_0101, 0x1000);
        assert_eq!(bl.mnemonic, "bl");
        assert_eq!(bl.flow, Flow::Call(0x1100));
        // b -0x100 : LI=-0x100 -> 0x4BFFFF00
        let b = be(0x4BFF_FF00, 0x1000);
        assert_eq!(b.mnemonic, "b");
        assert_eq!(b.flow, Flow::Jump(0x0f00));
        // blr = 0x4E800020 (bclr BO=20) -> Return
        assert_eq!(be(0x4E80_0020, 0).mnemonic, "blr");
        assert_eq!(be(0x4E80_0020, 0).flow, Flow::Return);
        // bctr = 0x4E800420 -> indirect jump
        assert_eq!(
            be(0x4E80_0420, 0).flow,
            Flow::IndirectJump {
                slot: None,
                table: None
            }
        );
        // bctrl = 0x4E800421 -> indirect call
        assert_eq!(be(0x4E80_0421, 0).flow, Flow::IndirectCall { slot: None });
        // bc 12,0,+0x8 (beq-style) : opcode 16 BO=12 BI=0 BD=8 -> 0x41800008
        let bc = be(0x4180_0008, 0x2000);
        assert_eq!(bc.mnemonic, "bc");
        assert_eq!(bc.flow, Flow::CondJump(0x2008));
    }

    #[test]
    fn special_register_moves() {
        // mflr r0 : opcode 31 xo=339, SPR=8 -> 0x7C0802A6
        assert_eq!(be(0x7C08_02A6, 0).mnemonic, "mflr");
        // mtlr r0 : xo=467, SPR=8 -> 0x7C0803A6
        assert_eq!(be(0x7C08_03A6, 0).mnemonic, "mtlr");
        // mtctr r3 : SPR=9 -> 0x7C6903A6
        assert_eq!(be(0x7C69_03A6, 0).mnemonic, "mtctr");
    }

    #[test]
    fn little_endian_read() {
        // The ppc64le byte order: the same `add r3,r4,r5` word stored little-endian.
        let le = decode(&0x7C64_2A14u32.to_le_bytes(), 0, true, true).unwrap();
        assert_eq!(le.mnemonic, "add");
    }

    #[test]
    fn unknown_is_none() {
        // Primary opcode 1 is unused.
        assert!(decode(&0x0400_0000u32.to_be_bytes(), 0, false, false).is_none());
        assert!(decode(&[0, 0], 0, false, false).is_none());
    }
}
