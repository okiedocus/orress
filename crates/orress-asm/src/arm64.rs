//! AArch64 (A64) encoder, hand-written by bitfield packing. Every A64 instruction is a fixed 32-bit
//! word, so each statement is exactly 4 bytes and label addresses are simply `base + 4 * index` —
//! branch resolution needs no fixup pass.
//!
//! Coverage is a common patching subset: nop/ret/br/blr, mov (register and small immediate),
//! movz/movk/movn, add/sub/adds/subs and cmp/cmn (imm12 with optional `lsl #12`, or a register with
//! an optional `lsl`/`lsr`/`asr` shift), neg, and/orr/eor/ands (with shifts), tst, mvn, mul,
//! lsl/lsr/asr/ror (register and immediate), ldr/str/ldrb/strb/ldrh/strh/ldrsw (base, `#imm` offset
//! or register offset with an optional `lsl` scale), b/bl, `b.<cond>`, cbz/cbnz (to a label or an
//! absolute address), svc, brk. Operand widths follow the destination register (`x` = 64-bit, `w` =
//! 32-bit). Register 31 is validated per field: `sp` where the encoding reads it as the stack
//! pointer (add/sub immediate, load/store base), `xzr` elsewhere; add/sub/cmp with `sp` and a
//! register use the extended-register form. Bitmask immediates for the logical ops and
//! pre/post-indexed loads come later.

use std::collections::HashMap;

use crate::parse::{self, Operand, ShiftOp};
use crate::{Assembled, Diagnostic, LineOutput};

/// A parsed A64 register.
#[derive(Clone, Copy)]
struct Reg {
    /// Register number 0..=31 (31 is the zero register or the stack pointer, per `is_sp`).
    n: u32,
    /// 64-bit `x`/`sp` register (`true`) or 32-bit `w`/`wsp` (`false`).
    is64: bool,
    /// Written as `sp`/`wsp` rather than `xzr`/`wzr` (both are number 31).
    is_sp: bool,
}

pub(crate) fn assemble(source: &str, base_addr: u64) -> Result<Assembled, Vec<Diagnostic>> {
    let lines = parse::parse(source)?;
    let mut errors = Vec::new();

    // Pass 1: every statement is one 4-byte instruction, so label addresses fall out directly.
    let mut labels: HashMap<String, u64> = HashMap::new();
    let mut addr = base_addr;
    for l in &lines {
        if let Some(name) = &l.label
            && labels.insert(name.clone(), addr).is_some()
        {
            errors.push(Diagnostic::new(
                l.line,
                format!("label `{name}` defined twice"),
            ));
        }
        if l.stmt.is_some() {
            addr = addr.wrapping_add(4);
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // Pass 2: encode each instruction at its now-known address.
    let mut out_lines = Vec::with_capacity(lines.len());
    let mut pc = base_addr;
    for l in &lines {
        let (address, bytes) = if let Some(stmt) = &l.stmt {
            let a = pc;
            let b = match encode(&stmt.mnemonic, &stmt.operands, pc, &labels) {
                Ok(word) => word.to_le_bytes().to_vec(),
                Err(msg) => {
                    errors.push(Diagnostic::new(l.line, msg));
                    Vec::new()
                }
            };
            pc = pc.wrapping_add(4);
            (a, b)
        } else {
            (pc, Vec::new())
        };
        out_lines.push(LineOutput {
            line: l.line,
            address,
            bytes,
            source: l.source.clone(),
        });
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut bytes = Vec::new();
    for l in &out_lines {
        bytes.extend_from_slice(&l.bytes);
    }
    Ok(Assembled {
        bytes,
        lines: out_lines,
    })
}

fn encode(m: &str, ops: &[Operand], pc: u64, labels: &HashMap<String, u64>) -> Result<u32, String> {
    match m {
        "nop" => {
            arity(ops, 0, m)?;
            Ok(0xD503_201F)
        }
        "ret" => {
            let rn = if ops.is_empty() {
                30
            } else {
                arity(ops, 1, m)?;
                let r = as_reg(&ops[0])?;
                need64(r, m)?;
                r.n
            };
            Ok(0xD65F_0000 | (rn << 5))
        }
        "br" => Ok(0xD61F_0000 | (unary_x(ops, m)? << 5)),
        "blr" => Ok(0xD63F_0000 | (unary_x(ops, m)? << 5)),
        "mov" => encode_mov(ops),
        "movz" | "movk" | "movn" => encode_movw(m, ops),
        "add" | "sub" | "adds" | "subs" => encode_addsub(m, ops),
        "cmp" | "cmn" => encode_cmp(m, ops),
        "neg" => encode_two_reg(ops, 0xCB00_0000, 0x4B00_0000, 31),
        "mvn" => encode_two_reg(ops, 0xAA20_0000, 0x2A20_0000, 31),
        "and" | "orr" | "eor" | "ands" => encode_logic(m, ops),
        "tst" => {
            arity(ops, 2, m)?;
            let (n, mm) = (as_reg(&ops[0])?, as_reg(&ops[1])?);
            same_width(&[n, mm], m)?;
            let base = if n.is64 { 0xEA00_0000 } else { 0x6A00_0000 };
            Ok(base | (mm.n << 16) | (n.n << 5) | 31)
        }
        "mul" => encode_mul(ops),
        "ldr" | "str" | "ldrb" | "strb" | "ldrh" | "strh" | "ldrsw" => encode_ldst(m, ops),
        "lsl" | "lsr" | "asr" | "ror" => encode_shift(m, ops),
        "b" => Ok(0x1400_0000 | (branch(ops, m, pc, labels, 26)? & 0x03FF_FFFF)),
        "bl" => Ok(0x9400_0000 | (branch(ops, m, pc, labels, 26)? & 0x03FF_FFFF)),
        "cbz" | "cbnz" => encode_cb(m, ops, pc, labels),
        "svc" => Ok(0xD400_0001 | (imm16(ops, m)? << 5)),
        "brk" => Ok(0xD420_0000 | (imm16(ops, m)? << 5)),
        _ if m.starts_with("b.") => {
            arity(ops, 1, m)?;
            let cond = cond_code(&m[2..]).ok_or_else(|| format!("unknown condition in `{m}`"))?;
            let target = as_label(&ops[0], labels)?;
            let off = branch_off(target, pc, 19)?;
            Ok(0x5400_0000 | ((off as u32 & 0x7_FFFF) << 5) | cond)
        }
        _ => Err(format!("unsupported A64 instruction `{m}`")),
    }
}

/// `mov Xd, Xm` (ORR, or ADD #0 when the stack pointer is involved) or `mov Xd, #imm`.
fn encode_mov(ops: &[Operand]) -> Result<u32, String> {
    arity(ops, 2, "mov")?;
    let d = as_reg_any(&ops[0])?;
    match &ops[1] {
        Operand::Imm(v) => mov_imm(as_reg(&ops[0])?, *v),
        Operand::Name(_) => {
            let s = as_reg_any(&ops[1])?;
            same_width(&[d, s], "mov")?;
            if d.is_sp || s.is_sp {
                // In ADD (immediate) register 31 is sp on both sides: the zero register cannot
                // appear there.
                not_zr(d, "mov")?;
                not_zr(s, "mov")?;
                // `mov` to/from sp is ADD Xd, Xn, #0.
                let base = if d.is64 { 0x9100_0000 } else { 0x1100_0000 };
                Ok(base | (s.n << 5) | d.n)
            } else {
                // ORR Xd, (W|X)ZR, Xm.
                let base = if d.is64 { 0xAA00_03E0 } else { 0x2A00_03E0 };
                Ok(base | (s.n << 16) | d.n)
            }
        }
        Operand::Mem(_) => Err("`mov` does not take a memory operand".into()),
        Operand::Shift { .. } => Err("`mov` does not take a shift operand".into()),
    }
}

/// `mov Xd, #imm` using a single MOVZ (value in the low 16 bits) or MOVN (its inverse).
fn mov_imm(d: Reg, v: i64) -> Result<u32, String> {
    let mask = if d.is64 { u64::MAX } else { 0xFFFF_FFFF };
    let u = (v as u64) & mask;
    if u <= 0xFFFF {
        let base = if d.is64 { 0xD280_0000 } else { 0x5280_0000 };
        return Ok(base | ((u as u32) << 5) | d.n);
    }
    let inv = !u & mask;
    if inv <= 0xFFFF {
        let base = if d.is64 { 0x9280_0000 } else { 0x1280_0000 };
        return Ok(base | ((inv as u32) << 5) | d.n);
    }
    Err("constant needs more than one instruction; build it with movz + movk (shifts not yet supported)".into())
}

/// `movz`/`movk`/`movn Xd, #imm16` (shift 0 only for now).
fn encode_movw(m: &str, ops: &[Operand]) -> Result<u32, String> {
    arity(ops, 2, m)?;
    let d = as_reg(&ops[0])?;
    let v = as_imm(&ops[1])?;
    if !(0..=0xFFFF).contains(&v) {
        return Err(format!(
            "`{m}` immediate must be 0..65535 (shifted forms not yet supported)"
        ));
    }
    let base = match (m, d.is64) {
        ("movz", true) => 0xD280_0000,
        ("movz", false) => 0x5280_0000,
        ("movn", true) => 0x9280_0000,
        ("movn", false) => 0x1280_0000,
        ("movk", true) => 0xF280_0000,
        ("movk", false) => 0x7280_0000,
        _ => unreachable!(),
    };
    Ok(base | ((v as u32) << 5) | d.n)
}

/// `add`/`sub`/`adds`/`subs Xd, Xn, #imm12{, lsl #12} | Xm{, lsl|lsr|asr #n}`.
fn encode_addsub(m: &str, ops: &[Operand]) -> Result<u32, String> {
    if ops.len() != 3 && ops.len() != 4 {
        return Err(format!("`{m}` takes 3 operands plus an optional shift"));
    }
    let d = as_reg_any(&ops[0])?;
    let n = as_reg_any(&ops[1])?;
    same_width(&[d, n], m)?;
    let width = reg_width(d);
    // `adds`/`subs` write flags; their Rd 31 is the zero register (`cmp`/`cmn`), never sp.
    let sets_flags = m.ends_with('s');
    // Register-31 rules for the immediate and extended-register forms: Rn is sp; Rd is sp for
    // add/sub and the zero register for adds/subs.
    let check_sp_form = |d: Reg, n: Reg| -> Result<(), String> {
        not_zr(n, m)?;
        if sets_flags && d.is_sp {
            return Err(format!("`{m}` cannot write sp"));
        }
        if !sets_flags {
            not_zr(d, m)?;
        }
        Ok(())
    };
    match &ops[2] {
        Operand::Imm(v) => {
            if !(0..=4095).contains(v) {
                return Err(format!("`{m}` immediate must be 0..4095"));
            }
            check_sp_form(d, n)?;
            let sh = imm_lsl12(ops.get(3))?;
            let base = match (m, d.is64) {
                ("add", true) => 0x9100_0000,
                ("add", false) => 0x1100_0000,
                ("sub", true) => 0xD100_0000,
                ("sub", false) => 0x5100_0000,
                ("adds", true) => 0xB100_0000,
                ("adds", false) => 0x3100_0000,
                ("subs", true) => 0xF100_0000,
                ("subs", false) => 0x7100_0000,
                _ => unreachable!(),
            };
            Ok(base | (sh << 22) | ((*v as u32 & 0xFFF) << 10) | (n.n << 5) | d.n)
        }
        Operand::Name(_) => {
            let mm = as_reg(&ops[2])?;
            same_width(&[d, mm], m)?;
            let base = match (m, d.is64) {
                ("add", true) => 0x8B00_0000,
                ("add", false) => 0x0B00_0000,
                ("sub", true) => 0xCB00_0000,
                ("sub", false) => 0x4B00_0000,
                ("adds", true) => 0xAB00_0000,
                ("adds", false) => 0x2B00_0000,
                ("subs", true) => 0xEB00_0000,
                ("subs", false) => 0x6B00_0000,
                _ => unreachable!(),
            };
            if d.is_sp || n.is_sp {
                // The shifted-register form reads register 31 as the zero register, so with sp
                // use the extended-register form (`uxtx`/`uxtw`, where Rd/Rn 31 is sp).
                check_sp_form(d, n)?;
                let (option, imm3) = sp_extend(ops.get(3), d.is64)?;
                return Ok(base
                    | 0x0020_0000
                    | (mm.n << 16)
                    | (option << 13)
                    | (imm3 << 10)
                    | (n.n << 5)
                    | d.n);
            }
            let (ty, amt) = reg_shift(ops.get(3), false, width)?;
            Ok(base | (ty << 22) | (mm.n << 16) | (amt << 10) | (n.n << 5) | d.n)
        }
        _ => Err(format!(
            "`{m}` third operand must be a register or immediate"
        )),
    }
}

/// `cmp`/`cmn Xn, #imm12 | Xm{, lsl|lsr|asr #n}` — aliases of SUBS/ADDS writing the zero register.
fn encode_cmp(m: &str, ops: &[Operand]) -> Result<u32, String> {
    if ops.len() != 2 && ops.len() != 3 {
        return Err(format!("`{m}` takes 2 operands plus an optional shift"));
    }
    let n = as_reg_any(&ops[0])?;
    let width = reg_width(n);
    // (imm64, imm32, reg64, reg32)
    let bases = if m == "cmp" {
        (
            0xF100_0000u32,
            0x7100_0000u32,
            0xEB00_0000u32,
            0x6B00_0000u32,
        )
    } else {
        (0xB100_0000, 0x3100_0000, 0xAB00_0000, 0x2B00_0000)
    };
    match &ops[1] {
        Operand::Imm(v) => {
            if ops.len() != 2 {
                return Err(format!("`{m}` with an immediate takes no shift"));
            }
            if !(0..=4095).contains(v) {
                return Err(format!("`{m}` immediate must be 0..4095"));
            }
            // Rn 31 is sp in the immediate form.
            not_zr(n, m)?;
            let base = if n.is64 { bases.0 } else { bases.1 };
            Ok(base | ((*v as u32 & 0xFFF) << 10) | (n.n << 5) | 31)
        }
        Operand::Name(_) => {
            let mm = as_reg(&ops[1])?;
            same_width(&[n, mm], m)?;
            let base = if n.is64 { bases.2 } else { bases.3 };
            if n.is_sp {
                // Extended-register form, where Rn 31 is sp.
                let (option, imm3) = sp_extend(ops.get(2), n.is64)?;
                return Ok(base
                    | 0x0020_0000
                    | (mm.n << 16)
                    | (option << 13)
                    | (imm3 << 10)
                    | (n.n << 5)
                    | 31);
            }
            let (ty, amt) = reg_shift(ops.get(2), false, width)?;
            Ok(base | (ty << 22) | (mm.n << 16) | (amt << 10) | (n.n << 5) | 31)
        }
        Operand::Mem(_) => Err(format!("`{m}` does not take a memory operand")),
        Operand::Shift { .. } => Err(format!("`{m}` second operand cannot be a shift")),
    }
}

/// `and`/`orr`/`eor`/`ands Xd, Xn, Xm{, lsl|lsr|asr|ror #n}` (shifted-register form).
fn encode_logic(m: &str, ops: &[Operand]) -> Result<u32, String> {
    if ops.len() != 3 && ops.len() != 4 {
        return Err(format!("`{m}` takes 3 operands plus an optional shift"));
    }
    let d = as_reg(&ops[0])?;
    let n = as_reg(&ops[1])?;
    let mm = as_reg(&ops[2])?;
    same_width(&[d, n, mm], m)?;
    let (ty, amt) = reg_shift(ops.get(3), true, reg_width(d))?;
    let base = match (m, d.is64) {
        ("and", true) => 0x8A00_0000,
        ("and", false) => 0x0A00_0000,
        ("orr", true) => 0xAA00_0000,
        ("orr", false) => 0x2A00_0000,
        ("eor", true) => 0xCA00_0000,
        ("eor", false) => 0x4A00_0000,
        ("ands", true) => 0xEA00_0000,
        ("ands", false) => 0x6A00_0000,
        _ => unreachable!(),
    };
    Ok(base | (ty << 22) | (mm.n << 16) | (amt << 10) | (n.n << 5) | d.n)
}

/// `ldr`/`str`/`ldrb`/`strb`/`ldrh`/`strh`/`ldrsw Xt, [Xn{, #imm | , Xm{, lsl #s}}]`.
fn encode_ldst(m: &str, ops: &[Operand]) -> Result<u32, String> {
    arity(ops, 2, m)?;
    let t = as_reg(&ops[0])?;
    let Operand::Mem(mem) = &ops[1] else {
        return Err(format!("`{m}` needs a memory operand like `[x0, #8]`"));
    };
    // The base register is always 64-bit (x or sp).
    let base_name = mem
        .base
        .as_deref()
        .ok_or("memory operand needs a base register")?;
    let rn = reg(base_name)
        .filter(|r| r.is64)
        .ok_or_else(|| format!("memory base `{base_name}` must be a 64-bit register"))?;
    // The base field's register 31 is sp.
    not_zr(rn, m)?;

    // (is_load, is_signed, size_log2, dest_must_be_64)
    let (is_load, signed, size_log2, dest64): (bool, bool, u32, bool) = match m {
        "ldr" => (true, false, if t.is64 { 3 } else { 2 }, t.is64),
        "str" => (false, false, if t.is64 { 3 } else { 2 }, t.is64),
        "ldrb" => (true, false, 0, false),
        "strb" => (false, false, 0, false),
        "ldrh" => (true, false, 1, false),
        "strh" => (false, false, 1, false),
        "ldrsw" => (true, true, 2, true),
        _ => unreachable!(),
    };
    if t.is64 != dest64 {
        return Err(format!(
            "`{m}` uses a {} register",
            if dest64 { "64-bit (x)" } else { "32-bit (w)" }
        ));
    }
    let opc = if !is_load {
        0b00
    } else if signed {
        0b10
    } else {
        0b01
    };

    if let Some(index) = &mem.index {
        // Register offset: [Xn, Xm {, lsl #s}]. There is no room for a displacement as well.
        if mem.disp != 0 {
            return Err(format!(
                "`{m}` with a register offset cannot also take an immediate offset"
            ));
        }
        // The index field's register 31 is the zero register.
        let rm = reg(index)
            .filter(|r| r.is64 && !r.is_sp)
            .ok_or_else(|| format!("index `{index}` must be a 64-bit x register"))?;
        let size = 1u8 << size_log2;
        let s_bit = match mem.scale {
            1 => 0u32,
            x if x == size => 1u32,
            _ => return Err(format!("`lsl` here must be #0 or #{size_log2}")),
        };
        let base = 0x3820_0800u32 | (size_log2 << 30) | (opc << 22);
        return Ok(base | (rm.n << 16) | (0b011 << 13) | (s_bit << 12) | (rn.n << 5) | t.n);
    }

    // Immediate offset: [Xn{, #imm}].
    let off = mem.disp;
    let size = 1i64 << size_log2;
    if off >= 0 && off % size == 0 && off / size <= 4095 {
        let imm12 = (off / size) as u32;
        let base = 0x3900_0000u32 | (size_log2 << 30) | (opc << 22);
        return Ok(base | (imm12 << 10) | (rn.n << 5) | t.n);
    }
    if (-256..=255).contains(&off) {
        // Unscaled signed 9-bit offset (LDUR/STUR family).
        let base = 0x3800_0000u32 | (size_log2 << 30) | (opc << 22);
        return Ok(base | ((off as u32 & 0x1FF) << 12) | (rn.n << 5) | t.n);
    }
    Err(format!("offset {off} is out of range for `{m}`"))
}

/// `lsl`/`lsr`/`asr`/`ror Xd, Xn, Xm | #imm` (variable shifts and the UBFM/SBFM/EXTR aliases).
fn encode_shift(m: &str, ops: &[Operand]) -> Result<u32, String> {
    arity(ops, 3, m)?;
    let d = as_reg(&ops[0])?;
    let n = as_reg(&ops[1])?;
    same_width(&[d, n], m)?;
    let width = reg_width(d);
    match &ops[2] {
        Operand::Name(_) => {
            let mm = as_reg(&ops[2])?;
            same_width(&[d, mm], m)?;
            let sf = if d.is64 { 0x9AC0_0000 } else { 0x1AC0_0000 };
            let opfield = match m {
                "lsl" => 0x2000,
                "lsr" => 0x2400,
                "asr" => 0x2800,
                "ror" => 0x2C00,
                _ => unreachable!(),
            };
            Ok(sf | opfield | (mm.n << 16) | (n.n << 5) | d.n)
        }
        Operand::Imm(s) => {
            if *s < 0 || *s as u32 >= width {
                return Err(format!("shift amount must be 0..{}", width - 1));
            }
            let s = *s as u32;
            match m {
                "ror" => {
                    // EXTR Xd, Xn, Xn, #s.
                    let base = if d.is64 { 0x93C0_0000 } else { 0x1380_0000 };
                    Ok(base | (n.n << 16) | (s << 10) | (n.n << 5) | d.n)
                }
                _ => {
                    // lsl/lsr/asr via UBFM (lsl/lsr) or SBFM (asr).
                    let (immr, imms) = if m == "lsl" {
                        ((width - s) & (width - 1), width - 1 - s)
                    } else {
                        (s, width - 1)
                    };
                    let base = match (m, d.is64) {
                        ("asr", true) => 0x9340_0000,
                        ("asr", false) => 0x1300_0000,
                        (_, true) => 0xD340_0000,
                        (_, false) => 0x5300_0000,
                    };
                    Ok(base | (immr << 16) | (imms << 10) | (n.n << 5) | d.n)
                }
            }
        }
        _ => Err(format!("`{m}` third operand must be a register or #imm")),
    }
}

fn reg_width(r: Reg) -> u32 {
    if r.is64 { 64 } else { 32 }
}

/// A trailing `, lsl #12` on an add/sub immediate: returns the `sh` bit (0 or 1).
fn imm_lsl12(op: Option<&Operand>) -> Result<u32, String> {
    match op {
        None => Ok(0),
        Some(Operand::Shift {
            op: ShiftOp::Lsl,
            amount: 0,
        }) => Ok(0),
        Some(Operand::Shift {
            op: ShiftOp::Lsl,
            amount: 12,
        }) => Ok(1),
        Some(_) => Err("an add/sub immediate only allows `lsl #12`".into()),
    }
}

/// A trailing shifted-register modifier → (shift-type bits, amount). `ror` is allowed only for
/// logical ops.
fn reg_shift(op: Option<&Operand>, allow_ror: bool, width: u32) -> Result<(u32, u32), String> {
    match op {
        None => Ok((0, 0)),
        Some(Operand::Shift { op, amount }) => {
            let ty = match op {
                ShiftOp::Lsl => 0,
                ShiftOp::Lsr => 1,
                ShiftOp::Asr => 2,
                ShiftOp::Ror if allow_ror => 3,
                ShiftOp::Ror => return Err("`ror` is not allowed on this instruction".into()),
                _ => return Err("only lsl/lsr/asr (or ror for logical) are allowed here".into()),
            };
            if *amount < 0 || *amount as u32 >= width {
                return Err(format!("shift amount must be 0..{}", width - 1));
            }
            Ok((ty, *amount as u32))
        }
        Some(_) => Err("expected a shift like `lsl #2`".into()),
    }
}

/// `mul Xd, Xn, Xm` — MADD with the zero register as the addend.
fn encode_mul(ops: &[Operand]) -> Result<u32, String> {
    arity(ops, 3, "mul")?;
    let d = as_reg(&ops[0])?;
    let n = as_reg(&ops[1])?;
    let mm = as_reg(&ops[2])?;
    same_width(&[d, n, mm], "mul")?;
    let base = if d.is64 { 0x9B00_0000 } else { 0x1B00_0000 };
    Ok(base | (mm.n << 16) | (31 << 10) | (n.n << 5) | d.n)
}

/// `cbz`/`cbnz Xn, <label>`.
fn encode_cb(
    m: &str,
    ops: &[Operand],
    pc: u64,
    labels: &HashMap<String, u64>,
) -> Result<u32, String> {
    arity(ops, 2, m)?;
    let n = as_reg(&ops[0])?;
    let target = as_label(&ops[1], labels)?;
    let off = branch_off(target, pc, 19)?;
    let base = match (m, n.is64) {
        ("cbz", true) => 0xB400_0000,
        ("cbz", false) => 0x3400_0000,
        ("cbnz", true) => 0xB500_0000,
        ("cbnz", false) => 0x3500_0000,
        _ => unreachable!(),
    };
    Ok(base | ((off as u32 & 0x7_FFFF) << 5) | n.n)
}

/// Two-register data-processing with a fixed `Rn` (e.g. `neg`/`mvn`, which use the zero register).
fn encode_two_reg(ops: &[Operand], base64: u32, base32: u32, rn: u32) -> Result<u32, String> {
    arity(ops, 2, "op")?;
    let d = as_reg(&ops[0])?;
    let mm = as_reg(&ops[1])?;
    same_width(&[d, mm], "op")?;
    let base = if d.is64 { base64 } else { base32 };
    Ok(base | (mm.n << 16) | (rn << 5) | d.n)
}

fn unary_x(ops: &[Operand], m: &str) -> Result<u32, String> {
    arity(ops, 1, m)?;
    let r = as_reg(&ops[0])?;
    need64(r, m)?;
    Ok(r.n)
}

fn branch(
    ops: &[Operand],
    m: &str,
    pc: u64,
    labels: &HashMap<String, u64>,
    bits: u32,
) -> Result<u32, String> {
    arity(ops, 1, m)?;
    let target = as_label(&ops[0], labels)?;
    Ok(branch_off(target, pc, bits)? as u32)
}

fn imm16(ops: &[Operand], m: &str) -> Result<u32, String> {
    arity(ops, 1, m)?;
    let v = as_imm(&ops[0])?;
    if !(0..=0xFFFF).contains(&v) {
        return Err(format!("`{m}` immediate must be 0..65535"));
    }
    Ok(v as u32 & 0xFFFF)
}

/// PC-relative branch offset in instructions, range-checked for a signed `bits`-bit field.
fn branch_off(target: u64, pc: u64, bits: u32) -> Result<i64, String> {
    let diff = target.wrapping_sub(pc) as i64;
    if diff % 4 != 0 {
        return Err("branch target is not 4-byte aligned".into());
    }
    let off = diff / 4;
    let lim = 1i64 << (bits - 1);
    if off < -lim || off >= lim {
        return Err("branch target is out of range".into());
    }
    Ok(off)
}

fn cond_code(suffix: &str) -> Option<u32> {
    Some(match suffix {
        "eq" => 0,
        "ne" => 1,
        "cs" | "hs" => 2,
        "cc" | "lo" => 3,
        "mi" => 4,
        "pl" => 5,
        "vs" => 6,
        "vc" => 7,
        "hi" => 8,
        "ls" => 9,
        "ge" => 10,
        "lt" => 11,
        "gt" => 12,
        "le" => 13,
        "al" => 14,
        _ => return None,
    })
}

fn arity(ops: &[Operand], want: usize, m: &str) -> Result<(), String> {
    if ops.len() == want {
        Ok(())
    } else {
        Err(format!("`{m}` takes {want} operand(s), got {}", ops.len()))
    }
}

fn need64(r: Reg, m: &str) -> Result<(), String> {
    if r.is64 {
        Ok(())
    } else {
        Err(format!("`{m}` needs a 64-bit (x) register"))
    }
}

fn same_width(regs: &[Reg], m: &str) -> Result<(), String> {
    if regs.windows(2).all(|w| w[0].is64 == w[1].is64) {
        Ok(())
    } else {
        Err(format!(
            "`{m}` operands must all be the same width (all x or all w)"
        ))
    }
}

/// A register where number 31 means the zero register (`xzr`/`wzr`) — the default for most
/// fields. `sp` is rejected, since encoding it would silently mean `xzr`.
fn as_reg(op: &Operand) -> Result<Reg, String> {
    let r = as_reg_any(op)?;
    if r.is_sp {
        return Err(
            "`sp` cannot be used here (register 31 in this position is the zero register)".into(),
        );
    }
    Ok(r)
}

/// A register in any role; the caller checks what register 31 means for its field.
fn as_reg_any(op: &Operand) -> Result<Reg, String> {
    match op {
        Operand::Name(n) => reg(n).ok_or_else(|| format!("`{n}` is not an A64 register")),
        _ => Err("expected a register".into()),
    }
}

/// `xzr`/`wzr` (register 31 written as the zero register).
fn is_zr(r: Reg) -> bool {
    r.n == 31 && !r.is_sp
}

/// Rejects the zero register in a field where register 31 is the stack pointer.
fn not_zr(r: Reg, m: &str) -> Result<Reg, String> {
    if is_zr(r) {
        Err(format!(
            "`{m}` cannot use the zero register here (register 31 in this position is sp)"
        ))
    } else {
        Ok(r)
    }
}

/// The extend for the extended-register add/sub form used with `sp`: `uxtx` (64-bit) or `uxtw`
/// (32-bit), written as `lsl #0..4` or the extend itself. Returns (option, imm3).
fn sp_extend(op: Option<&Operand>, is64: bool) -> Result<(u32, u32), String> {
    let option = if is64 { 0b011 } else { 0b010 };
    let amount = match op {
        None => 0,
        Some(Operand::Shift {
            op: ShiftOp::Lsl,
            amount,
        }) => *amount,
        Some(Operand::Shift {
            op: ShiftOp::Uxtx,
            amount,
        }) if is64 => *amount,
        Some(Operand::Shift {
            op: ShiftOp::Uxtw,
            amount,
        }) if !is64 => *amount,
        Some(_) => return Err("with `sp`, only `lsl #0..4` is allowed".into()),
    };
    if !(0..=4).contains(&amount) {
        return Err("with `sp`, the shift must be `lsl #0..4`".into());
    }
    Ok((option, amount as u32))
}

fn as_imm(op: &Operand) -> Result<i64, String> {
    match op {
        Operand::Imm(v) => Ok(*v),
        _ => Err("expected an immediate".into()),
    }
}

/// A branch target: a label, or an absolute address (`b 0x401000`, `bl #0x401000`). Label
/// addresses already include the assembly base, so both are absolute.
fn as_label(op: &Operand, labels: &HashMap<String, u64>) -> Result<u64, String> {
    match op {
        Operand::Name(n) => labels
            .get(n)
            .copied()
            .ok_or_else(|| format!("unknown label `{n}`")),
        Operand::Imm(v) => Ok(*v as u64),
        _ => Err("expected a label or an address".into()),
    }
}

/// Resolve an A64 register name (lower-cased).
fn reg(name: &str) -> Option<Reg> {
    match name {
        "xzr" => {
            return Some(Reg {
                n: 31,
                is64: true,
                is_sp: false,
            });
        }
        "wzr" => {
            return Some(Reg {
                n: 31,
                is64: false,
                is_sp: false,
            });
        }
        "sp" => {
            return Some(Reg {
                n: 31,
                is64: true,
                is_sp: true,
            });
        }
        "wsp" => {
            return Some(Reg {
                n: 31,
                is64: false,
                is_sp: true,
            });
        }
        "lr" => {
            return Some(Reg {
                n: 30,
                is64: true,
                is_sp: false,
            });
        }
        "fp" => {
            return Some(Reg {
                n: 29,
                is64: true,
                is_sp: false,
            });
        }
        _ => {}
    }
    let (is64, rest) = match name.strip_prefix('x') {
        Some(r) => (true, r),
        None => (false, name.strip_prefix('w')?),
    };
    let n: u32 = rest.parse().ok()?;
    (n <= 30).then_some(Reg {
        n,
        is64,
        is_sp: false,
    })
}

#[cfg(test)]
mod tests {
    use crate::{Arch, assemble as asm};

    fn word(src: &str) -> u32 {
        let out = asm(src, Arch::Arm64, 0).unwrap_or_else(|e| panic!("assemble failed: {e:?}"));
        assert_eq!(out.bytes.len(), 4, "expected one instruction");
        u32::from_le_bytes(out.bytes.try_into().unwrap())
    }

    #[test]
    fn known_encodings() {
        assert_eq!(word("nop"), 0xD503_201F);
        assert_eq!(word("ret"), 0xD65F_03C0);
        assert_eq!(word("mov x0, x1"), 0xAA01_03E0);
        assert_eq!(word("mov x0, #1"), 0xD280_0020);
        assert_eq!(word("mov x0, #-1"), 0x9280_0000); // movn x0, #0
        assert_eq!(word("add x0, x1, #1"), 0x9100_0420);
        assert_eq!(word("sub x2, x3, #4"), 0xD100_1062);
        assert_eq!(word("cmp x0, #0"), 0xF100_001F);
        assert_eq!(word("and x0, x1, x2"), 0x8A02_0020);
        assert_eq!(word("orr w0, w1, w2"), 0x2A02_0020);
        assert_eq!(word("mul x0, x1, x2"), 0x9B02_7C20);
        assert_eq!(word("svc #0"), 0xD400_0001);
        assert_eq!(word("ret x30"), 0xD65F_03C0);
    }

    #[test]
    fn branch_labels_resolve() {
        // sub at 0x1000, cbnz at 0x1004 jumping back to loop (0x1000): offset -1.
        let out = asm(
            "loop:\n    sub x0, x0, #1\n    cbnz x0, loop\n    ret\n",
            Arch::Arm64,
            0x1000,
        )
        .expect("assembles");
        assert_eq!(out.bytes.len(), 12);
        let cbnz = u32::from_le_bytes(out.bytes[4..8].try_into().unwrap());
        assert_eq!(cbnz, 0xB5FF_FFE0); // cbnz x0, #-4
        // forward branch
        let fwd = asm("b done\n    nop\ndone:\n    ret\n", Arch::Arm64, 0).expect("assembles");
        let b = u32::from_le_bytes(fwd.bytes[0..4].try_into().unwrap());
        assert_eq!(b, 0x1400_0002); // b +8 (two instructions ahead)
    }

    #[test]
    fn conditional_branch() {
        let out = asm("start:\n    b.eq start\n", Arch::Arm64, 0).expect("assembles");
        assert_eq!(out.bytes.len(), 4);
        // b.eq to self: offset 0, cond eq (0).
        assert_eq!(
            u32::from_le_bytes(out.bytes.try_into().unwrap()),
            0x5400_0000
        );
    }

    #[test]
    fn width_mismatch_is_an_error() {
        let err = asm("add x0, w1, #1", Arch::Arm64, 0).unwrap_err();
        assert_eq!(err[0].line, 1);
    }

    #[test]
    fn hash_immediates_parse() {
        assert_eq!(word("movz x0, #0x1234"), 0xD280_0000 | (0x1234 << 5));
    }

    #[test]
    fn loads_and_stores() {
        assert_eq!(word("ldr x0, [x1]"), 0xF940_0020);
        assert_eq!(word("ldr x0, [x1, #8]"), 0xF940_0420);
        assert_eq!(word("str w0, [x1, #4]"), 0xB900_0420);
        assert_eq!(word("ldrb w0, [x1]"), 0x3940_0020);
        assert_eq!(word("ldrsw x0, [x1, #4]"), 0xB980_0420);
        // register offset, with and without the scaling shift
        assert_eq!(word("ldr x0, [x1, x2]"), 0xF862_6820);
        assert_eq!(word("ldr x0, [x1, x2, lsl #3]"), 0xF862_7820);
        // small negative offset falls back to the unscaled LDUR form
        assert_eq!(word("ldr x0, [x1, #-8]"), 0xF85F_8020);
    }

    #[test]
    fn shift_instructions() {
        assert_eq!(word("lsl x0, x1, #4"), 0xD37C_EC20);
        assert_eq!(word("lsr x0, x1, #4"), 0xD344_FC20);
        assert_eq!(word("asr x0, x1, #4"), 0x9344_FC20);
        assert_eq!(word("lsl x0, x1, x2"), 0x9AC2_2020); // LSLV
    }

    #[test]
    fn shifted_register_and_lsl12_operands() {
        assert_eq!(word("add x0, x1, x2, lsl #4"), 0x8B02_1020);
        assert_eq!(word("add x0, x1, #1, lsl #12"), 0x9140_0420);
        assert_eq!(word("orr x0, x1, x2, lsr #1"), 0xAA42_0420);
        assert_eq!(word("cmp x0, x1, lsl #2"), 0xEB01_081F);
    }

    #[test]
    fn absolute_branch_targets() {
        // Absolute targets are relative to where the code is assembled (here 0x1000).
        let w = |src: &str| {
            let out = asm(src, Arch::Arm64, 0x1000).expect("assembles");
            u32::from_le_bytes(out.bytes[..4].try_into().unwrap())
        };
        assert_eq!(w("b 0x1008"), 0x1400_0002);
        assert_eq!(w("bl #0x0ffc"), 0x97FF_FFFF);
        assert_eq!(w("b.ne 0x1010"), 0x5400_0081);
        assert_eq!(w("cbz x0, 0x1004"), 0xB400_0020);
        assert!(asm("b 0x1002", Arch::Arm64, 0x1000).is_err()); // misaligned
    }

    #[test]
    fn register_31_is_sp_or_zero_per_field() {
        // add/sub immediate: Rd/Rn 31 is sp, so xzr is rejected.
        assert!(asm("add x0, xzr, #1", Arch::Arm64, 0).is_err());
        assert!(asm("add xzr, x0, #1", Arch::Arm64, 0).is_err());
        assert_eq!(word("add sp, sp, #16"), 0x9100_43FF);
        assert_eq!(word("sub sp, sp, #32"), 0xD100_83FF);
        // ...but adds/subs write the zero register (cmp), never sp.
        assert!(asm("subs sp, x0, #1", Arch::Arm64, 0).is_err());
        assert_eq!(word("subs xzr, x0, #1"), 0xF100_041F);
        // Shifted-register forms read 31 as xzr; with sp the extended (uxtx) form is used.
        assert_eq!(word("add x0, x1, xzr"), 0x8B1F_0020);
        assert_eq!(word("add sp, sp, x1"), 0x8B21_63FF);
        assert_eq!(word("add x0, sp, x1, lsl #3"), 0x8B21_6FE0);
        assert_eq!(word("cmp sp, x1"), 0xEB21_63FF);
        assert!(asm("add sp, sp, x1, lsr #2", Arch::Arm64, 0).is_err());
        assert!(asm("and sp, x0, x1", Arch::Arm64, 0).is_err());
        assert!(asm("add x0, x1, sp", Arch::Arm64, 0).is_err());
        // Load/store base: 31 is sp.
        assert!(asm("ldr x0, [xzr]", Arch::Arm64, 0).is_err());
        assert_eq!(word("ldr x0, [sp, #8]"), 0xF940_07E0);
        assert!(asm("ldr sp, [x0]", Arch::Arm64, 0).is_err());
        // mov between sp and xzr has no encoding.
        assert!(asm("mov sp, xzr", Arch::Arm64, 0).is_err());
        assert_eq!(word("mov x29, sp"), 0x9100_03FD);
    }

    #[test]
    fn register_offset_rejects_a_displacement() {
        let err = asm("ldr x0, [x0, x1, #8]", Arch::Arm64, 0).unwrap_err();
        assert!(err[0].message.contains("register offset"), "{err:?}");
    }
}
