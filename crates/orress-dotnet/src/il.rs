//! CIL (MSIL) disassembly: decode a method body's bytecode into instructions, resolving metadata
//! tokens and user-string tokens through caller-provided closures. The opcode table is the stable
//! ECMA-335 set (single-byte plus the `0xFE` two-byte prefix); every opcode's operand size is
//! known, so decoding stays aligned.

/// The operand that follows an opcode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Opr {
    None,
    /// 1-byte unsigned (prefix operands: `unaligned.`, `no.`).
    U8,
    /// 1-/2-byte local/arg index.
    Var8,
    Var16,
    /// Inline integers.
    ShortI,
    I,
    I8,
    /// Inline floats.
    ShortR,
    R,
    /// Branch offsets (relative to the next instruction).
    ShortBr,
    Br,
    Switch,
    /// A 4-byte metadata token (method/field/type/tok/sig).
    Tok,
    /// A 4-byte user-string token.
    Str,
}

/// One decoded CIL instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Il {
    /// Offset within the method body's code (matches ildasm `IL_xxxx`).
    pub offset: usize,
    pub opcode: &'static str,
    /// Rendered operand (token resolved to a name, string to its literal, branch to a target).
    pub operand: String,
    pub branch_target: Option<usize>,
    pub is_branch_target: bool,
}

/// Disassembles a method body's `code`. `resolve_tok` turns a metadata token into a name;
/// `resolve_str` turns a user-string token into the quoted literal.
pub fn disassemble(
    code: &[u8],
    resolve_tok: impl Fn(u32) -> String,
    resolve_str: impl Fn(u32) -> String,
) -> Vec<Il> {
    let mut out = Vec::new();
    let mut targets: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut i = 0usize;

    let u8 = |c: &[u8], i: &mut usize| -> Option<u8> {
        let v = *c.get(*i)?;
        *i += 1;
        Some(v)
    };
    let u16 = |c: &[u8], i: &mut usize| -> Option<u16> {
        let v = u16::from_le_bytes([*c.get(*i)?, *c.get(*i + 1)?]);
        *i += 2;
        Some(v)
    };
    let u32r = |c: &[u8], i: &mut usize| -> Option<u32> {
        let v = u32::from_le_bytes([
            *c.get(*i)?,
            *c.get(*i + 1)?,
            *c.get(*i + 2)?,
            *c.get(*i + 3)?,
        ]);
        *i += 4;
        Some(v)
    };

    while i < code.len() {
        let start = i;
        let b = code[i];
        i += 1;
        let (name, opr) = if b == 0xFE {
            match u8(code, &mut i) {
                Some(b2) => op2(b2),
                None => break,
            }
        } else {
            op1(b)
        }
        .unwrap_or(("unknown", Opr::None));

        let mut operand = String::new();
        let mut branch_target = None;
        let ok = (|| -> Option<()> {
            match opr {
                Opr::None => {}
                Opr::U8 => operand = u8(code, &mut i)?.to_string(),
                Opr::Var8 => operand = u8(code, &mut i)?.to_string(),
                Opr::Var16 => operand = u16(code, &mut i)?.to_string(),
                Opr::ShortI => operand = (u8(code, &mut i)? as i8).to_string(),
                Opr::I => operand = (u32r(code, &mut i)? as i32).to_string(),
                Opr::I8 => {
                    let lo = u32r(code, &mut i)? as u64;
                    let hi = u32r(code, &mut i)? as u64;
                    operand = ((lo | (hi << 32)) as i64).to_string();
                }
                Opr::ShortR => operand = f32::from_bits(u32r(code, &mut i)?).to_string(),
                Opr::R => {
                    let lo = u32r(code, &mut i)? as u64;
                    let hi = u32r(code, &mut i)? as u64;
                    operand = f64::from_bits(lo | (hi << 32)).to_string();
                }
                Opr::ShortBr => {
                    let rel = u8(code, &mut i)? as i8 as isize;
                    let t = (i as isize + rel) as usize;
                    branch_target = Some(t);
                    targets.insert(t);
                    operand = format!("IL_{t:04x}");
                }
                Opr::Br => {
                    let rel = u32r(code, &mut i)? as i32 as isize;
                    let t = (i as isize + rel) as usize;
                    branch_target = Some(t);
                    targets.insert(t);
                    operand = format!("IL_{t:04x}");
                }
                Opr::Switch => {
                    let n = u32r(code, &mut i)? as usize;
                    let mut rels = Vec::with_capacity(n.min(4096));
                    for _ in 0..n {
                        rels.push(u32r(code, &mut i)? as i32 as isize);
                    }
                    let base = i as isize;
                    let ts: Vec<String> = rels
                        .iter()
                        .map(|r| {
                            let t = (base + r) as usize;
                            targets.insert(t);
                            format!("IL_{t:04x}")
                        })
                        .collect();
                    operand = format!("({})", ts.join(", "));
                }
                Opr::Tok => operand = resolve_tok(u32r(code, &mut i)?),
                Opr::Str => operand = resolve_str(u32r(code, &mut i)?),
            }
            Some(())
        })();
        if ok.is_none() {
            out.push(Il {
                offset: start,
                opcode: name,
                operand: "(truncated)".into(),
                branch_target: None,
                is_branch_target: false,
            });
            break;
        }

        out.push(Il {
            offset: start,
            opcode: name,
            operand,
            branch_target,
            is_branch_target: false,
        });
    }

    for il in &mut out {
        if targets.contains(&il.offset) {
            il.is_branch_target = true;
        }
    }
    out
}

/// Single-byte opcodes.
fn op1(b: u8) -> Option<(&'static str, Opr)> {
    use Opr::*;
    Some(match b {
        0x00 => ("nop", None),
        0x01 => ("break", None),
        0x02 => ("ldarg.0", None),
        0x03 => ("ldarg.1", None),
        0x04 => ("ldarg.2", None),
        0x05 => ("ldarg.3", None),
        0x06 => ("ldloc.0", None),
        0x07 => ("ldloc.1", None),
        0x08 => ("ldloc.2", None),
        0x09 => ("ldloc.3", None),
        0x0A => ("stloc.0", None),
        0x0B => ("stloc.1", None),
        0x0C => ("stloc.2", None),
        0x0D => ("stloc.3", None),
        0x0E => ("ldarg.s", Var8),
        0x0F => ("ldarga.s", Var8),
        0x10 => ("starg.s", Var8),
        0x11 => ("ldloc.s", Var8),
        0x12 => ("ldloca.s", Var8),
        0x13 => ("stloc.s", Var8),
        0x14 => ("ldnull", None),
        0x15 => ("ldc.i4.m1", None),
        0x16 => ("ldc.i4.0", None),
        0x17 => ("ldc.i4.1", None),
        0x18 => ("ldc.i4.2", None),
        0x19 => ("ldc.i4.3", None),
        0x1A => ("ldc.i4.4", None),
        0x1B => ("ldc.i4.5", None),
        0x1C => ("ldc.i4.6", None),
        0x1D => ("ldc.i4.7", None),
        0x1E => ("ldc.i4.8", None),
        0x1F => ("ldc.i4.s", ShortI),
        0x20 => ("ldc.i4", I),
        0x21 => ("ldc.i8", I8),
        0x22 => ("ldc.r4", ShortR),
        0x23 => ("ldc.r8", R),
        0x25 => ("dup", None),
        0x26 => ("pop", None),
        0x27 => ("jmp", Tok),
        0x28 => ("call", Tok),
        0x29 => ("calli", Tok),
        0x2A => ("ret", None),
        0x2B => ("br.s", ShortBr),
        0x2C => ("brfalse.s", ShortBr),
        0x2D => ("brtrue.s", ShortBr),
        0x2E => ("beq.s", ShortBr),
        0x2F => ("bge.s", ShortBr),
        0x30 => ("bgt.s", ShortBr),
        0x31 => ("ble.s", ShortBr),
        0x32 => ("blt.s", ShortBr),
        0x33 => ("bne.un.s", ShortBr),
        0x34 => ("bge.un.s", ShortBr),
        0x35 => ("bgt.un.s", ShortBr),
        0x36 => ("ble.un.s", ShortBr),
        0x37 => ("blt.un.s", ShortBr),
        0x38 => ("br", Br),
        0x39 => ("brfalse", Br),
        0x3A => ("brtrue", Br),
        0x3B => ("beq", Br),
        0x3C => ("bge", Br),
        0x3D => ("bgt", Br),
        0x3E => ("ble", Br),
        0x3F => ("blt", Br),
        0x40 => ("bne.un", Br),
        0x41 => ("bge.un", Br),
        0x42 => ("bgt.un", Br),
        0x43 => ("ble.un", Br),
        0x44 => ("blt.un", Br),
        0x45 => ("switch", Switch),
        0x46 => ("ldind.i1", None),
        0x47 => ("ldind.u1", None),
        0x48 => ("ldind.i2", None),
        0x49 => ("ldind.u2", None),
        0x4A => ("ldind.i4", None),
        0x4B => ("ldind.u4", None),
        0x4C => ("ldind.i8", None),
        0x4D => ("ldind.i", None),
        0x4E => ("ldind.r4", None),
        0x4F => ("ldind.r8", None),
        0x50 => ("ldind.ref", None),
        0x51 => ("stind.ref", None),
        0x52 => ("stind.i1", None),
        0x53 => ("stind.i2", None),
        0x54 => ("stind.i4", None),
        0x55 => ("stind.i8", None),
        0x56 => ("stind.r4", None),
        0x57 => ("stind.r8", None),
        0x58 => ("add", None),
        0x59 => ("sub", None),
        0x5A => ("mul", None),
        0x5B => ("div", None),
        0x5C => ("div.un", None),
        0x5D => ("rem", None),
        0x5E => ("rem.un", None),
        0x5F => ("and", None),
        0x60 => ("or", None),
        0x61 => ("xor", None),
        0x62 => ("shl", None),
        0x63 => ("shr", None),
        0x64 => ("shr.un", None),
        0x65 => ("neg", None),
        0x66 => ("not", None),
        0x67 => ("conv.i1", None),
        0x68 => ("conv.i2", None),
        0x69 => ("conv.i4", None),
        0x6A => ("conv.i8", None),
        0x6B => ("conv.r4", None),
        0x6C => ("conv.r8", None),
        0x6D => ("conv.u4", None),
        0x6E => ("conv.u8", None),
        0x6F => ("callvirt", Tok),
        0x70 => ("cpobj", Tok),
        0x71 => ("ldobj", Tok),
        0x72 => ("ldstr", Str),
        0x73 => ("newobj", Tok),
        0x74 => ("castclass", Tok),
        0x75 => ("isinst", Tok),
        0x76 => ("conv.r.un", None),
        0x79 => ("unbox", Tok),
        0x7A => ("throw", None),
        0x7B => ("ldfld", Tok),
        0x7C => ("ldflda", Tok),
        0x7D => ("stfld", Tok),
        0x7E => ("ldsfld", Tok),
        0x7F => ("ldsflda", Tok),
        0x80 => ("stsfld", Tok),
        0x81 => ("stobj", Tok),
        0x82 => ("conv.ovf.i1.un", None),
        0x83 => ("conv.ovf.i2.un", None),
        0x84 => ("conv.ovf.i4.un", None),
        0x85 => ("conv.ovf.i8.un", None),
        0x86 => ("conv.ovf.u1.un", None),
        0x87 => ("conv.ovf.u2.un", None),
        0x88 => ("conv.ovf.u4.un", None),
        0x89 => ("conv.ovf.u8.un", None),
        0x8A => ("conv.ovf.i.un", None),
        0x8B => ("conv.ovf.u.un", None),
        0x8C => ("box", Tok),
        0x8D => ("newarr", Tok),
        0x8E => ("ldlen", None),
        0x8F => ("ldelema", Tok),
        0x90 => ("ldelem.i1", None),
        0x91 => ("ldelem.u1", None),
        0x92 => ("ldelem.i2", None),
        0x93 => ("ldelem.u2", None),
        0x94 => ("ldelem.i4", None),
        0x95 => ("ldelem.u4", None),
        0x96 => ("ldelem.i8", None),
        0x97 => ("ldelem.i", None),
        0x98 => ("ldelem.r4", None),
        0x99 => ("ldelem.r8", None),
        0x9A => ("ldelem.ref", None),
        0x9B => ("stelem.i", None),
        0x9C => ("stelem.i1", None),
        0x9D => ("stelem.i2", None),
        0x9E => ("stelem.i4", None),
        0x9F => ("stelem.i8", None),
        0xA0 => ("stelem.r4", None),
        0xA1 => ("stelem.r8", None),
        0xA2 => ("stelem.ref", None),
        0xA3 => ("ldelem", Tok),
        0xA4 => ("stelem", Tok),
        0xA5 => ("unbox.any", Tok),
        0xB3 => ("conv.ovf.i1", None),
        0xB4 => ("conv.ovf.u1", None),
        0xB5 => ("conv.ovf.i2", None),
        0xB6 => ("conv.ovf.u2", None),
        0xB7 => ("conv.ovf.i4", None),
        0xB8 => ("conv.ovf.u4", None),
        0xB9 => ("conv.ovf.i8", None),
        0xBA => ("conv.ovf.u8", None),
        0xC2 => ("refanyval", Tok),
        0xC3 => ("ckfinite", None),
        0xC6 => ("mkrefany", Tok),
        0xD0 => ("ldtoken", Tok),
        0xD1 => ("conv.u2", None),
        0xD2 => ("conv.u1", None),
        0xD3 => ("conv.i", None),
        0xD4 => ("conv.ovf.i", None),
        0xD5 => ("conv.ovf.u", None),
        0xD6 => ("add.ovf", None),
        0xD7 => ("add.ovf.un", None),
        0xD8 => ("mul.ovf", None),
        0xD9 => ("mul.ovf.un", None),
        0xDA => ("sub.ovf", None),
        0xDB => ("sub.ovf.un", None),
        0xDC => ("endfinally", None),
        0xDD => ("leave", Br),
        0xDE => ("leave.s", ShortBr),
        0xDF => ("stind.i", None),
        0xE0 => ("conv.u", None),
        _ => return Option::None,
    })
}

/// Two-byte opcodes (after the `0xFE` prefix).
fn op2(b: u8) -> Option<(&'static str, Opr)> {
    use Opr::*;
    Some(match b {
        0x00 => ("arglist", None),
        0x01 => ("ceq", None),
        0x02 => ("cgt", None),
        0x03 => ("cgt.un", None),
        0x04 => ("clt", None),
        0x05 => ("clt.un", None),
        0x06 => ("ldftn", Tok),
        0x07 => ("ldvirtftn", Tok),
        0x09 => ("ldarg", Var16),
        0x0A => ("ldarga", Var16),
        0x0B => ("starg", Var16),
        0x0C => ("ldloc", Var16),
        0x0D => ("ldloca", Var16),
        0x0E => ("stloc", Var16),
        0x0F => ("localloc", None),
        0x11 => ("endfilter", None),
        0x12 => ("unaligned.", U8),
        0x13 => ("volatile.", None),
        0x14 => ("tail.", None),
        0x15 => ("initobj", Tok),
        0x16 => ("constrained.", Tok),
        0x17 => ("cpblk", None),
        0x18 => ("initblk", None),
        0x19 => ("no.", U8),
        0x1A => ("rethrow", None),
        0x1C => ("sizeof", Tok),
        0x1D => ("refanytype", None),
        0x1E => ("readonly.", None),
        _ => return Option::None,
    })
}
