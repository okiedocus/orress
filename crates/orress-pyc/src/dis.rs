//! Disassembles CPython 3.11+ "wordcode" (2-byte code units) into instructions.
//!
//! Since 3.11 the bytecode stream is interleaved with inline `CACHE` units (opcode 0) used by the
//! adaptive interpreter. A marshaled `.pyc` holds the *un-specialized* opcodes, and every unit is
//! two bytes, so a linear walk that skips `CACHE` units reproduces CPython's own instruction
//! offsets exactly. Opcode *names* and operand classes are version-specific; the bundled table is
//! authoritative for CPython 3.14 (see [`crate::opcodes_314`]), so named disassembly is offered
//! only for that version — other versions still get the full structure and raw bytecode.

use std::collections::HashSet;

use crate::marshal::CodeObject;
use crate::opcodes_314 as op;

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Insn {
    /// Byte offset in `co_code` (matches CPython `dis`).
    pub offset: usize,
    pub opcode: u8,
    pub opname: String,
    /// The operand, if the opcode takes one (and after folding any `EXTENDED_ARG`).
    pub arg: Option<u32>,
    /// A resolved operand (const value, name, local, jump target), where ORRESS knows how.
    pub argval: Option<String>,
    /// True if some jump lands here.
    pub is_jump_target: bool,
}

fn in_set(set: &[u8], op: u8) -> bool {
    set.contains(&op)
}

/// Disassembles a code object with the CPython 3.14 opcode table.
pub fn disassemble_314(code: &CodeObject) -> Vec<Insn> {
    let b = &code.code;

    // Pass 1: fold caches + EXTENDED_ARG into (start_offset, opcode, full_arg).
    let mut raw: Vec<(usize, u8, u32)> = Vec::new();
    let mut i = 0;
    let mut ext: u32 = 0;
    let mut ext_start: Option<usize> = None;
    while i + 1 < b.len() {
        let opcode = b[i];
        let argbyte = b[i + 1] as u32;
        if opcode == op::CACHE {
            i += 2;
            continue;
        }
        if opcode == op::EXTENDED_ARG {
            if ext_start.is_none() {
                ext_start = Some(i);
            }
            ext = (ext << 8) | argbyte;
            i += 2;
            continue;
        }
        let start = ext_start.take().unwrap_or(i);
        raw.push((start, opcode, (ext << 8) | argbyte));
        ext = 0;
        i += 2;
    }

    // Pass 2: names, operands and jump targets.
    let mut insns: Vec<Insn> = Vec::with_capacity(raw.len());
    let mut targets: HashSet<usize> = HashSet::new();
    for (k, &(offset, opcode, full)) in raw.iter().enumerate() {
        let opname = op::opname(opcode)
            .map(String::from)
            .unwrap_or_else(|| format!("<op {opcode}>"));
        let has_arg = opcode >= op::HAVE_ARGUMENT;
        let arg = has_arg.then_some(full);

        // The unit after this instruction + its caches = the next instruction's start.
        let after = raw.get(k + 1).map(|n| n.0).unwrap_or(b.len());
        let mut jump_target = None;
        if in_set(op::HASJREL, opcode) {
            let delta = (full as usize).saturating_mul(2);
            let t = if opname.contains("JUMP_BACKWARD") {
                after.saturating_sub(delta)
            } else {
                after + delta
            };
            jump_target = Some(t);
            targets.insert(t);
        }

        let argval = arg.and_then(|a| resolve(code, opcode, &opname, a, jump_target));
        insns.push(Insn {
            offset,
            opcode,
            opname,
            arg,
            argval,
            is_jump_target: false,
        });
    }
    for ins in &mut insns {
        if targets.contains(&ins.offset) {
            ins.is_jump_target = true;
        }
    }
    insns
}

fn resolve(
    code: &CodeObject,
    opcode: u8,
    opname: &str,
    arg: u32,
    jump_target: Option<usize>,
) -> Option<String> {
    let a = arg as usize;
    // A few opcodes pack flags into the low bit of the operand (3.12+).
    if matches!(opname, "LOAD_GLOBAL" | "LOAD_ATTR" | "LOAD_SUPER_ATTR") {
        // LOAD_SUPER_ATTR packs two flags (method load, two-arg super) below the name index.
        let shift = if opname == "LOAD_SUPER_ATTR" { 2 } else { 1 };
        let name = code.names.get(arg as usize >> shift).cloned();
        let extra = if arg & 1 != 0 {
            match opname {
                "LOAD_GLOBAL" => " + NULL",
                "LOAD_SUPER_ATTR" => " + NULL|self",
                _ => " + self",
            }
        } else {
            ""
        };
        return name.map(|n| format!("{n}{extra}"));
    }
    if opname == "LOAD_SMALL_INT" {
        return Some(arg.to_string());
    }
    // Operators encoded in the operand (authoritative for CPython 3.14).
    match opname {
        "COMPARE_OP" => {
            // 3.12+: the comparison is in the high bits; the low bits are a cache flag.
            const CMP: [&str; 6] = ["<", "<=", "==", "!=", ">", ">="];
            return CMP.get((arg >> 5) as usize).map(|s| s.to_string());
        }
        "BINARY_OP" => return binary_op_symbol(arg).map(str::to_string),
        "IS_OP" => return Some(if arg == 0 { "is" } else { "is not" }.to_string()),
        "CONTAINS_OP" => return Some(if arg == 0 { "in" } else { "not in" }.to_string()),
        _ => {}
    }
    if in_set(op::HASCONST, opcode) {
        return code.consts.get(a).map(crate::marshal::Obj::render);
    }
    if in_set(op::HASNAME, opcode) {
        return code.names.get(a).cloned();
    }
    if in_set(op::HASLOCAL, opcode) || in_set(op::HASFREE, opcode) {
        return code.localsplus.get(a).cloned();
    }
    if let Some(t) = jump_target {
        return Some(format!("to {t}"));
    }
    None
}

/// The operator symbol for a `BINARY_OP` operand (CPython 3.14 `_nb_ops` order).
fn binary_op_symbol(arg: u32) -> Option<&'static str> {
    const OPS: [&str; 27] = [
        "+", "&", "//", "<<", "@", "*", "%", "|", "**", ">>", "-", "/", "^", // 0..=12
        "+=", "&=", "//=", "<<=", "@=", "*=", "%=", "|=", "**=", ">>=", "-=", "/=",
        "^=", // 13..=25
        "[]", // 26 NB_SUBSCR
    ];
    OPS.get(arg as usize).copied()
}
