//! Disassembles JVM bytecode (a method's `Code` attribute) into instructions, resolving
//! constant-pool references and branch targets. The opcode set is stable across all class
//! versions, so this needs no per-version table.

use crate::{Code, ConstantPool};

/// One decoded JVM instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Insn {
    /// Byte offset in the method's `code[]` (matches `javap`).
    pub offset: usize,
    pub opcode: u8,
    pub mnemonic: &'static str,
    /// Rendered operands (indices resolved, with `// comment`), empty if the op takes none.
    pub operands: String,
    /// Absolute target offset for a branch instruction.
    pub branch_target: Option<usize>,
    /// True if some branch lands on this instruction.
    pub is_branch_target: bool,
}

/// Disassembles a method's bytecode.
pub fn disassemble(code: &Code, cp: &ConstantPool) -> Vec<Insn> {
    let b = &code.bytecode;
    let mut insns: Vec<Insn> = Vec::new();
    let mut targets: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut i = 0usize;

    while i < b.len() {
        let start = i;
        let op = b[i];
        i += 1;
        let (operands, target) = match operands(op, b, &mut i, start, cp) {
            Some(x) => x,
            None => {
                // Truncated or malformed operand stream — stop cleanly.
                insns.push(Insn {
                    offset: start,
                    opcode: op,
                    mnemonic: mnemonic(op),
                    operands: "(truncated)".into(),
                    branch_target: None,
                    is_branch_target: false,
                });
                break;
            }
        };
        if let Some(t) = target {
            targets.insert(t);
        }
        insns.push(Insn {
            offset: start,
            opcode: op,
            mnemonic: mnemonic(op),
            operands,
            branch_target: target,
            is_branch_target: false,
        });
    }

    for ins in &mut insns {
        if targets.contains(&ins.offset) {
            ins.is_branch_target = true;
        }
    }
    insns
}

/// Reads an opcode's operands, advancing `*i`. Returns `(rendered, branch_target)`, or `None` on a
/// truncated/invalid stream. For switches it also records targets via the returned string only;
/// the caller's single `target` is the primary one (switches render all targets inline).
fn operands(
    op: u8,
    b: &[u8],
    i: &mut usize,
    start: usize,
    cp: &ConstantPool,
) -> Option<(String, Option<usize>)> {
    let u1 = |i: &mut usize| -> Option<u8> {
        let v = *b.get(*i)?;
        *i += 1;
        Some(v)
    };
    let u2 = |i: &mut usize| -> Option<u16> {
        let v = u16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]);
        *i += 2;
        Some(v)
    };
    let i2 = |i: &mut usize| -> Option<i16> { u2(i).map(|v| v as i16) };
    let i4 = |i: &mut usize| -> Option<i32> {
        let v = i32::from_be_bytes([
            *b.get(*i)?,
            *b.get(*i + 1)?,
            *b.get(*i + 2)?,
            *b.get(*i + 3)?,
        ]);
        *i += 4;
        Some(v)
    };

    Some(match op {
        // Immediate pushes.
        0x10 => (format!("{}", u1(i)? as i8), None), // bipush
        0x11 => (format!("{}", i2(i)?), None),       // sipush
        // Constant-pool loads (1- and 2-byte index).
        0x12 => cp_ref(u1(i)? as u16, cp), // ldc
        0x13 | 0x14 => cp_ref(u2(i)?, cp), // ldc_w, ldc2_w
        // Local-variable access (1-byte index).
        0x15..=0x19 | 0x36..=0x3a | 0xa9 => (format!("{}", u1(i)?), None),
        0x84 => {
            // iinc index, const
            let idx = u1(i)?;
            let c = u1(i)? as i8;
            (format!("{idx}, {c}"), None)
        }
        // Conditional/unconditional branches (2-byte signed, relative to the opcode).
        0x99..=0xa8 | 0xc6 | 0xc7 => {
            let t = (start as isize + i2(i)? as isize) as usize;
            (t.to_string(), Some(t))
        }
        // Wide branches (4-byte).
        0xc8 | 0xc9 => {
            let t = (start as isize + i4(i)? as isize) as usize;
            (t.to_string(), Some(t))
        }
        // Field/method/type references (2-byte index).
        0xb2..=0xb8 | 0xbb | 0xbd | 0xc0 | 0xc1 => cp_ref(u2(i)?, cp),
        0xb9 => {
            // invokeinterface: index, count, 0
            let (txt, _) = cp_ref(u2(i)?, cp);
            let count = u1(i)?;
            let _zero = u1(i)?;
            (format!("{txt}, {count}"), None)
        }
        0xba => {
            // invokedynamic: index, 0, 0
            let (txt, _) = cp_ref(u2(i)?, cp);
            let _ = u2(i)?;
            (txt, None)
        }
        0xbc => (newarray_type(u1(i)?).to_string(), None), // newarray
        0xc5 => {
            // multianewarray: index, dimensions
            let (txt, _) = cp_ref(u2(i)?, cp);
            let dims = u1(i)?;
            (format!("{txt}, dim {dims}"), None)
        }
        0xaa => tableswitch(b, i, start)?,
        0xab => lookupswitch(b, i, start)?,
        0xc4 => wide(b, i, cp)?,
        _ => (String::new(), None),
    })
}

fn cp_ref(idx: u16, cp: &ConstantPool) -> (String, Option<usize>) {
    (format!("#{idx}  // {}", cp.resolve(idx)), None)
}

fn newarray_type(atype: u8) -> &'static str {
    match atype {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => "?",
    }
}

fn tableswitch(b: &[u8], i: &mut usize, start: usize) -> Option<(String, Option<usize>)> {
    // 0-3 bytes padding so the default operand is 4-byte aligned from the code start.
    *i += (4 - (*i % 4)) % 4;
    let rd4 = |i: &mut usize| -> Option<i32> {
        let v = i32::from_be_bytes([
            *b.get(*i)?,
            *b.get(*i + 1)?,
            *b.get(*i + 2)?,
            *b.get(*i + 3)?,
        ]);
        *i += 4;
        Some(v)
    };
    let default = start as isize + rd4(i)? as isize;
    let low = rd4(i)?;
    let high = rd4(i)?;
    let n = (high as i64 - low as i64 + 1).max(0) as usize;
    let mut cases = Vec::new();
    for k in 0..n {
        let t = start as isize + rd4(i)? as isize;
        cases.push(format!("{}: {}", low as i64 + k as i64, t));
    }
    Some((
        format!("default: {default}, {} case(s) [{}]", n, cases.join(", ")),
        Some(default as usize),
    ))
}

fn lookupswitch(b: &[u8], i: &mut usize, start: usize) -> Option<(String, Option<usize>)> {
    *i += (4 - (*i % 4)) % 4;
    let rd4 = |i: &mut usize| -> Option<i32> {
        let v = i32::from_be_bytes([
            *b.get(*i)?,
            *b.get(*i + 1)?,
            *b.get(*i + 2)?,
            *b.get(*i + 3)?,
        ]);
        *i += 4;
        Some(v)
    };
    let default = start as isize + rd4(i)? as isize;
    let npairs = rd4(i)?.max(0) as usize;
    let mut cases = Vec::new();
    for _ in 0..npairs {
        let m = rd4(i)?;
        let t = start as isize + rd4(i)? as isize;
        cases.push(format!("{m}: {t}"));
    }
    Some((
        format!(
            "default: {default}, {npairs} pair(s) [{}]",
            cases.join(", ")
        ),
        Some(default as usize),
    ))
}

fn wide(b: &[u8], i: &mut usize, _cp: &ConstantPool) -> Option<(String, Option<usize>)> {
    let op = *b.get(*i)?;
    *i += 1;
    let idx = u16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]);
    *i += 2;
    if op == 0x84 {
        // wide iinc: index (2), const (2)
        let c = i16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]);
        *i += 2;
        Some((format!("{} {idx}, {c}", mnemonic(op)), None))
    } else {
        Some((format!("{} {idx}", mnemonic(op)), None))
    }
}

/// The mnemonic for a JVM opcode.
pub fn mnemonic(op: u8) -> &'static str {
    match op {
        0x00 => "nop",
        0x01 => "aconst_null",
        0x02 => "iconst_m1",
        0x03 => "iconst_0",
        0x04 => "iconst_1",
        0x05 => "iconst_2",
        0x06 => "iconst_3",
        0x07 => "iconst_4",
        0x08 => "iconst_5",
        0x09 => "lconst_0",
        0x0a => "lconst_1",
        0x0b => "fconst_0",
        0x0c => "fconst_1",
        0x0d => "fconst_2",
        0x0e => "dconst_0",
        0x0f => "dconst_1",
        0x10 => "bipush",
        0x11 => "sipush",
        0x12 => "ldc",
        0x13 => "ldc_w",
        0x14 => "ldc2_w",
        0x15 => "iload",
        0x16 => "lload",
        0x17 => "fload",
        0x18 => "dload",
        0x19 => "aload",
        0x1a => "iload_0",
        0x1b => "iload_1",
        0x1c => "iload_2",
        0x1d => "iload_3",
        0x1e => "lload_0",
        0x1f => "lload_1",
        0x20 => "lload_2",
        0x21 => "lload_3",
        0x22 => "fload_0",
        0x23 => "fload_1",
        0x24 => "fload_2",
        0x25 => "fload_3",
        0x26 => "dload_0",
        0x27 => "dload_1",
        0x28 => "dload_2",
        0x29 => "dload_3",
        0x2a => "aload_0",
        0x2b => "aload_1",
        0x2c => "aload_2",
        0x2d => "aload_3",
        0x2e => "iaload",
        0x2f => "laload",
        0x30 => "faload",
        0x31 => "daload",
        0x32 => "aaload",
        0x33 => "baload",
        0x34 => "caload",
        0x35 => "saload",
        0x36 => "istore",
        0x37 => "lstore",
        0x38 => "fstore",
        0x39 => "dstore",
        0x3a => "astore",
        0x3b => "istore_0",
        0x3c => "istore_1",
        0x3d => "istore_2",
        0x3e => "istore_3",
        0x3f => "lstore_0",
        0x40 => "lstore_1",
        0x41 => "lstore_2",
        0x42 => "lstore_3",
        0x43 => "fstore_0",
        0x44 => "fstore_1",
        0x45 => "fstore_2",
        0x46 => "fstore_3",
        0x47 => "dstore_0",
        0x48 => "dstore_1",
        0x49 => "dstore_2",
        0x4a => "dstore_3",
        0x4b => "astore_0",
        0x4c => "astore_1",
        0x4d => "astore_2",
        0x4e => "astore_3",
        0x4f => "iastore",
        0x50 => "lastore",
        0x51 => "fastore",
        0x52 => "dastore",
        0x53 => "aastore",
        0x54 => "bastore",
        0x55 => "castore",
        0x56 => "sastore",
        0x57 => "pop",
        0x58 => "pop2",
        0x59 => "dup",
        0x5a => "dup_x1",
        0x5b => "dup_x2",
        0x5c => "dup2",
        0x5d => "dup2_x1",
        0x5e => "dup2_x2",
        0x5f => "swap",
        0x60 => "iadd",
        0x61 => "ladd",
        0x62 => "fadd",
        0x63 => "dadd",
        0x64 => "isub",
        0x65 => "lsub",
        0x66 => "fsub",
        0x67 => "dsub",
        0x68 => "imul",
        0x69 => "lmul",
        0x6a => "fmul",
        0x6b => "dmul",
        0x6c => "idiv",
        0x6d => "ldiv",
        0x6e => "fdiv",
        0x6f => "ddiv",
        0x70 => "irem",
        0x71 => "lrem",
        0x72 => "frem",
        0x73 => "drem",
        0x74 => "ineg",
        0x75 => "lneg",
        0x76 => "fneg",
        0x77 => "dneg",
        0x78 => "ishl",
        0x79 => "lshl",
        0x7a => "ishr",
        0x7b => "lshr",
        0x7c => "iushr",
        0x7d => "lushr",
        0x7e => "iand",
        0x7f => "land",
        0x80 => "ior",
        0x81 => "lor",
        0x82 => "ixor",
        0x83 => "lxor",
        0x84 => "iinc",
        0x85 => "i2l",
        0x86 => "i2f",
        0x87 => "i2d",
        0x88 => "l2i",
        0x89 => "l2f",
        0x8a => "l2d",
        0x8b => "f2i",
        0x8c => "f2l",
        0x8d => "f2d",
        0x8e => "d2i",
        0x8f => "d2l",
        0x90 => "d2f",
        0x91 => "i2b",
        0x92 => "i2c",
        0x93 => "i2s",
        0x94 => "lcmp",
        0x95 => "fcmpl",
        0x96 => "fcmpg",
        0x97 => "dcmpl",
        0x98 => "dcmpg",
        0x99 => "ifeq",
        0x9a => "ifne",
        0x9b => "iflt",
        0x9c => "ifge",
        0x9d => "ifgt",
        0x9e => "ifle",
        0x9f => "if_icmpeq",
        0xa0 => "if_icmpne",
        0xa1 => "if_icmplt",
        0xa2 => "if_icmpge",
        0xa3 => "if_icmpgt",
        0xa4 => "if_icmple",
        0xa5 => "if_acmpeq",
        0xa6 => "if_acmpne",
        0xa7 => "goto",
        0xa8 => "jsr",
        0xa9 => "ret",
        0xaa => "tableswitch",
        0xab => "lookupswitch",
        0xac => "ireturn",
        0xad => "lreturn",
        0xae => "freturn",
        0xaf => "dreturn",
        0xb0 => "areturn",
        0xb1 => "return",
        0xb2 => "getstatic",
        0xb3 => "putstatic",
        0xb4 => "getfield",
        0xb5 => "putfield",
        0xb6 => "invokevirtual",
        0xb7 => "invokespecial",
        0xb8 => "invokestatic",
        0xb9 => "invokeinterface",
        0xba => "invokedynamic",
        0xbb => "new",
        0xbc => "newarray",
        0xbd => "anewarray",
        0xbe => "arraylength",
        0xbf => "athrow",
        0xc0 => "checkcast",
        0xc1 => "instanceof",
        0xc2 => "monitorenter",
        0xc3 => "monitorexit",
        0xc4 => "wide",
        0xc5 => "multianewarray",
        0xc6 => "ifnull",
        0xc7 => "ifnonnull",
        0xc8 => "goto_w",
        0xc9 => "jsr_w",
        0xca => "breakpoint",
        0xfe => "impdep1",
        0xff => "impdep2",
        _ => "<unknown>",
    }
}
