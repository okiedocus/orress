//! x86-64 encoder, built on `iced-x86`'s `code_asm` assembler. We parse text into [`parse::Line`]s,
//! then drive `CodeAssembler` instruction by instruction; it resolves relative branches to labels
//! and emits the final bytes, from which we slice a per-line listing.
//!
//! Coverage is the common patching set: no-operand ops, push/pop, inc/dec/neg/not, jmp/call/jcc to
//! a label, an absolute address or a register, mov/movzx/movsx/movsxd/xchg/cmovcc/setcc,
//! add/sub/and/or/xor/cmp/test, 1-, 2- and 3-operand imul, shifts by an immediate or `cl`, and
//! `lea`, with register, immediate, `[base + index*scale + disp]` (64-bit base/index) and
//! `[rip + disp]` memory operands.

use std::collections::HashMap;

use iced_x86::code_asm::*;
use iced_x86::{BlockEncoderOptions, Code, Instruction, Register};

use crate::parse::{self, Operand};
use crate::{Assembled, Diagnostic, LineOutput};

/// A resolved x86-64 register, tagged with its width.
#[derive(Clone, Copy)]
enum XReg {
    R8(AsmRegister8),
    R16(AsmRegister16),
    R32(AsmRegister32),
    R64(AsmRegister64),
}

/// A resolved operand: a register, an immediate, a memory reference, a RIP-relative memory
/// reference, or a branch-target label.
#[derive(Clone, Copy)]
enum XOp {
    Reg(XReg),
    Imm(i64),
    Mem(AsmMemoryOperand),
    /// `[rip + disp]`: relative to the *next* instruction's address, so it is encoded once that
    /// address is known (see [`assemble`]).
    RipMem {
        size: Option<parse::MemSize>,
        disp: i64,
    },
    Label(CodeLabel),
}

/// The output of one encoding pass over the source.
struct Pass {
    a: CodeAssembler,
    /// For each source line that produced instructions: (first instruction index, count).
    line_instr: Vec<Option<(usize, usize)>>,
    /// Instruction indices of the RIP-relative instructions, in source order.
    rip_insns: Vec<usize>,
}

pub(crate) fn assemble(source: &str, base_addr: u64) -> Result<Assembled, Vec<Diagnostic>> {
    let lines = parse::parse(source)?;
    let mut pass = build(&lines, base_addr, &[])?;
    if !pass.rip_insns.is_empty() {
        // `[rip + disp]` is relative to the next instruction, whose address is only known after
        // layout. RIP-relative operands always use a 32-bit displacement, so instruction sizes do
        // not depend on the targets: one layout pass gives the exact addresses for the second.
        let first = encode(&mut pass.a, base_addr)?;
        let next_ips: Vec<u64> = pass
            .rip_insns
            .iter()
            .map(|&i| {
                let end = first
                    .offsets
                    .get(i + 1)
                    .map_or(first.bytes.len(), |&o| o as usize);
                base_addr.wrapping_add(end as u64)
            })
            .collect();
        pass = build(&lines, base_addr, &next_ips)?;
    }
    let encoded = encode(&mut pass.a, base_addr)?;
    let bytes = encoded.bytes;
    let offsets = &encoded.offsets;

    let mut out_lines = Vec::with_capacity(lines.len());
    let mut cursor = 0usize; // byte offset reached so far
    for (l, instr) in lines.iter().zip(pass.line_instr.iter()) {
        let (addr, line_bytes) = match instr {
            Some((start, count)) => {
                let begin = offsets[*start] as usize;
                let end = offsets
                    .get(*start + *count)
                    .map(|o| *o as usize)
                    .unwrap_or(bytes.len());
                cursor = end;
                (base_addr + begin as u64, bytes[begin..end].to_vec())
            }
            // A label/blank line sits at the current position and emits no bytes.
            None => (base_addr + cursor as u64, Vec::new()),
        };
        out_lines.push(LineOutput {
            line: l.line,
            address: addr,
            bytes: line_bytes,
            source: l.source.clone(),
        });
    }

    Ok(Assembled {
        bytes,
        lines: out_lines,
    })
}

struct Encoded {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

fn encode(a: &mut CodeAssembler, base_addr: u64) -> Result<Encoded, Vec<Diagnostic>> {
    let result = a
        .assemble_options(
            base_addr,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|e| vec![Diagnostic::new(0, e.to_string())])?;
    Ok(Encoded {
        bytes: result.inner.code_buffer.clone(),
        offsets: result.inner.new_instruction_offsets.clone(),
    })
}

/// One encoding pass. `rip_next[k]` is the address after the `k`-th RIP-relative instruction
/// (unknown on the first pass, when `base_addr` stands in).
fn build(lines: &[parse::Line], base_addr: u64, rip_next: &[u64]) -> Result<Pass, Vec<Diagnostic>> {
    let mut a = CodeAssembler::new(64).map_err(|e| vec![Diagnostic::new(0, e.to_string())])?;

    // Pre-create a label for every `name:` so forward references resolve. Consecutive labels (with
    // no instruction between them) name the same position, so they share one `CodeLabel`.
    let mut labels: HashMap<String, CodeLabel> = HashMap::new();
    // Each line's label group (an index into `groups`), for the main loop.
    let mut group_of_line: Vec<Option<usize>> = Vec::with_capacity(lines.len());
    let mut groups: Vec<CodeLabel> = Vec::new();
    let mut pending: Option<usize> = None;
    for l in lines {
        let mut group = None;
        if let Some(name) = &l.label {
            if labels.contains_key(name) {
                return Err(vec![Diagnostic::new(
                    l.line,
                    format!("label `{name}` defined twice"),
                )]);
            }
            let g = *pending.get_or_insert_with(|| {
                groups.push(a.create_label());
                groups.len() - 1
            });
            labels.insert(name.clone(), groups[g]);
            group = Some(g);
        }
        if l.stmt.is_some() {
            pending = None;
        }
        group_of_line.push(group);
    }

    let mut errors = Vec::new();
    let mut line_instr: Vec<Option<(usize, usize)>> = Vec::with_capacity(lines.len());
    let mut rip_insns = Vec::new();
    // The label group set at the current position and not yet followed by an instruction.
    let mut label_pending: Option<usize> = None;

    for (l, group) in lines.iter().zip(&group_of_line) {
        if let Some(g) = *group
            && label_pending != Some(g)
        {
            if let Err(e) = a.set_label(&mut groups[g]) {
                errors.push(Diagnostic::new(l.line, e.to_string()));
            }
            label_pending = Some(g);
        }

        let Some(stmt) = &l.stmt else {
            line_instr.push(None);
            continue;
        };

        let before = a.instructions().len();
        let next_ip = rip_next.get(rip_insns.len()).copied().unwrap_or(base_addr);
        match encode_stmt(&mut a, &stmt.mnemonic, &stmt.operands, &labels, next_ip) {
            Ok(rip) => {
                if rip && a.instructions().len() > before {
                    rip_insns.push(a.instructions().len() - 1);
                }
            }
            Err(msg) => errors.push(Diagnostic::new(l.line, msg)),
        }
        let count = a.instructions().len() - before;
        line_instr.push(if count > 0 {
            Some((before, count))
        } else {
            None
        });
        if count > 0 {
            label_pending = None;
        }
    }

    // A label at the very end of the source marks the end of the code: anchor it to a zero-byte
    // pseudo-instruction so it still resolves (e.g. `jmp done` ... `done:`).
    if label_pending.is_some()
        && let Err(e) = a.zero_bytes()
    {
        errors.push(Diagnostic::new(0, e.to_string()));
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Pass {
        a,
        line_instr,
        rip_insns,
    })
}

/// Standard 2-operand integer ops over `reg, reg` / `reg, imm` / `reg, mem` / `mem, reg` /
/// `mem, imm`. Immediates are sign-extended into a 32-bit field by iced; a `mem, imm` form needs
/// an explicit size prefix (iced reports that). `$dst`/`$src` are `&XOp`. Diverges on an
/// unsupported combination.
macro_rules! two_op {
    ($a:expr, $m:ident, $dst:expr, $src:expr) => {{
        match ($dst, $src) {
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R64(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R32(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R16(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R8(d)), XOp::Reg(XReg::R8(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Imm(v)) => $a.$m(*d, imm32(*v)?),
            (XOp::Reg(XReg::R32(d)), XOp::Imm(v)) => $a.$m(*d, imm32(*v)?),
            (XOp::Reg(XReg::R16(d)), XOp::Imm(v)) => $a.$m(*d, imm32(*v)?),
            (XOp::Reg(XReg::R8(d)), XOp::Imm(v)) => $a.$m(*d, imm32(*v)?),
            (XOp::Reg(XReg::R64(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            (XOp::Reg(XReg::R32(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            (XOp::Reg(XReg::R16(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            (XOp::Reg(XReg::R8(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            (XOp::Mem(m), XOp::Reg(XReg::R64(s))) => $a.$m(*m, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R32(s))) => $a.$m(*m, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R16(s))) => $a.$m(*m, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R8(s))) => $a.$m(*m, *s),
            (XOp::Mem(m), XOp::Imm(v)) => $a.$m(*m, imm32(*v)?),
            _ => {
                return Err(format!(
                    "unsupported operands for `{}` (check register widths and sizes match)",
                    stringify!($m)
                ));
            }
        }
    }};
}

/// `test` is like [`two_op`] but has no `reg, mem` form (its memory operand is the r/m slot, so
/// write `test [mem], reg`). Covers `reg, reg` / `reg, imm` / `mem, reg` / `mem, imm`.
macro_rules! test_op {
    ($a:expr, $dst:expr, $src:expr) => {{
        match ($dst, $src) {
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R64(s))) => $a.test(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R32(s))) => $a.test(*d, *s),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R16(s))) => $a.test(*d, *s),
            (XOp::Reg(XReg::R8(d)), XOp::Reg(XReg::R8(s))) => $a.test(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Imm(v)) => $a.test(*d, imm32(*v)?),
            (XOp::Reg(XReg::R32(d)), XOp::Imm(v)) => $a.test(*d, imm32(*v)?),
            (XOp::Reg(XReg::R16(d)), XOp::Imm(v)) => $a.test(*d, imm32(*v)?),
            (XOp::Reg(XReg::R8(d)), XOp::Imm(v)) => $a.test(*d, imm32(*v)?),
            (XOp::Mem(m), XOp::Reg(XReg::R64(s))) => $a.test(*m, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R32(s))) => $a.test(*m, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R16(s))) => $a.test(*m, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R8(s))) => $a.test(*m, *s),
            (XOp::Mem(m), XOp::Imm(v)) => $a.test(*m, imm32(*v)?),
            _ => return Err("unsupported operands for `test` (write `test [mem], reg`)".into()),
        }
    }};
}

/// Shift ops: `reg, imm` / `mem, imm`, or a shift count in `cl` (`reg, cl` / `mem, cl`).
macro_rules! shift_op {
    ($a:expr, $m:ident, $dst:expr, $src:expr) => {{
        match ($dst, $src) {
            (XOp::Reg(XReg::R64(d)), XOp::Imm(v)) => $a.$m(*d, imm_u32(*v)?),
            (XOp::Reg(XReg::R32(d)), XOp::Imm(v)) => $a.$m(*d, imm_u32(*v)?),
            (XOp::Reg(XReg::R16(d)), XOp::Imm(v)) => $a.$m(*d, imm_u32(*v)?),
            (XOp::Reg(XReg::R8(d)), XOp::Imm(v)) => $a.$m(*d, imm_u32(*v)?),
            (XOp::Mem(m), XOp::Imm(v)) => $a.$m(*m, imm_u32(*v)?),
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R8(c))) if is_cl(*c) => $a.$m(*d, *c),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R8(c))) if is_cl(*c) => $a.$m(*d, *c),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R8(c))) if is_cl(*c) => $a.$m(*d, *c),
            (XOp::Reg(XReg::R8(d)), XOp::Reg(XReg::R8(c))) if is_cl(*c) => $a.$m(*d, *c),
            (XOp::Mem(m), XOp::Reg(XReg::R8(c))) if is_cl(*c) => $a.$m(*m, *c),
            _ => {
                return Err(format!(
                    "`{}` takes `reg, imm`, `mem, imm`, `reg, cl` or `mem, cl`",
                    stringify!($m)
                ));
            }
        }
    }};
}

/// One-operand ops over a register (any width) or a sized memory operand. `$op` is `&XOp`.
macro_rules! unary_rm {
    ($a:expr, $m:ident, $op:expr) => {{
        match $op {
            XOp::Reg(XReg::R64(r)) => $a.$m(*r),
            XOp::Reg(XReg::R32(r)) => $a.$m(*r),
            XOp::Reg(XReg::R16(r)) => $a.$m(*r),
            XOp::Reg(XReg::R8(r)) => $a.$m(*r),
            XOp::Mem(m) => $a.$m(*m),
            _ => {
                return Err(format!(
                    "`{}` takes a register or memory operand",
                    stringify!($m)
                ));
            }
        }
    }};
}

/// A branch to a label or an absolute address. `$t` is `&XOp` (a `Label` or an `Imm`).
macro_rules! branch {
    ($a:expr, $m:ident, $t:expr) => {{
        match $t {
            XOp::Label(l) => $a.$m(*l),
            XOp::Imm(v) => $a.$m(*v as u64),
            _ => return Err(format!("`{}` takes a label or an address", stringify!($m))),
        }
    }};
}

/// `cmovcc reg, reg|mem` (16/32/64-bit).
macro_rules! cmov_op {
    ($a:expr, $m:ident, $dst:expr, $src:expr) => {{
        match ($dst, $src) {
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R64(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R32(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R16(s))) => $a.$m(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            (XOp::Reg(XReg::R32(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            (XOp::Reg(XReg::R16(d)), XOp::Mem(m)) => $a.$m(*d, *m),
            _ => {
                return Err(format!(
                    "`{}` takes a 16/32/64-bit register and a same-width register or memory",
                    stringify!($m)
                ));
            }
        }
    }};
}

/// `setcc r8|byte [mem]`.
macro_rules! set_op {
    ($a:expr, $m:ident, $op:expr) => {{
        match $op {
            XOp::Reg(XReg::R8(r)) => $a.$m(*r),
            XOp::Mem(m) => $a.$m(*m),
            _ => {
                return Err(format!(
                    "`{}` takes an 8-bit register or a byte memory operand",
                    stringify!($m)
                ));
            }
        }
    }};
}

/// Expands `$body!(a, <mnemonic>, args...)` for the condition code `$cc` (already normalized),
/// with `$what` naming the instruction family (`j`, `cmov` or `set`). `$args` is a parenthesized
/// argument list.
macro_rules! by_cc {
    (@pick "j", $body:ident, $a:expr, $j:ident, $c:ident, $s:ident, ($($x:expr),*)) => {
        $body!($a, $j, $($x),*)
    };
    (@pick "cmov", $body:ident, $a:expr, $j:ident, $c:ident, $s:ident, ($($x:expr),*)) => {
        $body!($a, $c, $($x),*)
    };
    (@pick "set", $body:ident, $a:expr, $j:ident, $c:ident, $s:ident, ($($x:expr),*)) => {
        $body!($a, $s, $($x),*)
    };
    ($cc:expr, $what:tt, $body:ident, $a:expr, $args:tt, [$($j:ident $c:ident $s:ident $name:literal),*]) => {{
        match $cc {
            $($name => by_cc!(@pick $what, $body, $a, $j, $c, $s, $args),)*
            other => return Err(format!("unknown condition `{other}`")),
        }
    }};
}

/// Dispatches on a condition code across the jcc / cmovcc / setcc families.
macro_rules! conditions {
    ($what:tt, $body:ident, $a:expr, $cc:expr, $args:tt) => {
        by_cc!($cc, $what, $body, $a, $args, [
            je cmove sete "e", jne cmovne setne "ne",
            jl cmovl setl "l", jle cmovle setle "le", jg cmovg setg "g", jge cmovge setge "ge",
            jb cmovb setb "b", jbe cmovbe setbe "be", ja cmova seta "a", jae cmovae setae "ae",
            js cmovs sets "s", jns cmovns setns "ns", jo cmovo seto "o", jno cmovno setno "no",
            jp cmovp setp "p", jnp cmovnp setnp "np"
        ])
    };
}

/// Encodes one statement. Returns whether it is RIP-relative (`[rip + disp]`); `next_ip` is the
/// address after this instruction, used to resolve such an operand to its absolute target.
fn encode_stmt(
    a: &mut CodeAssembler,
    mnemonic: &str,
    operands: &[Operand],
    labels: &HashMap<String, CodeLabel>,
    next_ip: u64,
) -> Result<bool, String> {
    let ops = resolve_operands(operands, labels)?;
    let m = normalize_mnemonic(mnemonic);
    let rip = ops.iter().find_map(|o| match o {
        XOp::RipMem { size, disp } => Some((*size, *disp)),
        _ => None,
    });
    let Some((size, disp)) = rip else {
        encode_ops(a, &m, &ops)?;
        return Ok(false);
    };
    if ops
        .iter()
        .filter(|o| matches!(o, XOp::RipMem { .. }))
        .count()
        > 1
    {
        return Err("only one memory operand is allowed".into());
    }
    // Encode with a placeholder absolute `[0]` operand in a scratch assembler, then turn it into
    // RIP-relative with the absolute target; iced's block encoder computes the displacement.
    let placeholder = sized(AsmMemoryOperand::from(0i64), size);
    let ops: Vec<XOp> = ops
        .iter()
        .map(|o| match o {
            XOp::RipMem { .. } => XOp::Mem(placeholder),
            other => *other,
        })
        .collect();
    let mut scratch = CodeAssembler::new(64).map_err(|e| e.to_string())?;
    encode_ops(&mut scratch, &m, &ops)?;
    let [ins] = scratch.instructions() else {
        return Err(format!("`{m}` cannot take a RIP-relative operand"));
    };
    let mut ins: Instruction = *ins;
    ins.set_memory_base(Register::RIP);
    ins.set_memory_index(Register::None);
    ins.set_memory_index_scale(1);
    ins.set_memory_displ_size(8);
    ins.set_memory_displacement64(next_ip.wrapping_add_signed(disp));
    a.add_instruction(ins).map_err(|e| e.to_string())?;
    Ok(true)
}

fn encode_ops(a: &mut CodeAssembler, m: &str, ops: &[XOp]) -> Result<(), String> {
    let iced_result: Result<(), iced_x86::IcedError> = match (m, ops) {
        // No operands.
        ("nop", []) => a.nop(),
        ("ret", []) => a.ret(),
        ("leave", []) => a.leave(),
        ("int3", []) => a.int3(),
        ("cdq", []) => a.cdq(),
        ("cqo", []) => a.cqo(),
        ("syscall", []) => a.syscall(),
        ("pause", []) => a.pause(),
        ("hlt", []) => a.hlt(),
        ("ud2", []) => a.ud2(),
        ("cld", []) => a.cld(),
        ("std", []) => a.std(),

        // Stack.
        ("push", [XOp::Reg(XReg::R64(r))]) => a.push(*r),
        ("push", [XOp::Reg(XReg::R16(r))]) => a.push(*r),
        ("push", [XOp::Imm(v)]) => a.push(imm32(*v)?),
        ("push", [XOp::Mem(m)]) => a.push(*m),
        ("pop", [XOp::Reg(XReg::R64(r))]) => a.pop(*r),
        ("pop", [XOp::Reg(XReg::R16(r))]) => a.pop(*r),
        ("pop", [XOp::Mem(m)]) => a.pop(*m),

        // Unary register-or-memory ops.
        ("inc", [op]) => unary_rm!(a, inc, op),
        ("dec", [op]) => unary_rm!(a, dec, op),
        ("neg", [op]) => unary_rm!(a, neg, op),
        ("not", [op]) => unary_rm!(a, not, op),
        ("mul", [op]) => unary_rm!(a, mul, op),
        ("imul", [op]) => unary_rm!(a, imul, op),
        ("div", [op]) => unary_rm!(a, div, op),
        ("idiv", [op]) => unary_rm!(a, idiv, op),

        // 2- and 3-operand imul.
        ("imul", [d, s]) => cmov_op!(a, imul_2, d, s),
        ("imul", [d, s, XOp::Imm(v)]) => {
            let v = imm32(*v)?;
            match (d, s) {
                (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R64(s))) => a.imul_3(*d, *s, v),
                (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R32(s))) => a.imul_3(*d, *s, v),
                (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R16(s))) => a.imul_3(*d, *s, v),
                (XOp::Reg(XReg::R64(d)), XOp::Mem(m)) => a.imul_3(*d, *m, v),
                (XOp::Reg(XReg::R32(d)), XOp::Mem(m)) => a.imul_3(*d, *m, v),
                (XOp::Reg(XReg::R16(d)), XOp::Mem(m)) => a.imul_3(*d, *m, v),
                _ => return Err("`imul reg, reg|mem, imm` needs matching register widths".into()),
            }
        }

        // Branches to a label or an absolute address.
        ("jmp", [t @ (XOp::Label(_) | XOp::Imm(_))]) => branch!(a, jmp, t),
        ("call", [t @ (XOp::Label(_) | XOp::Imm(_))]) => branch!(a, call, t),
        (name, [t @ (XOp::Label(_) | XOp::Imm(_))]) if name.starts_with('j') => {
            conditions!("j", branch, a, &name[1..], (t))
        }

        // Indirect branches through a register or memory.
        ("jmp", [XOp::Reg(XReg::R64(r))]) => a.jmp(*r),
        ("call", [XOp::Reg(XReg::R64(r))]) => a.call(*r),
        ("jmp", [XOp::Mem(m)]) => a.jmp(*m),
        ("call", [XOp::Mem(m)]) => a.call(*m),

        // Conditional move / set.
        (name, [d, s]) if name.starts_with("cmov") => {
            conditions!("cmov", cmov_op, a, &name[4..], (d, s))
        }
        (name, [op]) if name.starts_with("set") => conditions!("set", set_op, a, &name[3..], (op)),

        // mov has width-specific immediate forms.
        ("mov", [d, s]) => return mov(a, d, s),

        // Zero/sign extension.
        ("movzx", [d, s]) => match (d, s) {
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R8(s))) => a.movzx(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R16(s))) => a.movzx(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R8(s))) => a.movzx(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R16(s))) => a.movzx(*d, *s),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R8(s))) => a.movzx(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Mem(m)) => a.movzx(*d, *m),
            (XOp::Reg(XReg::R32(d)), XOp::Mem(m)) => a.movzx(*d, *m),
            (XOp::Reg(XReg::R16(d)), XOp::Mem(m)) => a.movzx(*d, *m),
            _ => return Err("`movzx` takes a wider register and an 8/16-bit source".into()),
        },
        ("movsx", [d, s]) => match (d, s) {
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R8(s))) => a.movsx(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R16(s))) => a.movsx(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R8(s))) => a.movsx(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R16(s))) => a.movsx(*d, *s),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R8(s))) => a.movsx(*d, *s),
            (XOp::Reg(XReg::R64(d)), XOp::Mem(m)) => a.movsx(*d, *m),
            (XOp::Reg(XReg::R32(d)), XOp::Mem(m)) => a.movsx(*d, *m),
            (XOp::Reg(XReg::R16(d)), XOp::Mem(m)) => a.movsx(*d, *m),
            _ => return Err("`movsx` takes a wider register and an 8/16-bit source".into()),
        },
        ("movsxd", [XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R32(s))]) => a.movsxd(*d, *s),
        ("movsxd", [XOp::Reg(XReg::R64(d)), XOp::Mem(m)]) => a.movsxd(*d, *m),

        // Exchange (the operands commute, so `reg, mem` is encoded as `mem, reg`).
        ("xchg", [d, s]) => match (d, s) {
            (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R64(s))) => a.xchg(*d, *s),
            (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R32(s))) => a.xchg(*d, *s),
            (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R16(s))) => a.xchg(*d, *s),
            (XOp::Reg(XReg::R8(d)), XOp::Reg(XReg::R8(s))) => a.xchg(*d, *s),
            (XOp::Mem(m), XOp::Reg(XReg::R64(r))) | (XOp::Reg(XReg::R64(r)), XOp::Mem(m)) => {
                a.xchg(*m, *r)
            }
            (XOp::Mem(m), XOp::Reg(XReg::R32(r))) | (XOp::Reg(XReg::R32(r)), XOp::Mem(m)) => {
                a.xchg(*m, *r)
            }
            (XOp::Mem(m), XOp::Reg(XReg::R16(r))) | (XOp::Reg(XReg::R16(r)), XOp::Mem(m)) => {
                a.xchg(*m, *r)
            }
            (XOp::Mem(m), XOp::Reg(XReg::R8(r))) | (XOp::Reg(XReg::R8(r)), XOp::Mem(m)) => {
                a.xchg(*m, *r)
            }
            _ => {
                return Err(
                    "`xchg` takes two same-width registers, or a register and memory".into(),
                );
            }
        },

        // lea reg, mem.
        ("lea", [XOp::Reg(d), XOp::Mem(m)]) => match d {
            XReg::R64(r) => a.lea(*r, *m),
            XReg::R32(r) => a.lea(*r, *m),
            XReg::R16(r) => a.lea(*r, *m),
            XReg::R8(_) => return Err("`lea` destination must be a 16/32/64-bit register".into()),
        },

        // Standard ALU: reg/mem/imm combinations.
        ("add", [d, s]) => two_op!(a, add, d, s),
        ("sub", [d, s]) => two_op!(a, sub, d, s),
        ("and", [d, s]) => two_op!(a, and, d, s),
        ("or", [d, s]) => two_op!(a, or, d, s),
        ("xor", [d, s]) => two_op!(a, xor, d, s),
        ("cmp", [d, s]) => two_op!(a, cmp, d, s),
        ("test", [d, s]) => test_op!(a, d, s),
        ("adc", [d, s]) => two_op!(a, adc, d, s),
        ("sbb", [d, s]) => two_op!(a, sbb, d, s),

        // Shifts: by an immediate or by `cl`.
        ("shl" | "sal", [d, s]) => shift_op!(a, shl, d, s),
        ("shr", [d, s]) => shift_op!(a, shr, d, s),
        ("sar", [d, s]) => shift_op!(a, sar, d, s),
        ("rol", [d, s]) => shift_op!(a, rol, d, s),
        ("ror", [d, s]) => shift_op!(a, ror, d, s),

        _ => {
            return Err(format!(
                "unsupported instruction `{m}` with {} operand(s)",
                ops.len()
            ));
        }
    };
    iced_result.map_err(|e| e.to_string())
}

fn is_cl(r: AsmRegister8) -> bool {
    Register::from(r) == Register::CL
}

/// `mov` with the right immediate width per destination, plus `reg, mem` / `mem, reg` / `mem, imm`.
/// `mov r64, imm` uses the short sign-extended imm32 form when the value fits, else `movabs`.
fn mov(a: &mut CodeAssembler, dst: &XOp, src: &XOp) -> Result<(), String> {
    let r = match (dst, src) {
        (XOp::Reg(XReg::R64(d)), XOp::Reg(XReg::R64(s))) => a.mov(*d, *s),
        (XOp::Reg(XReg::R32(d)), XOp::Reg(XReg::R32(s))) => a.mov(*d, *s),
        (XOp::Reg(XReg::R16(d)), XOp::Reg(XReg::R16(s))) => a.mov(*d, *s),
        (XOp::Reg(XReg::R8(d)), XOp::Reg(XReg::R8(s))) => a.mov(*d, *s),
        // code_asm only exposes the 10-byte movabs (imm64) form; when the value is a sign-extended
        // imm32, add the 7-byte `REX.W C7 /0 id` form directly.
        (XOp::Reg(XReg::R64(d)), XOp::Imm(v)) => match i32::try_from(*v) {
            Ok(v32) => Instruction::with2(Code::Mov_rm64_imm32, Register::from(*d), v32)
                .and_then(|ins| a.add_instruction(ins)),
            Err(_) => a.mov(*d, *v as u64),
        },
        (XOp::Reg(XReg::R32(d)), XOp::Imm(v)) => a.mov(*d, imm_u32(*v)?),
        (XOp::Reg(XReg::R16(d)), XOp::Imm(v)) => a.mov(*d, imm_u32(*v)?),
        (XOp::Reg(XReg::R8(d)), XOp::Imm(v)) => a.mov(*d, imm_u32(*v)?),
        (XOp::Reg(XReg::R64(d)), XOp::Mem(m)) => a.mov(*d, *m),
        (XOp::Reg(XReg::R32(d)), XOp::Mem(m)) => a.mov(*d, *m),
        (XOp::Reg(XReg::R16(d)), XOp::Mem(m)) => a.mov(*d, *m),
        (XOp::Reg(XReg::R8(d)), XOp::Mem(m)) => a.mov(*d, *m),
        (XOp::Mem(m), XOp::Reg(XReg::R64(s))) => a.mov(*m, *s),
        (XOp::Mem(m), XOp::Reg(XReg::R32(s))) => a.mov(*m, *s),
        (XOp::Mem(m), XOp::Reg(XReg::R16(s))) => a.mov(*m, *s),
        (XOp::Mem(m), XOp::Reg(XReg::R8(s))) => a.mov(*m, *s),
        (XOp::Mem(m), XOp::Imm(v)) => a.mov(*m, imm32(*v)?),
        _ => return Err("unsupported operands for `mov` (check widths and sizes)".into()),
    };
    r.map_err(|e| e.to_string())
}

fn resolve_operands(
    operands: &[Operand],
    labels: &HashMap<String, CodeLabel>,
) -> Result<Vec<XOp>, String> {
    let mut out = Vec::with_capacity(operands.len());
    for op in operands {
        out.push(match op {
            Operand::Imm(v) => XOp::Imm(*v),
            Operand::Name(n) => {
                if let Some(r) = reg(n) {
                    XOp::Reg(r)
                } else if let Some(l) = labels.get(n) {
                    XOp::Label(*l)
                } else {
                    return Err(format!("`{n}` is not a known register or label"));
                }
            }
            Operand::Mem(m) if m.base.as_deref() == Some("rip") => {
                if m.index.is_some() {
                    return Err("a `[rip + disp]` operand cannot have an index register".into());
                }
                XOp::RipMem {
                    size: m.size,
                    disp: m.disp,
                }
            }
            Operand::Mem(m) => XOp::Mem(build_mem(m)?),
            Operand::Shift { .. } => {
                return Err("shift/extend operands are not used in x86-64".into());
            }
        });
    }
    Ok(out)
}

/// Applies a size prefix as the memory operand's size hint.
fn sized(acc: AsmMemoryOperand, size: Option<parse::MemSize>) -> AsmMemoryOperand {
    match size {
        Some(parse::MemSize::Byte) => byte_ptr(acc),
        Some(parse::MemSize::Word) => word_ptr(acc),
        Some(parse::MemSize::Dword) => dword_ptr(acc),
        Some(parse::MemSize::Qword) => qword_ptr(acc),
        None => acc,
    }
}

/// Build an iced memory operand from parsed components. Base and index must be 64-bit registers
/// (the common case for patching); a size prefix becomes the operand's size hint.
fn build_mem(m: &parse::Mem) -> Result<AsmMemoryOperand, String> {
    let mut acc = AsmMemoryOperand::from(m.disp);
    if let Some(base) = &m.base {
        acc = reg64(base)? + acc;
    }
    if let Some(index) = &m.index {
        if m.base.as_deref() == Some(index.as_str()) {
            // Same register as base and index is legal but almost always a typo; reject for safety.
            return Err(format!("`{index}` used as both base and index"));
        }
        acc = acc + reg64(index)? * i64::from(m.scale);
    }
    Ok(sized(acc, m.size))
}

/// Resolve a 64-bit register by name for use in a memory operand.
fn reg64(name: &str) -> Result<AsmRegister64, String> {
    match reg(name) {
        Some(XReg::R64(r)) => Ok(r),
        Some(_) => Err(format!(
            "memory base/index register `{name}` must be 64-bit (e.g. rax, not eax)"
        )),
        None => Err(format!("`{name}` is not a register")),
    }
}

/// Fold condition-code aliases (`jz`, `cmovnz`, `setc`, ...) onto the names iced exposes.
fn normalize_mnemonic(m: &str) -> String {
    for prefix in ["cmov", "set", "j"] {
        if let Some(cc) = m.strip_prefix(prefix) {
            let canon = match cc {
                "z" => "e",
                "nz" => "ne",
                "c" | "nae" => "b",
                "nc" | "nb" => "ae",
                "na" => "be",
                "nbe" => "a",
                "nge" => "l",
                "nl" => "ge",
                "ng" => "le",
                "nle" => "g",
                "pe" => "p",
                "po" => "np",
                _ => continue,
            };
            return format!("{prefix}{canon}");
        }
    }
    m.to_string()
}

/// An immediate that must fit in a signed 32-bit field.
fn imm32(v: i64) -> Result<i32, String> {
    i32::try_from(v).map_err(|_| format!("immediate {v} does not fit in 32 bits"))
}

/// An unsigned-ish immediate for shifts / small movs; we accept the low 32 bits.
fn imm_u32(v: i64) -> Result<u32, String> {
    u32::try_from(v)
        .or_else(|_| i32::try_from(v).map(|x| x as u32))
        .map_err(|_| format!("immediate {v} does not fit in 32 bits"))
}

// Look up an x86-64 register by (lower-cased) name.
fn reg(name: &str) -> Option<XReg> {
    Some(match name {
        // 64-bit
        "rax" => XReg::R64(rax),
        "rbx" => XReg::R64(rbx),
        "rcx" => XReg::R64(rcx),
        "rdx" => XReg::R64(rdx),
        "rsi" => XReg::R64(rsi),
        "rdi" => XReg::R64(rdi),
        "rbp" => XReg::R64(rbp),
        "rsp" => XReg::R64(rsp),
        "r8" => XReg::R64(r8),
        "r9" => XReg::R64(r9),
        "r10" => XReg::R64(r10),
        "r11" => XReg::R64(r11),
        "r12" => XReg::R64(r12),
        "r13" => XReg::R64(r13),
        "r14" => XReg::R64(r14),
        "r15" => XReg::R64(r15),
        // 32-bit
        "eax" => XReg::R32(eax),
        "ebx" => XReg::R32(ebx),
        "ecx" => XReg::R32(ecx),
        "edx" => XReg::R32(edx),
        "esi" => XReg::R32(esi),
        "edi" => XReg::R32(edi),
        "ebp" => XReg::R32(ebp),
        "esp" => XReg::R32(esp),
        "r8d" => XReg::R32(r8d),
        "r9d" => XReg::R32(r9d),
        "r10d" => XReg::R32(r10d),
        "r11d" => XReg::R32(r11d),
        "r12d" => XReg::R32(r12d),
        "r13d" => XReg::R32(r13d),
        "r14d" => XReg::R32(r14d),
        "r15d" => XReg::R32(r15d),
        // 16-bit
        "ax" => XReg::R16(ax),
        "bx" => XReg::R16(bx),
        "cx" => XReg::R16(cx),
        "dx" => XReg::R16(dx),
        "si" => XReg::R16(si),
        "di" => XReg::R16(di),
        "bp" => XReg::R16(bp),
        "sp" => XReg::R16(sp),
        "r8w" => XReg::R16(r8w),
        "r9w" => XReg::R16(r9w),
        "r10w" => XReg::R16(r10w),
        "r11w" => XReg::R16(r11w),
        "r12w" => XReg::R16(r12w),
        "r13w" => XReg::R16(r13w),
        "r14w" => XReg::R16(r14w),
        "r15w" => XReg::R16(r15w),
        // 8-bit
        "al" => XReg::R8(al),
        "bl" => XReg::R8(bl),
        "cl" => XReg::R8(cl),
        "dl" => XReg::R8(dl),
        "sil" => XReg::R8(sil),
        "dil" => XReg::R8(dil),
        "bpl" => XReg::R8(bpl),
        "spl" => XReg::R8(spl),
        "ah" => XReg::R8(ah),
        "bh" => XReg::R8(bh),
        "ch" => XReg::R8(ch),
        "dh" => XReg::R8(dh),
        "r8b" => XReg::R8(r8b),
        "r9b" => XReg::R8(r9b),
        "r10b" => XReg::R8(r10b),
        "r11b" => XReg::R8(r11b),
        "r12b" => XReg::R8(r12b),
        "r13b" => XReg::R8(r13b),
        "r14b" => XReg::R8(r14b),
        "r15b" => XReg::R8(r15b),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use crate::{Arch, assemble as asm};

    fn bytes(src: &str) -> Vec<u8> {
        asm(src, Arch::X64, 0x1000)
            .unwrap_or_else(|e| panic!("assemble failed: {e:?}"))
            .bytes
    }

    #[test]
    fn simple_known_encodings() {
        assert_eq!(bytes("nop"), vec![0x90]);
        assert_eq!(bytes("ret"), vec![0xc3]);
        assert_eq!(bytes("int3"), vec![0xcc]);
        // xor eax, eax => 31 c0
        assert_eq!(bytes("xor eax, eax"), vec![0x31, 0xc0]);
        // mov eax, 1 => b8 01 00 00 00
        assert_eq!(bytes("mov eax, 1"), vec![0xb8, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn round_trip_through_the_disassembler() {
        let src = "\
start:
    mov rax, rdi
    add rax, 5
    cmp rax, 0x10
    jne start
    ret";
        let out = asm(src, Arch::X64, 0x401000).expect("assembles");
        // Decode the bytes back and check the mnemonics we put in appear in order.
        let mut dec =
            iced_x86::Decoder::with_ip(64, &out.bytes, 0x401000, iced_x86::DecoderOptions::NONE);
        let mnemonics: Vec<_> = dec
            .iter()
            .map(|i| format!("{:?}", i.mnemonic()).to_lowercase())
            .collect();
        assert_eq!(mnemonics, vec!["mov", "add", "cmp", "jne", "ret"]);
    }

    #[test]
    fn listing_has_addresses_and_bytes() {
        let out = asm("nop\nret", Arch::X64, 0x2000).expect("assembles");
        let code: Vec<_> = out.lines.iter().filter(|l| !l.bytes.is_empty()).collect();
        assert_eq!(code.len(), 2);
        assert_eq!(code[0].address, 0x2000);
        assert_eq!(code[0].bytes, vec![0x90]);
        assert_eq!(code[1].address, 0x2001);
        assert_eq!(code[1].bytes, vec![0xc3]);
    }

    #[test]
    fn unknown_mnemonic_reports_line() {
        let err = asm("nop\n    frobnicate rax", Arch::X64, 0).unwrap_err();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].line, 2);
    }

    /// Assemble, then disassemble each instruction back to Intel text for comparison.
    fn disasm(src: &str) -> Vec<String> {
        let out =
            asm(src, Arch::X64, 0x401000).unwrap_or_else(|e| panic!("assemble failed: {e:?}"));
        let mut dec =
            iced_x86::Decoder::with_ip(64, &out.bytes, 0x401000, iced_x86::DecoderOptions::NONE);
        let mut fmt = iced_x86::IntelFormatter::new();
        let mut text = Vec::new();
        for insn in dec.iter() {
            use iced_x86::Formatter as _;
            let mut s = String::new();
            fmt.format(&insn, &mut s);
            text.push(s);
        }
        text
    }

    #[test]
    fn memory_load_and_store_round_trip() {
        assert_eq!(disasm("mov rax, [rbx]"), vec!["mov rax,[rbx]"]);
        assert_eq!(
            disasm("mov qword ptr [rbx+rcx*4+8], rax"),
            vec!["mov [rbx+rcx*4+8],rax"]
        );
        assert_eq!(disasm("lea rdi, [rsi+16]"), vec!["lea rdi,[rsi+10h]"]);
        assert_eq!(
            disasm("add dword ptr [rbp-4], 1"),
            vec!["add dword ptr [rbp-4],1"]
        );
        assert_eq!(disasm("inc qword ptr [rax]"), vec!["inc qword ptr [rax]"]);
    }

    #[test]
    fn mem_with_immediate_needs_a_size() {
        // Ambiguous without a size prefix — iced reports it, anchored to the line.
        let err = asm("mov [rax], 1", Arch::X64, 0).unwrap_err();
        assert_eq!(err[0].line, 1);
    }

    #[test]
    fn consecutive_and_trailing_labels() {
        // Two labels naming the same position, and a label at the very end of the source.
        let src = "\
a:
b:
    jmp done
    jmp a
    jmp b
done:";
        let out = asm(src, Arch::X64, 0x1000).expect("assembles");
        assert_eq!(
            disasm(src),
            vec![
                "jmp short 0000000000401006h",
                "jmp short 0000000000401000h",
                "jmp short 0000000000401000h",
            ]
        );
        // The trailing label adds no bytes.
        assert_eq!(out.bytes.len(), 6);
        assert_eq!(out.lines.last().unwrap().address, 0x1006);
    }

    #[test]
    fn absolute_branch_targets() {
        assert_eq!(
            disasm("jmp 0x401100\ncall 0x401200\njnz 0x401000"),
            vec![
                "jmp 0000000000401100h",
                "call 0000000000401200h",
                "jne short 0000000000401000h"
            ]
        );
    }

    #[test]
    fn extension_exchange_and_conditional_ops() {
        assert_eq!(
            disasm(
                "movzx eax, byte ptr [rdi]\nmovzx ecx, al\nmovsx rax, word ptr [rsi+2]\n\
                 movsxd rax, ecx\nxchg rax, rbx\nxchg [rdi], eax\ncmovz eax, ecx\n\
                 cmovl rax, qword ptr [rbx]\nsetne al\nsetg byte ptr [rdi]"
            ),
            vec![
                "movzx eax,byte ptr [rdi]",
                "movzx ecx,al",
                "movsx rax,word ptr [rsi+2]",
                "movsxd rax,ecx",
                "xchg rax,rbx",
                "xchg [rdi],eax",
                "cmove eax,ecx",
                "cmovl rax,[rbx]",
                "setne al",
                "setg [rdi]",
            ]
        );
    }

    #[test]
    fn imul_forms_and_shifts_by_cl() {
        assert_eq!(
            disasm(
                "imul rax, rcx\nimul eax, ecx, 10\nimul rdx, [rbx], -3\nshl rax, cl\nsar dword ptr [rdi], cl"
            ),
            vec![
                "imul rax,rcx",
                "imul eax,ecx,0Ah",
                "imul rdx,[rbx],0FFFFFFFFFFFFFFFDh",
                "shl rax,cl",
                "sar dword ptr [rdi],cl",
            ]
        );
        // Only `cl` can hold a shift count.
        assert!(asm("shl rax, bl", Arch::X64, 0).is_err());
    }

    #[test]
    fn rip_relative_operands() {
        // At 0x401000: `lea rax, [rip+0x100]` is 7 bytes, so it addresses 0x401107; the second
        // instruction (also 7 bytes) ends at 0x40100e and reads 0x40100e - 0x10 = 0x400ffe.
        assert_eq!(
            disasm("lea rax, [rip+0x100]\nmov rcx, qword ptr [rip-0x10]\njmp start\nstart:"),
            vec![
                "lea rax,[401107h]",
                "mov rcx,[400FFEh]",
                "jmp short 0000000000401010h"
            ]
        );
        let out = asm("lea rax, [rip+0x100]", Arch::X64, 0x401000).unwrap();
        assert_eq!(out.bytes, vec![0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn mov_r64_uses_the_short_form_when_it_fits() {
        // mov rax, 1 => 48 c7 c0 01 00 00 00 (sign-extended imm32)
        assert_eq!(bytes("mov rax, 1"), vec![0x48, 0xc7, 0xc0, 1, 0, 0, 0]);
        assert_eq!(
            bytes("mov rcx, -1"),
            vec![0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff]
        );
        // Too wide for a sign-extended imm32: movabs.
        assert_eq!(
            bytes("mov rax, 0x80000000"),
            vec![0x48, 0xb8, 0, 0, 0, 0x80, 0, 0, 0, 0]
        );
        assert_eq!(
            bytes("mov rax, 0xffffffff00000000"),
            vec![0x48, 0xb8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn thirty_two_bit_base_is_rejected_clearly() {
        let err = asm("mov rax, [ebx]", Arch::X64, 0).unwrap_err();
        assert_eq!(err[0].line, 1);
        assert!(err[0].message.contains("64-bit"));
    }
}
