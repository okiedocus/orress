use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind,
    Instruction, InstructionInfoFactory, IntelFormatter, Mnemonic, OpAccess, OpKind, Register,
};

use crate::{Flow, Insn, MemRef, Reg, RegInfo, Token, TokenKind};

/// Maps an iced register to a stable 0..16 general-purpose index (by its full 64-bit register),
/// or `None` for non-GP registers (xmm, flags, rip, segment, ...).
fn gp(r: Register) -> Option<Reg> {
    use Register::*;
    Some(match r.full_register() {
        RAX => 0,
        RCX => 1,
        RDX => 2,
        RBX => 3,
        RSP => 4,
        RBP => 5,
        RSI => 6,
        RDI => 7,
        R8 => 8,
        R9 => 9,
        R10 => 10,
        R11 => 11,
        R12 => 12,
        R13 => 13,
        R14 => 14,
        R15 => 15,
        _ => return Option::None,
    })
}

fn is_imm(ins: &Instruction, op: u32) -> bool {
    matches!(
        ins.op_kind(op),
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn push_unique(v: &mut Vec<Reg>, r: Reg) {
    if !v.contains(&r) {
        v.push(r);
    }
}

pub fn reg_info(bitness: u32, bytes: &[u8], address: u64) -> Option<RegInfo> {
    if bytes.is_empty() {
        return None;
    }
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let ins = decoder.decode();
    if ins.is_invalid() {
        return None;
    }
    let mut info = RegInfo::default();
    let mut factory = InstructionInfoFactory::new();
    for ur in factory.info(&ins).used_registers() {
        let Some(r) = gp(ur.register()) else { continue };
        match ur.access() {
            OpAccess::Read | OpAccess::CondRead => push_unique(&mut info.uses, r),
            OpAccess::Write | OpAccess::CondWrite => push_unique(&mut info.defs, r),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                push_unique(&mut info.uses, r);
                push_unique(&mut info.defs, r);
            }
            _ => {}
        }
    }
    if ins.mnemonic() == Mnemonic::Cmp
        && let Some(reg) = gp(ins.op0_register())
        && matches!(
            ins.op1_kind(),
            OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        )
    {
        info.cmp_imm = Some((reg, ins.immediate(1)));
    }
    // A constant delta applied to a register in place (how a handler advances a counter).
    let imm1 = || ins.immediate(1) as i64;
    info.delta = match ins.mnemonic() {
        Mnemonic::Add => gp(ins.op0_register())
            .filter(|_| is_imm(&ins, 1))
            .map(|r| (r, imm1())),
        Mnemonic::Sub => gp(ins.op0_register())
            .filter(|_| is_imm(&ins, 1))
            .map(|r| (r, -imm1())),
        Mnemonic::Inc => gp(ins.op0_register()).map(|r| (r, 1)),
        Mnemonic::Dec => gp(ins.op0_register()).map(|r| (r, -1)),
        // `lea reg, [reg+disp]` with no index is an in-place add of `disp`.
        Mnemonic::Lea
            if gp(ins.op0_register()) == gp(ins.memory_base())
                && ins.memory_index() == Register::None
                && !ins.is_ip_rel_memory_operand() =>
        {
            gp(ins.op0_register()).map(|r| (r, ins.memory_displacement64() as i64))
        }
        _ => None,
    };

    if ins.mnemonic() == Mnemonic::Lea {
        // `lea` computes an address; it is not a memory access, and when rip-relative it loads a
        // constant address into its destination register.
        if ins.is_ip_rel_memory_operand()
            && let Some(dest) = gp(ins.op0_register())
        {
            info.lea_const = Some((dest, ins.ip_rel_memory_address()));
        }
    } else if let Some(mem_op) = (0..ins.op_count()).find(|&i| ins.op_kind(i) == OpKind::Memory) {
        info.mem = Some(MemRef {
            base: gp(ins.memory_base()),
            index: gp(ins.memory_index()),
            size: ins.memory_size().size() as u8,
            // The memory operand is a pure store only when it is the written destination (op0 of a
            // write); otherwise it is read.
            is_load: mem_op != 0 || ins.op_count() == 1,
        });
    }
    Some(info)
}

struct Output {
    tokens: Vec<Token>,
}

impl FormatterOutput for Output {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let kind = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Prefix => TokenKind::Mnemonic,
            FormatterTextKind::Register => TokenKind::Register,
            FormatterTextKind::Number => TokenKind::Number,
            FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => {
                match parse_hex(text) {
                    Some(v) => TokenKind::Address(v),
                    None => TokenKind::Number,
                }
            }
            FormatterTextKind::Keyword | FormatterTextKind::Directive => TokenKind::Keyword,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => TokenKind::Punct,
            _ => TokenKind::Text,
        };
        self.tokens.push(Token {
            kind,
            text: text.to_owned(),
        });
    }
}

fn parse_hex(text: &str) -> Option<u64> {
    let t = text.trim_start_matches("0x");
    u64::from_str_radix(t, 16).ok()
}

fn formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_space_after_operand_separator(false);
    // `false` shows `[0x140003000]` instead of `[rip+0x2000]`: the absolute address is
    // what you look up and what a name can replace.
    o.set_rip_relative_addresses(false);
    o.set_branch_leading_zeros(false);
    o.set_show_branch_size(false);
    f
}

thread_local! {
    static FORMATTER: std::cell::RefCell<IntelFormatter> = std::cell::RefCell::new(formatter());
}

pub fn decode(bitness: u32, bytes: &[u8], address: u64) -> Option<Insn> {
    if bytes.is_empty() {
        return None;
    }
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let ins: Instruction = decoder.decode();
    if ins.is_invalid() {
        return None;
    }

    // Absolute address of the memory operand, when it can be known statically.
    let mem_addr = memory_address(&ins, bitness);

    let flow = match ins.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Next,
        FlowControl::UnconditionalBranch => Flow::Jump(ins.near_branch_target()),
        FlowControl::ConditionalBranch => Flow::CondJump(ins.near_branch_target()),
        FlowControl::Call => Flow::Call(ins.near_branch_target()),
        FlowControl::IndirectBranch => Flow::IndirectJump {
            slot: mem_addr,
            table: jump_table(&ins),
        },
        FlowControl::IndirectCall => Flow::IndirectCall { slot: mem_addr },
        FlowControl::Return => Flow::Return,
        FlowControl::Interrupt => match ins.mnemonic() {
            // `int 0x80` / syscall continue after the kernel returns.
            Mnemonic::Int | Mnemonic::Into => Flow::Next,
            _ => Flow::Stop,
        },
        FlowControl::Exception => Flow::Stop,
    };
    // syscall/sysenter and the hypervisor calls are `FlowControl::Call` in iced, but they
    // return to the next instruction and have no near target: plain fall-through.
    let flow = match ins.mnemonic() {
        Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Vmcall | Mnemonic::Vmmcall => Flow::Next,
        _ => flow,
    };
    // Far branches have no near target; treat them as stops.
    let flow = match flow {
        Flow::Jump(0) | Flow::Call(0) if ins.near_branch_target() == 0 && !is_near_branch(&ins) => {
            Flow::Stop
        }
        other => other,
    };

    let mut data_refs = Vec::new();
    if let Some(a) = mem_addr
        && !matches!(flow, Flow::IndirectJump { .. } | Flow::IndirectCall { .. })
    {
        data_refs.push(a);
    }
    for i in 0..ins.op_count() {
        let value = match ins.op_kind(i) {
            OpKind::Immediate32 => u64::from(ins.immediate32()),
            OpKind::Immediate64 => ins.immediate64(),
            OpKind::Immediate32to64 => ins.immediate32to64() as u64,
            _ => continue,
        };
        // Small constants are counters and flags, not addresses.
        if value >= 0x1_0000 {
            data_refs.push(value);
        }
    }

    let mut out = Output { tokens: Vec::new() };
    FORMATTER.with(|f| f.borrow_mut().format(&ins, &mut out));
    let mut tokens = out.tokens.into_iter().peekable();
    let mut mnemonic = String::new();
    while let Some(t) = tokens.peek() {
        if t.kind == TokenKind::Mnemonic
            || (t.kind == TokenKind::Text && t.text.trim().is_empty() && mnemonic.is_empty())
        {
            let t = tokens.next().expect("peeked");
            if t.kind == TokenKind::Mnemonic {
                if !mnemonic.is_empty() {
                    mnemonic.push(' ');
                }
                mnemonic.push_str(&t.text);
            }
        } else if t.kind == TokenKind::Text && t.text.trim().is_empty() {
            tokens.next();
            break;
        } else {
            break;
        }
    }
    // Memory operands shown with an absolute address become clickable addresses too.
    let operands = tokens
        .map(|mut t| {
            if t.kind == TokenKind::Number
                && let Some(v) = parse_hex(&t.text)
                && (Some(v) == mem_addr || data_refs.contains(&v))
            {
                t.kind = TokenKind::Address(v);
            }
            t
        })
        .collect();

    Some(Insn {
        address,
        len: ins.len() as u8,
        mnemonic,
        operands,
        flow,
        data_refs,
    })
}

fn is_near_branch(ins: &Instruction) -> bool {
    matches!(
        ins.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

/// A statically-addressable jump table `[base + index*entry]` (no base register, a scaled
/// index, and a 4- or 8-byte entry) — the non-PIE `switch` form. PIE tables add the loaded
/// value to a runtime base, so they stay unresolved.
fn jump_table(ins: &Instruction) -> Option<crate::JumpTable> {
    if ins.memory_base() != Register::None || ins.memory_index() == Register::None {
        return None;
    }
    let entry = ins.memory_index_scale();
    if !matches!(entry, 4 | 8) {
        return None;
    }
    Some(crate::JumpTable {
        base: ins.memory_displacement64(),
        entry: entry as u8,
    })
}

fn memory_address(ins: &Instruction, bitness: u32) -> Option<u64> {
    let has_mem = (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory);
    if !has_mem {
        return None;
    }
    if ins.is_ip_rel_memory_operand() {
        return Some(ins.ip_rel_memory_address());
    }
    // `[disp32]` with no base or index register: an absolute address (32-bit code).
    if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
        let disp = ins.memory_displacement64();
        if bitness == 32 {
            return Some(disp & 0xffff_ffff);
        }
        return Some(disp);
    }
    None
}
