//! Instruction decoding behind one interface, for every supported architecture.
//!
//! [`decode`] returns an [`Insn`]: its length, its text as colored tokens, how it
//! affects control flow (needed to build control-flow graphs) and which addresses it
//! refers to (needed for cross-references). [`explain`] has plain-language
//! explanations of mnemonics and registers for Explain Mode.

mod arm64;
pub mod explain;
mod mips;
pub mod patch;
mod ppc;
mod riscv;
mod x86;

/// Instruction set architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Isa {
    X86,
    X64,
    Arm64,
    /// RISC-V 64-bit (RV64I + M; compressed instructions are length-aware).
    Riscv64,
    /// MIPS32, big-endian (the classic byte order).
    Mips32,
    /// MIPS32, little-endian (`mipsel`).
    Mips32El,
    /// MIPS64, big-endian.
    Mips64,
    /// MIPS64, little-endian.
    Mips64El,
    /// PowerPC, 32-bit, big-endian (the classic byte order).
    Ppc32,
    /// PowerPC, 64-bit, big-endian (ELFv1).
    Ppc64,
    /// PowerPC, 64-bit, little-endian (`ppc64le`, ELFv2).
    Ppc64El,
}

impl Isa {
    /// Picks the ISA from the loader's architecture name and byte order. `little` selects the
    /// little-endian variant where an ISA has both (MIPS).
    pub fn from_arch_name(arch: &str, little: bool) -> Option<Self> {
        match arch {
            "x86 (32-bit)" => Some(Self::X86),
            "x86-64" | "x86-64 (x32 ABI)" => Some(Self::X64),
            "ARM64 (AArch64)" => Some(Self::Arm64),
            "RISC-V (64-bit)" => Some(Self::Riscv64),
            "MIPS (32-bit)" => Some(if little { Self::Mips32El } else { Self::Mips32 }),
            "MIPS64" => Some(if little { Self::Mips64El } else { Self::Mips64 }),
            "PowerPC (32-bit)" => Some(Self::Ppc32),
            "PowerPC64" => Some(if little { Self::Ppc64El } else { Self::Ppc64 }),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x86-64",
            Self::Arm64 => "ARM64",
            Self::Riscv64 => "RISC-V (64-bit)",
            Self::Mips32 | Self::Mips32El => "MIPS (32-bit)",
            Self::Mips64 | Self::Mips64El => "MIPS64",
            Self::Ppc32 => "PowerPC (32-bit)",
            Self::Ppc64 | Self::Ppc64El => "PowerPC64",
        }
    }

    /// Longest possible instruction, for reading enough bytes.
    pub fn max_len(self) -> usize {
        match self {
            Self::X86 | Self::X64 => 15,
            Self::Arm64
            | Self::Riscv64
            | Self::Mips32
            | Self::Mips32El
            | Self::Mips64
            | Self::Mips64El
            | Self::Ppc32
            | Self::Ppc64
            | Self::Ppc64El => 4,
        }
    }

    pub fn pointer_size(self) -> u64 {
        match self {
            Self::X86 | Self::Mips32 | Self::Mips32El | Self::Ppc32 => 4,
            Self::X64
            | Self::Arm64
            | Self::Riscv64
            | Self::Mips64
            | Self::Mips64El
            | Self::Ppc64
            | Self::Ppc64El => 8,
        }
    }

    /// Whether a control-flow instruction has a *delay slot*: the next instruction executes
    /// before the transfer takes effect. True for MIPS, so the CFG keeps the delay slot in the
    /// branch's block (it runs on both the taken and not-taken paths).
    pub fn has_delay_slots(self) -> bool {
        matches!(
            self,
            Self::Mips32 | Self::Mips32El | Self::Mips64 | Self::Mips64El
        )
    }
}

/// A statically-addressable jump table `[base + index*entry]`: `base` is the absolute address
/// of slot 0 and `entry` is the entry size in bytes (4 or 8). Used to recover `switch`/`match`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JumpTable {
    pub base: u64,
    pub entry: u8,
}

/// How an instruction affects the flow of execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Continues with the next instruction.
    Next,
    /// Always jumps to the target.
    Jump(u64),
    /// Jumps to the target if a condition holds, otherwise continues.
    CondJump(u64),
    /// Calls a function and continues after it returns.
    Call(u64),
    /// Jumps to a computed address. `slot` is the memory slot read, if known
    /// (e.g. `jmp [rip+0x2000]`, used by PLT stubs and import thunks). `table` describes a
    /// statically-addressable jump table `[base + index*entry]`, for switch recovery.
    IndirectJump {
        slot: Option<u64>,
        table: Option<JumpTable>,
    },
    /// Calls a computed address, e.g. `call [IsDebuggerPresent]` through the IAT.
    IndirectCall {
        slot: Option<u64>,
    },
    Return,
    /// Stops execution here (int3, hlt, ud2, brk ...).
    Stop,
}

impl Flow {
    /// Whether execution can continue with the next instruction.
    pub fn falls_through(self) -> bool {
        matches!(
            self,
            Self::Next | Self::CondJump(_) | Self::Call(_) | Self::IndirectCall { .. }
        )
    }

    /// Whether this instruction ends a basic block.
    pub fn ends_block(self) -> bool {
        !matches!(self, Self::Next | Self::Call(_) | Self::IndirectCall { .. })
    }
}

/// What a piece of instruction text is, for coloring and interaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Mnemonic,
    Register,
    Number,
    /// A number that is an address in the program; the UI may show a name instead and
    /// makes it clickable.
    Address(u64),
    Keyword,
    Punct,
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    pub address: u64,
    pub len: u8,
    pub mnemonic: String,
    /// Operand text as tokens (without the mnemonic).
    pub operands: Vec<Token>,
    pub flow: Flow,
    /// Addresses this instruction refers to as data (memory operands, address-like
    /// immediates, ADRP/ADR results).
    pub data_refs: Vec<u64>,
}

impl Insn {
    pub fn text(&self) -> String {
        let ops: String = self.operands.iter().map(|t| t.text.as_str()).collect();
        if ops.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {ops}", self.mnemonic)
        }
    }

    pub fn end(&self) -> u64 {
        self.address + u64::from(self.len)
    }

    /// Code target of a direct jump or call.
    pub fn branch_target(&self) -> Option<u64> {
        match self.flow {
            Flow::Jump(t) | Flow::CondJump(t) | Flow::Call(t) => Some(t),
            _ => None,
        }
    }
}

/// Decodes one instruction at `address` from `bytes`. `None` for invalid encodings or
/// too few bytes.
pub fn decode(isa: Isa, bytes: &[u8], address: u64) -> Option<Insn> {
    match isa {
        Isa::X86 => x86::decode(32, bytes, address),
        Isa::X64 => x86::decode(64, bytes, address),
        Isa::Arm64 => arm64::decode(bytes, address),
        Isa::Riscv64 => riscv::decode(bytes, address),
        Isa::Mips32 => mips::decode(bytes, address, true, false),
        Isa::Mips32El => mips::decode(bytes, address, false, false),
        Isa::Mips64 => mips::decode(bytes, address, true, true),
        Isa::Mips64El => mips::decode(bytes, address, false, true),
        Isa::Ppc32 => ppc::decode(bytes, address, false, false),
        Isa::Ppc64 => ppc::decode(bytes, address, false, true),
        Isa::Ppc64El => ppc::decode(bytes, address, true, true),
    }
}

/// A general-purpose register, numbered 0..16 in a stable order (the 64-bit register that a
/// narrower access belongs to). Only the ordering's consistency matters to analyses.
pub type Reg = u8;

/// The memory operand of an instruction, reduced to the registers that form its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRef {
    pub base: Option<Reg>,
    pub index: Option<Reg>,
    /// Access size in bytes.
    pub size: u8,
    /// The memory operand is read (a load) rather than only written.
    pub is_load: bool,
}

/// Structured register effects of one instruction, for register dataflow analysis — which GP
/// registers it writes and reads, any memory operand's address registers, and whether it is a
/// `lea reg, [rip+addr]` that loads a constant address. Only general-purpose registers are tracked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegInfo {
    pub defs: Vec<Reg>,
    pub uses: Vec<Reg>,
    pub mem: Option<MemRef>,
    /// `(dest, addr)` when the instruction is `lea dest, [rip+addr]`.
    pub lea_const: Option<(Reg, u64)>,
    /// `(reg, imm)` when the instruction is `cmp reg, imm` — the register compared against a
    /// constant, e.g. the loop bound a virtual program counter is checked against.
    pub cmp_imm: Option<(Reg, u64)>,
    /// `(reg, delta)` when the instruction adds a constant to a register in place: `add`/`sub`/
    /// `inc`/`dec reg, imm`, or `lea reg, [reg+disp]`. Used to measure how far a handler advances a
    /// virtual program counter.
    pub delta: Option<(Reg, i64)>,
}

/// Register effects of the instruction at `address`. `None` for invalid encodings, or for an ISA
/// whose register model is not yet extracted (currently only x86/x86-64).
pub fn reg_info(isa: Isa, bytes: &[u8], address: u64) -> Option<RegInfo> {
    match isa {
        Isa::X86 => x86::reg_info(32, bytes, address),
        Isa::X64 => x86::reg_info(64, bytes, address),
        Isa::Arm64
        | Isa::Riscv64
        | Isa::Mips32
        | Isa::Mips32El
        | Isa::Mips64
        | Isa::Mips64El
        | Isa::Ppc32
        | Isa::Ppc64
        | Isa::Ppc64El => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(isa: Isa, bytes: &[u8], addr: u64) -> Insn {
        decode(isa, bytes, addr).expect("valid instruction")
    }

    #[test]
    fn x64_basics() {
        let i = d(Isa::X64, &[0x48, 0x83, 0xec, 0x28], 0x1000);
        assert_eq!(i.text(), "sub rsp,0x28");
        assert_eq!(i.len, 4);
        assert_eq!(i.flow, Flow::Next);
        assert_eq!(i.operands[0].kind, TokenKind::Register);

        // call rel32 to 0x1000 + 5 + 0x10
        let call = d(Isa::X64, &[0xe8, 0x10, 0, 0, 0], 0x1000);
        assert_eq!(call.flow, Flow::Call(0x1015));
        assert!(
            call.operands
                .iter()
                .any(|t| t.kind == TokenKind::Address(0x1015))
        );

        // jz short +2
        let jz = d(Isa::X64, &[0x74, 0x02], 0x2000);
        assert_eq!(jz.flow, Flow::CondJump(0x2004));
        assert!(jz.flow.falls_through() && jz.flow.ends_block());

        assert_eq!(d(Isa::X64, &[0xc3], 0).flow, Flow::Return);
        assert_eq!(d(Isa::X64, &[0xcc], 0).flow, Flow::Stop);
    }

    #[test]
    fn x64_rip_relative_refs() {
        // lea rcx, [rip+0x100] at 0x1000 (7 bytes) -> 0x1107
        let lea = d(Isa::X64, &[0x48, 0x8d, 0x0d, 0x00, 0x01, 0, 0], 0x1000);
        assert_eq!(lea.data_refs, vec![0x1107]);
        assert!(
            lea.operands
                .iter()
                .any(|t| t.kind == TokenKind::Address(0x1107))
        );
        // call [rip+0x2000] at 0x1000 (6 bytes): an import call through a slot
        let call = d(Isa::X64, &[0xff, 0x15, 0x00, 0x20, 0, 0], 0x1000);
        assert_eq!(call.flow, Flow::IndirectCall { slot: Some(0x3006) });
        // jmp [rip+0x10]: a PLT/thunk-style indirect jump
        let jmp = d(Isa::X64, &[0xff, 0x25, 0x10, 0, 0, 0], 0x1000);
        assert_eq!(
            jmp.flow,
            Flow::IndirectJump {
                slot: Some(0x1016),
                table: None
            }
        );
    }

    #[test]
    fn x86_32_absolute_memory() {
        // call dword ptr [0x402000]
        let call = d(Isa::X86, &[0xff, 0x15, 0x00, 0x20, 0x40, 0x00], 0x401000);
        assert_eq!(
            call.flow,
            Flow::IndirectCall {
                slot: Some(0x402000)
            }
        );
        // push 0x403000 (a string address, typically)
        let push = d(Isa::X86, &[0x68, 0x00, 0x30, 0x40, 0x00], 0x401000);
        assert_eq!(push.data_refs, vec![0x403000]);
    }

    #[test]
    fn invalid_is_none() {
        // `push es` does not exist in 64-bit mode.
        assert!(decode(Isa::X64, &[0x06], 0).is_none());
        assert_eq!(decode(Isa::X86, &[0x06], 0).unwrap().mnemonic, "push");
        assert!(decode(Isa::X64, &[], 0).is_none());
        assert!(decode(Isa::Arm64, &[0, 0], 0).is_none());
    }

    #[test]
    fn arm64_branches() {
        // bl #+0x100  (0x94000040)
        let bl = d(Isa::Arm64, &0x9400_0040u32.to_le_bytes(), 0x1000);
        assert_eq!(bl.flow, Flow::Call(0x1100));
        // ret (0xd65f03c0)
        assert_eq!(
            d(Isa::Arm64, &0xd65f_03c0u32.to_le_bytes(), 0).flow,
            Flow::Return
        );
        // b.eq #+0x8 (0x54000040)
        let beq = d(Isa::Arm64, &0x5400_0040u32.to_le_bytes(), 0x2000);
        assert_eq!(beq.flow, Flow::CondJump(0x2008));
        // cbz x0, #+0x10 (0xb4000080)
        let cbz = d(Isa::Arm64, &0xb400_0080u32.to_le_bytes(), 0x3000);
        assert_eq!(cbz.flow, Flow::CondJump(0x3010));
        // b #-0x4 (0x17ffffff)
        let b = d(Isa::Arm64, &0x17ff_ffffu32.to_le_bytes(), 0x4000);
        assert_eq!(b.flow, Flow::Jump(0x3ffc));
        // adrp x0, page +1 (0x90000000 | immlo/immhi for 1 page = 0xb0000000)
        let adrp = d(Isa::Arm64, &0xb000_0000u32.to_le_bytes(), 0x4123);
        assert_eq!(adrp.data_refs, vec![0x5000]);
    }

    #[test]
    fn x64_syscall_falls_through() {
        // syscall, vmcall, sysenter (32-bit): the kernel/hypervisor returns to the next insn.
        assert_eq!(d(Isa::X64, &[0x0f, 0x05], 0x1000).flow, Flow::Next);
        assert_eq!(d(Isa::X64, &[0x0f, 0x01, 0xc1], 0x1000).flow, Flow::Next);
        assert_eq!(d(Isa::X64, &[0x0f, 0x01, 0xd9], 0x1000).flow, Flow::Next);
        assert_eq!(d(Isa::X86, &[0x0f, 0x34], 0x1000).flow, Flow::Next);
        // A real far call still stops.
        assert_eq!(
            d(Isa::X86, &[0x9a, 0, 0, 0, 0, 0x08, 0], 0x1000).flow,
            Flow::Stop
        );
    }

    #[test]
    fn arm64_pac_branches() {
        let flow = |w: u32| d(Isa::Arm64, &w.to_le_bytes(), 0x1000).flow;
        let ij = Flow::IndirectJump {
            slot: None,
            table: None,
        };
        let ic = Flow::IndirectCall { slot: None };
        assert_eq!(flow(0xd65f_0bff), Flow::Return); // retaa
        assert_eq!(flow(0xd65f_0fff), Flow::Return); // retab
        assert_eq!(flow(0xd69f_0bff), Flow::Return); // eretaa
        assert_eq!(flow(0xd69f_0fff), Flow::Return); // eretab
        assert_eq!(flow(0xd61f_081f), ij); // braaz x0
        assert_eq!(flow(0xd61f_0c1f), ij); // brabz x0
        assert_eq!(flow(0xd71f_0c01), ij); // brab x0, x1
        assert_eq!(flow(0xd63f_081f), ic); // blraaz x0
        assert_eq!(flow(0xd63f_0c1f), ic); // blrabz x0
        assert_eq!(flow(0xd73f_0c01), ic); // blrab x0, x1
        assert_eq!(flow(0x0000_0000), Flow::Stop); // udf #0
    }
}
