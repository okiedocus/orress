//! The CPU state: 16 general-purpose registers (iced-x86 encoding order), the instruction
//! pointer, and the arithmetic flags. Register reads/writes respect sub-register widths and
//! the x86-64 rule that a 32-bit write zeroes the upper 32 bits.

use iced_x86::Register;

/// The six arithmetic flags an integer emulator needs.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Flags {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

impl Flags {
    /// Packs into the low bits of RFLAGS (bit 1 is the reserved, always-1 bit).
    pub fn to_rflags(self) -> u64 {
        let mut v = 0b10u64;
        v |= u64::from(self.cf);
        v |= u64::from(self.pf) << 2;
        v |= u64::from(self.af) << 4;
        v |= u64::from(self.zf) << 6;
        v |= u64::from(self.sf) << 7;
        v |= u64::from(self.of) << 11;
        v
    }
}

/// x86-64 integer register file plus RIP and flags.
#[derive(Clone, Debug, Default)]
pub struct Cpu {
    /// Indexed in iced-x86 order: rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15.
    pub regs: [u64; 16],
    pub rip: u64,
    pub flags: Flags,
    /// The FS segment base (SysV thread pointer: `fs:[0x28]` is the stack canary).
    pub fs_base: u64,
    /// The GS segment base (Win64 TEB: `gs:[0x30]` is the TEB self-pointer, `gs:[0x60]` the PEB).
    pub gs_base: u64,
}

/// The 64-bit container index (0..16) for a general-purpose register, or `None` for a
/// non-GPR (segment, xmm, rip, ...).
fn gpr_index(full: Register) -> Option<usize> {
    use Register::*;
    Some(match full {
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
        // `use Register::*` brings `Register::None` into scope, so qualify the Option here.
        _ => return Option::None,
    })
}

/// The four legacy high-byte registers (bits 8..16 of their container).
fn is_high_byte(reg: Register) -> bool {
    matches!(
        reg,
        Register::AH | Register::CH | Register::DH | Register::BH
    )
}

impl Cpu {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a register, honouring its width (and the AH/CH/DH/BH high-byte regs).
    pub fn reg(&self, r: Register) -> u64 {
        if r == Register::RIP || r == Register::EIP {
            return self.rip;
        }
        let Some(idx) = gpr_index(r.full_register()) else {
            return 0;
        };
        let v = self.regs[idx];
        if is_high_byte(r) {
            return (v >> 8) & 0xff;
        }
        match r.size() {
            1 => v & 0xff,
            2 => v & 0xffff,
            4 => v & 0xffff_ffff,
            _ => v,
        }
    }

    /// Writes a register, honouring width rules (32-bit writes zero the upper 32 bits).
    pub fn set_reg(&mut self, r: Register, val: u64) {
        if r == Register::RIP || r == Register::EIP {
            self.rip = val;
            return;
        }
        let Some(idx) = gpr_index(r.full_register()) else {
            return;
        };
        let cur = self.regs[idx];
        self.regs[idx] = if is_high_byte(r) {
            (cur & !0xff00) | ((val & 0xff) << 8)
        } else {
            match r.size() {
                1 => (cur & !0xff) | (val & 0xff),
                2 => (cur & !0xffff) | (val & 0xffff),
                4 => val & 0xffff_ffff, // zero-extend to 64
                _ => val,
            }
        };
    }

    // Named accessors for the registers the harness touches directly.
    pub fn rsp(&self) -> u64 {
        self.regs[4]
    }
    pub fn set_rsp(&mut self, v: u64) {
        self.regs[4] = v;
    }
    pub fn rax(&self) -> u64 {
        self.regs[0]
    }
}
