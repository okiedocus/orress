//! The x86-64 register set as the debugger reports it, plus plain-language flag meanings
//! so beginners can read the processor state.

/// The general-purpose registers, instruction pointer and flags of a stopped thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// The 16 general-purpose registers in the usual display order, with their names.
pub const GP_NAMES: [&str; 16] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

impl Registers {
    /// The 16 general-purpose registers in display order, paired with their names.
    pub fn gp(&self) -> [(&'static str, u64); 16] {
        [
            ("rax", self.rax),
            ("rbx", self.rbx),
            ("rcx", self.rcx),
            ("rdx", self.rdx),
            ("rsi", self.rsi),
            ("rdi", self.rdi),
            ("rbp", self.rbp),
            ("rsp", self.rsp),
            ("r8", self.r8),
            ("r9", self.r9),
            ("r10", self.r10),
            ("r11", self.r11),
            ("r12", self.r12),
            ("r13", self.r13),
            ("r14", self.r14),
            ("r15", self.r15),
        ]
    }

    /// Reads a general-purpose register by name (lower-case), plus `rip`/`rsp`/`rbp`.
    pub fn get(&self, name: &str) -> Option<u64> {
        Some(match name {
            "rax" => self.rax,
            "rbx" => self.rbx,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rbp" => self.rbp,
            "rsp" => self.rsp,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            "rip" | "pc" => self.rip,
            "rflags" | "eflags" => self.rflags,
            _ => return None,
        })
    }

    /// Writes a general-purpose register by name. Returns false for an unknown name.
    pub fn set(&mut self, name: &str, value: u64) -> bool {
        match name {
            "rax" => self.rax = value,
            "rbx" => self.rbx = value,
            "rcx" => self.rcx = value,
            "rdx" => self.rdx = value,
            "rsi" => self.rsi = value,
            "rdi" => self.rdi = value,
            "rbp" => self.rbp = value,
            "rsp" => self.rsp = value,
            "r8" => self.r8 = value,
            "r9" => self.r9 = value,
            "r10" => self.r10 = value,
            "r11" => self.r11 = value,
            "r12" => self.r12 = value,
            "r13" => self.r13 = value,
            "r14" => self.r14 = value,
            "r15" => self.r15 = value,
            "rip" | "pc" => self.rip = value,
            "rflags" | "eflags" => self.rflags = value,
            _ => return false,
        }
        true
    }
}

/// One CPU status flag with its bit, short name and meaning.
pub struct FlagInfo {
    pub bit: u32,
    pub short: &'static str,
    pub name: &'static str,
    pub meaning: &'static str,
}

/// The status flags ORRESS shows, most useful first.
pub const FLAGS: [FlagInfo; 7] = [
    FlagInfo {
        bit: 0,
        short: "CF",
        name: "Carry",
        meaning: "unsigned overflow or borrow (after a compare: the first value was smaller, unsigned)",
    },
    FlagInfo {
        bit: 6,
        short: "ZF",
        name: "Zero",
        meaning: "the result was zero (after a compare: the two values were equal)",
    },
    FlagInfo {
        bit: 7,
        short: "SF",
        name: "Sign",
        meaning: "the result was negative (its top bit is set)",
    },
    FlagInfo {
        bit: 11,
        short: "OF",
        name: "Overflow",
        meaning: "signed overflow: the result did not fit as a signed number",
    },
    FlagInfo {
        bit: 2,
        short: "PF",
        name: "Parity",
        meaning: "the low byte has an even number of set bits",
    },
    FlagInfo {
        bit: 10,
        short: "DF",
        name: "Direction",
        meaning: "string instructions step backwards when set",
    },
    FlagInfo {
        bit: 8,
        short: "TF",
        name: "Trap",
        meaning: "single-step mode: the CPU traps after each instruction (the debugger uses this to step)",
    },
];

/// Whether a flag bit is set in `rflags`.
pub fn flag_set(rflags: u64, bit: u32) -> bool {
    (rflags >> bit) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_set_roundtrip() {
        let mut r = Registers::default();
        for name in GP_NAMES {
            assert!(r.set(name, 0x1234));
            assert_eq!(r.get(name), Some(0x1234));
        }
        assert!(r.set("rip", 0x4000));
        assert_eq!(r.get("rip"), Some(0x4000));
        assert_eq!(r.get("nope"), None);
        assert!(!r.set("nope", 1));
    }

    #[test]
    fn flags_decode() {
        // ZF (bit 6) and CF (bit 0) set.
        let f = (1 << 6) | 1;
        assert!(flag_set(f, 0));
        assert!(flag_set(f, 6));
        assert!(!flag_set(f, 7));
    }
}
