//! Time-travel debugging (M14): a recorded execution trace you can scrub backward and forward.
//!
//! The emulator is deterministic, so instead of a heavyweight record/replay engine we capture a
//! lightweight per-instruction snapshot of the CPU (registers + flags + the address executed). The
//! UI (or a test) can then jump to any step, watch a register's value evolve, and find exactly
//! where it changed — the core time-travel experience. (Memory rewind is not recorded; it can be
//! reconstructed by deterministic replay from the start, a later extension.)

use crate::cpu::Cpu;
use crate::{EmuError, Stop};

/// One executed instruction: the address it was at, and the CPU state immediately after it ran.
#[derive(Clone, Debug)]
pub struct TraceStep {
    pub addr: u64,
    pub cpu: Cpu,
}

/// A full recorded run, navigable in both directions.
#[derive(Clone, Debug)]
pub struct Trace {
    /// The CPU state before the first instruction (step index "before 0").
    pub initial: Cpu,
    pub steps: Vec<TraceStep>,
    /// Why recording stopped. When `fault` is set this is [`Stop::StepLimit`] (the run neither
    /// reached its stop address nor a breakpoint).
    pub stop: Stop,
    /// The error that ended the run early, if any (memory fault, unsupported instruction, ...).
    /// The steps recorded up to the fault are kept, so the UI can scrub to the faulting point.
    pub fault: Option<EmuError>,
}

impl Trace {
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The address of the instruction executed at step `i`.
    pub fn addr_at(&self, i: usize) -> Option<u64> {
        self.steps.get(i).map(|s| s.addr)
    }

    /// The CPU state after step `i`, or the initial state when `i` is out of range below 0 — call
    /// with `i` in `0..len()`.
    pub fn cpu_at(&self, i: usize) -> &Cpu {
        self.steps.get(i).map_or(&self.initial, |s| &s.cpu)
    }

    /// The general-purpose registers whose value changed at step `i` (vs. the previous state), as
    /// (register index 0..16, new value) — for highlighting in the UI.
    pub fn changed_regs(&self, i: usize) -> Vec<(usize, u64)> {
        let prev = if i == 0 {
            &self.initial
        } else {
            self.cpu_at(i - 1)
        };
        let Some(cur) = self.steps.get(i).map(|s| &s.cpu) else {
            return Vec::new();
        };
        (0..16)
            .filter(|&r| prev.regs[r] != cur.regs[r])
            .map(|r| (r, cur.regs[r]))
            .collect()
    }

    /// The first step at which general-purpose register `reg` (0..16) holds `value`, if any — the
    /// "when did this register become X?" query.
    pub fn first_step_with(&self, reg: usize, value: u64) -> Option<usize> {
        self.steps
            .iter()
            .position(|s| s.cpu.regs.get(reg) == Some(&value))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Abi, Emulator, Stop};

    #[test]
    fn records_a_navigable_trace() {
        let mut emu = Emulator::new();
        // mov eax, 5 ; add eax, 3 ; ret
        emu.map(
            0x1000,
            &[0xB8, 0x05, 0x00, 0x00, 0x00, 0x83, 0xC0, 0x03, 0xC3],
        );
        let t = emu.record_call(0x1000, &[], Abi::SysV, 100).unwrap();

        assert!(
            matches!(t.stop, Stop::Target(_)),
            "function returned to the sentinel"
        );
        assert_eq!(t.len(), 3); // mov, add, ret
        assert_eq!(t.addr_at(0), Some(0x1000));
        assert_eq!(t.addr_at(1), Some(0x1005));
        assert_eq!(t.cpu_at(0).regs[0], 5); // rax after `mov eax, 5`
        assert_eq!(t.cpu_at(1).regs[0], 8); // rax after `add eax, 3`
        // Scrub: the register that changed at step 0 is rax -> 5.
        assert_eq!(t.changed_regs(0), vec![(0, 5)]);
        // "When did rax become 8?" -> step 1.
        assert_eq!(t.first_step_with(0, 8), Some(1));
        assert_eq!(t.fault, None);
    }

    #[test]
    fn a_fault_keeps_the_recorded_steps() {
        let mut emu = Emulator::new();
        // mov eax, 5 ; add eax, 3 ; mov [0], eax (null write faults) ; ret
        emu.map(
            0x1000,
            &[
                0xB8, 0x05, 0x00, 0x00, 0x00, 0x83, 0xC0, 0x03, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00,
                0x00, 0xC3,
            ],
        );
        let t = emu
            .record_call_with_fault(0x1000, &[], Abi::SysV, 100)
            .unwrap();
        assert_eq!(t.fault, Some(crate::EmuError::Fault(0)));
        assert_eq!(t.len(), 2, "the two steps before the fault survive");
        assert_eq!(t.cpu_at(1).regs[0], 8);
        // The legacy API still reports the fault as an error.
        let mut emu2 = Emulator::new();
        emu2.map(0x1000, &[0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xC3]);
        assert_eq!(
            emu2.record_call(0x1000, &[], Abi::SysV, 100).unwrap_err(),
            crate::EmuError::Fault(0)
        );
    }
}
