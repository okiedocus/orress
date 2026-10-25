//! Malware-analysis safety for ORRESS: keep samples defanged at rest, detect whether we are
//! inside a VM, gate execution behind a guard, and launch a sample with an activity log. This is
//! the safe foundation for the dynamic-analysis track; it runs nothing on its own — the caller
//! must pass [`guard`] before [`run`].

pub mod etw;
mod event_log;
pub mod fakenet;
mod guard;
#[cfg(windows)]
mod job;
mod launch;
mod store;
pub mod vbox;
mod vm;

/// Cap *this* process's committed memory (Windows Job Object), best-effort — returns false if the
/// OS refuses or off Windows. Protects the analyzer itself: a malicious sample it only *parses*
/// (never runs) can still provoke a giant allocation from a bogus header, and this makes that fail
/// in-process and abort this process instead of exhausting host RAM.
pub fn limit_self_memory(bytes: usize) -> bool {
    #[cfg(windows)]
    {
        job::limit_current_process_memory(bytes)
    }
    #[cfg(not(windows))]
    {
        let _ = bytes;
        false
    }
}

pub use etw::{ActivityEvent, Category, Monitor};
pub use fakenet::{Config as FakeNetConfig, FakeNet, NetEvent, NetKind};
pub use guard::{Decision, Policy, guard};
pub use launch::{RunEvent, RunLog, run, run_with_pty, run_with_stdin};
pub use store::{defang, load, refang, store};
pub use vm::{VmEvidence, detect, in_vm};
