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

pub use etw::{ActivityEvent, Category, Monitor};
pub use fakenet::{Config as FakeNetConfig, FakeNet, NetEvent, NetKind};
pub use guard::{Decision, Policy, guard};
pub use launch::{RunEvent, RunLog, run};
pub use store::{defang, load, refang, store};
pub use vm::{VmEvidence, detect, in_vm};
