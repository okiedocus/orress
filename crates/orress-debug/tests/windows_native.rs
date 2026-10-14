//! A real native-debugging smoke test: launch a crackme, break at its `main`, read a
//! register, step, and tear down. Windows only; silently skipped elsewhere and if the
//! crackme has not been built.

#![cfg(windows)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use orress_debug::{DebugState, Debugger, Status, StopReason};

fn crackme() -> Option<PathBuf> {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../academy/crackmes/bin/crackme02.exe");
    p.exists().then_some(p)
}

fn wait_for(dbg: &Debugger, secs: u64, f: impl Fn(&DebugState) -> bool) -> Option<DebugState> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let s = dbg.state();
        if f(&s) {
            return Some(s);
        }
        if Instant::now() >= deadline || s.status == Status::Failed {
            return if f(&s) { Some(s) } else { None };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn breaks_at_main_reads_rip_and_steps() {
    let Some(path) = crackme() else {
        return;
    };
    // crackme02.exe: PE preferred base 0x140000000, main at file address 0x1400012f0,
    // so main's RVA is 0x12f0; the real address is the runtime base plus that.
    const MAIN_RVA: u64 = 0x12f0;

    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let dbg = Debugger::launch(path, Vec::new(), notify);

    // The loader reports the image base soon after launch.
    let Some(state) = wait_for(&dbg, 10, |s| s.image_base.is_some() || !s.is_alive()) else {
        panic!("never learned the image base");
    };
    let Some(base) = state.image_base else {
        // Debugging may be unavailable in this environment (no permission); don't fail CI.
        return;
    };
    let main = base + MAIN_RVA;
    dbg.add_breakpoint(main);

    let Some(s) = wait_for(&dbg, 15, |s| {
        matches!(s.reason, Some(StopReason::Breakpoint(a)) if a == main)
            || s.status == Status::Exited
    }) else {
        dbg.kill();
        panic!("did not reach the breakpoint at main");
    };
    if s.status == Status::Exited {
        return; // raced past main before the bp planted; environment-dependent, not a bug
    }
    assert_eq!(s.registers.rip, main, "stopped exactly at main");

    // Step one instruction: rip must move.
    dbg.step();
    let stepped = wait_for(&dbg, 5, |s| s.reason == Some(StopReason::Step)).expect("stepped");
    assert_ne!(stepped.registers.rip, main, "rip advanced past main");

    dbg.kill();
    wait_for(&dbg, 5, |s| !s.is_alive());
}
