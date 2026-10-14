//! Controller tests driven by the mock target, so they run on any platform.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::*;

/// Waits until `f` of the current state is true, or panics after a short timeout.
fn wait_for(dbg: &Debugger, what: &str, f: impl Fn(&DebugState) -> bool) -> DebugState {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let s = dbg.state();
        if f(&s) {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}; status {:?}",
            s.status
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn mock(trace: Vec<u64>, exit: i32, notify: Arc<dyn Fn() + Send + Sync>) -> Debugger {
    Debugger::with_backend(move || Ok(Box::new(MockTarget::new(trace, exit))), notify)
}

#[test]
fn breakpoint_then_registers_then_continue() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });
    let trace = vec![0x1000, 0x1004, 0x1008, 0x100c, 0x1010];
    let dbg = mock(trace, 7, notify);

    dbg.add_breakpoint(0x1008);
    // The mock starts "running"; let it reach the breakpoint.
    dbg.resume();
    let s = wait_for(&dbg, "breakpoint", |s| {
        s.reason == Some(StopReason::Breakpoint(0x1008))
    });
    assert_eq!(s.status, Status::Stopped);
    assert_eq!(s.registers.rip, 0x1008);

    dbg.resume();
    let s = wait_for(&dbg, "exit", |s| s.status == Status::Exited);
    assert_eq!(s.reason, Some(StopReason::Exited(7)));
    assert!(hits.load(Ordering::SeqCst) > 0, "notify was called");
}

#[test]
fn stepping_advances_one_at_a_time() {
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let dbg = mock(vec![0x2000, 0x2004, 0x2008, 0x200c], 0, notify);
    // Consume the initial run so we land stopped somewhere deterministic: set a bp.
    dbg.add_breakpoint(0x2004);
    dbg.resume();
    wait_for(&dbg, "bp", |s| {
        s.reason == Some(StopReason::Breakpoint(0x2004))
    });

    dbg.step();
    let s = wait_for(&dbg, "step", |s| s.reason == Some(StopReason::Step));
    assert_eq!(s.registers.rip, 0x2008);
}

#[test]
fn edit_register_and_memory_while_stopped() {
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let dbg = mock(vec![0x3000, 0x3004, 0x3008], 0, notify);
    dbg.add_breakpoint(0x3004);
    dbg.resume();
    wait_for(&dbg, "bp", |s| s.is_stopped());

    dbg.set_register("rbx", 0xdead_beef);
    wait_for(&dbg, "reg write", |s| s.registers.rbx == 0xdead_beef);

    dbg.write_memory(0x5000, vec![1, 2, 3, 4]);
    dbg.read_memory(0x5000, 4);
    let s = wait_for(&dbg, "mem", |s| s.memory.is_some());
    assert_eq!(s.memory.unwrap().1, vec![1, 2, 3, 4]);
}

#[test]
fn removing_a_breakpoint_lets_it_run_past() {
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let dbg = mock(vec![0x4000, 0x4004, 0x4008, 0x400c], 3, notify);
    dbg.add_breakpoint(0x4008);
    wait_for(&dbg, "bp registered", |s| {
        s.breakpoints.contains_key(&0x4008)
    });
    dbg.remove_breakpoint(0x4008);
    wait_for(&dbg, "bp removed", |s| !s.breakpoints.contains_key(&0x4008));
    dbg.resume();
    let s = wait_for(&dbg, "exit", |s| s.status == Status::Exited);
    assert_eq!(s.reason, Some(StopReason::Exited(3)));
}

#[test]
fn unsupported_backend_reports_cleanly() {
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let dbg = Debugger::with_backend(|| Ok(Box::new(Unsupported("test platform"))), notify);
    let s = wait_for(&dbg, "failure", |s| s.status == Status::Failed);
    assert!(s.last_error.as_deref().unwrap().contains("test platform"));
}

/// A guard so the mutex-poisoning lint stays happy in tests that share state.
#[allow(dead_code)]
fn _assert_state_is_send_sync() {
    fn is_send<T: Send>() {}
    is_send::<Mutex<DebugState>>();
}
