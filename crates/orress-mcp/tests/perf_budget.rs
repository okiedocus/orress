//! Performance-budget guard for the "open" path. PLAN §16: opening a 50 MB binary with interactive
//! navigation must take < 2 s (full disassembly then runs in the background). Opening is dominated
//! by `triage` (format/sections/imports) over the whole file, so this asserts triage stays linear
//! and fast on a large input.
//!
//! Measured on this dev machine (release): triage of a 50 MB blob ~166 ms, of real 8–13 MB PEs
//! 26–38 ms — a ~12× margin under the 2 s budget. This test runs in a debug build and on arbitrary
//! CI hardware, so its threshold is deliberately generous: its job is to catch an algorithmic
//! regression (an accidental O(n²) or a hang), not to re-measure the exact budget.

use std::time::Instant;

/// A deterministic ~size-byte pseudo-random blob (no `rand` dependency).
fn blob(size: usize) -> Vec<u8> {
    let mut x = 0x1234_5678_9abc_def0u64;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn opening_a_large_binary_is_fast() {
    let data = blob(50 * 1_048_576); // 50 MB — the budget's reference size
    let t = Instant::now();
    let _ = orress_loaders::triage(&data);
    let elapsed = t.elapsed();
    // Generous ceiling for a debug build on slow CI; a linear triage is well under this (hundreds
    // of ms in release, ~1 s in debug), while an O(n²) regression would take minutes.
    assert!(
        elapsed.as_secs_f64() < 5.0,
        "triage of 50 MB took {elapsed:?} — far over budget, likely an algorithmic regression"
    );
}
