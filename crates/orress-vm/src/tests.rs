use super::*;
use orress_analysis::{Block, Edge, EdgeKind, Function, FunctionKind};

fn block(start: u64, succs: &[u64]) -> Block {
    Block {
        start,
        end: start + 8,
        insns: vec![start],
        succs: succs
            .iter()
            .map(|&t| Edge {
                target: t,
                kind: EdgeKind::Jump,
            })
            .collect(),
    }
}

fn func(entry: u64, blocks: Vec<Block>) -> Function {
    Function {
        entry,
        kind: FunctionKind::Normal,
        blocks,
        calls: Vec::new(),
    }
}

/// A classic interpreter: one dispatcher that `n` handlers each branch back to, plus the dispatcher
/// fanning out to them.
fn vm_like(handlers: usize) -> Function {
    let dispatcher = 0x1000;
    let mut blocks = Vec::new();
    // The dispatcher branches out to every handler.
    let handler_addrs: Vec<u64> = (0..handlers).map(|i| 0x1100 + i as u64 * 0x20).collect();
    blocks.push(block(dispatcher, &handler_addrs));
    // Each handler does its work, then branches back to the dispatcher (a back edge).
    for &h in &handler_addrs {
        blocks.push(block(h, &[dispatcher]));
    }
    func(dispatcher, blocks)
}

#[test]
fn detects_an_interpreter_dispatch_loop() {
    let report = detect(&vm_like(20)).expect("a VM interpreter shape is detected");
    assert_eq!(report.dispatcher, 0x1000);
    assert_eq!(report.handlers, 20);
    assert_eq!(report.max_fan_in, 20); // all 20 handlers branch back
    assert!(report.confidence > 0.7, "confidence {}", report.confidence);
}

#[test]
fn small_functions_are_not_interpreters() {
    // A short linear function: a → b → c (3 blocks).
    let f = func(
        0x400,
        vec![
            block(0x400, &[0x408]),
            block(0x408, &[0x410]),
            block(0x410, &[]),
        ],
    );
    assert!(detect(&f).is_none());
}

#[test]
fn a_big_but_flat_function_is_not_an_interpreter() {
    // 20 blocks in a straight chain: no block has a high fan-in, and no back edge.
    let blocks: Vec<Block> = (0..20)
        .map(|i| block(0x1000 + i * 8, &[0x1000 + (i + 1) * 8]))
        .collect();
    assert!(detect(&func(0x1000, blocks)).is_none());
}

#[test]
fn a_simple_loop_is_not_an_interpreter() {
    // A 15-block function with one back edge but only a small fan-in (a normal loop, not dispatch).
    let mut blocks: Vec<Block> = (0..14)
        .map(|i| block(0x1000 + i * 8, &[0x1000 + (i + 1) * 8]))
        .collect();
    // Last block loops back to the top (fan-in of the head is only 2).
    blocks.push(block(0x1000 + 14 * 8, &[0x1000]));
    assert!(detect(&func(0x1000, blocks)).is_none());
}

#[test]
fn detects_a_split_dispatch_loop() {
    // The real compiled shape: the dispatcher D fans out to 10 handlers, each handler returns to a
    // separate loop header H, and H branches to D. The handlers don't jump to D directly, but they
    // *reach* it through H — so the detector must follow reachability, not just direct back edges.
    let (d, h) = (0x1000, 0x900);
    let handlers: Vec<u64> = (0..10).map(|i| 0x1100 + i * 0x20).collect();
    let mut blocks = vec![block(h, &[d]), block(d, &handlers)];
    for &x in &handlers {
        blocks.push(block(x, &[h]));
    }
    let report = detect(&func(h, blocks)).expect("a split dispatch loop is detected");
    assert_eq!(report.dispatcher, d);
    assert_eq!(report.handlers, 10);
}

#[test]
fn a_one_shot_switch_is_not_an_interpreter() {
    // A high-fan-out block whose cases do NOT loop back (an ordinary switch, not a dispatch loop):
    // the dispatcher fans out to 10 cases that each fall through to a common exit. No looping
    // handlers, so despite the fan-out it must not be flagged.
    let sw = 0x1000;
    let exit = 0x2000;
    let cases: Vec<u64> = (0..10).map(|i| 0x1100 + i * 0x20).collect();
    let mut blocks = vec![block(sw, &cases)];
    for &c in &cases {
        blocks.push(block(c, &[exit]));
    }
    blocks.push(block(exit, &[]));
    assert!(
        detect(&func(sw, blocks)).is_none(),
        "a one-shot switch must not be flagged"
    );
}

#[test]
fn a_sprawling_loop_with_few_handlers_is_not_an_interpreter() {
    // The library-code false positive: a big function (30 blocks) with a high-fan-in latch that 8
    // blocks branch back to, but the other ~21 blocks are a non-handler chain. High fan-in, but the
    // dispatch loop does not dominate the function (handler ratio 8/30 < 0.5), so it is not a VM.
    let latch = 0x1000;
    let mut blocks = vec![block(latch, &[0x1100])];
    // 8 handlers that each return to the latch (fan-in 8, well over MIN_FAN_IN).
    for i in 0..8u64 {
        blocks.push(block(0x1100 + i * 8, &[latch]));
    }
    // A long tail of ordinary blocks that are not handlers (they don't branch to the latch).
    for i in 0..21u64 {
        blocks.push(block(0x2000 + i * 8, &[0x2000 + (i + 1) * 8]));
    }
    let report = detect(&func(latch, blocks));
    assert!(
        report.is_none(),
        "a low-handler-ratio loop must not be flagged, got {report:?}"
    );
}

#[test]
fn more_handlers_means_higher_confidence() {
    // Both are interpreters (≥ MIN_BLOCKS), but the one with more handlers scores higher.
    let strong = detect(&vm_like(20)).expect("strong VM detected");
    let weak = detect(&vm_like(11)).expect("weak VM detected");
    assert!(
        strong.confidence > weak.confidence,
        "{} vs {}",
        strong.confidence,
        weak.confidence
    );
}

/// A blob shorter than the recovered extent (`Memory::read` stops at the region end) must not be
/// indexed past its end: the walk is bounded by the bytes actually read, and an operand run that
/// overhangs the end is clipped.
#[test]
fn bytecode_walk_is_bounded_by_the_blob() {
    let blob = [0x01, 0xaa, 0xbb, 0x02, 0xcc];
    // Opcode 1 takes two operand bytes, opcode 2 claims four (only one is left).
    let size = |op: u8| if op == 1 { 2 } else { 4 };
    let insns = walk_bytecode(&blob, size, |_| "op");
    assert_eq!(insns.len(), 2);
    assert_eq!(insns[0].operands, vec![0xaa, 0xbb]);
    assert_eq!(insns[1].offset, 3);
    assert_eq!(insns[1].operands, vec![0xcc]);
    assert!(walk_bytecode(&[], size, |_| "op").is_empty());
}
