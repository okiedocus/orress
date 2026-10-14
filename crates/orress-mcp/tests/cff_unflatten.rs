//! End-to-end guard for control-flow-flattening unflattening. crackme08 is a real rustc-compiled
//! binary whose password check is control-flow-flattened (a `match state` dispatch loop). This
//! decompiles it and verifies the decompiler recovers the original straight-line check — i.e. the
//! unflattening pass fires on genuine compiler output, not just hand-built IR.

use std::sync::Arc;

fn analyze(name: &str) -> orress_analysis::Program {
    let path = format!(
        "{}/../../academy/crackmes/bin/{}.exe",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let data = Arc::new(std::fs::read(&path).expect("read crackme"));
    let a = orress_project::Analysis::run(&data);
    orress_analysis::Program::analyze(&a.info, Arc::clone(&data), &a.strings).expect("analyze")
}

#[test]
fn crackme08_control_flow_flattening_is_undone() {
    let p = analyze("crackme08");
    let conv = orress_decompiler::convention(orress_loaders::Format::Pe);

    let mut noted = Vec::new();
    for f in p.functions.values() {
        // The flattened check is ~36 blocks; skip the large std/runtime functions for speed.
        if f.blocks.len() > 80 {
            continue;
        }
        let Ok(out) = orress_decompiler::decompile(&p, f.entry, conv) else {
            continue;
        };
        let text = out.text();
        if text.contains("deobfuscated by ORRESS: control-flow flattening") {
            noted.push((f.entry, text));
        }
    }

    assert!(
        !noted.is_empty(),
        "unflattening should fire on crackme08's control-flow-flattened check"
    );
    // The recovered function must read as a real check (the dispatcher and its `match` are gone,
    // replaced by straight-line control flow that returns true/false).
    let (entry, text) = &noted[0];
    assert!(
        text.contains("return true") && text.contains("return false"),
        "the unflattened function at {entry:#x} should be a recovered check:\n{text}"
    );
    assert!(
        !text.contains("match "),
        "the dispatcher's match should be gone after unflattening:\n{text}"
    );
}
