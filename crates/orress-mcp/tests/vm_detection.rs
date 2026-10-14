//! Integration guard: on the bundled crackmes, VM detection is precise (the VM crackme is flagged,
//! the others are not) and jump-table recovery stays bounded (no phantom-block explosion). These
//! run against the real analysis + disassembly, so they catch jump-table over-recovery regressions
//! that unit tests on synthetic CFGs cannot.

fn analyze(name: &str) -> orress_analysis::Program {
    let path = format!(
        "{}/../../academy/crackmes/bin/{}.exe",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let data = std::sync::Arc::new(std::fs::read(&path).expect("read crackme"));
    let analysis = orress_project::Analysis::run(&data);
    orress_analysis::Program::analyze(
        &analysis.info,
        std::sync::Arc::clone(&data),
        &analysis.strings,
    )
    .expect("analyze crackme")
}

#[test]
fn vm_crackme_is_detected_and_others_are_not() {
    assert_eq!(
        orress_vm::scan(&analyze("crackme05")).len(),
        1,
        "the VM crackme should be flagged"
    );
    for name in ["crackme01", "crackme02", "crackme03", "crackme04"] {
        assert!(
            orress_vm::scan(&analyze(name)).is_empty(),
            "{name} is not a VM and must not be flagged (false positive)"
        );
    }
}

#[test]
fn vm_opcode_table_is_recovered() {
    // The first devirtualization step: crackme05's 10-opcode dispatch yields a 10-entry opcode
    // table, and the handlers' recovered operations include the VM's distinctive ops (xor, rotate).
    let p = analyze("crackme05");
    let report = &orress_vm::scan(&p)[0];
    let table = orress_vm::handlers(&p, report);
    assert_eq!(table.len(), 10, "crackme05's VM has 10 opcodes");
    let ops: std::collections::HashSet<&str> = table
        .iter()
        .flat_map(|h| h.ops.iter().map(String::as_str))
        .collect();
    assert!(ops.contains("xor"), "a handler should XOR: {ops:?}");
    assert!(ops.contains("rol"), "a handler should rotate: {ops:?}");
    // The named virtual operations single out the distinctive opcodes (ISA skeleton).
    let named: std::collections::HashSet<&str> = table.iter().map(orress_vm::operation).collect();
    for op in ["xor", "subtract", "rotate", "halt/return", "push"] {
        assert!(
            named.contains(op),
            "opcode table should name a `{op}` op: {named:?}"
        );
    }
}

#[test]
fn vm_bytecode_blob_is_located() {
    // Register dataflow traces the opcode-fetch's base register to the bytecode blob. We verify the
    // right blob by reading its first bytes: crackme05's CODE array begins [8, 8, 0, 0, 1, ...]
    // (LEN 8, PUSHIN 0, ...), independent of where the linker placed it.
    let p = analyze("crackme05");
    let report = &orress_vm::scan(&p)[0];
    let bc = orress_vm::bytecode(&p, report).expect("bytecode blob located");
    let head = p.memory.read(bc.base, 5).expect("blob readable");
    assert_eq!(
        head,
        [8, 8, 0, 0, 1],
        "blob at {:#x} is crackme05's bytecode",
        bc.base
    );
    // The disassembly recovers the exact program: crackme05's is 83 bytes ending in a HALT (op 9).
    let dis = orress_vm::disassemble(&p, report).expect("disassembled");
    let last = dis.last().expect("instructions");
    assert_eq!(
        last.offset + 1 + last.operands.len(),
        83,
        "recovered program length"
    );
    assert_eq!(last.opcode, 9, "the bytecode ends in a HALT opcode");
}

#[test]
fn vm_bytecode_disassembles() {
    // The bytecode disassembles into the per-byte check pattern crackme05 uses:
    // PUSHIN i, PUSHIM k, XOR, ROL n, PUSHIM c, EQ ... x8, then HALT. We verify the recovered
    // operand sizes and operations: the XOR/ROL opcodes land where expected, and it ends in a halt.
    let p = analyze("crackme05");
    let report = &orress_vm::scan(&p)[0];
    let dis = orress_vm::disassemble(&p, report).expect("bytecode disassembled");
    assert!(
        dis.last().is_some_and(|i| i.op == "halt/return"),
        "ends in halt: {dis:?}"
    );
    // The first XOR is at offset 6 with no operand; the first rotate follows with a 1-byte operand.
    let xor = dis
        .iter()
        .find(|i| i.op == "xor")
        .expect("an xor instruction");
    assert!(xor.operands.is_empty(), "xor takes no operand");
    let rot = dis
        .iter()
        .find(|i| i.op == "rotate")
        .expect("a rotate instruction");
    assert_eq!(
        rot.operands.len(),
        1,
        "rotate takes a 1-byte operand (the amount)"
    );
    assert!(
        dis.len() >= 40,
        "the full program decodes: {} instructions",
        dis.len()
    );
}

#[test]
fn second_vm_crackme06_generalises() {
    // A structurally different VM (16-bit stack, 2-byte immediate operand, different opcodes) must
    // flow through the same pipeline — proof the analysis isn't over-fit to crackme05.
    let p = analyze("crackme06");
    let reports = orress_vm::scan(&p);
    assert_eq!(reports.len(), 1, "crackme06's VM is detected");
    let report = &reports[0];

    let named: std::collections::HashSet<&str> = orress_vm::handlers(&p, report)
        .iter()
        .map(orress_vm::operation)
        .collect();
    assert!(
        named.contains("multiply"),
        "its MUL opcode is named: {named:?}"
    );
    assert!(
        named.contains("push") && named.contains("xor"),
        "push/xor recovered: {named:?}"
    );

    orress_vm::bytecode(&p, report).expect("bytecode located despite a reused base register");

    let dis = orress_vm::disassemble(&p, report).expect("disassembled");
    let last = dis.last().expect("instructions");
    assert_eq!(
        last.offset + 1 + last.operands.len(),
        113,
        "recovered program length"
    );
    // PUSHI carries a 2-byte immediate: the operand-size recovery handles a 3-byte instruction.
    assert!(
        dis.iter().any(|i| i.operands.len() == 2),
        "a 2-byte-operand instruction decodes: {dis:?}"
    );
}

#[test]
fn third_vm_crackme07_register_machine_generalises() {
    // A register-based VM (no operand stack, uniform 3-byte instructions) — the hardest shape for
    // the stack-oriented assumptions. The pipeline must still detect it, locate and fully
    // disassemble the bytecode with correct operand sizes, and name its arithmetic opcodes.
    let p = analyze("crackme07");
    let reports = orress_vm::scan(&p);
    assert_eq!(reports.len(), 1, "register VM is detected");
    let report = &reports[0];

    let named: std::collections::HashSet<&str> = orress_vm::handlers(&p, report)
        .iter()
        .map(orress_vm::operation)
        .collect();
    assert!(
        named.contains("rotate") && named.contains("xor"),
        "arith ops named: {named:?}"
    );
    // A register machine has no operand stack, so nothing should be mislabeled "push".
    assert!(
        !named.contains("push"),
        "no spurious push on a register VM: {named:?}"
    );

    let dis = orress_vm::disassemble(&p, report).expect("disassembled");
    let last = dis.last().expect("instructions");
    assert_eq!(
        last.offset + 1 + last.operands.len(),
        99,
        "exact program length (33 x 3 bytes)"
    );
    // Every instruction is 3 bytes: a uniform 2-operand encoding, recovered from the shared advance.
    assert!(
        dis.iter().all(|i| i.operands.len() == 2),
        "uniform 2-operand decode: {dis:?}"
    );
}

#[test]
fn vm_keys_are_recovered_by_concolic_lift() {
    // The devirtualization payoff: symbolically executing each interpreter over its concrete
    // bytecode captures the per-byte constraints and solves a key that passes the real binary.
    // Ground truth: the keys the crackmes were built with. Three structurally-different VMs.
    for (name, key) in [
        ("crackme05", "vm_0wned"),
        ("crackme06", "h4ckv3rs"),
        ("crackme07", "r3g_v4lz"),
        // crackme08 is control-flow-flattened, not a bytecode VM, but its dispatch loop is the same
        // shape, so the concolic engine devirtualizes it the same way.
        ("crackme08", "unfl4tt3"),
    ] {
        let p = analyze(name);
        let report = &orress_vm::scan(&p)[0];
        let sol = orress_vm::solve(&p, report).unwrap_or_else(|| panic!("{name}: no solution"));
        assert!(
            sol.complete,
            "{name}: incomplete solve ({} constraints), got {:?}",
            sol.constraints,
            String::from_utf8_lossy(&sol.key)
        );
        assert_eq!(
            String::from_utf8_lossy(&sol.key),
            key,
            "{name}: recovered key must match the real one"
        );
        // Each byte yields one lifted check mentioning that input byte (the devirtualized logic).
        assert_eq!(
            sol.checks.len(),
            key.len(),
            "{name}: one lifted check per byte"
        );
        for (j, c) in sol.checks.iter().enumerate() {
            assert!(
                c.contains(&format!("in[{j}]")),
                "{name}: check {j} should read in[{j}]: {c}"
            );
            assert!(
                c.contains("=="),
                "{name}: check {j} should be an equality: {c}"
            );
        }
    }
    // crackme05's lifted checks are exactly the per-byte rotate-xor the bytecode encodes.
    let p = analyze("crackme05");
    let sol = orress_vm::solve(&p, &orress_vm::scan(&p)[0]).expect("solved");
    assert_eq!(sol.checks[0], "rol((in[0] ^ 0x3b), 1) == 0x9a");
    assert_eq!(sol.checks[7], "rol((in[7] ^ 0x10), 2) == 0xd1");
}

#[test]
fn jump_table_recovery_stays_bounded() {
    // A runaway offset-table read inflates a function with hundreds of phantom blocks (seen at ~888
    // before the fix). These binaries top out near ~220 blocks; 400 leaves margin while still
    // catching an over-recovery regression.
    for name in ["crackme01", "crackme05"] {
        let program = analyze(name);
        let max_blocks = program
            .functions
            .values()
            .map(|f| f.blocks.len())
            .max()
            .unwrap_or(0);
        assert!(
            max_blocks < 400,
            "{name}: a function has {max_blocks} blocks — jump-table over-recovery?"
        );
    }
}
