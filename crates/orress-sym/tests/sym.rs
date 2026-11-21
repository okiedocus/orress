//! End-to-end symbolic solving: assemble an xor-and-compare check, run it symbolically, and
//! recover the input that passes — without ever running a correct input concretely.

use iced_x86::code_asm::*;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use orress_emu::Memory;
use orress_sym::{expr, solve, solve_check};

const BASE: u64 = 0x1000;
const TARGET_ADDR: u64 = 0x8000;
const INPUT: u64 = 0x9000;
const KEY: u32 = 0x5a;

/// Builds `check(ptr) { for i in 0..len { if (ptr[i]^KEY) != target[i] return 0 } return 1 }`.
fn build(len: i32) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut loop_l = a.create_label();
    let mut pass_l = a.create_label();
    let mut fail_l = a.create_label();
    a.xor(ecx, ecx).unwrap();
    a.set_label(&mut loop_l).unwrap();
    a.cmp(rcx, len).unwrap();
    a.jae(pass_l).unwrap();
    a.movzx(eax, byte_ptr(rdi + rcx)).unwrap();
    a.xor(al, KEY as i32).unwrap();
    a.mov(r8, TARGET_ADDR).unwrap();
    a.movzx(edx, byte_ptr(r8 + rcx)).unwrap();
    a.cmp(al, dl).unwrap();
    a.jne(fail_l).unwrap();
    a.inc(rcx).unwrap();
    a.jmp(loop_l).unwrap();
    a.set_label(&mut pass_l).unwrap();
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail_l).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    a.assemble(BASE).unwrap()
}

/// The address the `jne` branches to (the fail block) — the block to avoid.
fn fail_addr(code: &[u8]) -> u64 {
    let mut dec = Decoder::with_ip(64, code, BASE, DecoderOptions::NONE);
    while dec.can_decode() {
        let insn = dec.decode();
        if insn.mnemonic() == Mnemonic::Jne {
            return insn.near_branch_target();
        }
    }
    panic!("no jne found");
}

#[test]
fn recovers_xor_check_input() {
    let target = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
    let code = build(target.len() as i32);
    let fail = fail_addr(&code);

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.write_bytes(TARGET_ADDR, &target);

    let found = solve_check(
        mem,
        BASE,
        &[INPUT],
        INPUT,
        target.len() as u32,
        0,
        vec![fail],
        Default::default(),
        orress_sym::Abi::SysV,
    )
    .unwrap();
    assert!(
        found.result.complete,
        "solve incomplete: {}",
        found.result.message
    );
    // Each recovered byte must be target[i] ^ KEY.
    let expected: Vec<u8> = target.iter().map(|&t| t ^ KEY as u8).collect();
    assert_eq!(found.result.input, expected);
    assert_eq!(found.constraints, target.len());
}

/// Input read *internally* via a hooked `gets` (not passed as an argument): the `ReadInput` stub
/// must redirect the symbolic input region onto the buffer the call fills, so the subsequent
/// per-byte check becomes constraints and the key is recovered. The `input_base` we pass is a
/// decoy the hook must override.
#[test]
fn recovers_input_read_via_hooked_gets() {
    use orress_emu::{Abi, InputReturn, Stub};
    let target = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
    let buf = 0x9000u64; // the gets destination buffer
    let decoy = 0xd000u64; // the input_base we pass; the hook must override it to `buf`
    let len = target.len() as i32;

    let mut a = CodeAssembler::new(64).unwrap();
    let mut loop_l = a.create_label();
    let mut pass_l = a.create_label();
    let mut fail_l = a.create_label();
    // gets(buf) — Win64 arg0 is rcx; the hook symbolizes [buf, buf+len).
    a.mov(rcx, buf).unwrap();
    a.call(qword_ptr(SLOT)).unwrap();
    // for i in 0..len { if (buf[i] ^ KEY) != target[i] return 0 }
    a.xor(ecx, ecx).unwrap();
    a.set_label(&mut loop_l).unwrap();
    a.cmp(rcx, len).unwrap();
    a.jae(pass_l).unwrap();
    a.mov(rdi, buf).unwrap();
    a.movzx(eax, byte_ptr(rdi + rcx)).unwrap();
    a.xor(al, KEY as i32).unwrap();
    a.mov(r8, TARGET_ADDR).unwrap();
    a.movzx(edx, byte_ptr(r8 + rcx)).unwrap();
    a.cmp(al, dl).unwrap();
    a.jne(fail_l).unwrap();
    a.inc(rcx).unwrap();
    a.jmp(loop_l).unwrap();
    a.set_label(&mut pass_l).unwrap();
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail_l).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    let code = a.assemble(BASE).unwrap();
    let fail = fail_addr(&code);

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.write_bytes(TARGET_ADDR, &target);
    mem.map_zeroed(buf, 64);
    mem.write_bytes(SLOT, &0u64.to_le_bytes());

    let hooks = [(SLOT, Stub::ReadInput { buf_arg: 0, fmt_arg: None, ret: InputReturn::Buffer })]
        .into_iter()
        .collect();
    let found = orress_sym::solve_check_return(
        mem,
        BASE,
        &[],
        decoy,
        len as u32,
        vec![fail],
        hooks,
        Abi::Win64,
    )
    .unwrap();
    assert!(found.result.complete, "incomplete: {}", found.result.message);
    let expected: Vec<u8> = target.iter().map(|&t| t ^ KEY as u8).collect();
    assert_eq!(found.result.input, expected, "key read via gets must be recovered");
}

/// A check with a **symbolic-length `strlen` loop** whose loop-back is the *taken* edge, so the
/// single-path steerer exits it on the first byte and never discovers the accepting path. The
/// path explorer forks the loop and finds it. Shape:
///   gets(buf); i=0; while buf[i]!=0 { i++ }      // strlen, loop-back taken
///   if i < 3 return;                              // length gate
///   if buf[0..3] != "abc" return;                 // per-byte check
///   success:                                      // the target block
#[test]
fn path_explorer_solves_a_symbolic_length_loop() {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use orress_emu::{Abi, InputReturn, Stub};
    let buf = 0x9000u64;
    let mut a = CodeAssembler::new(64).unwrap();
    let mut top = a.create_label();
    let mut done = a.create_label();
    let mut fail = a.create_label();
    a.mov(rcx, buf).unwrap();
    a.call(qword_ptr(SLOT)).unwrap(); // gets(buf) → symbolize [buf, buf+len)
    a.mov(rsi, buf).unwrap();
    a.xor(edx, edx).unwrap(); // i = 0
    a.set_label(&mut top).unwrap();
    a.movzx(eax, byte_ptr(rsi + rdx)).unwrap();
    a.inc(rdx).unwrap();
    a.test(eax, eax).unwrap();
    a.jne(top).unwrap(); // continue while buf[i] != 0  (taken edge = loop-back)
    a.set_label(&mut done).unwrap();
    a.dec(rdx).unwrap(); // rdx = strlen
    a.cmp(rdx, 3).unwrap();
    a.jb(fail).unwrap(); // length < 3 → reject
    a.movzx(eax, byte_ptr(rsi)).unwrap();
    a.cmp(eax, b'a' as i32).unwrap();
    a.jne(fail).unwrap();
    a.movzx(eax, byte_ptr(rsi + 1u64)).unwrap();
    a.cmp(eax, b'b' as i32).unwrap();
    a.jne(fail).unwrap();
    a.movzx(eax, byte_ptr(rsi + 2u64)).unwrap();
    a.cmp(eax, b'c' as i32).unwrap();
    a.jne(fail).unwrap(); // success falls through here
    a.nop().unwrap(); // the success/target block
    a.ret().unwrap();
    a.set_label(&mut fail).unwrap();
    a.ret().unwrap();
    let code = a.assemble(BASE).unwrap();

    // The success block is the fall-through of the last `jne` (the nop).
    let mut dec = Decoder::with_ip(64, &code, BASE, DecoderOptions::NONE);
    let mut last_jne_end = 0u64;
    while dec.can_decode() {
        let insn = dec.decode();
        if insn.mnemonic() == Mnemonic::Jne {
            last_jne_end = insn.next_ip();
        }
    }
    let success = last_jne_end;

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.map_zeroed(buf, 64);
    mem.write_bytes(SLOT, &0u64.to_le_bytes());
    let hooks: std::collections::HashMap<u64, Stub> =
        [(SLOT, Stub::ReadInput { buf_arg: 0, fmt_arg: None, ret: InputReturn::Buffer })].into_iter().collect();

    // Single-path steerer exits the strlen loop immediately → can't reach success.
    let single = orress_sym::solve_check(
        mem.clone(), BASE, &[], 0xd000, 4, success, vec![], hooks.clone(), Abi::Win64,
    )
    .unwrap();
    assert!(!single.result.complete || &single.result.input[..3] != b"abc",
        "single-path should NOT solve the symbolic-length loop (got {:?})", single.result.input);

    // Path explorer forks the loop and finds "abc".
    let found = orress_sym::solve_check_explore(
        mem, BASE, &[], 0xd000, 4, success, vec![], hooks, Abi::Win64, 4000, 2_000_000,
    )
    .expect("explorer should find an accepting path");
    assert!(found.result.complete, "explorer solve incomplete: {}", found.result.message);
    assert_eq!(&found.result.input[..3], b"abc", "explorer must recover the key prefix");
}

/// Return-verdict path exploration: a `check() -> bool` that reads its input internally (hooked
/// `gets`) and has a symbolic-length `strlen` loop before a per-byte test. The single-path return
/// solver exits the loop immediately and can't solve it; the return-model explorer forks the loop
/// and recovers the key — with no printed success string to steer at.
#[test]
fn return_model_explorer_solves_internal_read_with_loop() {
    use iced_x86::code_asm::*;
    use orress_emu::{Abi, InputReturn, Stub};
    let buf = 0x9000u64;
    let mut a = CodeAssembler::new(64).unwrap();
    let mut top = a.create_label();
    let mut fail = a.create_label();
    a.mov(rcx, buf).unwrap();
    a.call(qword_ptr(SLOT)).unwrap(); // gets(buf)
    a.mov(rsi, buf).unwrap();
    a.xor(edx, edx).unwrap();
    a.set_label(&mut top).unwrap();
    a.movzx(eax, byte_ptr(rsi + rdx)).unwrap();
    a.inc(rdx).unwrap();
    a.test(eax, eax).unwrap();
    a.jne(top).unwrap(); // continue while buf[i] != 0 (loop-back is the taken edge)
    a.dec(rdx).unwrap(); // rdx = strlen
    a.cmp(rdx, 3).unwrap();
    a.jb(fail).unwrap();
    a.movzx(eax, byte_ptr(rsi)).unwrap();
    a.cmp(eax, b'a' as i32).unwrap();
    a.jne(fail).unwrap();
    a.movzx(eax, byte_ptr(rsi + 1u64)).unwrap();
    a.cmp(eax, b'b' as i32).unwrap();
    a.jne(fail).unwrap();
    a.movzx(eax, byte_ptr(rsi + 2u64)).unwrap();
    a.cmp(eax, b'c' as i32).unwrap();
    a.jne(fail).unwrap();
    a.mov(eax, 1).unwrap(); // return true
    a.ret().unwrap();
    a.set_label(&mut fail).unwrap();
    a.xor(eax, eax).unwrap(); // return false
    a.ret().unwrap();
    let code = a.assemble(BASE).unwrap();

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.map_zeroed(buf, 64);
    mem.write_bytes(SLOT, &0u64.to_le_bytes());
    let hooks: std::collections::HashMap<u64, Stub> =
        [(SLOT, Stub::ReadInput { buf_arg: 0, fmt_arg: None, ret: InputReturn::Buffer })].into_iter().collect();

    // Single-path return solver exits the strlen loop on the first byte → cannot solve.
    let single = orress_sym::solve_check_return(
        mem.clone(), BASE, &[], 0xd000, 4, vec![], hooks.clone(), Abi::Win64,
    );
    let single_ok = single
        .map(|f| f.result.complete && f.result.input.get(..3) == Some(b"abc"))
        .unwrap_or(false);
    assert!(!single_ok, "single-path must not solve the symbolic-length loop");

    // The return-model explorer forks the loop and recovers "abc".
    let found = orress_sym::solve_check_return_explore(
        mem, BASE, &[], 0xd000, 4, vec![], hooks, Abi::Win64, 4000, 2_000_000,
    )
    .expect("return-model explorer should find an accepting path");
    assert!(found.result.complete, "incomplete: {}", found.result.message);
    assert_eq!(&found.result.input[..3], b"abc", "must recover the key prefix");
}

/// A **32-bit cdecl** per-byte check: the input pointer arrives on the stack (`[esp+4]`), not in a
/// register, and the stack slots are 4 bytes wide. Exercises the pointer-size parameterization and
/// cdecl stack-argument reading.
#[test]
fn recovers_a_32bit_cdecl_check() {
    use iced_x86::code_asm::*;
    use orress_emu::Abi;
    let target = [0x11u8, 0x22, 0x33, 0x44];
    let len = target.len();

    let mut a = CodeAssembler::new(32).unwrap();
    let mut loop_l = a.create_label();
    let mut pass_l = a.create_label();
    let mut fail_l = a.create_label();
    a.mov(ecx, dword_ptr(esp + 4)).unwrap(); // s = arg0 (cdecl: on the stack)
    a.xor(edx, edx).unwrap(); // i = 0
    a.set_label(&mut loop_l).unwrap();
    a.cmp(edx, len as i32).unwrap();
    a.jae(pass_l).unwrap();
    a.movzx(eax, byte_ptr(ecx + edx)).unwrap();
    a.xor(al, KEY as i32).unwrap();
    a.mov(esi, TARGET_ADDR as u32).unwrap();
    a.movzx(ebx, byte_ptr(esi + edx)).unwrap();
    a.cmp(al, bl).unwrap();
    a.jne(fail_l).unwrap();
    a.inc(edx).unwrap();
    a.jmp(loop_l).unwrap();
    a.set_label(&mut pass_l).unwrap();
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail_l).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    let code = a.assemble(BASE).unwrap();

    // 32-bit decode to find the `jne fail` target (the shared fail_addr uses a 64-bit decoder).
    let mut dec = Decoder::with_ip(32, &code, BASE, DecoderOptions::NONE);
    let mut fail = 0u64;
    while dec.can_decode() {
        let insn = dec.decode();
        if insn.mnemonic() == Mnemonic::Jne {
            fail = insn.near_branch_target();
        }
    }

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.write_bytes(TARGET_ADDR, &target);
    mem.map_zeroed(INPUT, 64);

    let found = orress_sym::solve_check_return(
        mem,
        BASE,
        &[INPUT],
        INPUT,
        len as u32,
        vec![fail],
        Default::default(),
        Abi::Cdecl,
    )
    .unwrap();
    assert!(found.result.complete, "incomplete: {}", found.result.message);
    let expected: Vec<u8> = target.iter().map(|&t| t ^ KEY as u8).collect();
    assert_eq!(found.result.input, expected, "32-bit cdecl key must be recovered");
}

/// `check(ptr) { for i { if rol(ptr[i]^KEY, 3) != target[i] return 0 } return 1 }` — the kind of
/// per-byte transform a bytecode VM performs. Exercises symbolic `rol`.
fn build_rol(len: i32) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut loop_l = a.create_label();
    let mut pass_l = a.create_label();
    let mut fail_l = a.create_label();
    a.xor(ecx, ecx).unwrap();
    a.set_label(&mut loop_l).unwrap();
    a.cmp(rcx, len).unwrap();
    a.jae(pass_l).unwrap();
    a.movzx(eax, byte_ptr(rdi + rcx)).unwrap();
    a.xor(al, KEY as i32).unwrap();
    a.rol(al, 3u32).unwrap();
    a.mov(r8, TARGET_ADDR).unwrap();
    a.movzx(edx, byte_ptr(r8 + rcx)).unwrap();
    a.cmp(al, dl).unwrap();
    a.jne(fail_l).unwrap();
    a.inc(rcx).unwrap();
    a.jmp(loop_l).unwrap();
    a.set_label(&mut pass_l).unwrap();
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail_l).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    a.assemble(BASE).unwrap()
}

#[test]
fn recovers_xor_rol_check_input() {
    use orress_emu::{Abi, Emulator};
    let target = [0x9au8, 0x4e, 0x2c, 0x76, 0x09];
    let code = build_rol(target.len() as i32);
    let fail = fail_addr(&code);

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.write_bytes(TARGET_ADDR, &target);
    let found = solve_check(
        mem,
        BASE,
        &[INPUT],
        INPUT,
        target.len() as u32,
        0,
        vec![fail],
        Default::default(),
        Abi::SysV,
    )
    .unwrap();
    assert!(
        found.result.complete,
        "solve incomplete: {}",
        found.result.message
    );
    assert_eq!(found.constraints, target.len());

    // The recovered input must make the real (rol-using) check return 1 concretely.
    let mut emu = Emulator::new();
    emu.map(BASE, &code);
    emu.map(TARGET_ADDR, &target);
    emu.map(INPUT, &found.result.input);
    assert_eq!(
        emu.call(BASE, &[INPUT], Abi::SysV).unwrap(),
        1,
        "rol solution must pass"
    );
}

#[test]
fn solved_input_actually_passes_in_the_emulator() {
    use orress_emu::{Abi, Emulator};
    let target = [0x41u8, 0x42, 0x43, 0x44];
    let code = build(target.len() as i32);
    let fail = fail_addr(&code);

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.write_bytes(TARGET_ADDR, &target);
    let found = solve_check(
        mem,
        BASE,
        &[INPUT],
        INPUT,
        target.len() as u32,
        0,
        vec![fail],
        Default::default(),
        orress_sym::Abi::SysV,
    )
    .unwrap();
    assert!(found.result.complete);

    // Concretely confirm the recovered input makes the real check return 1.
    let mut emu = Emulator::new();
    emu.map(BASE, &code);
    emu.map(TARGET_ADDR, &target);
    emu.map(INPUT, &found.result.input);
    assert_eq!(emu.call(BASE, &[INPUT], Abi::SysV).unwrap(), 1);
}

#[test]
fn recovers_memcmp_check_input() {
    // check(ptr) { return memcmp(ptr, target, len) == 0 }  — memcmp is a symbolic stub.
    const MEMCMP: u64 = 0xa000;
    let target = b"passw0rd";
    let mut a = CodeAssembler::new(64).unwrap();
    let mut fail_l = a.create_label();
    a.mov(rsi, TARGET_ADDR).unwrap();
    a.mov(edx, target.len() as i32).unwrap();
    a.call(MEMCMP).unwrap();
    a.test(eax, eax).unwrap();
    a.jne(fail_l).unwrap();
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail_l).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    let code = a.assemble(BASE).unwrap();
    let fail = fail_addr(&code);

    let mut mem = Memory::new();
    mem.write_bytes(BASE, &code);
    mem.write_bytes(TARGET_ADDR, target);

    let mut hooks = std::collections::HashMap::new();
    hooks.insert(MEMCMP, orress_emu::Stub::Memcmp);
    let found = solve_check(
        mem,
        BASE,
        &[INPUT],
        INPUT,
        target.len() as u32,
        0,
        vec![fail],
        hooks,
        orress_sym::Abi::SysV,
    )
    .unwrap();
    assert!(
        found.result.complete,
        "incomplete: {}",
        found.result.message
    );
    assert_eq!(found.result.input, target);
}

#[test]
fn solver_handles_coupled_bytes() {
    // b0 + b1 == 0x90 and b0 == 0x30  →  b0=0x30, b1=0x60.
    let c0 = expr::rel(expr::Rel::Eq, expr::var(0), expr::konst(0x30, 8));
    let sum = expr::bin(expr::Op::Add, expr::var(0), expr::var(1));
    let c1 = expr::rel(expr::Rel::Eq, sum, expr::konst(0x90, 8));
    let r = solve(&[c0, c1], 2);
    assert!(r.complete, "{}", r.message);
    assert_eq!(r.input, vec![0x30, 0x60]);
}

#[test]
fn exports_smt2() {
    let c = expr::rel(
        expr::Rel::Eq,
        expr::bin(expr::Op::Xor, expr::var(0), expr::konst(0x5a, 8)),
        expr::konst(0x11, 8),
    );
    let smt = expr::to_smt2(&[c], 1);
    assert!(smt.contains("declare-const b0 (_ BitVec 8)"));
    assert!(smt.contains("bvxor"));
    assert!(smt.contains("check-sat"));
}

#[test]
fn simplify_preserves_value() {
    // The display simplifier must be value-preserving. Differential-test it against eval over the
    // whole single-byte input space on the noisy width-juggling the executor emits and on a rotate.
    use orress_sym::expr::{self, Op};
    let x = expr::var(0);
    let noisy = expr::extract(
        expr::zext(
            expr::bin(Op::Xor, expr::zext(x.clone(), 32), expr::konst(0x3b, 32)),
            64,
        ),
        7,
        0,
    );
    let core = expr::bin(Op::Xor, x.clone(), expr::konst(0x3b, 8));
    let rol = expr::bin(
        Op::Or,
        expr::bin(Op::Shl, core.clone(), expr::konst(1, 8)),
        expr::bin(Op::Lshr, core, expr::konst(7, 8)),
    );
    for e in [&noisy, &rol] {
        let s = expr::simplify(e);
        for b in 0u16..=255 {
            assert_eq!(
                e.eval(&[b as u8]),
                s.eval(&[b as u8]),
                "simplify changed value at {b}"
            );
        }
    }
}

#[test]
fn renders_lifted_check_readably() {
    // The payoff: the captured constraint renders as the readable per-byte check, rotate and all.
    use orress_sym::expr::{self, Op, Rel};
    let x = expr::var(0);
    let core = expr::bin(Op::Xor, x, expr::konst(0x3b, 8));
    let rol = expr::bin(
        Op::Or,
        expr::bin(Op::Shl, core.clone(), expr::konst(1, 8)),
        expr::bin(Op::Lshr, core, expr::konst(7, 8)),
    );
    let check = expr::rel(Rel::Eq, rol, expr::konst(0x9a, 8));
    assert_eq!(
        expr::render(&expr::simplify(&check)),
        "rol((in[0] ^ 0x3b), 1) == 0x9a"
    );
}

// --- audit regression tests (flags, unmodelled instructions, stubs, memory) ----

use orress_sym::{SymError, SymExec};

/// Assembles `body` (which reads the input byte at [rdi] and sets flags) followed by `jcc fail`,
/// a pass block (`mov eax, 1; ret`) and the fail block (`xor eax, eax; ret`, the last 3 bytes).
fn flag_check(
    body: impl FnOnce(&mut CodeAssembler),
    jcc: impl FnOnce(&mut CodeAssembler, CodeLabel),
) -> (Vec<u8>, u64) {
    let mut a = CodeAssembler::new(64).unwrap();
    let fail_l = a.create_label();
    body(&mut a);
    jcc(&mut a, fail_l);
    finish(a, fail_l)
}

/// Appends the pass block and the fail block (the last 3 bytes) and assembles.
fn finish(mut a: CodeAssembler, mut fail_l: CodeLabel) -> (Vec<u8>, u64) {
    a.mov(eax, 1).unwrap();
    a.ret().unwrap();
    a.set_label(&mut fail_l).unwrap();
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();
    let code = a.assemble(BASE).unwrap();
    let fail = BASE + code.len() as u64 - 3;
    (code, fail)
}

/// Runs a check symbolically (input at INPUT, `len` bytes), returning the executor.
fn run_sym(
    code: &[u8],
    fail: u64,
    len: u32,
    hooks: std::collections::HashMap<u64, orress_emu::Stub>,
    abi: orress_emu::Abi,
    extra: impl FnOnce(&mut Memory),
) -> Result<SymExec, SymError> {
    let mut mem = Memory::new();
    mem.write_bytes(BASE, code);
    extra(&mut mem);
    let mut sx = SymExec::new(mem, INPUT, len, 0, vec![fail]);
    sx.set_hooks(hooks);
    sx.run_check(BASE, &[INPUT, u64::from(len)], abi)?;
    Ok(sx)
}

/// Runs the check symbolically over a 1-byte input, then compares the captured constraints with
/// the concrete emulator for every byte value: the constraints must hold exactly for the inputs
/// that really pass. (Before, CF/OF after add/inc/dec/shl were constants, L/G ignored OF, and
/// O/P were always false.)
fn assert_exact(name: &str, (code, fail): (Vec<u8>, u64)) {
    use orress_emu::{Abi, Emulator};
    let sym = run_sym(&code, fail, 1, Default::default(), Abi::SysV, |_| {});
    let mut emu = Emulator::new();
    emu.map(BASE, &code);
    for b in 0u16..=255 {
        let b = b as u8;
        emu.map(INPUT, &[b, 0]);
        let passes = emu.call(BASE, &[INPUT, 1], Abi::SysV).unwrap() == 1;
        let predicted = match &sym {
            Ok(sx) => sx.constraints.iter().all(|c| c.eval(&[b]) != 0),
            // Execution was forced into the avoided block: nothing passes.
            Err(SymError::HitAvoid(_)) => false,
            Err(e) => panic!("{name}: symbolic run failed: {e}"),
        };
        assert_eq!(predicted, passes, "{name}: input byte {b:#04x}");
    }
}

#[test]
fn branch_conditions_match_the_cpu_exactly() {
    let load = |a: &mut CodeAssembler| a.movzx(eax, byte_ptr(rdi)).unwrap();
    assert_exact(
        "add/jb",
        flag_check(
            |a| {
                load(a);
                a.add(al, 0xf0u32 as i32).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
    );
    assert_exact(
        "add/jl",
        flag_check(
            |a| {
                load(a);
                a.add(al, 0x40).unwrap();
            },
            |a, l| a.jl(l).unwrap(),
        ),
    );
    assert_exact(
        "add/jo",
        flag_check(
            |a| {
                load(a);
                a.add(al, 0x40).unwrap();
            },
            |a, l| a.jo(l).unwrap(),
        ),
    );
    assert_exact(
        "add/ja",
        flag_check(
            |a| {
                load(a);
                a.add(al, 0x30).unwrap();
            },
            |a, l| a.ja(l).unwrap(),
        ),
    );
    assert_exact(
        "xor/jp",
        flag_check(
            |a| {
                load(a);
                a.xor(al, 0x5a).unwrap();
            },
            |a, l| a.jp(l).unwrap(),
        ),
    );
    assert_exact(
        "cmp/jo",
        flag_check(
            |a| {
                load(a);
                a.cmp(al, 0x30).unwrap();
            },
            |a, l| a.jo(l).unwrap(),
        ),
    );
    assert_exact(
        "cmp/jnp",
        flag_check(
            |a| {
                load(a);
                a.cmp(al, 0x30).unwrap();
            },
            |a, l| a.jnp(l).unwrap(),
        ),
    );
    assert_exact(
        "inc/jle",
        flag_check(
            |a| {
                load(a);
                a.inc(al).unwrap();
            },
            |a, l| a.jle(l).unwrap(),
        ),
    );
    assert_exact(
        "dec/jo",
        flag_check(
            |a| {
                load(a);
                a.dec(al).unwrap();
            },
            |a, l| a.jo(l).unwrap(),
        ),
    );
    // INC preserves the carry from the preceding CMP.
    assert_exact(
        "cmp+inc/jb",
        flag_check(
            |a| {
                load(a);
                a.cmp(al, 0x50).unwrap();
                a.inc(ecx).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
    );
    assert_exact(
        "neg/jb",
        flag_check(
            |a| {
                load(a);
                a.neg(al).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
    );
    assert_exact(
        "shl1/jb",
        flag_check(
            |a| {
                load(a);
                a.shl(al, 1).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
    );
    assert_exact(
        "shl1/jo",
        flag_check(
            |a| {
                load(a);
                a.shl(al, 1).unwrap();
            },
            |a, l| a.jo(l).unwrap(),
        ),
    );
    assert_exact(
        "shr3/jb",
        flag_check(
            |a| {
                load(a);
                a.shr(al, 3).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
    );
    // A shift by (masked) zero leaves the CMP's flags in place.
    assert_exact(
        "cmp+shl0/jb",
        flag_check(
            |a| {
                load(a);
                a.mov(ecx, 0x20).unwrap(); // masks to 0 for a 32-bit shift
                a.cmp(al, 0x50).unwrap();
                a.shl(edx, cl).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
    );
}

/// A branch on flags the executor doesn't know is an error, not a guess: on entry (no flag
/// setter yet), after an unmodelled flag writer (`bt`), and on OF after a multi-bit shift.
#[test]
fn unknown_flags_are_an_error() {
    use orress_emu::Abi;
    let cases = [
        flag_check(
            |a| a.movzx(eax, byte_ptr(rdi)).unwrap(),
            |a, l| a.je(l).unwrap(),
        ),
        flag_check(
            |a| {
                a.movzx(eax, byte_ptr(rdi)).unwrap();
                a.cmp(al, 0x41).unwrap();
                a.bt(eax, 0).unwrap();
            },
            |a, l| a.jb(l).unwrap(),
        ),
        flag_check(
            |a| {
                a.movzx(eax, byte_ptr(rdi)).unwrap();
                a.shl(al, 3).unwrap();
            },
            |a, l| a.jo(l).unwrap(),
        ),
    ];
    for (i, (code, fail)) in cases.into_iter().enumerate() {
        let r = run_sym(&code, fail, 1, Default::default(), Abi::SysV, |_| {});
        assert!(
            matches!(r, Err(SymError::Unsupported { .. })),
            "case {i}: {:?}",
            r.err()
        );
    }
}

/// Unmodelled instructions that write a register conditionally (`cmovcc`) or read symbolic input
/// (`movdqu xmm0, [input]`) must stop the run instead of being skipped.
#[test]
fn unmodelled_instructions_touching_symbolic_data_bail() {
    use orress_emu::Abi;
    let cmov = flag_check(
        |a| {
            a.movzx(eax, byte_ptr(rdi)).unwrap();
            a.mov(ecx, 0x41).unwrap();
            a.cmp(al, cl).unwrap();
            a.cmove(rax, rcx).unwrap();
            a.cmp(al, 0x41).unwrap();
        },
        |a, l| a.jne(l).unwrap(),
    );
    // An unmodelled SSE instruction that reads symbolic memory still bails (movdqu/pcmpeqb/pmovmskb
    // are modelled now, but a packed-float op is not).
    let addps = flag_check(
        |a| {
            a.addps(xmm0, xmmword_ptr(rdi)).unwrap();
            a.movzx(eax, byte_ptr(rdi)).unwrap();
            a.cmp(al, 0x41).unwrap();
        },
        |a, l| a.jne(l).unwrap(),
    );
    for (name, (code, fail)) in [("cmove", cmov), ("addps", addps)] {
        let r = run_sym(&code, fail, 16, Default::default(), Abi::SysV, |_| {});
        assert!(
            matches!(r, Err(SymError::Unsupported { .. })),
            "{name}: {:?}",
            r.err()
        );
    }
    // A concrete-only SSE read (constant data) is modelled and adds no constraint of its own.
    let ok = flag_check(
        |a| {
            a.mov(rax, TARGET_ADDR).unwrap();
            a.movdqu(xmm0, xmmword_ptr(rax)).unwrap();
            a.movzx(eax, byte_ptr(rdi)).unwrap();
            a.cmp(al, 0x41).unwrap();
        },
        |a, l| a.jne(l).unwrap(),
    );
    let sx = run_sym(&ok.0, ok.1, 1, Default::default(), Abi::SysV, |m| {
        m.write_bytes(TARGET_ADDR, &[0u8; 16]);
    })
    .unwrap();
    assert_eq!(sx.constraints.len(), 1);
}

/// Reading unmapped memory is a fault, not a silent 0 that fabricates a constraint.
#[test]
fn unmapped_reads_fault() {
    use orress_emu::Abi;
    let (code, fail) = flag_check(
        |a| {
            a.mov(rax, 0x7777_0000u64).unwrap();
            a.movzx(ecx, byte_ptr(rax)).unwrap();
            a.movzx(eax, byte_ptr(rdi)).unwrap();
            a.cmp(al, cl).unwrap();
        },
        |a, l| a.jne(l).unwrap(),
    );
    let r = run_sym(&code, fail, 1, Default::default(), Abi::SysV, |_| {});
    assert_eq!(r.err(), Some(SymError::Fault(0x7777_0000)));
}

/// `fs:[0x28]` reads the canary from the mapped thread block, so a stack-protector prologue /
/// epilogue pair works (and doesn't fault).
#[test]
fn stack_canary_reads_work() {
    use orress_emu::Abi;
    let (code, fail) = flag_check(
        |a| {
            a.db(&[0x64, 0x48, 0x8B, 0x0C, 0x25, 0x28, 0, 0, 0])
                .unwrap(); // mov rcx, fs:[0x28]
            a.db(&[0x64, 0x48, 0x33, 0x0C, 0x25, 0x28, 0, 0, 0])
                .unwrap(); // xor rcx, fs:[0x28]
            a.test(rcx, rcx).unwrap();
        },
        |a, l| a.jne(l).unwrap(),
    );
    let sx = run_sym(&code, fail, 1, Default::default(), Abi::SysV, |_| {}).unwrap();
    assert!(sx.constraints.is_empty(), "the canary check is concrete");
}

const STUB: u64 = 0xa000;
const STUB2: u64 = 0xa100;
const SLOT: u64 = 0xa800;

fn hooks(list: &[(u64, orress_emu::Stub)]) -> std::collections::HashMap<u64, orress_emu::Stub> {
    list.iter().cloned().collect()
}

/// Stubs read their arguments from the run's ABI: a Win64 memcmp takes rcx/rdx/r8 (before, the
/// executor always read rdi/rsi/rdx). The import is called through its slot (`call [slot]`).
#[test]
fn win64_memcmp_through_an_import_slot() {
    use orress_emu::{Abi, Stub};
    let target = b"s3cr3t!";
    let mut a = CodeAssembler::new(64).unwrap();
    let fail_l = a.create_label();
    // Win64: rcx = input already; rdx = target; r8 = len.
    a.mov(rdx, TARGET_ADDR).unwrap();
    a.mov(r8d, target.len() as i32).unwrap();
    a.mov(rdi, 0x1234u64).unwrap(); // junk in the SysV argument registers
    a.mov(rsi, 0x5678u64).unwrap();
    a.call(qword_ptr(SLOT)).unwrap();
    a.test(eax, eax).unwrap();
    a.jne(fail_l).unwrap();
    let (code, fail) = finish(a, fail_l);
    let sx = run_sym(
        &code,
        fail,
        target.len() as u32,
        hooks(&[(SLOT, Stub::Memcmp)]),
        Abi::Win64,
        |m| {
            m.write_bytes(TARGET_ADDR, target);
            m.write_bytes(SLOT, &0x0001_2345u64.to_le_bytes()); // hint/name RVA, not code
        },
    )
    .unwrap();
    let r = solve(&sx.constraints, target.len());
    assert!(r.complete, "{}", r.message);
    assert_eq!(r.input, target);
}

/// malloc hands out mapped memory, memcpy copies the symbolic input bytes (it returned 0 and
/// copied nothing before), and a `Return` stub no longer demands a concrete first argument.
#[test]
fn malloc_memcpy_and_return_stubs_are_modelled() {
    use orress_emu::{Abi, Stub};
    const PUTS: u64 = 0xa200;
    let mut a = CodeAssembler::new(64).unwrap();
    let fail_l = a.create_label();
    a.mov(rbx, rdi).unwrap(); // the input
    a.mov(edi, 16).unwrap();
    a.call(STUB).unwrap(); // malloc(16)
    a.mov(r12, rax).unwrap();
    a.mov(rdi, rax).unwrap();
    a.mov(rsi, rbx).unwrap();
    a.mov(edx, 4).unwrap();
    a.call(STUB2).unwrap(); // memcpy(buf, input, 4)
    a.movzx(edi, byte_ptr(rbx)).unwrap(); // symbolic first argument
    a.call(PUTS).unwrap(); // putchar-like import (Return 0)
    a.movzx(eax, byte_ptr(r12 + 2)).unwrap();
    a.cmp(al, 0x43).unwrap();
    a.jne(fail_l).unwrap();
    a.movzx(eax, byte_ptr(r12 + 8)).unwrap(); // untouched malloc memory reads as 0
    a.test(al, al).unwrap();
    a.jne(fail_l).unwrap();
    let (code, fail) = finish(a, fail_l);
    let sx = run_sym(
        &code,
        fail,
        4,
        hooks(&[
            (STUB, Stub::Malloc),
            (STUB2, Stub::Memcpy),
            (PUTS, Stub::Return(0)),
        ]),
        Abi::SysV,
        |_| {},
    )
    .unwrap();
    let r = solve(&sx.constraints, 4);
    assert!(r.complete, "{}", r.message);
    assert_eq!(r.input[2], b'C');
}

/// strlen of a non-input string is its real length (it returned the input length before).
#[test]
fn strlen_of_a_constant_string_is_concrete() {
    use orress_emu::{Abi, Stub};
    let mut a = CodeAssembler::new(64).unwrap();
    let fail_l = a.create_label();
    a.mov(rbx, rdi).unwrap();
    a.mov(rdi, TARGET_ADDR).unwrap();
    a.call(STUB).unwrap(); // strlen("abcde") = 5
    a.movzx(ecx, byte_ptr(rbx)).unwrap();
    a.cmp(rcx, rax).unwrap();
    a.jne(fail_l).unwrap();
    let (code, fail) = finish(a, fail_l);
    let sx = run_sym(
        &code,
        fail,
        3,
        hooks(&[(STUB, Stub::Strlen)]),
        Abi::SysV,
        |m| m.write_bytes(TARGET_ADDR, b"abcde\0"),
    )
    .unwrap();
    let r = solve(&sx.constraints, 3);
    assert!(r.complete, "{}", r.message);
    assert_eq!(r.input[0], 5);
}
