//! Proves the instruction-counting side-channel solver recovers a secret from a check routine
//! that bails on the first wrong byte — without ever producing a passing input.

use iced_x86::code_asm::*;
use orress_emu::{Abi, Cpu, Emulator, solve_by_count};

const CODE: u64 = 0x1000;
const SECRET_ADDR: u64 = 0x8000;
const BUF: u64 = 0x9000;

/// A byte-by-byte comparison that returns early on the first mismatch — the classic shape a
/// side channel defeats.
fn build_check(secret_len: usize) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut loop_l = a.create_label();
    let mut pass_l = a.create_label();
    let mut fail_l = a.create_label();
    a.mov(r8, SECRET_ADDR).unwrap(); // secret base
    a.xor(ecx, ecx).unwrap(); // i = 0
    a.set_label(&mut loop_l).unwrap();
    a.cmp(rcx, secret_len as i32).unwrap();
    a.jae(pass_l).unwrap();
    a.mov(al, byte_ptr(rdi + rcx)).unwrap(); // input[i]
    a.mov(dl, byte_ptr(r8 + rcx)).unwrap(); // secret[i]
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
    a.assemble(CODE).unwrap()
}

#[test]
fn side_channel_recovers_the_secret() {
    let secret = b"R3v3rs3!";
    let mut emu = Emulator::new();
    emu.map(CODE, &build_check(secret.len()));
    emu.map(SECRET_ADDR, secret);

    let candidates: Vec<u8> = (0x20u8..=0x7e).collect(); // printable ASCII
    let solution = solve_by_count(secret.len(), &candidates, |input| {
        emu.map(BUF, input);
        emu.cpu = Cpu::new(); // fresh registers/flags each trial
        emu.call(CODE, &[BUF], Abi::SysV).unwrap();
        emu.steps
    });

    assert_eq!(&solution.input, secret);
    // The winning byte at each position beat the runner-up (a clean signal).
    for step in &solution.steps {
        assert!(
            step.count > step.runner_up,
            "position {} had no clear winner",
            step.index
        );
    }

    // Sanity: the recovered input actually passes the real check.
    emu.map(BUF, &solution.input);
    emu.cpu = Cpu::new();
    assert_eq!(emu.call(CODE, &[BUF], Abi::SysV).unwrap(), 1);
}
