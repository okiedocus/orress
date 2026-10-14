//! End-to-end emulator tests. Each test assembles a real function with iced-x86's assembler,
//! loads it, and runs it through the emulator — exercising the operand, flag and control-flow
//! paths the interpreter implements.

use iced_x86::code_asm::*;
use orress_emu::{Abi, Emulator, Stub};

/// Assembles `build` at `ip` and returns the machine code.
fn asm(ip: u64, build: impl FnOnce(&mut CodeAssembler)) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    build(&mut a);
    a.assemble(ip).unwrap()
}

#[test]
fn adds_two_arguments() {
    // fn add(a: i32, b: i32) -> i32 { a + b }
    let code = asm(0x1000, |a| {
        a.mov(eax, edi).unwrap();
        a.add(eax, esi).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[3, 4], Abi::SysV).unwrap(), 7);
    assert_eq!(emu.call(0x1000, &[100, 23], Abi::SysV).unwrap(), 123);
}

#[test]
fn sums_a_loop() {
    // fn sum(n: u32) -> u32 { let mut s = 0; while n > 0 { s += n; n -= 1; } s }
    let code = asm(0x2000, |a| {
        let mut loop_l = a.create_label();
        let mut done_l = a.create_label();
        a.xor(eax, eax).unwrap();
        a.set_label(&mut loop_l).unwrap();
        a.test(edi, edi).unwrap();
        a.jz(done_l).unwrap();
        a.add(eax, edi).unwrap();
        a.dec(edi).unwrap();
        a.jmp(loop_l).unwrap();
        a.set_label(&mut done_l).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x2000, &code);
    assert_eq!(emu.call(0x2000, &[10], Abi::SysV).unwrap(), 55);
    assert_eq!(emu.call(0x2000, &[100], Abi::SysV).unwrap(), 5050);
}

#[test]
fn xor_decrypts_a_buffer_in_memory() {
    // fn xor(ptr: *mut u8, len: usize, key: u8) { for i in 0..len { ptr[i] ^= key; } }
    let code = asm(0x3000, |a| {
        let mut loop_l = a.create_label();
        let mut done_l = a.create_label();
        a.xor(ecx, ecx).unwrap(); // i = 0
        a.set_label(&mut loop_l).unwrap();
        a.cmp(rcx, rsi).unwrap();
        a.jae(done_l).unwrap();
        a.mov(al, byte_ptr(rdi + rcx)).unwrap();
        a.xor(al, dl).unwrap();
        a.mov(byte_ptr(rdi + rcx), al).unwrap();
        a.inc(rcx).unwrap();
        a.jmp(loop_l).unwrap();
        a.set_label(&mut done_l).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x3000, &code);
    let buf = 0x5000;
    let data = b"Secret message";
    emu.map(buf, data);
    let key = 0x42u64;
    emu.call(0x3000, &[buf, data.len() as u64, key], Abi::SysV)
        .unwrap();
    let out = emu.mem.read_vec(buf, data.len()).unwrap();
    let expected: Vec<u8> = data.iter().map(|b| b ^ 0x42).collect();
    assert_eq!(out, expected);
    // And it round-trips: xor again restores the plaintext.
    emu.call(0x3000, &[buf, data.len() as u64, key], Abi::SysV)
        .unwrap();
    assert_eq!(emu.mem.read_vec(buf, data.len()).unwrap(), data);
}

#[test]
fn check_function_returns_bool() {
    // fn check(c: u8) -> bool { c == b'A' }
    let code = asm(0x4000, |a| {
        a.cmp(dil, 0x41).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x4000, &code);
    assert_eq!(emu.call(0x4000, &[u64::from(b'A')], Abi::SysV).unwrap(), 1);
    assert_eq!(emu.call(0x4000, &[u64::from(b'B')], Abi::SysV).unwrap(), 0);
}

#[test]
fn instruction_count_is_the_side_channel_signal() {
    // The sum loop runs more instructions for larger n — the signal a side-channel solver reads.
    let code = asm(0x2000, |a| {
        let mut loop_l = a.create_label();
        let mut done_l = a.create_label();
        a.xor(eax, eax).unwrap();
        a.set_label(&mut loop_l).unwrap();
        a.test(edi, edi).unwrap();
        a.jz(done_l).unwrap();
        a.add(eax, edi).unwrap();
        a.dec(edi).unwrap();
        a.jmp(loop_l).unwrap();
        a.set_label(&mut done_l).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x2000, &code);
    emu.call(0x2000, &[5], Abi::SysV).unwrap();
    let five = emu.steps;
    emu.call(0x2000, &[20], Abi::SysV).unwrap();
    let twenty = emu.steps;
    assert!(twenty > five, "more iterations => more instructions");
}

#[test]
fn signed_multiply_and_negative_args() {
    // fn mul(a: i64, b: i64) -> i64 { a * b }
    let code = asm(0x6000, |a| {
        a.mov(rax, rdi).unwrap();
        a.imul_2(rax, rsi).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x6000, &code);
    let r = emu.call(0x6000, &[6, 7], Abi::SysV).unwrap();
    assert_eq!(r, 42);
    // -3 * 4 = -12 (two's complement)
    let neg3 = (-3i64) as u64;
    let r = emu.call(0x6000, &[neg3, 4], Abi::SysV).unwrap();
    assert_eq!(r as i64, -12);
}

#[test]
fn calls_a_stubbed_import() {
    // fn check(s: *const u8) -> bool { strcmp(s, SECRET) == 0 }
    const SECRET_ADDR: u64 = 0xb000;
    const STRCMP: u64 = 0xa000;
    let code = asm(0x8000, |a| {
        a.mov(rsi, SECRET_ADDR).unwrap(); // arg1 = secret
        a.call(STRCMP).unwrap(); // arg0 = rdi (the input, already in place)
        a.test(rax, rax).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x8000, &code);
    emu.hook(STRCMP, Stub::Strcmp);
    emu.map(SECRET_ADDR, b"hunter2\0");
    emu.map(0xc000, b"hunter2\0");
    emu.map(0xd000, b"wrong\0");
    assert_eq!(emu.call(0x8000, &[0xc000], Abi::SysV).unwrap(), 1);
    assert_eq!(emu.call(0x8000, &[0xd000], Abi::SysV).unwrap(), 0);
}

#[test]
fn win64_abi_uses_rcx_rdx() {
    let code = asm(0x7000, |a| {
        // Win64: arg0=rcx, arg1=rdx
        a.mov(rax, rcx).unwrap();
        a.add(rax, rdx).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x7000, &code);
    assert_eq!(emu.call(0x7000, &[40, 2], Abi::Win64).unwrap(), 42);
}

// --- QA regression tests (flags, shift/div edge cases) --------------------

use orress_emu::EmuError;

/// `shl al, 10`: the masked count (10) exceeds the 8-bit width. Must not panic (it did:
/// `bits - cnt` underflowed) and the result is 0.
#[test]
fn shl_count_over_width_does_not_panic() {
    let code = asm(0x1000, |a| {
        a.mov(eax, edi).unwrap();
        a.shl(al, 10i32).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[0xff], Abi::SysV).unwrap(), 0);
}

/// `shl eax, 32`: x86 masks the count for 32-bit operands to 5 bits, so 32 & 0x1f == 0 (a no-op).
/// The old code masked to 0x3f and shifted by 32, zeroing eax.
#[test]
fn shl_eax_by_32_is_a_noop() {
    let code = asm(0x1100, |a| {
        a.mov(eax, edi).unwrap();
        a.shl(eax, 32i32).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1100, &code);
    assert_eq!(
        emu.call(0x1100, &[0x1234_5678], Abi::SysV).unwrap(),
        0x1234_5678
    );
}

/// 64-bit `idiv` of INT_MIN by -1 must trap as #DE (DivideOverflow), not panic on i128 overflow.
#[test]
fn idiv_int_min_by_neg_one_traps() {
    let code = asm(0x1200, |a| {
        a.mov(rdx, 0x8000_0000_0000_0000u64).unwrap(); // dividend high
        a.xor(rax, rax).unwrap(); // dividend low -> rdx:rax = 2^127
        a.mov(rcx, rdi).unwrap(); // divisor = arg0 (-1)
        a.idiv(rcx).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1200, &code);
    assert!(matches!(
        emu.call(0x1200, &[u64::MAX], Abi::SysV),
        Err(EmuError::DivideOverflow(_))
    ));
}

/// 16-bit `div` whose quotient doesn't fit AX must raise #DE, not silently truncate.
#[test]
fn div_quotient_overflow_traps() {
    let code = asm(0x1300, |a| {
        a.mov(edx, 1u32).unwrap(); // dx = 1
        a.xor(eax, eax).unwrap(); // ax = 0 -> dx:ax = 0x1_0000
        a.mov(ebx, 1u32).unwrap(); // bx = 1
        a.div(bx).unwrap(); // quotient 0x10000 doesn't fit AX
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1300, &code);
    assert!(matches!(
        emu.call(0x1300, &[], Abi::SysV),
        Err(EmuError::DivideOverflow(_))
    ));
}

/// 32-bit signed `idiv` with a negative dividend (-8 / 2 = -4). The old code treated the
/// EDX:EAX dividend as unsigned, giving a huge positive quotient.
#[test]
fn idiv_negative_dividend_32bit() {
    let code = asm(0x1400, |a| {
        a.mov(eax, edi).unwrap(); // eax = arg0 (-8)
        a.cdq().unwrap(); // sign-extend into edx
        a.mov(ecx, 2u32).unwrap();
        a.idiv(ecx).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1400, &code);
    // arg0 = -8 as a 32-bit value; result is -4 = 0xFFFF_FFFC (upper 32 of rax zeroed).
    assert_eq!(
        emu.call(0x1400, &[0xFFFF_FFF8], Abi::SysV).unwrap(),
        0xFFFF_FFFC
    );
}

/// ADC 0x7f + 0x7f with CF=0 overflows signed -> OF=1. The old chained-add set OF from the
/// second (+carry) micro-op, yielding OF=0.
#[test]
fn adc_sets_overflow_flag() {
    let code = asm(0x1500, |a| {
        a.mov(eax, edi).unwrap();
        a.mov(ebx, esi).unwrap();
        a.clc().unwrap();
        a.adc(al, bl).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1500, &code);
    let _ = emu.call(0x1500, &[0x7f, 0x7f], Abi::SysV).unwrap();
    assert!(emu.cpu.flags.of, "ADC 0x7f+0x7f must set OF");
    assert_eq!(emu.cpu.rax() & 0xff, 0xfe);
}

/// SBB 0x00 - 0x00 - borrow(1): AF/OF must reflect the full a-b-borrow. Here 0-0-1 = 0xff,
/// borrow out (CF) = 1, AF = 1.
#[test]
fn sbb_borrow_flags() {
    let code = asm(0x1600, |a| {
        a.mov(eax, edi).unwrap();
        a.mov(ebx, esi).unwrap();
        a.stc().unwrap(); // CF = 1 -> borrow
        a.sbb(al, bl).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1600, &code);
    let _ = emu.call(0x1600, &[0, 0], Abi::SysV).unwrap();
    assert_eq!(emu.cpu.rax() & 0xff, 0xff);
    assert!(emu.cpu.flags.cf, "0-0-1 borrows");
    assert!(emu.cpu.flags.af, "0-0-1 half-borrows");
}

// --- audit regression tests (import slots, faults, segments, ABI, stubs) ----

/// `call [IAT slot]` loads the slot's contents (a hint/name RVA in a PE file image), so the hook
/// must match the slot address itself — before, execution jumped into the RVA and faulted.
#[test]
fn call_through_a_hooked_import_slot_runs_the_stub() {
    const SLOT: u64 = 0x9000;
    const SECRET_ADDR: u64 = 0xb000;
    let code = asm(0x8000, |a| {
        a.mov(rsi, SECRET_ADDR).unwrap();
        a.call(qword_ptr(SLOT)).unwrap();
        a.test(rax, rax).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x8000, &code);
    // The slot holds what a PE file image holds there: a hint/name RVA, not code.
    emu.map(SLOT, &0x0001_2345u64.to_le_bytes());
    emu.hook(SLOT, Stub::Strcmp);
    emu.map(SECRET_ADDR, b"hunter2\0");
    emu.map(0xc000, b"hunter2\0");
    emu.map(0xd000, b"wrong\0");
    assert_eq!(emu.call(0x8000, &[0xc000], Abi::SysV).unwrap(), 1);
    assert_eq!(emu.call(0x8000, &[0xd000], Abi::SysV).unwrap(), 0);
}

/// A PLT stub `jmp [GOT]` whose GOT slot is hooked: the file image's GOT holds the lazy-binding
/// address (PLT+6), so the hook must fire on the `jmp` and return to the original caller.
#[test]
fn jmp_through_a_hooked_got_slot_returns_to_the_caller() {
    const GOT: u64 = 0x9000;
    const PLT: u64 = 0xa000;
    let code = asm(0x8000, |a| {
        a.call(PLT).unwrap();
        a.add(rax, 1).unwrap();
        a.ret().unwrap();
    });
    let plt = asm(PLT, |a| {
        a.jmp(qword_ptr(GOT)).unwrap();
        a.push(0).unwrap(); // the lazy-binding path (never reached)
    });
    let mut emu = Emulator::new();
    emu.map(0x8000, &code);
    emu.map(PLT, &plt);
    emu.map(GOT, &(PLT + 6).to_le_bytes());
    emu.hook(GOT, Stub::Return(41));
    assert_eq!(emu.call(0x8000, &[], Abi::SysV).unwrap(), 42);
}

/// Guest writes fault on unmapped memory instead of allocating a page: a null-pointer store is
/// caught, and a striding write loop can't balloon host memory.
#[test]
fn writes_to_unmapped_memory_fault() {
    let code = asm(0x1000, |a| {
        a.mov(dword_ptr(rdi), 7).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[0], Abi::SysV), Err(EmuError::Fault(0)));
    emu.cpu = orress_emu::Cpu::new();
    assert_eq!(
        emu.call(0x1000, &[0x4000_0000], Abi::SysV),
        Err(EmuError::Fault(0x4000_0000))
    );
    assert!(
        !emu.mem.is_mapped(0),
        "the faulting write did not map a page"
    );
    assert!(!emu.mem.is_mapped(0x4000_0000));
    // Mapped memory is still writable.
    emu.cpu = orress_emu::Cpu::new();
    emu.mem.map_zeroed(0x5000, 0x1000);
    emu.call(0x1000, &[0x5000], Abi::SysV).unwrap();
    assert_eq!(emu.mem.read(0x5000, 4).unwrap(), 7);
}

/// `fs:[0x28]` (SysV stack canary) and `gs:[0x30]` (Win64 TEB self-pointer) honour the segment
/// base; before, the override was ignored and the load hit address 0x28 / 0x30.
#[test]
fn fs_and_gs_segment_overrides_use_the_segment_base() {
    let mut emu = Emulator::new();
    // mov rax, fs:[0x28] ; ret
    emu.map(0x1000, &[0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0, 0xC3]);
    // mov rax, gs:[0x30] ; mov rax, [rax+0x60] ; ret   (TEB -> PEB)
    emu.map(
        0x2000,
        &[
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0, 0, 0, 0x48, 0x8B, 0x40, 0x60, 0xC3,
        ],
    );
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        orress_emu::STACK_CANARY
    );
    assert_eq!(
        emu.call(0x2000, &[], Abi::Win64).unwrap(),
        orress_emu::PEB_BASE
    );
    // `lea` never applies a segment base.
    // lea rax, fs:[0x28] ; ret
    emu.map(0x3000, &[0x64, 0x48, 0x8D, 0x04, 0x25, 0x28, 0, 0, 0, 0xC3]);
    assert_eq!(emu.call(0x3000, &[], Abi::SysV).unwrap(), 0x28);
}

/// A 32-bit CMOVcc with a false condition still zero-extends its destination.
#[test]
fn cmov32_false_condition_zeroes_upper_half() {
    let code = asm(0x1000, |a| {
        a.mov(rax, -1i64).unwrap();
        a.cmp(edi, edi).unwrap(); // ZF = 1, so cmovne is false
        a.cmovne(eax, esi).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[1, 2], Abi::SysV).unwrap(), 0xffff_ffff);
}

/// Arguments past the register count go on the stack: SysV right after the return address,
/// Win64 after the 32-byte shadow space.
#[test]
fn stack_arguments_follow_the_abi() {
    // SysV: return arg7 * 1000 + arg8  (args 7 and 8 at [rsp+8], [rsp+16])
    let sysv = asm(0x1000, |a| {
        a.imul_3(rax, qword_ptr(rsp + 8), 1000).unwrap();
        a.add(rax, qword_ptr(rsp + 16)).unwrap();
        a.ret().unwrap();
    });
    // Win64: return arg5 * 1000 + arg6  (at [rsp+0x28], [rsp+0x30])
    let win = asm(0x2000, |a| {
        a.imul_3(rax, qword_ptr(rsp + 0x28), 1000).unwrap();
        a.add(rax, qword_ptr(rsp + 0x30)).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &sysv);
    emu.map(0x2000, &win);
    let args = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(emu.call(0x1000, &args, Abi::SysV).unwrap(), 7008);
    assert_eq!(emu.call(0x2000, &args[..6], Abi::Win64).unwrap(), 5006);
    // At entry RSP is 8 mod 16, as after a real `call`.
    let probe = asm(0x3000, |a| {
        a.mov(rax, rsp).unwrap();
        a.ret().unwrap();
    });
    emu.map(0x3000, &probe);
    for n in 0..10 {
        let args: Vec<u64> = (0..n).collect();
        assert_eq!(emu.call(0x3000, &args, Abi::SysV).unwrap() % 16, 8);
        assert_eq!(emu.call(0x3000, &args, Abi::Win64).unwrap() % 16, 8);
    }
}

/// `atoi` parses leading whitespace, a sign, and the leading digits only.
#[test]
fn atoi_stub_parses_a_numeric_prefix() {
    const ATOI: u64 = 0xa000;
    let code = asm(0x1000, |a| {
        a.call(ATOI).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.hook(ATOI, Stub::Atoi);
    for (s, want) in [
        (&b"123abc\0"[..], 123i64),
        (b"  -42\0", -42),
        (b"+7 apples\0", 7),
        (b"abc\0", 0),
        (b"\t\n99\0", 99),
    ] {
        emu.map(0x5000, s);
        assert_eq!(
            emu.call(0x1000, &[0x5000], Abi::SysV).unwrap() as i64,
            want,
            "{s:?}"
        );
    }
}

/// `stub_for` is the shared import-name -> stub mapping.
#[test]
fn stub_for_maps_libc_names() {
    assert_eq!(orress_emu::stub_for("_strcmp"), Stub::Strcmp);
    assert_eq!(orress_emu::stub_for("memmove"), Stub::Memcpy);
    assert_eq!(orress_emu::stub_for("puts"), Stub::Return(0));
}
