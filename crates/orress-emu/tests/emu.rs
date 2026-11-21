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

/// Assembles `build` as **32-bit** code (long mode cannot encode `push ebp` and friends).
fn asm32(ip: u64, build: impl FnOnce(&mut CodeAssembler)) -> Vec<u8> {
    let mut a = CodeAssembler::new(32).unwrap();
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

/// The first *assigned* conversion of a scanf format, and its destination width/base.
#[test]
fn scanf_conv_reads_the_first_numeric_destination() {
    use orress_emu::scanf_num_conv as c;
    assert_eq!(c(b"%d").map(|k| (k.width, k.radix)), Some((4, 10)));
    assert_eq!(
        c(b"Enter: %5u\n").map(|k| (k.width, k.radix)),
        Some((4, 10))
    );
    assert_eq!(c(b"%hd").map(|k| k.width), Some(2));
    assert_eq!(c(b"%hhd").map(|k| k.width), Some(1));
    assert_eq!(c(b"%lld").map(|k| k.width), Some(8));
    assert_eq!(c(b"%I64d").map(|k| k.width), Some(8));
    // A C `long` is stored as 4 bytes on purpose (see scanf_num_conv's docs).
    assert_eq!(c(b"%ld").map(|k| k.width), Some(4));
    assert_eq!(c(b"%x").map(|k| k.radix), Some(16));
    assert_eq!(c(b"%o").map(|k| k.radix), Some(8));
    assert_eq!(c(b"%f").map(|k| (k.width, k.float)), Some((4, true)));
    assert_eq!(c(b"%lf").map(|k| (k.width, k.float)), Some((8, true)));
    // Character destinations keep the byte-copy behaviour; a literal '%%' is not a conversion.
    assert_eq!(c(b"%s"), None);
    assert_eq!(c(b"%15s"), None);
    assert_eq!(c(b"%c"), None);
    assert_eq!(c(b"%[^\n]"), None);
    assert_eq!(c(b"100%% done"), None);
    assert_eq!(c(b"no conversions"), None);
    // Suppressed (`%*d`) stores nothing, so the first destination is the conversion after it.
    assert_eq!(c(b"%*d %s"), None);
    assert_eq!(c(b"%*s %d").map(|k| k.width), Some(4));
}

/// Seed text -> the value a numeric destination should hold.
#[test]
fn parse_num_converts_seed_text_per_conversion() {
    use orress_emu::{parse_num, scanf_num_conv};
    let conv = |f: &[u8]| scanf_num_conv(f).unwrap();
    assert_eq!(parse_num(b"25711", &conv(b"%d")), Some(25711));
    assert_eq!(parse_num(b"  42\n", &conv(b"%d")), Some(42));
    assert_eq!(parse_num(b"-7", &conv(b"%d")), Some(-7i64 as u64));
    assert_eq!(parse_num(b"25711abc", &conv(b"%d")), Some(25711));
    assert_eq!(parse_num(b"539", &conv(b"%x")), Some(0x539));
    assert_eq!(parse_num(b"0x539", &conv(b"%x")), Some(0x539));
    assert_eq!(parse_num(b"17", &conv(b"%o")), Some(0o17));
    assert_eq!(parse_num(b"1.5", &conv(b"%lf")), Some(1.5f64.to_bits()));
    assert_eq!(
        parse_num(b"1.5", &conv(b"%f")),
        Some(u64::from(1.5f32.to_bits()))
    );
    // A non-numeric candidate converts nothing — a numeric check must *fail* for it, not match
    // whatever bytes happened to land in the int.
    assert_eq!(parse_num(b"password", &conv(b"%d")), None);
    assert_eq!(parse_num(b"", &conv(b"%d")), None);
}

/// An "enter the number" crackme: `scanf("%d", &n)` then `cmp eax, 25711`. The stub must store the
/// *parsed* integer (not the seed's digits), and the whole-value comparison against it is recorded
/// so the key can be read off and a candidate confirmed without any success string.
#[test]
fn numeric_scanf_seed_is_parsed_and_its_compare_recorded() {
    const SCANF: u64 = 0xa000;
    const FMT: u64 = 0x5000;
    const SLOT: u64 = 0x6000;
    // main: scanf("%d", &n); return n == 25711;
    let code = asm(0x1000, |a| {
        a.mov(rdi, FMT).unwrap();
        a.mov(rsi, SLOT).unwrap();
        a.call(SCANF).unwrap();
        a.mov(eax, dword_ptr(SLOT)).unwrap();
        a.cmp(eax, 25711).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(FMT, b"%d\0");
    emu.map(SLOT, &[0u8; 8]);
    emu.hook(SCANF, orress_emu::stub_for("scanf"));

    emu.record_compares(true);
    emu.seed_input(b"25711".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 1, "parsed seed");
    assert!(
        emu.int_compares().contains(&(25711, 25711)),
        "the right number compares equal: {:?}",
        emu.int_compares()
    );

    // A wrong number still reveals the expected key on the non-input side, and does not compare
    // equal — which is what makes this a differential confirmation signal.
    emu.record_compares(true);
    emu.seed_input(b"999".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 0, "wrong seed");
    assert_eq!(emu.int_compares(), [(999, 25711)]);

    // A non-numeric candidate converts nothing, so the check rejects it.
    emu.record_compares(true);
    emu.seed_input(b"password".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 0, "non-numeric");
    assert!(!emu.int_compares().iter().any(|&(x, y)| x == y));
}

/// The `gets` + `atoi` shape: the number is parsed from the seeded *text* buffer and staged through
/// a stack slot before the compare, so the taint has to survive `atoi`'s return and the store.
/// REGRESSION. A stack slot that held the parsed number, then gets **reused** for something else,
/// must stop counting as the numeric input.
///
/// Compilers reuse slots freely. While the tag stayed put, every later load of that slot read as
/// "the input", so an unrelated `cmp` recorded its operand as the expected key — and because such
/// an operand is typically a pointer compared against itself, the pair came back *equal*, which is
/// precisely the signature of a satisfied numeric check. Three corpus binaries were "solved" this
/// way with the address of their own input buffer. The real compare must still be recorded.
#[test]
fn a_reused_stack_slot_stops_being_the_numeric_input() {
    const GETS: u64 = 0xa000;
    const ATOI: u64 = 0xb000;
    const BUF: u64 = 0x5000;
    // main: gets(buf); n = atoi(buf); ok = n == 1337; p = buf; return ok && p == buf;
    //                                                 ^ the slot now holds a pointer
    let code = asm(0x1000, |a| {
        a.push(rbp).unwrap();
        a.mov(rbp, rsp).unwrap();
        a.sub(rsp, 0x20).unwrap();
        a.mov(rdi, BUF).unwrap();
        a.call(GETS).unwrap();
        a.mov(rdi, BUF).unwrap();
        a.call(ATOI).unwrap();
        a.mov(dword_ptr(rbp - 4), eax).unwrap();
        a.mov(ecx, dword_ptr(rbp - 4)).unwrap();
        a.cmp(ecx, 1337).unwrap(); // the real check on the number
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.mov(dword_ptr(rbp - 4), BUF as u32).unwrap(); // slot reused for a pointer
        a.mov(edx, dword_ptr(rbp - 4)).unwrap();
        a.cmp(edx, BUF as u32).unwrap(); // trivially true, and nothing to do with the input
        a.sete(cl).unwrap();
        a.add(rsp, 0x20).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(BUF, &[0u8; 32]);
    emu.hook(GETS, orress_emu::stub_for("gets"));
    emu.hook(ATOI, orress_emu::stub_for("atoi"));

    emu.record_compares(true);
    emu.seed_input(b"1337".to_vec());
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        1,
        "the number matched"
    );
    assert!(
        emu.int_compares().contains(&(1337, 1337)),
        "the real numeric check is still recorded: {:?}",
        emu.int_compares()
    );
    assert!(
        !emu.int_compares().iter().any(|&(x, _)| x == BUF),
        "the reused slot's pointer must not be recorded as the input: {:?}",
        emu.int_compares()
    );
}

/// The `gets` + `atoi` shape: the number is parsed from the seeded *text* buffer and staged through
/// a stack slot before the compare, so the taint has to survive `atoi`'s return and the store.
#[test]
fn atoi_result_carries_numeric_taint_through_a_stack_slot() {
    const GETS: u64 = 0xa000;
    const ATOI: u64 = 0xb000;
    const BUF: u64 = 0x5000;
    // main: gets(buf); n = atoi(buf); return n == 1337;
    let code = asm(0x1000, |a| {
        a.push(rbp).unwrap();
        a.mov(rbp, rsp).unwrap();
        a.sub(rsp, 0x20).unwrap();
        a.mov(rdi, BUF).unwrap();
        a.call(GETS).unwrap();
        a.mov(rdi, BUF).unwrap();
        a.call(ATOI).unwrap();
        a.mov(dword_ptr(rbp - 4), eax).unwrap();
        a.mov(ecx, dword_ptr(rbp - 4)).unwrap();
        a.cmp(ecx, 1337).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.add(rsp, 0x20).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(BUF, &[0u8; 32]);
    emu.hook(GETS, orress_emu::stub_for("gets"));
    emu.hook(ATOI, Stub::Atoi);

    emu.record_compares(true);
    emu.seed_input(b"1337".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 1);
    assert!(
        emu.int_compares().contains(&(1337, 1337)),
        "{:?}",
        emu.int_compares()
    );

    emu.record_compares(true);
    emu.seed_input(b"1336".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 0);
    assert_eq!(emu.int_compares(), [(1336, 1337)]);
}

/// An *ordering* check (`if (n < 100) reject`) compares the numeric input too, and its operands
/// are equal for exactly one value — so it must NOT be recorded as a key comparison, or that bound
/// would confirm as the answer.
#[test]
fn an_ordering_check_is_not_a_numeric_key_compare() {
    const SCANF: u64 = 0xa000;
    const FMT: u64 = 0x5000;
    const SLOT: u64 = 0x6000;
    // main: scanf("%d", &n); if (n < 100) return 0; if (n == 4242) return 1; return 0;
    let code = asm(0x1000, |a| {
        let mut lo = a.create_label();
        let mut done = a.create_label();
        a.mov(rdi, FMT).unwrap();
        a.mov(rsi, SLOT).unwrap();
        a.call(SCANF).unwrap();
        a.mov(eax, dword_ptr(SLOT)).unwrap();
        a.cmp(eax, 100).unwrap();
        a.jl(lo).unwrap();
        a.mov(ecx, dword_ptr(SLOT)).unwrap();
        a.cmp(ecx, 4242).unwrap();
        a.jne(lo).unwrap();
        a.mov(eax, 1u32).unwrap();
        a.jmp(done).unwrap();
        a.set_label(&mut lo).unwrap();
        a.xor(eax, eax).unwrap();
        a.set_label(&mut done).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(FMT, b"%d\0");
    emu.map(SLOT, &[0u8; 8]);
    emu.hook(SCANF, orress_emu::stub_for("scanf"));

    // 100 satisfies the ordering compare exactly, but it is not the key: nothing is recorded for it.
    emu.record_compares(true);
    emu.seed_input(b"100".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 0);
    assert_eq!(
        emu.int_compares(),
        [(100, 4242)],
        "only the equality compare counts"
    );

    // The real key still confirms.
    emu.record_compares(true);
    emu.seed_input(b"4242".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 1);
    assert!(emu.int_compares().contains(&(4242, 4242)));
}

/// A 32-bit function with a REAL STACK FRAME must emulate without faulting. 32-bit code computes
/// frame addresses with 32-bit arithmetic, so a stack placed outside the low 4 GiB is a trap:
/// `mov ebp, esp` keeps only the low half of RSP and every later `[ebp-x]` lands on an unmapped
/// page, while the pushes themselves went to the real 64-bit address. That silently broke every
/// `call`-based path (the compare-hook, all the oracle-free signals, lead extraction) on x86-32 —
/// which is most of the crackme corpus.
#[test]
fn cdecl_stack_frame_does_not_fault() {
    // int f(int a, int b) { int x = a; int y = b; return x + y; }  — cdecl: args at [ebp+8],[ebp+12]
    let code = asm32(0x1000, |a| {
        a.push(ebp).unwrap();
        a.mov(ebp, esp).unwrap();
        a.sub(esp, 0xc4).unwrap(); // a big frame, like a real buffer-holding check
        a.mov(eax, dword_ptr(ebp + 8)).unwrap();
        a.mov(dword_ptr(ebp - 0xc4), eax).unwrap(); // touch the far end of the frame
        a.mov(ecx, dword_ptr(ebp + 12)).unwrap();
        a.mov(dword_ptr(ebp - 4), ecx).unwrap();
        a.mov(eax, dword_ptr(ebp - 0xc4)).unwrap();
        a.add(eax, dword_ptr(ebp - 4)).unwrap();
        a.mov(esp, ebp).unwrap();
        a.pop(ebp).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    let got = emu.call(0x1000, &[7, 35], Abi::Cdecl);
    assert_eq!(
        got.map(|v| v as u32),
        Ok(42),
        "32-bit frame must be reachable"
    );

    // The frame really is addressable with 32-bit arithmetic.
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.abi = Abi::Cdecl;
    let top = emu.setup_stack();
    assert!(
        top <= u64::from(u32::MAX),
        "a 32-bit stack must fit in 32 bits: {top:#x}"
    );
    assert_eq!(
        emu.cpu.rsp() >> 32,
        0,
        "and so must RSP: {:#x}",
        emu.cpu.rsp()
    );
}

/// The instruction batch an emulation probe over the corpus ranked as the top hard blockers:
/// `cld` alone stopped ~11% of binaries dead, and these all appear in hand-written 32-bit asm
/// crackmes. An unimplemented instruction is not a degraded result — the run stops, so the check's
/// decision is never reached and the sample is unconfirmable.
#[test]
fn direction_flag_and_flag_block_moves() {
    // pushfd/popfd must round-trip the modelled flags, and std/cld must be observable in them.
    let code = asm32(0x1000, |a| {
        a.std().unwrap();
        a.pushfd().unwrap();
        a.cld().unwrap();
        a.popfd().unwrap(); // restores DF=1
        a.pushfd().unwrap();
        a.pop(eax).unwrap(); // eax = flags
        a.and(eax, 0x400).unwrap(); // isolate DF
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(
        emu.call(0x1000, &[], Abi::Cdecl).unwrap(),
        0x400,
        "DF survived popfd"
    );
    assert!(emu.cpu.flags.df);
}

/// PUSHAD/POPAD move all eight 32-bit registers; POPAD discards the saved ESP slot.
#[test]
fn pushad_popad_round_trip_the_registers() {
    let code = asm32(0x1000, |a| {
        a.mov(eax, 0x1111u32).unwrap();
        a.mov(ebx, 0x2222u32).unwrap();
        a.mov(esi, 0x3333u32).unwrap();
        a.pushad().unwrap();
        a.mov(eax, 0xdeadu32).unwrap(); // clobber everything
        a.mov(ebx, 0xdeadu32).unwrap();
        a.mov(esi, 0xdeadu32).unwrap();
        a.popad().unwrap();
        a.add(eax, ebx).unwrap(); // 0x1111 + 0x2222
        a.add(eax, esi).unwrap(); // + 0x3333
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[], Abi::Cdecl).unwrap(), 0x6666);

    // And the pair must leave the stack exactly as it found it (8 slots pushed, 8 popped).
    let balance = asm32(0x2000, |a| {
        a.mov(eax, esp).unwrap();
        a.pushad().unwrap();
        a.popad().unwrap();
        a.sub(eax, esp).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x2000, &balance);
    assert_eq!(
        emu.call(0x2000, &[], Abi::Cdecl).unwrap(),
        0,
        "pushad/popad must balance"
    );
}

/// XCHG swaps, XADD sums into the destination while the source takes the old destination, and
/// CMPXCHG swaps only on an equal accumulator (and reports that in ZF).
#[test]
fn exchange_instructions() {
    let xchg = asm(0x1000, |a| {
        a.mov(eax, 5u32).unwrap();
        a.mov(ecx, 9u32).unwrap();
        a.xchg(eax, ecx).unwrap();
        a.sub(eax, ecx).unwrap(); // 9 - 5
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &xchg);
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 4);

    let xadd = asm(0x2000, |a| {
        a.mov(eax, 10u32).unwrap();
        a.mov(ecx, 3u32).unwrap();
        a.xadd(eax, ecx).unwrap(); // eax = 13, ecx = 10
        a.sub(eax, ecx).unwrap(); // 13 - 10
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x2000, &xadd);
    assert_eq!(emu.call(0x2000, &[], Abi::SysV).unwrap(), 3);

    // cmpxchg ecx, edx with eax == ecx -> ecx takes edx and ZF is set.
    let cmpxchg = asm(0x3000, |a| {
        a.mov(eax, 7u32).unwrap();
        a.mov(ecx, 7u32).unwrap();
        a.mov(edx, 42u32).unwrap();
        a.cmpxchg(ecx, edx).unwrap();
        a.mov(eax, ecx).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x3000, &cmpxchg);
    assert_eq!(emu.call(0x3000, &[], Abi::SysV).unwrap(), 42);
    assert!(emu.cpu.flags.zf, "an equal accumulator sets ZF");

    // ... and with eax != ecx the accumulator takes the destination instead.
    let cmpxchg_ne = asm(0x4000, |a| {
        a.mov(eax, 1u32).unwrap();
        a.mov(ecx, 7u32).unwrap();
        a.mov(edx, 42u32).unwrap();
        a.cmpxchg(ecx, edx).unwrap();
        a.ret().unwrap(); // returns eax
    });
    let mut emu = Emulator::new();
    emu.map(0x4000, &cmpxchg_ne);
    assert_eq!(emu.call(0x4000, &[], Abi::SysV).unwrap(), 7);
    assert!(!emu.cpu.flags.zf);
}

/// Anti-debug and anti-VM instructions must not stop the run: nothing is attached under emulation,
/// and an all-zero CPUID is the least remarkable answer a VM check can get.
#[test]
fn antidebug_instructions_do_not_halt_the_run() {
    let code = asm(0x1000, |a| {
        a.int3().unwrap();
        a.mov(eax, 1u32).unwrap();
        a.cpuid().unwrap();
        a.add(eax, 7u32).unwrap(); // cpuid zeroed eax
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 7);
}

/// `rep stosd` zeroing a frame and `rep movsb` copying a buffer — the inlined memset/memcpy pair
/// that sits in the prologue of most compiled checks, so a run that cannot execute them never
/// reaches the comparison at all.
#[test]
fn rep_stos_and_movs_fill_and_copy() {
    const DST: u64 = 0x5000;
    const SRC: u64 = 0x6000;
    let code = asm(0x1000, |a| {
        // memset(DST, 0, 8 dwords) via rep stosd
        a.mov(rdi, DST).unwrap();
        a.xor(eax, eax).unwrap();
        a.mov(ecx, 8u32).unwrap();
        a.cld().unwrap();
        a.rep().stosd().unwrap();
        // memcpy(DST, SRC, 6) via rep movsb
        a.mov(rdi, DST).unwrap();
        a.mov(rsi, SRC).unwrap();
        a.mov(ecx, 6u32).unwrap();
        a.rep().movsb().unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(DST, &[0xff; 32]);
    emu.map(SRC, b"abcdef");
    emu.call(0x1000, &[], Abi::SysV).unwrap();
    assert_eq!(
        emu.mem.read_vec(DST, 6).unwrap(),
        b"abcdef",
        "rep movsb copied"
    );
    assert_eq!(
        emu.mem.read_vec(DST + 6, 2).unwrap(),
        vec![0, 0],
        "rep stosd zeroed the rest"
    );
    // The counter is consumed and the pointers have advanced past the data.
    assert_eq!(emu.cpu.reg(iced_x86::Register::RCX), 0);
    assert_eq!(emu.cpu.reg(iced_x86::Register::RSI), SRC + 6);
}

/// The direction flag really reverses a string op.
#[test]
fn std_makes_a_string_op_walk_backwards() {
    const BUF: u64 = 0x5000;
    let code = asm(0x1000, |a| {
        a.mov(rdi, BUF + 3).unwrap(); // last byte of a 4-byte window
        a.mov(al, 0x41u32).unwrap();
        a.mov(ecx, 4u32).unwrap();
        a.std().unwrap();
        a.rep().stosb().unwrap();
        a.cld().unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(BUF, &[0; 8]);
    emu.call(0x1000, &[], Abi::SysV).unwrap();
    assert_eq!(
        emu.mem.read_vec(BUF, 5).unwrap(),
        b"AAAA\0",
        "filled downwards from BUF+3"
    );
}

/// `repe cmpsb` IS the comparison in a hand-written asm password check: it stops at the first
/// differing byte and leaves the verdict in ZF. With the input seeded, each compared byte is also
/// recorded, so the key falls out exactly as it does from an inline `cmp` loop.
#[test]
fn repe_cmpsb_compares_and_yields_the_key() {
    const INPUT: u64 = 0x5000;
    const KEY: u64 = 0x6000;
    const GETS: u64 = 0xa000;
    // check() { gets(input); return repe cmpsb(input, "sekret") == equal; }
    let code = asm(0x1000, |a| {
        a.mov(rdi, INPUT).unwrap();
        a.call(GETS).unwrap();
        a.mov(rsi, INPUT).unwrap();
        a.mov(rdi, KEY).unwrap();
        a.mov(ecx, 6u32).unwrap();
        a.cld().unwrap();
        a.repe().cmpsb().unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(INPUT, &[0; 32]);
    emu.map(KEY, b"sekret");
    emu.hook(GETS, orress_emu::stub_for("gets"));

    // The right input compares equal all the way through.
    emu.record_compares(true);
    emu.seed_input(b"sekret".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 1);

    // A wrong input stops at the first mismatch — and the recorded byte reveals the key there.
    emu.record_compares(true);
    emu.seed_input(b"AAAAAA".to_vec());
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 0);
    let recovered = emu.inline_key().expect("a cmpsb byte was recorded");
    assert_eq!(
        &recovered[..1],
        b"s",
        "the expected first byte, from repe cmpsb: {recovered:?}"
    );
}

/// Bit test takes CF from the selected bit, and BTS/BTR/BTC also write the bit back.
#[test]
fn bit_test_family() {
    // bt eax, 3 with eax = 0b1000 -> CF = 1; then bts sets bit 1 and btr clears bit 3.
    let code = asm(0x1000, |a| {
        a.mov(eax, 0b1000u32).unwrap();
        a.bt(eax, 3u32).unwrap();
        a.setc(cl).unwrap();
        a.bts(eax, 1u32).unwrap(); // 0b1010
        a.btr(eax, 3u32).unwrap(); // 0b0010
        a.movzx(ecx, cl).unwrap();
        a.shl(ecx, 8u32).unwrap();
        a.or(eax, ecx).unwrap(); // low byte = value, bit 8 = the CF we captured
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    assert_eq!(emu.call(0x1000, &[], Abi::SysV).unwrap(), 0b1_0000_0010);

    // A clear bit leaves CF clear, and the index wraps modulo the operand width.
    let code = asm(0x2000, |a| {
        a.mov(eax, 1u32).unwrap();
        a.bt(eax, 32u32).unwrap(); // 32 % 32 == bit 0, which is set
        a.setc(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x2000, &code);
    assert_eq!(emu.call(0x2000, &[], Abi::SysV).unwrap(), 1);
}

/// x87 CONTROL instructions must not stop a run: a compiled prologue initialises the FPU and reads
/// its control word even when the check does no floating-point work. The reported control word is
/// the real reset value, so a program that inspects it sees something sane.
#[test]
fn x87_control_instructions_do_not_halt_the_run() {
    const SLOT: u64 = 0x5000;
    let code = asm(0x1000, |a| {
        a.fninit().unwrap();
        a.fnstcw(word_ptr(SLOT)).unwrap();
        a.fldcw(word_ptr(SLOT)).unwrap();
        a.fnstenv(ptr(SLOT + 8)).unwrap();
        a.movzx(eax, word_ptr(SLOT)).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(SLOT, &[0xff; 64]);
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        0x037f,
        "x87 reset control word"
    );
    // The environment area was written (not left as the 0xff filler).
    assert_eq!(emu.mem.read_vec(SLOT + 8, 4).unwrap(), vec![0, 0, 0, 0]);
}

/// `stub_for` is the shared import-name -> stub mapping.
#[test]
fn stub_for_maps_libc_names() {
    assert_eq!(orress_emu::stub_for("_strcmp"), Stub::Strcmp);
    assert_eq!(orress_emu::stub_for("memmove"), Stub::Memcpy);
    assert_eq!(orress_emu::stub_for("puts"), Stub::Return(0));
    // Case-insensitive / Windows compare variants record their operands like strcmp/strncmp.
    assert_eq!(orress_emu::stub_for("_stricmp"), Stub::Strcmp);
    assert_eq!(orress_emu::stub_for("lstrcmpA"), Stub::Strcmp);
    assert_eq!(orress_emu::stub_for("strncasecmp"), Stub::Strncmp);
    // More input readers seed their destination buffer.
    assert_eq!(
        orress_emu::stub_for("ReadFile"),
        Stub::ReadInput {
            buf_arg: 1,
            fmt_arg: None,
            ret: orress_emu::InputReturn::Count(1)
        }
    );
    assert_eq!(
        orress_emu::stub_for("__isoc99_fscanf"),
        Stub::ReadInput {
            buf_arg: 2,
            fmt_arg: Some(1),
            ret: orress_emu::InputReturn::Count(1)
        }
    );
}

/// SSE2: a 16-byte slice comparison, exactly the shape Rust emits for `a == b` on `[u8; 16]`
/// (movdqu / pcmpeqb / pmovmskb). Equal buffers give al = 1, any difference gives 0.
#[test]
fn sse2_compares_sixteen_bytes() {
    // fn eq16(a: *const u8, b: *const u8) -> bool  (SysV: a=rdi, b=rsi)
    let code = asm(0x1000, |a| {
        a.movdqu(xmm0, xmmword_ptr(rdi)).unwrap();
        a.movdqu(xmm1, xmmword_ptr(rsi)).unwrap();
        a.pcmpeqb(xmm1, xmm0).unwrap();
        a.pmovmskb(eax, xmm1).unwrap();
        a.cmp(eax, 0xffff).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(0x4000, b"n0_debugger_here"); // 16 bytes
    emu.map(0x5000, b"n0_debugger_here");
    emu.map(0x6000, b"n0_debugger_XXXX");
    assert_eq!(emu.call(0x1000, &[0x4000, 0x5000], Abi::SysV).unwrap(), 1);
    assert_eq!(emu.call(0x1000, &[0x4000, 0x6000], Abi::SysV).unwrap(), 0);
}

/// SSE2 moves and bitwise ops: pxor zeros a register, a 128-bit store/load round-trips, and
/// movd/movq shuttle a scalar in and back out of an xmm register.
#[test]
fn sse2_move_xor_and_scalar() {
    let code = asm(0x1000, |a| {
        a.pxor(xmm0, xmm0).unwrap(); // xmm0 = 0
        a.movdqu(xmmword_ptr(0x5000u64), xmm0).unwrap(); // store 16 zero bytes
        a.movd(xmm1, edi).unwrap(); // xmm1.low32 = arg0
        a.movq(rax, xmm1).unwrap(); // rax = xmm1.low64 (upper zero from movd)
        a.ret().unwrap();
    });
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.mem.map_zeroed(0x5000, 16);
    emu.mem.write_bytes(0x5000, &[0xff; 16]);
    assert_eq!(
        emu.call(0x1000, &[0x1234_5678], Abi::SysV).unwrap(),
        0x1234_5678
    );
    // the pxor'd register was stored over the 0xff bytes, zeroing them
    assert_eq!(emu.mem.read(0x5000, 8).unwrap(), 0);
    assert_eq!(emu.mem.read(0x5008, 8).unwrap(), 0);
}

/// REGRESSION. A compare site that walks a **table** is not a key check, and must record nothing.
///
/// `cmp eax, [tbl + i*4]` in a loop compares the input against every entry in the table, so each
/// entry would be recorded as an "expected number" — and any input that appears ANYWHERE in the
/// table then compares equal, which is indistinguishable from a satisfied check. Three unrelated
/// MSVC GUI crackmes were "solved" with the key `252` because their scanned tables contain `0xfc`.
/// A real equality gate tests one value per site, so the scanning site is the one to drop — and its
/// first few entries have to be withdrawn too, since they look like a real gate until the loop
/// comes round again.
#[test]
fn a_compare_site_that_scans_a_table_records_nothing() {
    const GETS: u64 = 0xa000;
    const ATOI: u64 = 0xb000;
    const BUF: u64 = 0x5000;
    const TBL: u64 = 0x6000;
    // gets(buf); n = atoi(buf);
    // for (i = 0; i < 6; i++) if (n == tbl[i]) return 1;   // the scan
    // return n == 777;                                     // a real gate
    let code = asm(0x1000, |a| {
        a.push(rbp).unwrap();
        a.mov(rbp, rsp).unwrap();
        a.mov(rdi, BUF).unwrap();
        a.call(GETS).unwrap();
        a.mov(rdi, BUF).unwrap();
        a.call(ATOI).unwrap();
        a.xor(ecx, ecx).unwrap(); // i
        a.mov(rdx, TBL).unwrap();
        let mut top = a.create_label();
        let mut hit = a.create_label();
        let mut done = a.create_label();
        a.set_label(&mut top).unwrap();
        a.cmp(eax, dword_ptr(rdx + rcx * 4)).unwrap(); // THE SCANNING SITE
        a.je(hit).unwrap();
        a.inc(ecx).unwrap();
        a.cmp(ecx, 6).unwrap();
        a.jb(top).unwrap();
        a.cmp(eax, 777).unwrap(); // a genuine single-value gate, still recorded
        a.jne(done).unwrap();
        a.set_label(&mut hit).unwrap();
        a.mov(eax, 1u32).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
        a.set_label(&mut done).unwrap();
        a.xor(eax, eax).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
    });
    // The table holds 11, 22, 33, 44, 55 and 252 — the last being the value a corpus binary's
    // scanned table really did contain.
    let mut tbl = Vec::new();
    for v in [11u32, 22, 33, 44, 55, 252] {
        tbl.extend_from_slice(&v.to_le_bytes());
    }
    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(BUF, &[0u8; 32]);
    emu.map(TBL, &tbl);
    emu.hook(GETS, orress_emu::stub_for("gets"));
    emu.hook(ATOI, orress_emu::stub_for("atoi"));

    // An input that IS in the scanned table: the run "succeeds", but nothing may be recorded from
    // the scanning site, so there is no equal pair to mistake for a confirmation.
    emu.record_compares(true);
    emu.seed_input(b"252".to_vec());
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        1,
        "the scan found it"
    );
    assert!(
        !emu.int_compares().iter().any(|&(x, y)| x == y),
        "a table scan is not a satisfied check: {:?}",
        emu.int_compares()
    );
    assert!(
        !emu.int_compares()
            .iter()
            .any(|&(_, y)| matches!(y, 11 | 22 | 252)),
        "no table entry may be recorded as an expected key: {:?}",
        emu.int_compares()
    );

    // The genuine single-value gate behind the scan is still recorded, equal pair and all: dropping
    // the scanning site must not cost the real check that follows it.
    emu.record_compares(true);
    emu.seed_input(b"777".to_vec());
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        1,
        "the real gate passed"
    );
    assert!(
        emu.int_compares().contains(&(777, 777)),
        "the real gate is still recorded: {:?}",
        emu.int_compares()
    );
}

/// C++ `cin >> n`: the comparison behind a stream read must be observable.
///
/// The `cin` object appears in 12% of corpus binaries, the largest reader family with no hook, and
/// every oracle after triage needs the input SEEDED — a check whose read is invisible cannot be
/// extracted from, confirmed, or searched, whatever else is improved.
///
/// Two things differ from `scanf("%d", &n)`, and both are load-bearing:
///
/// * the conversion is fixed by the C++ overload rather than parsed from a format string, so there
///   is no format argument to read it from;
/// * `operator>>` returns the STREAM. `while (cin >> n)` tests that result, so returning 0 would
///   end the loop before the check ever ran — the stub has to hand back its first argument.
#[test]
fn a_cpp_stream_numeric_read_is_observable() {
    // The Itanium-ABI mangling of `std::istream::operator>>(int&)`, which is what a libstdc++ or
    // MinGW binary imports.
    const CIN_OP: u64 = 0xb000;
    const CIN_OBJ: u64 = 0x7000;

    // check() { int n; cin >> n; return n == 31337; }
    let code = asm(0x1000, |a| {
        a.push(rbp).unwrap();
        a.mov(rbp, rsp).unwrap();
        a.sub(rsp, 0x20).unwrap();
        a.mov(rdi, CIN_OBJ).unwrap(); // the stream
        a.lea(rsi, qword_ptr(rbp - 4)).unwrap(); // &n
        a.call(CIN_OP).unwrap();
        a.mov(eax, dword_ptr(rbp - 4)).unwrap();
        a.cmp(eax, 31337).unwrap();
        a.sete(al).unwrap();
        a.movzx(eax, al).unwrap();
        a.add(rsp, 0x20).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
    });

    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(CIN_OBJ, &[0u8; 16]);
    emu.hook(CIN_OP, orress_emu::stub_for("_ZNSirsERi"));

    // The right number is accepted, and the comparison that decided it is recorded — which is what
    // the oracle-free confirm stage needs in order to confirm anything at all.
    emu.record_compares(true);
    emu.seed_input(b"31337".to_vec());
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        1,
        "the right number is accepted"
    );
    assert!(
        emu.int_compares().contains(&(31337, 31337)),
        "the numeric comparison must be observable: {:?}",
        emu.int_compares()
    );

    // A wrong number is rejected, and the comparison still reveals the expected value — the
    // differential that makes this a usable oracle rather than a guess.
    emu.record_compares(true);
    emu.seed_input(b"12345".to_vec());
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        0,
        "a wrong number is rejected"
    );
    assert_eq!(emu.int_compares(), [(12345, 31337)]);

    // Non-numeric input converts nothing, exactly as a real stream leaves `n` untouched on a
    // failed extraction, so no equality is recorded.
    emu.record_compares(true);
    emu.seed_input(b"password".to_vec());
    let _ = emu.call(0x1000, &[], Abi::SysV);
    assert!(
        !emu.int_compares().iter().any(|&(x, y)| x == y),
        "nothing was converted, so nothing may compare equal: {:?}",
        emu.int_compares()
    );
}

/// `operator>>` must return the stream, because `while (cin >> n)` tests it.
///
/// Returning a count or zero here looks harmless and is not: the loop would exit on the first
/// iteration and every check inside it would go unexecuted, which is indistinguishable from the
/// binary having no observable check at all.
#[test]
fn a_cpp_stream_read_returns_the_stream_so_a_read_loop_iterates() {
    const CIN_OP: u64 = 0xb000;
    const CIN_OBJ: u64 = 0x7000;

    // if (cin >> n) return 7; else return 0;
    let code = asm(0x1000, |a| {
        a.push(rbp).unwrap();
        a.mov(rbp, rsp).unwrap();
        a.sub(rsp, 0x20).unwrap();
        a.mov(rdi, CIN_OBJ).unwrap();
        a.lea(rsi, qword_ptr(rbp - 4)).unwrap();
        a.call(CIN_OP).unwrap();
        a.test(rax, rax).unwrap();
        let mut fail = a.create_label();
        a.je(fail).unwrap();
        a.mov(eax, 7u32).unwrap();
        a.add(rsp, 0x20).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
        a.set_label(&mut fail).unwrap();
        a.xor(eax, eax).unwrap();
        a.add(rsp, 0x20).unwrap();
        a.pop(rbp).unwrap();
        a.ret().unwrap();
    });

    let mut emu = Emulator::new();
    emu.map(0x1000, &code);
    emu.map(CIN_OBJ, &[0u8; 16]);
    emu.hook(CIN_OP, orress_emu::stub_for("_ZNSirsERi"));
    emu.record_compares(true);
    emu.seed_input(b"42".to_vec());
    assert_eq!(
        emu.call(0x1000, &[], Abi::SysV).unwrap(),
        7,
        "the stream must come back truthy or the read loop never runs"
    );
}
