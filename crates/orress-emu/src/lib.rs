//! A small, pure-Rust x86-64 emulator built on iced-x86's decoder.
//!
//! It exists for the reverse-engineering jobs that need to *run* code, not just read it:
//! "run this function with these arguments" (string decryptors, CTF check functions), counting
//! instructions per input for side-channel solving, and single-stepping. It is deliberately
//! dependency-light (only iced-x86) and interprets a pragmatic integer/branch/stack/memory
//! subset — the instructions real crackme check routines use — faulting clearly on anything it
//! does not yet model, so coverage gaps are visible rather than silently wrong.
//!
//! This is the Rust-first counterpart to a Unicorn/QEMU back end: it composes with the rest of
//! ORRESS (no C toolchain) and is the base the side-channel and symbolic solvers build on.

#![allow(clippy::cast_possible_truncation)]

mod cpu;
mod exec;
mod mem;
mod solve;
pub mod trace;

pub use cpu::{Cpu, Flags};
pub use mem::Memory;
pub use solve::{MAX_SOLVE_LEN, Solution, SolveStep, solve_by_count};
pub use trace::{Trace, TraceStep};

/// Something the emulator could not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmuError {
    /// Access to unmapped memory at this address.
    Fault(u64),
    /// The bytes at this address did not decode to a valid instruction.
    InvalidInstruction(u64),
    /// A decoded instruction the interpreter does not model yet.
    Unsupported { addr: u64, mnemonic: String },
    /// Division by zero.
    DivideByZero(u64),
    /// The quotient did not fit the destination (x86 #DE), including INT_MIN / -1.
    DivideOverflow(u64),
}

impl std::fmt::Display for EmuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fault(a) => write!(f, "memory fault at {a:#x}"),
            Self::InvalidInstruction(a) => write!(f, "invalid instruction at {a:#x}"),
            Self::Unsupported { addr, mnemonic } => {
                write!(f, "unsupported instruction {mnemonic} at {addr:#x}")
            }
            Self::DivideByZero(a) => write!(f, "divide by zero at {a:#x}"),
            Self::DivideOverflow(a) => write!(f, "divide overflow at {a:#x}"),
        }
    }
}

impl std::error::Error for EmuError {}

/// Why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Reached the requested stop address (e.g. a function returned to the sentinel).
    Target(u64),
    /// Hit a set breakpoint.
    Breakpoint(u64),
    /// Ran out of the step budget.
    StepLimit,
}

/// Upper bound on bytes a single libc-stub (malloc/memset/…) will allocate or touch, so a
/// guest-controlled size can't exhaust host memory or spin an effectively unbounded loop.
const STUB_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// A stub that stands in for an imported library function, so calls into code we don't have
/// (libc / WinAPI) return something sensible instead of faulting. Arguments are read from the
/// current ABI's argument registers; the result goes in RAX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stub {
    /// Set RAX to a constant and return (the catch-all for unmodelled imports).
    Return(u64),
    /// `strlen(s)`.
    Strlen,
    /// `strcmp(a, b)` → 0 if equal.
    Strcmp,
    /// `strncmp(a, b, n)`.
    Strncmp,
    /// `memcmp(a, b, n)`.
    Memcmp,
    /// `memcpy(dst, src, n)` → dst.
    Memcpy,
    /// `memset(dst, c, n)` → dst.
    Memset,
    /// `strcpy(dst, src)` → dst.
    Strcpy,
    /// `atoi(s)` → parsed decimal integer.
    Atoi,
    /// `malloc(n)` → a fresh zeroed region (bump-allocated).
    Malloc,
}

/// The stub for an imported function, by name (leading underscores ignored): the libc routines a
/// check function typically calls get a real model, everything else returns 0. Shared by every
/// front end that seeds an emulator from a loaded program (see `orress_vm::import_hooks`).
pub fn stub_for(name: &str) -> Stub {
    match name.trim_start_matches('_') {
        "strlen" => Stub::Strlen,
        "strcmp" => Stub::Strcmp,
        "strncmp" => Stub::Strncmp,
        "memcmp" | "bcmp" => Stub::Memcmp,
        "memcpy" | "memmove" => Stub::Memcpy,
        "memset" => Stub::Memset,
        "strcpy" => Stub::Strcpy,
        "atoi" | "strtol" => Stub::Atoi,
        "malloc" | "calloc" => Stub::Malloc,
        _ => Stub::Return(0),
    }
}

/// C `atoi`: skips leading whitespace, takes an optional sign, then the leading decimal digits
/// (`"123abc"` -> 123, `"  -42"` -> -42, `"x1"` -> 0). Overflow wraps rather than panicking.
pub fn parse_atoi(s: &[u8]) -> i64 {
    let mut it = s
        .iter()
        .copied()
        .skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .peekable();
    let neg = match it.peek() {
        Some(b'-') => {
            it.next();
            true
        }
        Some(b'+') => {
            it.next();
            false
        }
        _ => false,
    };
    let mut v: i64 = 0;
    for c in it.take_while(u8::is_ascii_digit) {
        v = v.wrapping_mul(10).wrapping_add(i64::from(c - b'0'));
    }
    if neg { v.wrapping_neg() } else { v }
}

/// Where [`setup_tls`] places the SysV thread block (`fs_base`).
pub const TLS_BASE: u64 = 0x7ffd_0000_0000;
/// Where [`setup_tls`] places the fake Win64 TEB (`gs_base`).
pub const TEB_BASE: u64 = 0x7ffd_0001_0000;
/// Where [`setup_tls`] places the (zeroed) fake Win64 PEB that `gs:[0x60]` points at.
pub const PEB_BASE: u64 = 0x7ffd_0002_0000;
/// The stack-protector canary stored at `fs:[0x28]` (low byte 0, like glibc's).
pub const STACK_CANARY: u64 = 0x5ca1_ab1e_c0de_7700;

/// Maps a minimal thread environment so segment-relative loads don't fault: a SysV TCB at
/// [`TLS_BASE`] (self-pointer at `fs:0`/`fs:0x10`, canary at `fs:0x28`) and a Win64 TEB at
/// [`TEB_BASE`] (self-pointer at `gs:0x30`, PEB pointer at `gs:0x60`). Returns `(fs_base, gs_base)`.
/// Used by [`Emulator::setup_stack`] and by the symbolic executor.
pub fn setup_tls(mem: &mut Memory) -> (u64, u64) {
    mem.map_zeroed(TLS_BASE, 0x1000);
    mem.map_zeroed(TEB_BASE, 0x2000);
    mem.map_zeroed(PEB_BASE, 0x1000);
    // Every page was just mapped, so these writes cannot fault.
    let _ = mem.write(TLS_BASE, TLS_BASE, 8);
    let _ = mem.write(TLS_BASE + 0x10, TLS_BASE, 8);
    let _ = mem.write(TLS_BASE + 0x28, STACK_CANARY, 8);
    let _ = mem.write(TEB_BASE + 0x30, TEB_BASE, 8);
    let _ = mem.write(TEB_BASE + 0x60, PEB_BASE, 8);
    (TLS_BASE, TEB_BASE)
}

/// Calling convention for [`Emulator::call`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    /// Windows x64: rcx, rdx, r8, r9.
    Win64,
    /// System V (Linux/macOS): rdi, rsi, rdx, rcx, r8, r9.
    SysV,
}

/// C-style comparison result (0 equal, 1 / -1 as u64) for strcmp/memcmp stubs.
fn cmp_result(a: &[u8], b: &[u8]) -> u64 {
    match a.cmp(b) {
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Less => (-1i64) as u64,
        std::cmp::Ordering::Greater => 1,
    }
}

impl Abi {
    /// The register carrying integer/pointer argument `i` (0-based), or `None` past the
    /// register-argument count (the rest would come from the stack).
    pub fn arg_reg(self, i: usize) -> Option<iced_x86::Register> {
        use iced_x86::Register::*;
        let regs: &[iced_x86::Register] = match self {
            Self::Win64 => &[RCX, RDX, R8, R9],
            Self::SysV => &[RDI, RSI, RDX, RCX, R8, R9],
        };
        regs.get(i).copied()
    }

    /// How many integer arguments travel in registers.
    pub fn reg_arg_count(self) -> usize {
        match self {
            Self::Win64 => 4,
            Self::SysV => 6,
        }
    }

    /// Bytes the caller reserves above the return address before the stack arguments (Win64's
    /// 32-byte home/shadow space; none for System V).
    pub fn shadow_space(self) -> u64 {
        match self {
            Self::Win64 => 32,
            Self::SysV => 0,
        }
    }
}

/// The address a called function "returns to"; the run stops when RIP reaches it.
const SENTINEL: u64 = 0x1337_0000_0000_0000;
/// Where [`Emulator::setup_stack`] puts the stack top by default.
const DEFAULT_STACK_TOP: u64 = 0x7fff_0000_0000;
const DEFAULT_STACK_SIZE: u64 = 0x10_0000; // 1 MiB

/// The emulator: a CPU, its memory, and a running instruction count.
pub struct Emulator {
    pub cpu: Cpu,
    pub mem: Memory,
    /// Total instructions executed since the last reset (the side-channel signal).
    pub steps: u64,
    /// Addresses to stop at before executing.
    pub breakpoints: Vec<u64>,
    /// The per-run step budget, to bound runaway loops.
    pub budget: u64,
    /// The ABI the current run uses (how stubs read their arguments).
    pub abi: Abi,
    /// Import stubs, keyed by the address a call to that import lands on.
    pub hooks: std::collections::HashMap<u64, Stub>,
    /// The next address `malloc` hands out (a simple bump allocator).
    heap: u64,
}

impl Default for Emulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Emulator {
    pub fn new() -> Self {
        Self {
            cpu: Cpu::new(),
            mem: Memory::new(),
            steps: 0,
            breakpoints: Vec::new(),
            budget: 10_000_000,
            abi: Abi::SysV,
            hooks: std::collections::HashMap::new(),
            heap: 0x2000_0000,
        }
    }

    /// Registers an import stub at `addr` (the address a call to that import reaches).
    pub fn hook(&mut self, addr: u64, stub: Stub) {
        self.hooks.insert(addr, stub);
    }

    /// Reads a NUL-terminated string from guest memory (bounded), for stubs and results.
    pub fn read_cstr(&self, addr: u64, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..max as u64 {
            match self.mem.read_u8(addr.wrapping_add(i)) {
                Ok(0) | Err(_) => break,
                Ok(b) => out.push(b),
            }
        }
        out
    }

    fn arg(&self, i: usize) -> u64 {
        self.abi.arg_reg(i).map(|r| self.cpu.reg(r)).unwrap_or(0)
    }

    /// Applies an import stub: reads arguments, computes the result into RAX, and returns to
    /// the caller (popping the return address the `call` pushed).
    pub(crate) fn apply_stub(&mut self, stub: &Stub) -> Result<(), EmuError> {
        let result = match stub {
            Stub::Return(v) => *v,
            Stub::Strlen => self.read_cstr(self.arg(0), 1 << 20).len() as u64,
            Stub::Strcmp => {
                let a = self.read_cstr(self.arg(0), 1 << 20);
                let b = self.read_cstr(self.arg(1), 1 << 20);
                cmp_result(&a, &b)
            }
            Stub::Strncmp => {
                let n = self.arg(2) as usize;
                let a = self.read_cstr(self.arg(0), n);
                let b = self.read_cstr(self.arg(1), n);
                cmp_result(&a, &b)
            }
            Stub::Memcmp => {
                let n = self.arg(2) as usize;
                let a = self.mem.read_vec(self.arg(0), n)?;
                let b = self.mem.read_vec(self.arg(1), n)?;
                cmp_result(&a, &b)
            }
            Stub::Memcpy => {
                let (dst, src, n) = (self.arg(0), self.arg(1), self.arg(2) as usize);
                let bytes = self.mem.read_vec(src, n)?;
                self.mem.write_slice(dst, &bytes)?;
                dst
            }
            Stub::Memset => {
                // Cap the guest-controlled length so a bogus size can't spin a multi-GB loop.
                let (dst, c, n) = (
                    self.arg(0),
                    self.arg(1) as u8,
                    self.arg(2).min(STUB_MAX_BYTES),
                );
                for i in 0..n {
                    self.mem.write_u8(dst.wrapping_add(i), c)?;
                }
                dst
            }
            Stub::Strcpy => {
                let (dst, src) = (self.arg(0), self.arg(1));
                let bytes = self.read_cstr(src, 1 << 20);
                self.mem.write_slice(dst, &bytes)?;
                // wrapping_add: dst + len can overflow u64 (debug panic) for a wild pointer.
                self.mem.write_u8(dst.wrapping_add(bytes.len() as u64), 0)?;
                dst
            }
            Stub::Atoi => {
                let s = self.read_cstr(self.arg(0), 64);
                parse_atoi(&s) as u64
            }
            Stub::Malloc => {
                // Cap the request and use saturating math so a huge/overflowing size can't OOM
                // or panic; real crackme allocations are tiny.
                let size = self.arg(0).clamp(1, STUB_MAX_BYTES);
                let addr = self.heap;
                self.heap = self.heap.saturating_add(size).saturating_add(15) & !15;
                self.mem.map_zeroed(addr, size);
                addr
            }
        };
        let ret = self.pop_ret()?;
        self.cpu.regs[0] = result; // RAX
        self.cpu.rip = ret;
        Ok(())
    }

    /// Pops the return address (used by stubs; mirrors a `ret`).
    fn pop_ret(&mut self) -> Result<u64, EmuError> {
        let sp = self.cpu.rsp();
        let v = self.mem.read(sp, 8)?;
        self.cpu.set_rsp(sp.wrapping_add(8));
        Ok(v)
    }

    /// Loads code or data bytes at `addr`.
    pub fn map(&mut self, addr: u64, bytes: &[u8]) {
        self.mem.write_bytes(addr, bytes);
    }

    /// Reserves a zero-filled stack and points RSP near its top (16-byte aligned, with some
    /// headroom so a prologue's `sub rsp` / pushes stay in bounds). Also maps the thread
    /// environment ([`setup_tls`]) and points FS/GS at it, unless a base was already set.
    /// Returns the stack top.
    pub fn setup_stack(&mut self) -> u64 {
        let top = DEFAULT_STACK_TOP;
        self.mem
            .map_zeroed(top - DEFAULT_STACK_SIZE, DEFAULT_STACK_SIZE);
        let sp = (top - 0x100) & !0xf;
        self.cpu.set_rsp(sp);
        if self.cpu.fs_base == 0 && self.cpu.gs_base == 0 {
            let (fs, gs) = setup_tls(&mut self.mem);
            self.cpu.fs_base = fs;
            self.cpu.gs_base = gs;
        }
        top
    }

    /// Executes one instruction at RIP.
    pub fn step(&mut self) -> Result<(), EmuError> {
        let ip = self.cpu.rip;
        let mut buf = [0u8; 16];
        let mut n = 0;
        while n < 16 {
            match self.mem.read_u8(ip.wrapping_add(n as u64)) {
                Ok(b) => {
                    buf[n] = b;
                    n += 1;
                }
                Err(_) => break,
            }
        }
        if n == 0 {
            return Err(EmuError::Fault(ip));
        }
        let mut dec = iced_x86::Decoder::with_ip(64, &buf[..n], ip, iced_x86::DecoderOptions::NONE);
        let instr = dec.decode();
        if instr.is_invalid() {
            return Err(EmuError::InvalidInstruction(ip));
        }
        self.cpu.rip = instr.next_ip();
        self.steps += 1;
        self.exec(&instr)
    }

    /// Runs until RIP reaches `stop` (if given), a breakpoint, or the step budget.
    pub fn run_until(&mut self, stop: Option<u64>) -> Result<Stop, EmuError> {
        for _ in 0..self.budget {
            let ip = self.cpu.rip;
            if Some(ip) == stop {
                return Ok(Stop::Target(ip));
            }
            if self.breakpoints.contains(&ip) {
                return Ok(Stop::Breakpoint(ip));
            }
            if let Some(stub) = self.hooks.get(&ip).cloned() {
                self.apply_stub(&stub)?;
                self.steps += 1;
                continue;
            }
            self.step()?;
        }
        Ok(Stop::StepLimit)
    }

    /// Calls `func` with `args`, returning the value in RAX. Sets up the stack if RSP is 0,
    /// passes the arguments per `abi` (registers first, the rest on the stack), pushes a sentinel
    /// return address, and runs until the function returns to it.
    pub fn call(&mut self, func: u64, args: &[u64], abi: Abi) -> Result<u64, EmuError> {
        self.prepare_call(func, args, abi)?;
        self.run_until(Some(SENTINEL))?;
        Ok(self.cpu.rax())
    }

    /// The common call setup: ABI, stack, argument registers, stack arguments, the sentinel
    /// return address, and RIP.
    ///
    /// Stack layout at entry (RSP = 8 mod 16, as after a real `call`): `[rsp]` = return address,
    /// then (Win64 only) the 32-byte shadow space, then the stack arguments in ascending addresses.
    fn prepare_call(&mut self, func: u64, args: &[u64], abi: Abi) -> Result<(), EmuError> {
        self.abi = abi;
        if self.cpu.rsp() == 0 {
            self.setup_stack();
        }
        let nregs = abi.reg_arg_count();
        for (i, &a) in args.iter().take(nregs).enumerate() {
            if let Some(r) = abi.arg_reg(i) {
                self.cpu.set_reg(r, a);
            }
        }
        let extra = args.get(nregs..).unwrap_or(&[]);
        // The argument area (shadow space + stack args), kept a multiple of 16 so the callee sees
        // the ABI's entry alignment.
        let area = (abi.shadow_space() + 8 * extra.len() as u64 + 15) & !15;
        let base = (self.cpu.rsp() & !0xf).wrapping_sub(area);
        for (i, &a) in extra.iter().enumerate() {
            let slot = base
                .wrapping_add(abi.shadow_space())
                .wrapping_add(8 * i as u64);
            self.mem.write(slot, a, 8)?;
        }
        // Push the sentinel return address.
        let sp = base.wrapping_sub(8);
        self.mem.write(sp, SENTINEL, 8)?;
        self.cpu.set_rsp(sp);
        self.cpu.rip = func;
        self.steps = 0;
        Ok(())
    }

    /// Runs from the current state like [`Emulator::run_until`], but records a per-instruction CPU
    /// snapshot for time-travel debugging (bounded by `max_steps`). See [`trace::Trace`].
    ///
    /// A fault is returned as an error and the recorded steps are dropped; prefer
    /// [`Emulator::record_with_fault`], which keeps them.
    pub fn record(
        &mut self,
        stop: Option<u64>,
        max_steps: usize,
    ) -> Result<trace::Trace, EmuError> {
        let t = self.record_with_fault(stop, max_steps);
        match t.fault {
            Some(e) => Err(e),
            None => Ok(t),
        }
    }

    /// Like [`Emulator::record`], but never discards the recording: if a step faults, the
    /// returned trace holds every step executed before it and the error in [`trace::Trace::fault`].
    pub fn record_with_fault(&mut self, stop: Option<u64>, max_steps: usize) -> trace::Trace {
        let initial = self.cpu.clone();
        let mut steps = Vec::new();
        let mut outcome = Stop::StepLimit;
        let mut fault = None;
        for _ in 0..max_steps {
            let ip = self.cpu.rip;
            if Some(ip) == stop {
                outcome = Stop::Target(ip);
                break;
            }
            if self.breakpoints.contains(&ip) {
                outcome = Stop::Breakpoint(ip);
                break;
            }
            let r = if let Some(stub) = self.hooks.get(&ip).cloned() {
                self.apply_stub(&stub).map(|()| self.steps += 1)
            } else {
                self.step()
            };
            if let Err(e) = r {
                fault = Some(e);
                break;
            }
            steps.push(trace::TraceStep {
                addr: ip,
                cpu: self.cpu.clone(),
            });
        }
        trace::Trace {
            initial,
            steps,
            stop: outcome,
            fault,
        }
    }

    /// Calls `func` like [`Emulator::call`] but records the whole execution as a [`trace::Trace`].
    /// A fault is an error (the steps are dropped); see [`Emulator::record_call_with_fault`].
    pub fn record_call(
        &mut self,
        func: u64,
        args: &[u64],
        abi: Abi,
        max_steps: usize,
    ) -> Result<trace::Trace, EmuError> {
        self.prepare_call(func, args, abi)?;
        self.record(Some(SENTINEL), max_steps)
    }

    /// Calls `func` like [`Emulator::record_call`], keeping the recorded steps when the run
    /// faults (the error is in [`trace::Trace::fault`]). `Err` only if the call could not be set
    /// up at all (e.g. the stack is unmapped).
    pub fn record_call_with_fault(
        &mut self,
        func: u64,
        args: &[u64],
        abi: Abi,
        max_steps: usize,
    ) -> Result<trace::Trace, EmuError> {
        self.prepare_call(func, args, abi)?;
        Ok(self.record_with_fault(Some(SENTINEL), max_steps))
    }
}
