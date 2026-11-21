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

/// How many distinct watched addresses one run records before it stops collecting — a bound on the
/// trace's memory for a program with a very large code base. See [`Emulator::trace_sites`].
const MAX_TRACED_SITES: usize = 4096;

/// What an input-reading stub ([`Stub::ReadInput`]) returns in RAX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputReturn {
    /// The destination buffer pointer — `gets`/`fgets` return it.
    Buffer,
    /// A fixed success count — e.g. `scanf`'s number of conversions, or a WinAPI `BOOL`.
    Count(u64),
    /// The number of input bytes read — `read`/`fread` return a byte/element count.
    Len,
}

/// A stub that stands in for an imported library function, so calls into code we don't have
/// (libc / WinAPI) return something sensible instead of faulting. Arguments are read from the
/// current ABI's argument registers; the result goes in RAX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stub {
    /// Set RAX to a constant and return (the catch-all for unmodelled imports).
    Return(u64),
    /// An input read into a caller-supplied buffer (`gets`/`fgets`/`scanf`/`read`/…). The
    /// destination pointer is argument `buf_arg`; the symbolic executor marks that buffer as the
    /// symbolic input region so the subsequent checks become constraints on the input. (The
    /// concrete emulator has no real stdin, so it only returns a plausible value.)
    ///
    /// `fmt_arg` is the argument index of a `scanf`-family format string, when the function has
    /// one. It decides whether the destination is a character buffer or a *number*: for
    /// `scanf("%d", &n)` the seed's digits must be parsed and stored as a binary integer rather
    /// than copied in as text (see [`scanf_num_conv`]).
    ReadInput {
        buf_arg: usize,
        fmt_arg: Option<usize>,
        ret: InputReturn,
    },
    /// `operator>>(istream&, T&)` — C++ `cin >> n` for an integer `n`.
    ///
    /// Unlike [`Stub::ReadInput`], the conversion is fixed by the overload's own type rather than
    /// read from a format string, and the result is the **stream** (argument 0), because
    /// `while (cin >> n)` tests it: returning 0 would end the loop before the check ran.
    ///
    /// `dst_arg` is the reference the parsed value is written through, and the destination is
    /// tagged as the numeric input so the comparison behind it is observable
    /// (see [`Emulator::int_compares`]).
    ReadNumInto {
        dst_arg: usize,
        conv: NumConv,
        ret_arg: usize,
    },
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
    /// The length of the input, with no argument to read it from — `GetWindowTextLengthA`, which a
    /// GUI check calls to length-gate the edit box before reading it.
    InputLen,
    /// The input *as a number*, returned directly rather than written to a buffer —
    /// `GetDlgItemInt`, the GUI counterpart of `atoi`. The result is tagged as the numeric input so
    /// the comparison behind it is observable (see [`Emulator::int_compares`]).
    InputNum,
    /// `malloc(n)` → a fresh zeroed region (bump-allocated).
    Malloc,
}

/// The stub for an imported function, by name (leading underscores ignored): the libc routines a
/// check function typically calls get a real model, everything else returns 0. Shared by every
/// front end that seeds an emulator from a loaded program (see `orress_vm::import_hooks`).
pub fn stub_for(name: &str) -> Stub {
    match name.trim_start_matches('_') {
        "strlen" => Stub::Strlen,
        // Byte-string comparisons. Case-insensitive and Windows-named variants map to the same
        // stubs: the compare-hook only needs their operands recorded (the exact case-folding of the
        // return value doesn't affect which value the input was checked against).
        "strcmp" | "strcasecmp" | "stricmp" | "strcmpi" | "lstrcmp" | "lstrcmpA" | "lstrcmpiA" => {
            Stub::Strcmp
        }
        "strncmp" | "strncasecmp" | "strnicmp" => Stub::Strncmp,
        "memcmp" | "bcmp" => Stub::Memcmp,
        "memcpy" | "memmove" => Stub::Memcpy,
        "memset" => Stub::Memset,
        "strcpy" => Stub::Strcpy,
        "atoi" | "strtol" | "strtoul" => Stub::Atoi,
        "malloc" | "calloc" => Stub::Malloc,
        // Input readers: mark the destination buffer as symbolic input (and, under the compare-hook,
        // write the seed into it). Buffer-pointer argument index differs per function.
        "gets" | "gets_s" | "fgets" => Stub::ReadInput {
            buf_arg: 0,
            fmt_arg: None,
            ret: InputReturn::Buffer,
        },
        "scanf" | "isoc99_scanf" | "scanf_s" => Stub::ReadInput {
            buf_arg: 1,
            fmt_arg: Some(0),
            ret: InputReturn::Count(1),
        },
        // fscanf(FILE*, fmt, dst): the first %s target is the third argument.
        "fscanf" | "isoc99_fscanf" => Stub::ReadInput {
            buf_arg: 2,
            fmt_arg: Some(1),
            ret: InputReturn::Count(1),
        },
        "read" => Stub::ReadInput {
            buf_arg: 1,
            fmt_arg: None,
            ret: InputReturn::Len,
        },
        "fread" => Stub::ReadInput {
            buf_arg: 0,
            fmt_arg: None,
            ret: InputReturn::Len,
        },
        "ReadConsoleA" | "ReadConsoleW" => Stub::ReadInput {
            buf_arg: 1,
            fmt_arg: None,
            ret: InputReturn::Count(1),
        },
        // ReadFile(handle, buf, n, &read, ov): the destination buffer is the second argument.
        "ReadFile" => Stub::ReadInput {
            buf_arg: 1,
            fmt_arg: None,
            ret: InputReturn::Count(1),
        },
        // GUI edit-box reads — the largest single reader family in the crackme corpus, and the one
        // the sandbox can never drive (a dialog app has no stdin to pipe a guess into), so the
        // emulated check is the only oracle available for these.
        // GetWindowTextA(hwnd, buf, max) -> length copied.
        "GetWindowTextA" => Stub::ReadInput {
            buf_arg: 1,
            fmt_arg: None,
            ret: InputReturn::Len,
        },
        // GetDlgItemTextA(hwnd, id, buf, max) -> length copied.
        "GetDlgItemTextA" => Stub::ReadInput {
            buf_arg: 2,
            fmt_arg: None,
            ret: InputReturn::Len,
        },
        // C++ `cin >> n`. These are the Itanium-ABI manglings libstdc++ and MinGW emit for
        // `std::istream::operator>>`, one per integer type; the trailing letter is the argument
        // type (`i` int, `j` unsigned, `s` short, `x` long long, …). `l`/`m` (long) are mapped at
        // 4 bytes, which is right for 32-bit targets and for Windows x64, but wrong for the LP64
        // Unixes — a 64-bit Linux binary will read the low half. MSVC's mangling is not matched
        // yet; it encodes the full template signature and needs a different approach.
        "ZNSirsERi" => Stub::read_num_ref(4, true),
        "ZNSirsERj" => Stub::read_num_ref(4, false),
        "ZNSirsERs" => Stub::read_num_ref(2, true),
        "ZNSirsERt" => Stub::read_num_ref(2, false),
        "ZNSirsERl" => Stub::read_num_ref(4, true),
        "ZNSirsERm" => Stub::read_num_ref(4, false),
        "ZNSirsERx" => Stub::read_num_ref(8, true),
        "ZNSirsERy" => Stub::read_num_ref(8, false),
        "GetWindowTextLengthA" | "GetWindowTextLengthW" => Stub::InputLen,
        // GetDlgItemInt(hwnd, id, &translated, signed) -> the parsed number itself.
        "GetDlgItemInt" => Stub::InputNum,
        _ => Stub::Return(0),
    }
}

impl Stub {
    /// `operator>>(istream&, T&)` for an integer of `width` bytes.
    ///
    /// The stream is argument 0 (the implicit `this`) and the destination reference is argument 1.
    /// Base 10: a C++ stream reads decimal unless the caller changed the format flags, which is
    /// rare in a crackme and invisible from the call alone.
    fn read_num_ref(width: usize, _signed: bool) -> Self {
        Self::ReadNumInto {
            dst_arg: 1,
            conv: NumConv {
                width,
                radix: 10,
                float: false,
            },
            ret_arg: 0,
        }
    }
}

/// Whether a function with this name is a compare-hook **oracle** worth hooking even when it is
/// *statically linked* (not an import): the input readers (so the seed is injected into the buffer)
/// and the comparators / `strlen` (so the recorded operands and any length gate are observed).
///
/// Deliberately narrow. Statically-linked MinGW/MSVC binaries compile `scanf`/`strcmp`/`strlen` in,
/// so an import-only hook table misses the oracle entirely and the compare-hook sees nothing. But
/// hooking *computational* helpers (`memcpy`/`memset`/`malloc`/`strcpy`/`atoi`) by name would risk
/// replacing a keygen's own arithmetic with a stub, so those stay import-only — their real code runs.
pub fn is_oracle_name(name: &str) -> bool {
    matches!(
        stub_for(name),
        Stub::ReadInput { .. }
            | Stub::ReadNumInto { .. }
            | Stub::Strcmp
            | Stub::Strncmp
            | Stub::Memcmp
            | Stub::Strlen
    )
}

/// A **numeric** `scanf` conversion: how wide the destination is, and how input text parses into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumConv {
    /// Destination width in bytes (`%hd` -> 2, `%d` -> 4, `%lld` -> 8, `%lf` -> 8).
    pub width: usize,
    /// Number base of an integer conversion (10 for `%d`/`%u`, 16 for `%x`, 8 for `%o`).
    pub radix: u32,
    /// `%f`/`%e`/`%g`: the destination holds an IEEE float of `width` bytes, not an integer.
    pub float: bool,
}

/// The first *assigned* conversion of a `scanf`-family format string, when it is **numeric**.
/// `None` for `%s`/`%c`/`%[...]`/`%p` (the destination is a character buffer, so seed bytes go in
/// verbatim) and for a format with no conversion at all.
///
/// This is what makes `scanf("%d", &n)` work under the compare-hook: the destination is a 4-byte
/// int, so writing the seed *text* (`"25711"`) there would leave `n == 0x31373532` and the check
/// comparing against ASCII garbage. Knowing the conversion, the stub stores the parsed value.
///
/// `%ld` is deliberately treated as 4 bytes: where a C `long` really is 8 (SysV x86-64) its slot
/// sits in zeroed stack memory, so a 4-byte store of a small value still reads back correctly —
/// whereas an 8-byte store into a genuine 4-byte `int` would clobber the neighbouring variable.
/// `ll`/`j`/`z`/`t`/`I64` are a real 8 bytes.
pub fn scanf_num_conv(fmt: &[u8]) -> Option<NumConv> {
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if fmt.get(i) == Some(&b'%') {
            i += 1; // a literal percent sign, not a conversion
            continue;
        }
        // `%*d` consumes input without storing it, so the first destination argument belongs to a
        // later conversion: parse this spec, but don't report it.
        let suppressed = fmt.get(i) == Some(&b'*');
        if suppressed {
            i += 1;
        }
        while fmt.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1; // maximum field width
        }
        let (mut hs, mut ls) = (0usize, 0usize);
        loop {
            match fmt.get(i) {
                Some(b'h') => hs += 1,
                Some(b'l') => ls += 1,
                Some(b'L' | b'j' | b'z' | b't') => ls = 2,
                Some(b'I') if fmt[i..].starts_with(b"I64") => {
                    ls = 2;
                    i += 2;
                }
                Some(b'I') if fmt[i..].starts_with(b"I32") => i += 2,
                _ => break,
            }
            i += 1;
        }
        let conv = *fmt.get(i)?;
        i += 1;
        if suppressed {
            continue;
        }
        let int_width = match (hs, ls) {
            (2.., _) => 1,
            (1, _) => 2,
            (_, 2..) => 8,
            _ => 4,
        };
        let int = |radix| {
            Some(NumConv {
                width: int_width,
                radix,
                float: false,
            })
        };
        return match conv {
            b'd' | b'i' | b'u' => int(10),
            b'x' | b'X' => int(16),
            b'o' => int(8),
            b'f' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => Some(NumConv {
                width: if ls > 0 { 8 } else { 4 },
                radix: 10,
                float: true,
            }),
            // %s, %c, %[set], %p, %n: not a numeric destination.
            _ => None,
        };
    }
    None
}

/// Parses seed text for a numeric `scanf` conversion into the value its destination should hold:
/// leading whitespace, an optional sign, then digits in the conversion's base (trailing junk is
/// ignored, as `scanf` does). A float comes back as IEEE bits of the conversion's width.
///
/// `None` when the text holds no digits at all — a real `scanf` would convert nothing, so the stub
/// leaves the destination alone and reports zero conversions. That is what makes a non-numeric
/// candidate correctly *fail* a numeric check instead of landing arbitrary bytes in an int.
pub fn parse_num(text: &[u8], conv: &NumConv) -> Option<u64> {
    let s = std::str::from_utf8(text).ok()?.trim();
    if conv.float {
        let end = s
            .find(|c: char| !(c.is_ascii_digit() || "+-.eE".contains(c)))
            .unwrap_or(s.len());
        let v: f64 = s[..end].parse().ok()?;
        return Some(if conv.width == 4 {
            u64::from((v as f32).to_bits())
        } else {
            v.to_bits()
        });
    }
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let rest = if conv.radix == 16 {
        rest.strip_prefix("0x")
            .or_else(|| rest.strip_prefix("0X"))
            .unwrap_or(rest)
    } else {
        rest
    };
    let end = rest
        .find(|c: char| !c.is_digit(conv.radix))
        .unwrap_or(rest.len());
    let mag = u64::from_str_radix(rest.get(..end)?, conv.radix).ok()?;
    Some(if neg {
        (mag as i64).wrapping_neg() as u64
    } else {
        mag
    })
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
    /// 32-bit x86 cdecl/stdcall: all integer arguments on the stack (`[esp+4]`, `[esp+8]`, …),
    /// 4-byte pointers. (For *reading* arguments cdecl and stdcall are identical; who cleans the
    /// stack afterward doesn't matter to the solver.)
    Cdecl,
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
            Self::Cdecl => &[], // all arguments on the stack
        };
        regs.get(i).copied()
    }

    /// How many integer arguments travel in registers.
    pub fn reg_arg_count(self) -> usize {
        match self {
            Self::Win64 => 4,
            Self::SysV => 6,
            Self::Cdecl => 0,
        }
    }

    /// Bytes the caller reserves above the return address before the stack arguments (Win64's
    /// 32-byte home/shadow space; none for System V or cdecl).
    pub fn shadow_space(self) -> u64 {
        match self {
            Self::Win64 => 32,
            Self::SysV | Self::Cdecl => 0,
        }
    }

    /// Pointer / stack-slot width in bytes: 8 for the 64-bit ABIs, 4 for 32-bit cdecl.
    pub fn ptr_size(self) -> u64 {
        match self {
            Self::Win64 | Self::SysV => 8,
            Self::Cdecl => 4,
        }
    }

    /// Whether integer arguments are passed on the stack (cdecl) rather than in registers.
    pub fn stack_args(self) -> bool {
        matches!(self, Self::Cdecl)
    }
}

/// The address a called function "returns to"; the run stops when RIP reaches it. Chosen to fit in
/// 32 bits so a 32-bit cdecl `ret` pops it back intact (a 64-bit value would truncate to 0).
const SENTINEL: u64 = 0x1337_0000;
/// Where [`Emulator::setup_stack`] puts the stack top by default (64-bit ABIs).
const DEFAULT_STACK_TOP: u64 = 0x7fff_0000_0000;
/// Stack top for a **32-bit** ABI. The 64-bit default is not expressible in 32 bits, and 32-bit
/// code computes frame addresses with 32-bit arithmetic: `mov ebp, esp` would keep only
/// `low32(0x7fff_0000_0000 - 0x100)` = `0xffff_ff00`, so every later `[ebp-x]` would land on an
/// unmapped page while the pushes themselves went to the real 64-bit address. Same hazard the
/// [`SENTINEL`] constant already guards against for the return address.
///
/// Matches the address `orress_vm`'s own 32-bit scratch stack uses, and sits in the band its
/// input placement keeps clear.
const DEFAULT_STACK_TOP_32: u64 = 0x7fff_0000;
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
    /// Concrete bytes an input-reading stub (gets/scanf/…) writes into its destination buffer, so
    /// a keygen's serial algorithm runs *forward* on a known input. Empty = read nothing.
    input_seed: Vec<u8>,
    /// When set, every `strcmp`/`strncmp`/`memcmp` records its two operands here — the compare-hook
    /// oracle: a check compares the input against the *expected* value, so the operand that isn't
    /// the seed is the recovered key/serial. The same flag enables *inline* compare detection
    /// (see [`input_region`]/[`byte_expect`]/[`reg_taint`]) for statically-linked checks that
    /// compare the input byte-by-byte without calling a library routine.
    record_compares: bool,
    compares: Vec<(Vec<u8>, Vec<u8>)>,
    /// The call site each [`compares`] entry was recorded at, same order and length. Used only to
    /// recognise a site that SCANS a table of strings — see [`Emulator::record_compare`].
    cmp_sites: Vec<u64>,
    /// Call sites found to be scanning rather than checking: one place comparing the input against
    /// many different strings. Their entries are withdrawn and nothing more is recorded from them.
    ///
    /// The C++ locale's ctype-name lookup is the case that forced this: it compares its argument
    /// against `alnum`, `alpha`, `cntrl`, `digit`, … in a loop, so the compare-hook harvested the
    /// whole table as candidate keys and then "confirmed" the first one, in three unrelated
    /// binaries. Matching all five bytes of `alnum` proves nothing when the code compares against
    /// a table containing it.
    cmp_scan_sites: std::collections::HashSet<u64>,
    /// `[lo, hi)` of the seeded input buffer, so an inline `cmp` against an input byte can be seen.
    input_region: Option<(u64, u64)>,
    /// GPR (64-bit parent) → the input-buffer byte offset it currently holds, tracked across a
    /// byte load so a later `cmp reg, key` reveals the expected byte for that offset.
    reg_taint: std::collections::HashMap<iced_x86::Register, usize>,
    /// Recovered (input offset, expected byte) pairs from inline comparisons.
    byte_expect: Vec<(usize, u8)>,
    /// Length constants a seed-length-valued operand was compared against — a length gate
    /// (`strlen(input) == 19`) the caller can satisfy by re-seeding to that length. See
    /// [`wanted_lens`](Self::wanted_lens).
    wanted_lens: Vec<u64>,
    /// `(address, width)` of the seeded input *as a number*: the destination of a numeric `scanf`
    /// conversion, or a slot the `atoi` result was stored into. The numeric counterpart of
    /// [`input_region`] — an "enter the number" crackme compares a whole integer, not bytes, so
    /// its check is invisible to the per-byte taint.
    num_input: Option<(u64, usize)>,
    /// GPRs (64-bit parent) currently holding the numeric input value.
    reg_num: std::collections::HashSet<iced_x86::Register>,
    /// `(input value, compared-against value)` from whole-value comparisons involving the numeric
    /// input. See [`int_compares`](Self::int_compares).
    int_expect: Vec<(u64, u64)>,
    /// The instruction address each [`int_expect`] entry was recorded at, same order and length.
    /// Only used to recognise a *scanning* compare site — see [`int_scan_sites`].
    int_sites: Vec<u64>,
    /// Compare sites that turned out to be scanning a table rather than gating on a key: one
    /// instruction that compared the input against many different values in a single run. Their
    /// entries are dropped from [`int_expect`] and nothing more is recorded from them.
    ///
    /// This is not a tidy-up. A `cmp eax, [table + i*4]` in a loop makes every value in the table
    /// an "expected number", so any input that appears ANYWHERE in it compares equal — and a
    /// confirmation built on that equality accepts inputs that are not the key. The corpus had
    /// MSVC binaries whose scanned tables contain 252, which is how three unrelated GUI crackmes
    /// all "solved" to 252.
    int_scan_sites: std::collections::HashSet<u64>,
    /// Which call argument carries the numeric input, for a check that is *handed* the parsed
    /// number (`check(int n)`) instead of reading it. Applied by `prepare_call`, which knows where
    /// the ABI puts that argument. See [`seed_num_arg`](Self::seed_num_arg).
    num_arg: Option<usize>,
    /// Addresses whose execution is recorded this run (basic-block starts, for differential
    /// reachability). Empty = no tracing, and the per-instruction check costs nothing.
    traced: std::collections::HashSet<u64>,
    /// Watched addresses reached so far, in first-hit order, each recorded once.
    sites_hit: Vec<u64>,
    /// Membership half of [`sites_hit`], so recording a hit stays O(1).
    sites_seen: std::collections::HashSet<u64>,
    /// How much of a MULTI-LINE seed has been handed out. A keygenme reads twice — a name, then a
    /// serial — so a `name\nserial` seed must arrive one line per read. Only a seed that actually
    /// contains a newline is split this way; a single-line seed is returned whole to every read, as
    /// a check that reads the same password twice expects.
    seed_cursor: usize,
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
            input_seed: Vec::new(),
            record_compares: false,
            compares: Vec::new(),
            cmp_sites: Vec::new(),
            cmp_scan_sites: std::collections::HashSet::new(),
            input_region: None,
            reg_taint: std::collections::HashMap::new(),
            byte_expect: Vec::new(),
            wanted_lens: Vec::new(),
            num_input: None,
            reg_num: std::collections::HashSet::new(),
            int_expect: Vec::new(),
            int_sites: Vec::new(),
            int_scan_sites: std::collections::HashSet::new(),
            num_arg: None,
            traced: std::collections::HashSet::new(),
            sites_hit: Vec::new(),
            sites_seen: std::collections::HashSet::new(),
            seed_cursor: 0,
        }
    }

    /// Sets the concrete bytes each input-reading stub (gets/scanf/fgets/…) writes into its
    /// destination buffer. With a seed set, a keygen's serial algorithm runs *forward* on a known
    /// name, so the comparison that gates success sees the real expected serial — see [`compares`].
    pub fn seed_input(&mut self, seed: impl Into<Vec<u8>>) {
        self.input_seed = seed.into();
        self.seed_cursor = 0;
    }

    /// The bytes the next input-reading stub should hand over. For a multi-line seed that is the
    /// next line, consumed — which is how a keygenme's two reads (name, then serial) each see their
    /// own value; for a single-line seed it is the whole seed, left in place for every read.
    fn next_seed_line(&mut self) -> Vec<u8> {
        if !self.input_seed.contains(&b'\n') {
            return self.input_seed.clone();
        }
        let rest = &self.input_seed[self.seed_cursor.min(self.input_seed.len())..];
        let len = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        let line = rest[..len].to_vec();
        self.seed_cursor += len + usize::from(len < rest.len());
        line
    }

    /// Turns the compare-hook oracle on/off. While on, every `strcmp`/`strncmp`/`memcmp` appends its
    /// two operands to [`compares`](Self::compares) and inline per-byte comparisons against the
    /// seeded input are recorded into [`byte_expect`]. Toggling resets the recorded state.
    pub fn record_compares(&mut self, on: bool) {
        self.record_compares = on;
        self.compares.clear();
        self.cmp_sites.clear();
        self.cmp_scan_sites.clear();
        self.reg_taint.clear();
        self.byte_expect.clear();
        self.wanted_lens.clear();
        self.num_input = None;
        self.reg_num.clear();
        self.int_expect.clear();
        self.int_sites.clear();
        self.int_scan_sites.clear();
        self.num_arg = None;
        self.seed_cursor = 0;
    }

    /// Also treat `[lo, hi)` as the seeded input, for a check that is **handed a pointer** to it
    /// (`check(input, len)`) instead of reading it through a hooked `gets`/`scanf`. That stub is
    /// what normally records the region, so without this an inline `cmp input[i], key[i]` in an
    /// argument-passed check is invisible — which is most of the corpus, where the reader is
    /// statically linked and unnamed. Call it after [`record_compares`](Self::record_compares).
    pub fn mark_input_region(&mut self, lo: u64, hi: u64) {
        self.input_region = Some((lo, hi));
    }

    /// The operand pairs recorded by every string/memory compare since the last reset (oldest
    /// first), when [`record_compares`](Self::record_compares) is on. A crackme checks the input
    /// against the *expected* value, so the operand that isn't the seeded input is the key/serial.
    pub fn compares(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.compares
    }

    /// The expected key reconstructed from inline per-byte comparisons: for each input offset that
    /// was compared against a concrete byte, that byte; gaps (offsets never compared) are filled
    /// with the seed byte. `None` if no inline comparison against the input was observed. This is
    /// how a statically-linked check (`cmp input[i], key[i]` in a loop, no strcmp) yields its key.
    pub fn inline_key(&self) -> Option<Vec<u8>> {
        if self.byte_expect.is_empty() {
            return None;
        }
        let max = self.byte_expect.iter().map(|(o, _)| *o).max().unwrap();
        let mut key: Vec<u8> = (0..=max)
            .map(|i| self.input_seed.get(i).copied().unwrap_or(b'A'))
            .collect();
        // Last writer wins per offset (a later, tighter comparison overrides an earlier one).
        for &(off, b) in &self.byte_expect {
            key[off] = b;
        }
        Some(key)
    }

    /// Lengths a seed-length-valued operand was compared against during the run — the length(s) a
    /// gate like `strlen(input) == 19` requires. The compare-hook caller re-seeds to one of these so
    /// the input clears the gate and the byte-compare loop past it can be observed. Deduped, in the
    /// order first seen; empty when no length gate referenced the seed length.
    pub fn wanted_lens(&self) -> &[u64] {
        &self.wanted_lens
    }

    /// Whole-value comparisons against a *numeric* input (`scanf("%d", &n)`, `atoi(line)`), oldest
    /// first: each entry is `(the input's value, the value it was compared against)`. The non-input
    /// side is the expected number — the recovered key of an "enter the number" crackme — and an
    /// entry whose two sides are **equal** means the numeric check passed for the seeded number,
    /// which is an oracle-free confirmation signal (no success string needed).
    pub fn int_compares(&self) -> &[(u64, u64)] {
        &self.int_expect
    }

    /// Treat call argument `i` as the **numeric** input, for a check handed the parsed number
    /// (`check(int n)`) rather than reading it. The next [`call`](Self::call) tags wherever the ABI
    /// puts that argument — a register, or a stack slot under cdecl — so the prologue's spill
    /// (`mov [rbp-4], edi`) carries the tag along and the `cmp [rbp-4], 25711` behind it is
    /// recorded. Call it after [`record_compares`](Self::record_compares), which clears it.
    pub fn seed_num_arg(&mut self, i: usize) {
        self.num_arg = Some(i);
    }

    /// Record which of `sites` this run *reaches* (basic-block starts, typically). Unlike a
    /// breakpoint it does not stop execution, so one run yields the whole set of code the input
    /// drove the program through — the raw material for a differential: the accepting input is the
    /// one that reaches a block no wrong input does. Resets any previous trace.
    pub fn trace_sites(&mut self, sites: impl IntoIterator<Item = u64>) {
        self.traced = sites.into_iter().collect();
        self.sites_hit.clear();
        self.sites_seen.clear();
    }

    /// The watched addresses this run reached, in first-hit order (each once). Empty when nothing
    /// was traced. See [`trace_sites`](Self::trace_sites).
    pub fn sites_hit(&self) -> &[u64] {
        &self.sites_hit
    }

    /// Input-buffer offset of a guest address, if it falls in the seeded region.
    fn input_offset(&self, ea: u64) -> Option<usize> {
        let (lo, hi) = self.input_region?;
        (ea >= lo && ea < hi).then(|| (ea - lo) as usize)
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

    /// Stack-slot / pointer width in bytes for the current ABI (8 for 64-bit, 4 for 32-bit cdecl).
    fn ptr(&self) -> u64 {
        self.abi.ptr_size()
    }

    fn arg(&self, i: usize) -> u64 {
        if let Some(r) = self.abi.arg_reg(i) {
            return self.cpu.reg(r);
        }
        // Stack-passed (cdecl: every argument). At stub entry RSP points at the return address the
        // `call` pushed, so argument i sits at [RSP + ptr*(i+1)]. (Win64/SysV register args are
        // handled above; their stack-spilled tail is rare in crackmes and left as 0 as before.)
        if self.abi.stack_args() {
            let ptr = self.abi.ptr_size();
            let slot = self.cpu.rsp().wrapping_add(ptr * (i as u64 + 1));
            return self.mem.read(slot, ptr as usize).unwrap_or(0);
        }
        0
    }

    /// Whether the instruction at `ip` consumes the flags as an **equality** test (`je`/`jne`,
    /// `sete`/`setne`, `cmove`/`cmovne`). A numeric `cmp` is only evidence about a key when the
    /// branch behind it asks "equal?": `if (n >= 100)` compares too, and its operands are equal for
    /// exactly one value of `n`, which would otherwise confirm `100` as the key.
    fn is_equality_use(&self, ip: u64) -> bool {
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
            return false;
        }
        let bits = if self.abi.ptr_size() == 4 { 32 } else { 64 };
        let mut dec =
            iced_x86::Decoder::with_ip(bits, &buf[..n], ip, iced_x86::DecoderOptions::NONE);
        matches!(
            dec.decode().mnemonic(),
            iced_x86::Mnemonic::Je
                | iced_x86::Mnemonic::Jne
                | iced_x86::Mnemonic::Sete
                | iced_x86::Mnemonic::Setne
                | iced_x86::Mnemonic::Cmove
                | iced_x86::Mnemonic::Cmovne
        )
    }

    /// Records a compare's operands when the oracle is on (see [`record_compares`]). Skips a pair
    /// where either side is empty — a NUL/zero-length operand carries no key — and skips a call
    /// site that turns out to be **scanning a table** rather than checking a key.
    ///
    /// Scan detection mirrors the numeric path's (`note_int_cmp`). One call site comparing the
    /// input against many different strings is walking a list, so every entry in that list would
    /// otherwise become a candidate key AND satisfy the comparison when seeded back — which is how
    /// `alnum`, from the C++ ctype class-name table, was confirmed as the key of three unrelated
    /// binaries. Earlier entries are withdrawn too, because the first few look like a real check
    /// until the loop comes round again.
    fn record_compare(&mut self, a: &[u8], b: &[u8]) {
        if !self.record_compares || a.is_empty() || b.is_empty() {
            return;
        }
        // Inside a stub, RIP is the caller's return address: one `strcmp` call site, however many
        // times the loop goes round.
        let site = self.cpu.rip;
        if self.cmp_scan_sites.contains(&site) {
            return;
        }
        let pair = (a.to_vec(), b.to_vec());
        let distinct = self
            .cmp_sites
            .iter()
            .zip(&self.compares)
            .filter(|(s, _)| **s == site)
            .map(|(_, p)| p)
            .chain(std::iter::once(&pair))
            .collect::<std::collections::HashSet<_>>()
            .len();
        if distinct > Self::MAX_SITE_EXPECTED {
            self.cmp_scan_sites.insert(site);
            let keep: Vec<bool> = self.cmp_sites.iter().map(|s| *s != site).collect();
            let mut i = 0;
            self.compares.retain(|_| {
                let k = keep[i];
                i += 1;
                k
            });
            self.cmp_sites.retain(|s| *s != site);
            return;
        }
        self.compares.push(pair);
        self.cmp_sites.push(site);
    }

    /// Applies an import stub: reads arguments, computes the result into RAX, and returns to
    /// the caller (popping the return address the `call` pushed).
    pub(crate) fn apply_stub(&mut self, stub: &Stub) -> Result<(), EmuError> {
        let result = match stub {
            Stub::Return(v) => *v,
            // Concrete emulation has no real stdin. With a seed set (the compare-hook driver), write
            // it into the destination buffer so a keygen runs forward on a known input; otherwise
            // leave the buffer as-is. (Symbolic execution is what *symbolizes* the buffer instead.)
            Stub::ReadInput {
                buf_arg,
                fmt_arg,
                ret,
            } => {
                let buf = self.arg(*buf_arg);
                let line = self.next_seed_line();
                // A numeric conversion (`scanf("%d", &n)`) stores a binary integer, so the seed's
                // digits have to be *parsed*: copying the text in would leave the check comparing
                // against ASCII bytes. See [`scanf_num_conv`].
                let conv = fmt_arg
                    .map(|i| self.read_cstr(self.arg(i), 256))
                    .as_deref()
                    .and_then(scanf_num_conv);
                let mut converted = 1;
                if !line.is_empty() && buf != 0 {
                    match conv {
                        Some(c) => match parse_num(&line, &c) {
                            Some(v) => {
                                self.mem.write(buf, v, c.width)?;
                                // The numeric counterpart of `input_region`, so an inline
                                // `cmp eax, 25711` against it is observable.
                                if self.record_compares {
                                    self.num_input = Some((buf, c.width));
                                }
                            }
                            // The seed isn't a number: a real scanf converts nothing and leaves
                            // the destination untouched.
                            None => converted = 0,
                        },
                        None => {
                            self.mem.write_slice(buf, &line)?;
                            self.mem.write_u8(buf.wrapping_add(line.len() as u64), 0)?;
                            // Remember where the input lives so inline `cmp input[i], key[i]` is
                            // observable.
                            if self.record_compares {
                                self.input_region = Some((buf, buf + line.len() as u64));
                            }
                        }
                    }
                }
                match ret {
                    InputReturn::Buffer => buf,
                    InputReturn::Count(n) => *n * converted,
                    InputReturn::Len => line.len() as u64,
                }
            }
            Stub::ReadNumInto {
                dst_arg,
                conv,
                ret_arg,
            } => {
                let dst = self.arg(*dst_arg);
                let line = self.next_seed_line();
                if dst != 0
                    && !line.is_empty()
                    && let Some(v) = parse_num(&line, conv)
                {
                    self.mem.write(dst, v, conv.width)?;
                    if self.record_compares {
                        self.num_input = Some((dst, conv.width));
                    }
                }
                // The stream itself, so `cin >> a >> b` chains and `while (cin >> n)` iterates.
                self.arg(*ret_arg)
            }
            Stub::Strlen => self.read_cstr(self.arg(0), 1 << 20).len() as u64,
            Stub::Strcmp => {
                let a = self.read_cstr(self.arg(0), 1 << 20);
                let b = self.read_cstr(self.arg(1), 1 << 20);
                self.record_compare(&a, &b);
                cmp_result(&a, &b)
            }
            Stub::Strncmp => {
                let n = self.arg(2) as usize;
                let a = self.read_cstr(self.arg(0), n);
                let b = self.read_cstr(self.arg(1), n);
                self.record_compare(&a, &b);
                cmp_result(&a, &b)
            }
            Stub::Memcmp => {
                let n = self.arg(2) as usize;
                let a = self.mem.read_vec(self.arg(0), n)?;
                let b = self.mem.read_vec(self.arg(1), n)?;
                self.record_compare(&a, &b);
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
            Stub::InputLen => {
                let line = self.next_seed_line();
                line.len() as u64
            }
            Stub::InputNum => {
                // No buffer and no format string: the API converts the edit box itself, so parse
                // the seed as a decimal number and tag the result like `atoi` does.
                let seed = self.next_seed_line();
                if self.record_compares {
                    self.reg_num.insert(iced_x86::Register::RAX);
                }
                // A non-numeric seed converts to 0 and clears the caller's `translated` flag.
                match parse_num(
                    &seed,
                    &NumConv {
                        width: 4,
                        radix: 10,
                        float: false,
                    },
                ) {
                    Some(v) => v,
                    None => {
                        let flag = self.arg(2);
                        if flag != 0 {
                            let _ = self.mem.write(flag, 0, 4);
                        }
                        0
                    }
                }
            }
            Stub::Atoi => {
                let s = self.read_cstr(self.arg(0), 64);
                // `atoi(input)` turns the seeded text into the number the check compares, so tag
                // RAX: a later `cmp eax, 1337` is then an observable numeric check (and a store of
                // it into a stack slot carries the tag along — see `taint_from_load`).
                if self.record_compares && self.input_offset(self.arg(0)).is_some() {
                    self.reg_num.insert(iced_x86::Register::RAX);
                }
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

    /// Pops the return address (used by stubs; mirrors a `ret`). Pointer-width per ABI.
    fn pop_ret(&mut self) -> Result<u64, EmuError> {
        let sp = self.cpu.rsp();
        let ptr = self.ptr();
        let v = self.mem.read(sp, ptr as usize)?;
        self.cpu.set_rsp(sp.wrapping_add(ptr));
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
    ///
    /// The top depends on the current ABI's pointer width — see [`DEFAULT_STACK_TOP_32`] — so set
    /// [`abi`](Self::abi) before calling this directly. [`call`](Self::call) already does.
    pub fn setup_stack(&mut self) -> u64 {
        let top = if self.abi.ptr_size() == 4 {
            DEFAULT_STACK_TOP_32
        } else {
            DEFAULT_STACK_TOP
        };
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
        // Reachability trace (see `trace_sites`): note the first visit to each watched address.
        if !self.traced.is_empty()
            && self.sites_hit.len() < MAX_TRACED_SITES
            && self.traced.contains(&ip)
            && self.sites_seen.insert(ip)
        {
            self.sites_hit.push(ip);
        }
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
        // Decode at the ABI's bitness: a 32-bit cdecl binary must decode as 32-bit, or e.g.
        // `inc edx` (0x42) is misread as a REX prefix. 64-bit ABIs decode as 64-bit.
        let bits = if self.abi.ptr_size() == 4 { 32 } else { 64 };
        let mut dec =
            iced_x86::Decoder::with_ip(bits, &buf[..n], ip, iced_x86::DecoderOptions::NONE);
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

    /// Run from `addr` as if it were the **middle** of a function rather than its entry, with a
    /// synthetic frame: the stack is set up as usual and RBP is pointed into it, so the `[ebp-x]`
    /// locals the code expects resolve to mapped (zeroed) memory even though no prologue ran.
    ///
    /// This is for a handler whose interesting code is only reachable through a dispatch that would
    /// have to be guessed — a dialog procedure reads its edit box under `case WM_COMMAND:` with the
    /// right control id in `wParam`, so entering at the function start just falls through the
    /// `switch` and returns. Starting at the block that reads the input skips the guessing entirely.
    ///
    /// The frame is synthetic, so a value the real prologue would have initialised reads as zero and
    /// the epilogue returns to garbage; both are fine for an oracle that only needs the comparison,
    /// which happens first. A caller must still treat the result differentially.
    pub fn run_block(&mut self, addr: u64, abi: Abi) -> Result<Stop, EmuError> {
        self.prepare_call(addr, &[], abi)?;
        // RBP inside the mapped stack, with the frame's locals below it.
        let sp = self.cpu.rsp();
        self.cpu.set_reg(
            if abi.ptr_size() == 4 {
                iced_x86::Register::EBP
            } else {
                iced_x86::Register::RBP
            },
            sp,
        );
        self.run_until(Some(SENTINEL))
    }

    /// Like [`call`](Self::call), but returns *where* the run stopped — a breakpoint, the return
    /// sentinel, or the step limit — instead of the return value. A caller that set breakpoints on
    /// verdict blocks (a "Correct"/"Wrong" print site) uses this to learn which block the run
    /// reached, which is the real accept/reject signal when the check reports its verdict by
    /// branching rather than by a boolean return value.
    pub fn call_watch(&mut self, func: u64, args: &[u64], abi: Abi) -> Result<Stop, EmuError> {
        self.prepare_call(func, args, abi)?;
        self.run_until(Some(SENTINEL))
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
        let ptr = abi.ptr_size();
        // The argument area (shadow space + stack args), kept a multiple of 16 so the callee sees
        // the ABI's entry alignment.
        let area = (abi.shadow_space() + ptr * extra.len() as u64 + 15) & !15;
        let base = (self.cpu.rsp() & !0xf).wrapping_sub(area);
        for (i, &a) in extra.iter().enumerate() {
            let slot = base
                .wrapping_add(abi.shadow_space())
                .wrapping_add(ptr * i as u64);
            self.mem.write(slot, a, ptr as usize)?;
        }
        // A numeric input handed over as an *argument* (`check(int n)`): tag wherever it landed,
        // so the comparison behind the prologue's spill is observable. See [`seed_num_arg`].
        if self.record_compares
            && let Some(i) = self.num_arg
        {
            match abi.arg_reg(i) {
                Some(r) if i < nregs => {
                    self.reg_num.insert(r.full_register());
                }
                _ => {
                    let slot = base
                        .wrapping_add(abi.shadow_space())
                        .wrapping_add(ptr * (i.saturating_sub(nregs)) as u64);
                    self.num_input = Some((slot, ptr as usize));
                }
            }
        }
        // Push the sentinel return address (pointer-width).
        let sp = base.wrapping_sub(ptr);
        self.mem.write(sp, SENTINEL, ptr as usize)?;
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
