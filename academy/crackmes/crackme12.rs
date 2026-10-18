//! ORRESS Academy - Crackme #12 (Level 3, lesson "Practice: three guards")
//!
//! Three anti-debugging checks, and they fail silently: if any of them sees a debugger,
//! the program decodes a decoy password instead of the real one and always answers
//! "Wrong". Reading memory under the debugger without beating the checks shows the decoy.
//!
//!   1. `api_check`    - asks Windows with `IsDebuggerPresent`.
//!   2. `peb_check`    - reads the `BeingDebugged` byte of the PEB itself (`gs:[0x60]`,
//!                       then the byte at offset 2), no API call at all.
//!   3. `timing_check` - measures a short loop with `Instant` (QueryPerformanceCounter);
//!                       if it took longer than half a second, someone was stepping.
//!
//! Beat it the way the lessons teach:
//!   * Change registers: break right after each check's `call`, set `rax` to 0, continue.
//!     Then break at `check_password` and read the real secret at `r8`.
//!   * Patch: make each check return 0, save a patched copy.
//!   * Emulate: run `decode_secret` in the Emulator with a 16-character input and
//!     "pass input length" off (so the decoy flag, arg1, is 0). The scratch buffer shows
//!     the real password, and no check ever runs.

use std::hint::black_box;
use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

const REAL: [u8; 16] = [
    0x4a, 0x44, 0x8b, 0xcc, 0x06, 0x76, 0xe0, 0x61, 0x3d, 0xde, 0xc9, 0x42, 0x7a, 0x10, 0x4c, 0x28,
];
const DECOY: [u8; 16] = [
    0x54, 0x4c, 0xdf, 0xca, 0x31, 0x5d, 0xa2, 0x6a, 0x3d, 0x89, 0xc1, 0x55, 0x63, 0x16, 0x4a, 0x3a,
];

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn IsDebuggerPresent() -> i32;
}

/// Guard 1: the Windows API.
#[inline(never)]
fn api_check() -> bool {
    #[cfg(windows)]
    {
        unsafe { IsDebuggerPresent() != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Guard 2: the PEB's BeingDebugged byte, read directly.
#[inline(never)]
fn peb_check() -> bool {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let peb: *const u8;
        // SAFETY: on 64-bit Windows, gs:[0x60] always holds the address of this process's
        // PEB, and byte 2 of the PEB is BeingDebugged.
        unsafe {
            std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly, preserves_flags));
            *peb.add(2) != 0
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        false
    }
}

/// Guard 3: a timing check. The loop takes microseconds; stepping through it takes ages.
#[inline(never)]
fn timing_check() -> bool {
    let start = Instant::now();
    let mut sum: u64 = 0;
    for i in 0..black_box(1000u64) {
        sum = sum.wrapping_add(black_box(i));
    }
    black_box(sum);
    start.elapsed() > Duration::from_millis(500)
}

/// Decodes the real password (or, if `decoy` is true, the decoy) into `out`.
#[inline(never)]
fn decode_secret(out: &mut [u8; 16], decoy: bool) {
    let enc = if decoy { black_box(&DECOY) } else { black_box(&REAL) };
    let mut key: u8 = 0x3a;
    let mut i = 0;
    while i < out.len() {
        out[i] = enc[i] ^ key;
        key = key.wrapping_mul(5).wrapping_add(3);
        i += 1;
    }
}

/// Compares every byte (no early exit).
#[inline(never)]
fn check_password(input: &[u8], secret: &[u8]) -> bool {
    if input.len() != secret.len() {
        return false;
    }
    let mut same = true;
    let mut i = 0;
    while i < secret.len() {
        if black_box(input[i]) != secret[i] {
            same = false;
        }
        i += 1;
    }
    same
}

fn main() {
    println!("=== ORRESS Academy - Crackme #12 ===");
    print!("Password: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    // The three guard results are OR'd together into one `watched` flag (the compiler
    // combines them with `or`), which is then checked once near the end.
    let mut watched = false;
    if api_check() {
        watched = true;
    }
    if peb_check() {
        watched = true;
    }
    if timing_check() {
        watched = true;
    }

    let mut secret = [0u8; 16];
    decode_secret(&mut secret, black_box(watched));

    // Silent failure: when watched, even the right password is "wrong".
    if check_password(line.as_bytes(), &secret) && !watched {
        println!("Correct! Three guards down. You beat the anti-debugging.");
    } else {
        println!("Wrong password. Try again!");
        std::process::exit(1);
    }
}
