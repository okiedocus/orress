//! ORRESS Academy - Crackme #4 (Level 3, "Beating anti-debugging")
//!
//! This one fights back. It checks whether a debugger is attached with the Windows
//! API `IsDebuggerPresent`, and if so it bails out *before* ever telling you the
//! password was right. Run it under the debugger and it always says "detected";
//! the real check never gets to speak.
//!
//! Beat it the way the lesson teaches:
//!   * Patch and go  - find the `if debugger_present() { ... }` branch and NOP / invert
//!     it, so the bail never happens.
//!   * Emulate       - run check_password in the Emulator, where there is no real
//!     debugger to detect.
//!
//! The password itself is an ordinary fixed string, so once the guard is gone the
//! check is easy; the whole challenge is getting past the anti-debug branch.

use std::hint::black_box;
use std::io::{self, BufRead, Write};

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn IsDebuggerPresent() -> i32;
}

/// `#[inline(never)]` keeps the anti-debug check a separate, findable function.
#[inline(never)]
fn debugger_present() -> bool {
    #[cfg(windows)]
    {
        unsafe { IsDebuggerPresent() != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[inline(never)]
fn check_password(s: &[u8]) -> bool {
    s == black_box(b"n0_debugger_here")
}

fn main() {
    println!("=== ORRESS Academy - Crackme #4 ===");
    print!("Password: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    let ok = check_password(line.as_bytes());

    // The anti-debug gate: under a debugger, refuse to reveal success.
    if debugger_present() {
        println!("Debugger detected. Nice try.");
        std::process::exit(1);
    }

    if ok {
        println!("Correct! You slipped past the anti-debugging.");
    } else {
        println!("Wrong password. Try again!");
        std::process::exit(1);
    }
}
