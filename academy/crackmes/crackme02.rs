//! ORRESS Academy - Crackme #2 (Level 1, lesson "Byte by byte")
//!
//! The password is never stored as a string: each byte is compared on its own, so it
//! only appears as numbers (character codes) inside `cmp` instructions.

use std::hint::black_box;
use std::io::{self, BufRead, Write};

/// `#[inline(never)]` keeps this a separate function you can find and rename.
#[inline(never)]
fn check_password(s: &[u8]) -> bool {
    if s.len() != 7 {
        return false;
    }
    // `black_box` stops the compiler from merging the checks into one big comparison,
    // so every character stays a separate `cmp`.
    black_box(s)[0] == b'R'
        && black_box(s)[1] == b'3'
        && black_box(s)[2] == b'v'
        && black_box(s)[3] == b'3'
        && black_box(s)[4] == b'r'
        && black_box(s)[5] == b's'
        && black_box(s)[6] == b'3'
}

fn main() {
    println!("=== ORRESS Academy - Crackme #2 ===");
    print!("Password: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    // Remove the line ending: Enter adds "\n" (or "\r\n" on Windows).
    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_password(line.as_bytes()) {
        println!("Correct! You read the password byte by byte.");
    } else {
        println!("Wrong password. Try again!");
        std::process::exit(1);
    }
}
