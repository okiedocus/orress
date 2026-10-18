//! ORRESS Academy - Crackme #10 (Level 2, "Static analysis": the practice program for the
//! lessons on file formats, navigation, naming, the graph view and the decompiler)
//!
//! A small "licence checker" with a clear structure, so every static-analysis view has
//! something to show: `main` prints, reads a line and calls `is_valid`, which checks the
//! length and the first character and then calls `checksum`, a loop that adds up the
//! character codes. The graph view shows the if/else in `main` and the loop in `checksum`.
//!
//! Solve it in the decompiler lesson: a valid code is 6 characters long, starts with `K`,
//! and its character codes add up to 500 (0x1F4). `KUUUUU` works (75 + 5 * 85 = 500), and
//! so does any other code with the same sum.

use std::hint::black_box;
use std::io::{self, BufRead, Write};

/// The sum every valid code must reach.
const TARGET: u32 = 500;

/// Adds up the character codes. `#[inline(never)]` keeps it a separate function, and
/// `black_box` keeps the loop a real loop you can see in the graph view.
#[inline(never)]
fn checksum(code: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < code.len() {
        sum = sum.wrapping_add(u32::from(black_box(code[i])));
        i += 1;
    }
    sum
}

#[inline(never)]
fn is_valid(code: &[u8]) -> bool {
    if code.len() != 6 {
        return false;
    }
    if code[0] != b'K' {
        return false;
    }
    // `black_box` hides that the length is 6, so `checksum` stays a general loop.
    checksum(black_box(code)) == TARGET
}

fn main() {
    println!("=== ORRESS Academy - Crackme #10 ===");
    print!("Licence code: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if is_valid(line.as_bytes()) {
        println!("Licence accepted. Welcome!");
    } else {
        println!("Invalid licence code.");
        std::process::exit(1);
    }
}
