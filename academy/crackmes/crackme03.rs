//! ORRESS Academy - Crackme #3 (Level 2+, "XOR-encoded password")
//!
//! The password is never stored, not even as character codes. Each input byte is
//! XOR'd with a rolling 4-byte key and compared to a constant ciphertext. Three ways
//! to beat it, each taught by a lesson:
//!
//!   * Keygen (Level 2): XOR is its own inverse, so password[i] = CIPHER[i] ^ KEY[i % 4].
//!   * Symbolic execution (Level 4): the check is a byte-wise transform-and-compare.
//!   * Side channel (Level 4): the loop bails on the first wrong byte, so a correct
//!     byte makes it run further -> instruction counting recovers it one byte at a time.

use std::hint::black_box;
use std::io::{self, BufRead, Write};

const KEY: [u8; 4] = [0x5a, 0x1c, 0x7e, 0x33];
const CIPHER: [u8; 8] = [0x15, 0x4e, 0x2c, 0x76, 0x09, 0x4f, 0x4a, 0x01];

/// `#[inline(never)]` keeps this a separate function you can find and rename.
#[inline(never)]
fn check_password(s: &[u8]) -> bool {
    if s.len() != CIPHER.len() {
        return false;
    }
    let mut i = 0;
    while i < CIPHER.len() {
        // `black_box` stops the compiler from precomputing the comparison, so each
        // byte stays a real xor-then-compare you can see in the disassembly.
        if black_box(s[i] ^ KEY[i % 4]) != CIPHER[i] {
            return false; // bail on the first wrong byte: the side channel
        }
        i += 1;
    }
    true
}

fn main() {
    println!("=== ORRESS Academy - Crackme #3 ===");
    print!("Key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_password(line.as_bytes()) {
        println!("Correct! You decoded the XOR'd key.");
    } else {
        println!("Wrong key. Try again!");
        std::process::exit(1);
    }
}
