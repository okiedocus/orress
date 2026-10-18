//! ORRESS Academy - Crackme #17 (Level 7, "Time-travel debugging" and "Binary diffing")
//!
//! "KeyVault 1.0": a small licence-key checker with a security bug. Crackme #18 is version
//! 1.1 of the same program, with the bug fixed. Diffing the two shows exactly what changed.
//!
//! The key is never stored as text. Each key byte is XORed with 0x5c, its position is added,
//! and the result is compared with the bytes in `ENC`. Key: "ORR-DIFF-7".
//!
//! The bug: `check_key` only compares as many bytes as you type. An empty key, or any start
//! of the real key ("O", "ORR-"), is accepted. Version 1.1 first checks the key's length and
//! shape in a new function, `key_shape_ok`.

use std::hint::black_box;
use std::io::{self, BufRead, Write};

const KEY_LEN: usize = 10;
/// The encoded key, computed at compile time: the plain key is not in the binary.
const ENC: [u8; KEY_LEN] = encode(*b"ORR-DIFF-7");

const fn encode(key: [u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    let mut i = 0;
    while i < KEY_LEN {
        out[i] = (key[i] ^ 0x5c).wrapping_add(i as u8);
        i += 1;
    }
    out
}

/// `#[inline(never)]` keeps this a separate function you can find, record and diff.
#[inline(never)]
fn check_key(key: &[u8]) -> bool {
    // Only printable characters (space to `~`) can be part of a key.
    for &b in key {
        if !(0x20..=0x7e).contains(&b) {
            return false;
        }
    }
    // BUG: the loop below runs over the bytes you typed, not over the whole key.
    // `black_box` on the length keeps this a real loop (the compiler does not unroll it).
    let len = black_box(key.len());
    let mut i = 0;
    while i < len {
        if i >= KEY_LEN {
            return false;
        }
        // `black_box` keeps each byte a real xor-add-compare in the machine code.
        if black_box(key[i] ^ 0x5c).wrapping_add(i as u8) != ENC[i] {
            return false; // stops at the first wrong byte
        }
        i += 1;
    }
    true
}

fn main() {
    println!("=== ORRESS Academy - Crackme #17: KeyVault 1.0 ===");
    print!("Licence key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }
    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_key(line.as_bytes()) {
        println!("Access granted. Welcome to KeyVault.");
    } else {
        println!("Access denied.");
        std::process::exit(1);
    }
}
