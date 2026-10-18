//! ORRESS Academy - Crackme #18 (Level 7, "Binary diffing" and the final project)
//!
//! "KeyVault 1.1": crackme #17 with its security bug fixed. A binary diff of #17 against #18
//! shows one changed function (`check_key`) and one added function (`key_shape_ok`).
//!
//! The fix: before the byte loop, `key_shape_ok` checks that the key is exactly 10 bytes long
//! and has a `-` at positions 3 and 8. The key is the same as in #17: "ORR-DIFF-7", stored
//! encoded: ENC[i] = (key[i] ^ 0x5c) + i. A keygen reverses it: key[i] = (ENC[i] - i) ^ 0x5c.

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

/// New in 1.1: the key must have the right length and two dashes.
#[inline(never)]
fn key_shape_ok(key: &[u8]) -> bool {
    key.len() == KEY_LEN && key[3] == b'-' && key[8] == b'-'
}

/// `#[inline(never)]` keeps this a separate function you can find, record and diff.
#[inline(never)]
fn check_key(key: &[u8]) -> bool {
    // FIX: reject keys of the wrong length or shape before comparing anything.
    if !key_shape_ok(key) {
        return false;
    }
    // Only printable characters (space to `~`) can be part of a key.
    for &b in key {
        if !(0x20..=0x7e).contains(&b) {
            return false;
        }
    }
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
    println!("=== ORRESS Academy - Crackme #18: KeyVault 1.1 ===");
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
