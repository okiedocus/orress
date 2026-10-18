//! ORRESS Academy - Crackme #11 (Level 3, lesson "Reading memory at runtime")
//!
//! The password is never stored, not as text and not as character codes: `decode_secret`
//! builds it in memory only while the program runs, from scrambled bytes and a changing
//! key. Reading the file does not show it; watching the running program does.
//!
//! Solve it with the debugger: put a breakpoint on the first instruction of
//! `check_password`, run, type any input, and when it stops look at memory at the address
//! in `r8` (the third argument: a pointer to the decoded 12-byte secret).
//! The Emulator also works: run `decode_secret` and read the scratch buffer after the run.

use std::hint::black_box;
use std::io::{self, BufRead, Write};

/// The password, scrambled: byte i is XOR'd with a key that changes after every byte
/// (key = key * 5 + 3, starting at 0x5c).
const ENC: [u8; 12] = [
    0x2b, 0xfb, 0x7a, 0x2a, 0x18, 0x6c, 0x33, 0x79, 0x1b, 0x25, 0xc3, 0xff,
];

/// Decodes the password into `out`. `#[inline(never)]` keeps it a separate function.
#[inline(never)]
fn decode_secret(out: &mut [u8; 12]) {
    // `black_box` stops the compiler from decoding at compile time, which would put the
    // password straight back into the file.
    let enc = black_box(&ENC);
    let mut key: u8 = 0x5c;
    let mut i = 0;
    while i < out.len() {
        out[i] = enc[i] ^ key;
        key = key.wrapping_mul(5).wrapping_add(3);
        i += 1;
    }
}

/// Compares every byte (no early exit), so only the result tells you anything.
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
    println!("=== ORRESS Academy - Crackme #11 ===");
    print!("Password: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    let mut secret = [0u8; 12];
    decode_secret(&mut secret);

    if check_password(line.as_bytes(), &secret) {
        println!("Correct! You read the secret while the program was running.");
    } else {
        println!("Wrong password. Try again!");
        std::process::exit(1);
    }
}
