//! ORRESS Academy - Crackme #13 (Level 4, "Practice: break a real cipher")
//!
//! The flag is checked by *encrypting* your input with the TEA block cipher and comparing the
//! result (as hex text) with a stored ciphertext. Nothing here is custom: it is textbook TEA,
//! recognisable by its "delta" constant 0x9E3779B9 (twice in the disassembly of the encryption
//! function; the decompiler writes the `add` as `-= 0x61c88647`, the same number in two's
//! complement).
//!
//! Solve it the way the lesson teaches:
//!   1. Recognise the algorithm from the constant in the encryption function.
//!   2. Find the 16-byte key (a readable string the encryption function uses).
//!   3. Find the stored ciphertext (48 hex digits in the Strings view).
//!   4. In the Workbench: `from_hex | tea_decrypt key=<the key>` gives the flag.
//!
//! Flag: flag{te4_h4s_a_g0ld_k3y}

use std::hint::black_box;
use std::io::{self, BufRead, Write};

/// The TEA key: 16 bytes, read as four little-endian 32-bit words.
static KEY: [u8; 16] = *b"t1ny_crypt0_k3y!";

/// TEA-encrypted flag, as lowercase hex text.
static EXPECTED: &str = "0c0b5df889a72f0143b197b070de2a2c09c4c9db4af2ad80";

/// Encrypts one 8-byte block with TEA (32 cycles). `#[inline(never)]` keeps it a separate
/// function you can find.
#[inline(never)]
fn tea_encrypt(v: &mut [u32; 2], k: &[u32; 4]) {
    const DELTA: u32 = 0x9E37_79B9;
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum: u32 = 0;
    for _ in 0..32 {
        sum = sum.wrapping_add(DELTA);
        v0 = v0.wrapping_add(
            (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
        );
        v1 = v1.wrapping_add(
            (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
        );
    }
    v[0] = v0;
    v[1] = v1;
}

#[inline(never)]
fn check_flag(input: &[u8]) -> bool {
    if input.len() != 24 {
        return false;
    }
    let key = black_box(&KEY);
    let mut k = [0u32; 4];
    for (i, word) in k.iter_mut().enumerate() {
        *word = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    let mut hex = String::new();
    for block in input.chunks(8) {
        let mut v = [
            u32::from_le_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_le_bytes([block[4], block[5], block[6], block[7]]),
        ];
        tea_encrypt(&mut v, &k);
        for word in v {
            for byte in word.to_le_bytes() {
                hex.push_str(&format!("{byte:02x}"));
            }
        }
    }
    hex == black_box(EXPECTED)
}

fn main() {
    println!("=== ORRESS Academy - Crackme #13 ===");
    print!("Flag: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_flag(line.as_bytes()) {
        println!("Correct! You decrypted the flag.");
    } else {
        println!("Wrong flag. Try again!");
        std::process::exit(1);
    }
}
