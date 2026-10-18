//! ORRESS Academy - Crackme #14 (Level 4, "Symbolic execution")
//!
//! The 12-character key is checked two characters at a time. For each pair (a, b):
//!
//!   x = a ^ KA[j]        y = b ^ 0x3c
//!   (x ^ y) == MIX[j]   and   x.rotate_left(1) + y == ROT[j]      (the addition wraps at 256)
//!
//! Every condition mixes two input bytes, so you cannot read one character off a single
//! comparison the way you could in crackme03, and the instruction-counting side channel gets
//! confused. Symbolic execution does not care: it collects the twelve conditions and the solver
//! finds the only input that satisfies all of them.
//!
//! Solve it the way the lesson teaches: in the Emulator's **Symbolic solve** section, enter
//! `check_key` (0x1400012c0) as the function, 12 as the input length, the block that sets the
//! return value 0x600d (0x140001478) as the target and the shared failure exit (0x140001489) as
//! the avoid address. The solver collects 12 constraints and recovers the key.
//!
//! Key: s0lv3_m3_n0w

use std::hint::black_box;
use std::io::{self, BufRead, Write};

const KA: [u8; 6] = [0x5a, 0x13, 0xc7, 0x2e, 0x91, 0x64];
const MIX: [u8; 6] = [0x25, 0x35, 0x97, 0x4c, 0x9c, 0x1f];
const ROT: [u8; 6] = [0x5e, 0x48, 0x4c, 0x95, 0xef, 0xf3];

/// Returns 0x600d ("good") for the right key and 0 otherwise. It takes a fixed-size array,
/// so the only argument is a pointer to the 12 bytes.
#[inline(never)]
fn check_key(key: &[u8; 12]) -> u32 {
    let mut j = 0;
    while j < 6 {
        // `black_box` stops the compiler from folding the checks together.
        let x = black_box(key[2 * j]) ^ KA[j];
        let y = black_box(key[2 * j + 1]) ^ 0x3c;
        if x ^ y != MIX[j] {
            return 0;
        }
        if x.rotate_left(1).wrapping_add(y) != ROT[j] {
            return 0;
        }
        j += 1;
    }
    black_box(0x600d)
}

fn main() {
    println!("=== ORRESS Academy - Crackme #14 ===");
    print!("Key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    let ok = match <&[u8; 12]>::try_from(line.as_bytes()) {
        Ok(key) => check_key(key) == 0x600d,
        Err(_) => false,
    };
    if ok {
        println!("Correct! The solver was right.");
    } else {
        println!("Wrong key. Try again!");
        std::process::exit(1);
    }
}
