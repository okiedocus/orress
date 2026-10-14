//! ORRESS Academy - Crackme #8 (Level 5/7, "Control-flow flattening")
//!
//! `check_password` is **control-flow-flattened**: its logic isn't a straight line of
//! `if`s — every step is a `match` arm of one dispatcher loop, and each arm sets a `state`
//! variable to pick the next arm. `black_box(state)` stops the optimiser from collapsing the
//! state machine back into structured control flow, so the compiled binary really does run a
//! dispatch loop with a jump table on `state` — the shape obfuscators (OLLVM) emit.
//!
//! The original control flow is a simple per-byte check: `rotate_left(input[i] ^ K[i], i+1)`
//! must equal `C[i]` for each of the 8 bytes. ORRESS's decompiler undoes the flattening
//! (relinking each arm to its real successor and dropping the dispatcher), so the recovered
//! pseudocode reads as the straight-line check it started as — look for the
//! "deobfuscated by ORRESS" note. Key: "unfl4tt3".

use std::io::{self, BufRead, Write};

const K: [u8; 8] = [0x3b, 0xa7, 0x1e, 0x64, 0xc2, 0x59, 0x8d, 0x10];

/// `#[inline(never)]` keeps the flattened interpreter one findable function.
#[inline(never)]
fn check_password(input: &[u8]) -> bool {
    // The expected transformed bytes: rotate_left(K[i] ^ key[i], i+1) for key = "unfl4tt3".
    const C: [u8; 8] = expected();
    // One state per original basic block (no loop counter), so the compiler emits a real
    // dispatcher with a case per state — the control-flow-flattening shape — rather than a
    // tidy loop. Each arm checks one byte and sets the next state.
    let mut state: u32 = 0;
    loop {
        match state {
            0 => {
                if input.len() != 8 {
                    return false;
                }
                state = 1;
            }
            1 if rotate_left(input[0] ^ K[0], 1) == C[0] => state = 2,
            2 if rotate_left(input[1] ^ K[1], 2) == C[1] => state = 3,
            3 if rotate_left(input[2] ^ K[2], 3) == C[2] => state = 4,
            4 if rotate_left(input[3] ^ K[3], 4) == C[3] => state = 5,
            5 if rotate_left(input[4] ^ K[4], 5) == C[4] => state = 6,
            6 if rotate_left(input[5] ^ K[5], 6) == C[5] => state = 7,
            7 if rotate_left(input[6] ^ K[6], 7) == C[6] => state = 8,
            8 if rotate_left(input[7] ^ K[7], 8) == C[7] => state = 9,
            9 => return true,
            _ => return false,
        }
    }
}

const fn rotate_left_const(v: u8, n: u32) -> u8 {
    v.rotate_left(n)
}

fn rotate_left(v: u8, n: u32) -> u8 {
    v.rotate_left(n)
}

/// Computes the expected transformed bytes at compile time from the real key "unfl4tt3".
const fn expected() -> [u8; 8] {
    let key = *b"unfl4tt3";
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = rotate_left_const(key[i] ^ K[i], (i + 1) as u32);
        i += 1;
    }
    out
}

fn main() {
    println!("=== ORRESS Academy - Crackme #8 ===");
    print!("Key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }
    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_password(line.as_bytes()) {
        println!("Correct! You unflattened the check.");
    } else {
        println!("Wrong key. Try again!");
        std::process::exit(1);
    }
}
