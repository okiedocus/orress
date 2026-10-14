//! ORRESS Academy - Crackme #6 (Level 5, a second custom VM)
//!
//! Like crackme05 this is a bytecode VM, but built differently on purpose: a stack of 16-bit values,
//! a different opcode set, and a 2-byte little-endian immediate operand (PUSHI). It exists to prove
//! ORRESS's VM analysis isn't over-fit to crackme05's exact shape.
//!
//! ISA (stack of u16):
//!   0 HALT             success
//!   1 PUSHI  lo hi     push the 16-bit little-endian immediate
//!   2 PUSHIN idx       push input[idx] (zero-extended)
//!   3 ADD              pop b, pop a, push a + b
//!   4 MUL              pop b, pop a, push a * b
//!   5 XOR              pop b, pop a, push a ^ b
//!   6 EQ               pop b, pop a, fail unless a == b
//!   7 SUB              pop b, pop a, push a - b
//!
//! The check: for each input byte, ((input[i] ^ K[i]) * M[i]) & 0xffff == C[i] (M[i] odd, so solvable).

use std::hint::black_box;
use std::io::{self, BufRead, Write};

const CODE: [u8; 113] = [
    2, 0, 1, 17, 0, 5, 1, 143, 0, 4, 1, 151,
    67, 6, 2, 1, 1, 126, 0, 5, 1, 59, 0, 4,
    1, 14, 17, 6, 2, 2, 1, 44, 0, 5, 1, 213,
    0, 4, 1, 187, 65, 6, 2, 3, 1, 90, 0, 5,
    1, 39, 0, 4, 1, 119, 7, 6, 2, 4, 1, 147,
    0, 5, 1, 97, 0, 4, 1, 197, 86, 6, 2, 5,
    1, 8, 0, 5, 1, 171, 0, 4, 1, 105, 39, 6,
    2, 6, 1, 225, 0, 5, 1, 29, 0, 4, 1, 167,
    16, 6, 2, 7, 1, 64, 0, 5, 1, 243, 0, 4,
    1, 105, 48, 6, 0,
];

#[inline(never)]
fn check_key(input: &[u8]) -> bool {
    if input.len() != 8 {
        return false;
    }
    let mut stack = [0u16; 32];
    let mut sp = 0usize;
    let mut pc = 0usize;
    loop {
        let op = black_box(CODE[pc]);
        pc += 1;
        match op {
            0 => return true,
            1 => {
                stack[sp] = u16::from_le_bytes([CODE[pc], CODE[pc + 1]]);
                sp += 1;
                pc += 2;
            }
            2 => {
                let idx = CODE[pc] as usize;
                pc += 1;
                match input.get(idx) {
                    Some(&b) => {
                        stack[sp] = u16::from(b);
                        sp += 1;
                    }
                    None => return false,
                }
            }
            3 => {
                let b = stack[sp - 1];
                let a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = a.wrapping_add(b);
            }
            4 => {
                let b = stack[sp - 1];
                let a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = a.wrapping_mul(b);
            }
            5 => {
                let b = stack[sp - 1];
                let a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = a ^ b;
            }
            6 => {
                let b = stack[sp - 1];
                let a = stack[sp - 2];
                sp -= 2;
                if a != b {
                    return false;
                }
            }
            7 => {
                let b = stack[sp - 1];
                let a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = a.wrapping_sub(b);
            }
            _ => return false,
        }
    }
}

fn main() {
    println!("=== ORRESS Academy - Crackme #6 ===");
    print!("Key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_key(line.as_bytes()) {
        println!("Correct! You devirtualized the second VM.");
    } else {
        println!("Wrong key. Try again!");
        std::process::exit(1);
    }
}
