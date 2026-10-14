//! ORRESS Academy - Crackme #5 (Level 5, "VM-based obfuscation" / "Reversing a custom VM")
//!
//! The password check is not written as native code — it's a tiny **bytecode virtual
//! machine**. `check_password` is a classic fetch-decode-execute dispatch loop: it reads
//! an opcode from CODE, jumps to the handler for it, runs it, and loops back. The real
//! logic (XOR, rotate, compare) lives in the CODE array as data.
//!
//! That shape — one dispatcher block that many handler arms branch back to, inside a loop —
//! is exactly what ORRESS's VM detector looks for, so Triage flags it as VM-based
//! obfuscation. To solve it you map the opcodes (the "Reversing a custom VM" lesson), then
//! read the bytecode to recover the key.
//!
//! ISA: a stack machine over bytes.
//!   0 PUSHIN i : push input[i]        5 ROL n : a=pop; push rotate_left(a, n)
//!   1 PUSHIM v : push v               6 EQ    : b=pop; a=pop; fail unless a == b
//!   2 XOR      : b=pop; a=pop; a^b    7 DUP   : push top
//!   3 ADD      : b=pop; a=pop; a+b    8 LEN n : fail unless input.len() == n
//!   4 SUB      : b=pop; a=pop; a-b    9 HALT  : success

use std::hint::black_box;
use std::io::{self, BufRead, Write};

const CODE: [u8; 83] = [
    8, 8, 0, 0, 1, 59, 2, 5, 1, 1,
    154, 6, 0, 1, 1, 167, 2, 5, 3, 1,
    86, 6, 0, 2, 1, 30, 2, 5, 5, 1,
    40, 6, 0, 3, 1, 100, 2, 5, 2, 1,
    81, 6, 0, 4, 1, 194, 2, 5, 7, 1,
    218, 6, 0, 5, 1, 89, 2, 5, 4, 1,
    115, 6, 0, 6, 1, 141, 2, 5, 6, 1,
    58, 6, 0, 7, 1, 16, 2, 5, 2, 1,
    209, 6, 9,
];

/// `#[inline(never)]` keeps the interpreter a single findable function. The dispatch loop
/// below is the VM: one `match` (the dispatcher) that every handler arm loops back to.
#[inline(never)]
fn check_password(input: &[u8]) -> bool {
    let mut stack = [0u8; 32];
    let mut sp = 0usize;
    let mut pc = 0usize;
    loop {
        // `black_box` hides the opcode from the optimiser, so it can't fold the VM away or
        // prove any handler unreachable — every opcode stays a real arm of the dispatch.
        let op = black_box(CODE[pc]);
        pc += 1;
        match op {
            0 => {
                let i = CODE[pc] as usize;
                pc += 1;
                match input.get(i) {
                    Some(&b) => {
                        stack[sp] = b;
                        sp += 1;
                    }
                    None => return false,
                }
            }
            1 => {
                stack[sp] = CODE[pc];
                sp += 1;
                pc += 1;
            }
            2 => {
                let b = stack[sp - 1];
                let a = stack[sp - 2];
                sp -= 1;
                stack[sp - 1] = a ^ b;
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
                stack[sp - 1] = a.wrapping_sub(b);
            }
            5 => {
                let n = u32::from(CODE[pc]);
                pc += 1;
                stack[sp - 1] = stack[sp - 1].rotate_left(n);
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
                stack[sp] = stack[sp - 1];
                sp += 1;
            }
            8 => {
                let n = CODE[pc] as usize;
                pc += 1;
                if input.len() != n {
                    return false;
                }
            }
            9 => return true,
            _ => return false,
        }
    }
}

fn main() {
    println!("=== ORRESS Academy - Crackme #5 ===");
    print!("Key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_password(line.as_bytes()) {
        println!("Correct! You devirtualized the check.");
    } else {
        println!("Wrong key. Try again!");
        std::process::exit(1);
    }
}
