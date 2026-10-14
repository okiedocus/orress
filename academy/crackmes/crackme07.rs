//! ORRESS Academy - Crackme #7 (Level 5, a register-based VM)
//!
//! A third bytecode VM, deliberately *register*-based rather than stack-based, to prove ORRESS's VM
//! analysis isn't tied to a stack machine. Four virtual registers, uniform 3-byte instructions
//! `[opcode, rd, arg]`.
//!
//! ISA (regs: [u8; 4]):
//!   0 HALT              success
//!   1 LOADIN rd, idx    rd = input[idx]
//!   2 XORI   rd, imm    rd ^= imm
//!   3 ADDI   rd, imm    rd += imm
//!   4 ROLI   rd, amt    rd = rd.rotate_left(amt)
//!   5 CMPI   rd, imm    fail unless rd == imm
//!   6 SUBI   rd, imm    rd -= imm
//!   7 MOV    rd, rs     rd = rs
//!
//! The check: for each input byte, rotate_left(input[i] ^ K[i], R[i]) == C[i]. Key "r3g_v4lz".

use std::hint::black_box;
use std::io::{self, BufRead, Write};

const CODE: [u8; 99] = [
    1, 0, 0, 2, 0, 92, 4, 0, 1, 5, 0, 92,
    1, 0, 1, 2, 0, 18, 4, 0, 2, 5, 0, 132,
    1, 0, 2, 2, 0, 169, 4, 0, 3, 5, 0, 118,
    1, 0, 3, 2, 0, 126, 4, 0, 4, 5, 0, 18,
    1, 0, 4, 2, 0, 3, 4, 0, 5, 5, 0, 174,
    1, 0, 5, 2, 0, 241, 4, 0, 6, 5, 0, 113,
    1, 0, 6, 2, 0, 107, 4, 0, 7, 5, 0, 131,
    1, 0, 7, 2, 0, 141, 4, 0, 1, 5, 0, 239,
    0, 0, 0,
];

#[inline(never)]
fn check_key(input: &[u8]) -> bool {
    if input.len() != 8 {
        return false;
    }
    let mut regs = [0u8; 4];
    let mut pc = 0usize;
    loop {
        let op = black_box(CODE[pc]);
        let rd = CODE[pc + 1] as usize;
        let arg = CODE[pc + 2];
        pc += 3;
        match op {
            0 => return true,
            1 => match input.get(arg as usize) {
                Some(&b) => regs[rd] = b,
                None => return false,
            },
            2 => regs[rd] ^= arg,
            3 => regs[rd] = regs[rd].wrapping_add(arg),
            4 => regs[rd] = regs[rd].rotate_left(u32::from(arg)),
            5 => {
                if regs[rd] != arg {
                    return false;
                }
            }
            6 => regs[rd] = regs[rd].wrapping_sub(arg),
            7 => regs[rd] = regs[arg as usize],
            _ => return false,
        }
    }
}

fn main() {
    println!("=== ORRESS Academy - Crackme #7 ===");
    print!("Key: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    if check_key(line.as_bytes()) {
        println!("Correct! You devirtualized the register VM.");
    } else {
        println!("Wrong key. Try again!");
        std::process::exit(1);
    }
}
