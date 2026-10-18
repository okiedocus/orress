//! ORRESS Academy - Crackme #9 (Level 2, lesson "Writing a keygen")
//!
//! A keygen-me: the serial number is not fixed but computed from the name you type, so
//! every name has its own serial. `check_serial` adds up the character codes of the name,
//! starting from 0x1000, and XORs the sum with 0xBEEF:
//!
//!   serial = (0x1000 + name[0] + name[1] + ...) ^ 0xBEEF
//!
//! The lesson asks for the serial of the name `alice`: 0x1000 + 510 = 0x11FE, and
//! 0x11FE ^ 0xBEEF = 0xAF11 = 44817. A keygen in Rust:
//!
//!   let sum = name.bytes().fold(0x1000u32, |s, c| s + u32::from(c));
//!   println!("{}", sum ^ 0xBEEF);

use std::hint::black_box;
use std::io::{self, BufRead, Write};

/// Reads one line and removes the line ending.
#[inline(never)]
fn read_line() -> String {
    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }
    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.to_owned()
}

/// Reads a line and turns it into a number.
#[inline(never)]
fn read_serial() -> u32 {
    match read_line().trim().parse() {
        Ok(n) => n,
        Err(_) => {
            println!("A serial number is a number, like 12345.");
            std::process::exit(1);
        }
    }
}

/// `#[inline(never)]` keeps the check a separate function you can find and rename.
#[inline(never)]
fn check_serial(name: &[u8], serial: u32) -> bool {
    if name.len() < 3 {
        return false;
    }
    let mut sum: u32 = 0x1000;
    let mut i = 0;
    while i < name.len() {
        // `black_box` keeps the loop a real loop you can read.
        sum = sum.wrapping_add(u32::from(black_box(name[i])));
        i += 1;
    }
    (sum ^ 0xBEEF) == serial
}

fn main() {
    println!("=== ORRESS Academy - Crackme #9 (keygen-me) ===");
    print!("Name: ");
    io::stdout().flush().ok();
    let name = read_line();
    print!("Serial number: ");
    io::stdout().flush().ok();
    let serial = read_serial();

    if check_serial(name.as_bytes(), serial) {
        println!("Correct! That serial belongs to {name}.");
    } else {
        println!("Wrong serial for this name. Try again!");
        std::process::exit(1);
    }
}
