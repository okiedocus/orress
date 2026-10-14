//! ORRESS Academy - Crackme #1 (Level 1, lesson "Your first crackme")
//!
//! The password is stored as plain text, so the Strings view is enough to find it.

use std::io::{self, BufRead, Write};

fn main() {
    println!("=== ORRESS Academy - Crackme #1 ===");
    print!("Password: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().lock().read_line(&mut input).is_err() {
        std::process::exit(1);
    }

    // Remove the line ending: Enter adds "\n" (or "\r\n" on Windows).
    let line = input.strip_suffix('\n').unwrap_or(&input);
    let line = line.strip_suffix('\r').unwrap_or(line);

    // `black_box` keeps the password as text in the program's data. Without it, the
    // compiler turns the comparison into two 8-byte numbers (try it!).
    if line == std::hint::black_box("open_sesame_101") {
        println!("Correct! You cracked your first program.");
    } else {
        println!("Wrong password. Try again!");
        std::process::exit(1);
    }
}
