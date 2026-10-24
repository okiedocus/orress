//! External z3 fallback. When the built-in brute/descent solver can't fully satisfy a path's
//! constraints — tightly-coupled bytes, a checksum over the whole input — hand the SMT-LIB2 export
//! ([`crate::expr::to_smt2`]) to a `z3` binary and parse its model back into input bytes.
//!
//! Best-effort and dependency-free: if `z3` isn't on `PATH` (or errors/times out) this is a no-op
//! returning `None`, so builds and tests never depend on it. The caller always *verifies* z3's
//! model against the real constraints before trusting it (see [`crate::solve::solve_with_fallback`]),
//! so a model that z3 produced against a simplified/omitted assertion can never become a false solve.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::expr::{self, Expr};

/// Whether a callable `z3` binary is on `PATH` (probed once, then cached).
pub fn available() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        Command::new("z3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Solve `constraints` over `n` input bytes with z3. Returns the model as `n` bytes (filler `A`
/// for any byte z3 left free), or `None` if z3 is unavailable, unsat, or errored.
pub fn solve_z3(constraints: &[Expr], n: u32) -> Option<Vec<u8>> {
    if n == 0 || !available() {
        return None;
    }
    // `to_smt2` already declares `b0..bN` as `(_ BitVec 8)`, asserts the constraints, and ends with
    // (check-sat)(get-model). A :timeout bounds a hard checksum, and `-T` is the wall-clock backstop.
    let script = format!("(set-option :timeout 8000)\n{}", expr::to_smt2(constraints, n));
    let mut child = Command::new("z3")
        .arg("-smt2")
        .arg("-in")
        .arg("-T:10")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(script.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    parse_model(&String::from_utf8_lossy(&out.stdout), n as usize)
}

/// Parse a z3 `(get-model)` response: each `(define-fun bI () (_ BitVec 8) #xHH | #bBBBBBBBB)`
/// pins input byte `I`. `None` unless the first token is `sat`.
fn parse_model(out: &str, n: usize) -> Option<Vec<u8>> {
    if !out.trim_start().starts_with("sat") {
        return None; // unsat / unknown / error
    }
    let mut bytes = vec![b'A'; n];
    // split keeps each define-fun's text in its own chunk (up to the next one), so the first
    // `#x`/`#b` in a chunk is this variable's value even when z3 wraps it onto the next line.
    for part in out.split("define-fun").skip(1) {
        let p = part.trim_start();
        let Some(rest) = p.strip_prefix('b') else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let Ok(idx) = digits.parse::<usize>() else {
            continue;
        };
        if idx >= n {
            continue;
        }
        let val = if let Some(h) = p.find("#x") {
            let hex: String = p[h + 2..].chars().take_while(char::is_ascii_hexdigit).collect();
            u16::from_str_radix(&hex, 16)
        } else if let Some(b) = p.find("#b") {
            let bin: String = p[b + 2..].chars().take_while(|c| matches!(c, '0' | '1')).collect();
            u16::from_str_radix(&bin, 2)
        } else {
            continue;
        };
        if let Ok(v) = val {
            bytes[idx] = v as u8;
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_z3_bitvec_model() {
        // Mixed hex and binary literals, out of order, with the value wrapped onto the next line.
        let out = "sat\n(\n  (define-fun b0 () (_ BitVec 8) #x61)\n  \
                   (define-fun b2 () (_ BitVec 8)\n    #x63)\n  \
                   (define-fun b1 () (_ BitVec 8) #b01100010)\n)\n";
        assert_eq!(parse_model(out, 3).unwrap(), b"abc".to_vec());
    }

    #[test]
    fn free_bytes_default_to_filler() {
        let out = "sat\n(\n  (define-fun b0 () (_ BitVec 8) #x7a)\n)\n";
        assert_eq!(parse_model(out, 3).unwrap(), vec![0x7a, b'A', b'A']);
    }

    #[test]
    fn unsat_and_unknown_are_none() {
        assert!(parse_model("unsat\n", 3).is_none());
        assert!(parse_model("unknown\n", 3).is_none());
        assert!(parse_model("(error \"...\")\n", 3).is_none());
    }

    #[test]
    fn absent_z3_is_a_graceful_noop() {
        // In an environment without z3, the fallback must simply decline, never panic.
        if !available() {
            assert!(solve_z3(&[], 4).is_none());
        }
    }
}
