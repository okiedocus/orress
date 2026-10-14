//! Symbolic execution and constraint solving for ORRESS: find an input that reaches a chosen
//! target in a check function.
//!
//! A CFG-directed symbolic executor ([`SymExec`]) runs a check with the input bytes as symbolic
//! variables, steering input-dependent branches toward the target (away from the blocks you
//! mark to avoid) and collecting the branch conditions as constraints. A built-in bounded
//! solver ([`solve`]) then recovers an input satisfying them — which handles the usual byte-wise
//! transform-and-compare crackmes without any external dependency. For harder, tightly-coupled
//! constraints the same constraints export to SMT-LIB2 ([`expr::to_smt2`]) for an external z3.
//!
//! Pure Rust (only iced-x86 + the emulator's memory), so it composes with the rest of ORRESS
//! and needs no C/C++ solver toolchain.

#![allow(clippy::cast_possible_truncation)]

pub mod cc;
mod exec;
pub mod expr;
mod solve;

pub use exec::{SymError, SymExec};
pub use expr::{Expr, to_smt2};
pub use solve::{SolveResult, solve};

/// A full symbolic solve: run `func(args)` with `input_len` symbolic input bytes at
/// `input_base`, steer to `target` avoiding `avoid`, then solve the collected constraints.
pub struct Found {
    pub result: SolveResult,
    pub constraints: usize,
    pub smt2: String,
    /// The captured path constraints rendered as readable per-check expressions (e.g.
    /// `rol(in[0] ^ 0x3b, 1) == 0x9a`) — the lifted logic the check performs on the input.
    pub checks: Vec<String>,
}

pub use orress_emu::Abi;

#[allow(clippy::too_many_arguments)]
pub fn solve_check(
    mem: orress_emu::Memory,
    func: u64,
    args: &[u64],
    input_base: u64,
    input_len: u32,
    target: u64,
    avoid: Vec<u64>,
    hooks: std::collections::HashMap<u64, orress_emu::Stub>,
    abi: Abi,
) -> Result<Found, SymError> {
    let mut sx = SymExec::new(mem, input_base, input_len, target, avoid);
    sx.set_hooks(hooks);
    sx.run_check(func, args, abi)?;
    let result = solve::solve(&sx.constraints, input_len as usize);
    let smt2 = expr::to_smt2(&sx.constraints, input_len);
    let checks = sx
        .constraints
        .iter()
        .map(|c| expr::render(&expr::simplify(c)))
        .collect();
    Ok(Found {
        result,
        constraints: sx.constraints.len(),
        smt2,
        checks,
    })
}
