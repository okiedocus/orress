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
mod smt;
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
    let result = solve::solve_with_fallback(&sx.constraints, input_len as usize);
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

/// Path-exploring variant of [`solve_check`]: at a symbolic branch it forks and follows **both**
/// directions, so it can find an input the function accepts even when reaching `target` requires
/// looping N times on a symbolic condition (an input-length `strlen`, a digit-validation loop) —
/// which the single-path steerer cannot. Bounded by `max_states` (frontier size) and `max_steps`
/// (total instructions). Returns `None` if no accepting path is found within budget.
#[allow(clippy::too_many_arguments)]
pub fn solve_check_explore(
    mem: orress_emu::Memory,
    func: u64,
    args: &[u64],
    input_base: u64,
    input_len: u32,
    target: u64,
    avoid: Vec<u64>,
    hooks: std::collections::HashMap<u64, orress_emu::Stub>,
    abi: Abi,
    max_states: usize,
    max_steps: u64,
) -> Option<Found> {
    let mut sx = SymExec::new(mem, input_base, input_len, target, avoid);
    sx.set_hooks(hooks);
    let win = sx.run_explore(func, args, abi, max_states, max_steps)?;
    let result = solve::solve_with_fallback(&win.constraints, input_len as usize);
    let smt2 = expr::to_smt2(&win.constraints, input_len);
    let checks = win
        .constraints
        .iter()
        .map(|c| expr::render(&expr::simplify(c)))
        .collect();
    Some(Found {
        result,
        constraints: win.constraints.len(),
        smt2,
        checks,
    })
}

/// Like [`solve_check`], but instead of steering to a chosen success *block*, it runs `func` until
/// it **returns** (steering away from `avoid` — the `return false` blocks) and then requires the
/// return value be non-zero. This recovers an input a `check(input) -> bool` function *accepts*,
/// including when the deciding comparison is branchless (`return a[i] == c`), which a block target
/// cannot constrain. `avoid` should list the failure-verdict blocks.
#[allow(clippy::too_many_arguments)]
pub fn solve_check_return(
    mem: orress_emu::Memory,
    func: u64,
    args: &[u64],
    input_base: u64,
    input_len: u32,
    avoid: Vec<u64>,
    hooks: std::collections::HashMap<u64, orress_emu::Stub>,
    abi: Abi,
) -> Result<Found, SymError> {
    let mut sx = SymExec::new_to_return(mem, input_base, input_len, avoid);
    sx.set_hooks(hooks);
    sx.run_check(func, args, abi)?;
    sx.constrain_return_nonzero();
    let result = solve::solve_with_fallback(&sx.constraints, input_len as usize);
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
