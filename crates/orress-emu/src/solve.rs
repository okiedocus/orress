//! The instruction-counting side-channel solver.
//!
//! Many check routines bail out on the first wrong input byte, so a correct byte makes the
//! routine run *further* before failing. By emulating a candidate input and counting executed
//! instructions, the correct byte at each position is the one that maximises the count — so a
//! flag can be recovered one byte at a time without ever satisfying the final check. This is
//! the classic CTF "instruction counting" trick, and it is why the emulator tracks `steps`.

/// A step recorded during a solve, for the step-by-step explanation the UI shows learners.
#[derive(Debug, Clone)]
pub struct SolveStep {
    /// The position being recovered.
    pub index: usize,
    /// The byte chosen for this position.
    pub byte: u8,
    /// Its instruction count (the winning, highest count).
    pub count: u64,
    /// The runner-up count, so the UI can show how clear the signal was.
    pub runner_up: u64,
}

/// The result of a side-channel solve.
#[derive(Debug, Clone)]
pub struct Solution {
    pub input: Vec<u8>,
    pub steps: Vec<SolveStep>,
}

/// Longest input [`solve_by_count`] recovers; longer requests are clamped to this, so a typo
/// in a length field cannot allocate gigabytes or run for days.
pub const MAX_SOLVE_LEN: usize = 0x1_0000;

/// Recovers `len` input bytes by maximising executed instructions per position.
/// `len` is clamped to [`MAX_SOLVE_LEN`].
///
/// `trial(input)` runs the check routine against `input` and returns the number of
/// instructions executed; `candidates` are the byte values to try at each position (e.g.
/// printable ASCII). The recovered prefix is fixed as the search moves right.
pub fn solve_by_count<F>(len: usize, candidates: &[u8], mut trial: F) -> Solution
where
    F: FnMut(&[u8]) -> u64,
{
    let len = len.min(MAX_SOLVE_LEN);
    let mut input = vec![0u8; len];
    let mut steps = Vec::with_capacity(len);
    for index in 0..len {
        let mut best_byte = candidates.first().copied().unwrap_or(0);
        let mut best = 0u64;
        let mut runner_up = 0u64;
        for &c in candidates {
            input[index] = c;
            let count = trial(&input);
            if count > best {
                runner_up = best;
                best = count;
                best_byte = c;
            } else if count > runner_up {
                runner_up = count;
            }
        }
        input[index] = best_byte;
        steps.push(SolveStep {
            index,
            byte: best_byte,
            count: best,
            runner_up,
        });
    }
    Solution { input, steps }
}
