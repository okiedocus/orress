//! Cyclic (de Bruijn) patterns: generate a non-repeating pattern, then recover the offset of any
//! `n`-byte window in it — how you find the distance to the saved return address after a crash.

/// The default alphabet (lowercase ASCII) and window size, matching pwntools.
pub const DEFAULT_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const DEFAULT_N: usize = 4;

/// The first `length` bytes of a de Bruijn sequence over `alphabet` with window size `n`. Every
/// `n`-byte window is unique, so a window recovered from a crash pins down its offset.
pub fn cyclic(length: usize, alphabet: &[u8], n: usize) -> Vec<u8> {
    de_bruijn(alphabet, n, length)
}

/// The offset of the first occurrence of `sub` (an `n`-byte window) in `cyclic(..)`, or `None`.
pub fn cyclic_find(sub: &[u8], alphabet: &[u8], n: usize) -> Option<usize> {
    if sub.len() < n {
        return None;
    }
    let needle = &sub[..n];
    // The sequence is at most alphabet.len()^n long; generate it all and search.
    let full = de_bruijn(alphabet, n, usize::MAX);
    full.windows(n).position(|w| w == needle)
}

/// Generates up to `limit` bytes of the de Bruijn sequence B(k, n) (Frank Ruskey's algorithm),
/// mapping symbol indices through `alphabet`.
fn de_bruijn(alphabet: &[u8], n: usize, limit: usize) -> Vec<u8> {
    let k = alphabet.len();
    if k == 0 || n == 0 {
        return Vec::new();
    }
    let mut seq: Vec<u8> = Vec::new();
    let mut a = vec![0usize; k * n + 1];
    // Iterative form of the classic recursion db(t, p), to avoid deep recursion for large k^n.
    let mut stack: Vec<(usize, usize, usize)> = vec![(1, 1, 0)];
    // Each frame: (t, p, phase) — phase 0 = enter, >=1 = next j to try.
    'outer: while let Some(&mut (t, p, ref mut phase)) = stack.last_mut() {
        if t > n {
            if n.is_multiple_of(p) {
                for &idx in &a[1..=p] {
                    seq.push(alphabet[idx]);
                    if seq.len() >= limit {
                        break 'outer;
                    }
                }
            }
            stack.pop();
            continue;
        }
        if *phase == 0 {
            a[t] = a[t - p];
            *phase = a[t - p] + 1;
            stack.push((t + 1, p, 0));
            continue;
        }
        let j = *phase;
        if j < k {
            a[t] = j;
            *phase += 1;
            stack.push((t + 1, t, 0));
        } else {
            stack.pop();
        }
    }
    seq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_is_long_and_nonrepeating_in_windows() {
        let pat = cyclic(600, DEFAULT_ALPHABET, DEFAULT_N);
        assert_eq!(pat.len(), 600);
        // Every 4-byte window is unique.
        let mut seen = std::collections::HashSet::new();
        for w in pat.windows(DEFAULT_N) {
            assert!(seen.insert(w.to_vec()), "window {w:?} repeated");
        }
    }

    #[test]
    fn find_recovers_offsets() {
        let pat = cyclic(500, DEFAULT_ALPHABET, DEFAULT_N);
        for off in [0usize, 1, 42, 100, 255, 496] {
            let window = &pat[off..off + 4];
            assert_eq!(cyclic_find(window, DEFAULT_ALPHABET, DEFAULT_N), Some(off));
        }
    }
}
