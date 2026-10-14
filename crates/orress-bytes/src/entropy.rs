//! Shannon entropy: how unpredictable the bytes are, from 0.0 (all the same byte) to
//! 8.0 (perfectly random). Plain code and text sit around 4.5–6.5; compressed or
//! encrypted data is close to 8. A packed executable shows up as a large high-entropy
//! region.

/// Entropy in bits per byte, 0.0..=8.0. Empty input gives 0.0.
pub fn shannon(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }
    let len = data.len() as f64;
    let entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum();
    // A single repeated byte gives -0.0; report it as a plain 0.
    (entropy as f32).max(0.0) + 0.0
}

/// Entropy of consecutive blocks of `block_size` bytes (the last block may be shorter).
pub fn blocks(data: &[u8], block_size: usize) -> Vec<f32> {
    assert!(block_size > 0, "block size must be positive");
    data.chunks(block_size).map(shannon).collect()
}

/// Block size that gives about `target` blocks for `len` bytes, at least 256 bytes so
/// each block has enough bytes for a meaningful value.
pub fn block_size_for(len: usize, target: usize) -> usize {
    len.div_ceil(target.max(1)).max(256)
}

/// Plain-language reading of an entropy value.
pub fn describe(entropy: f32) -> &'static str {
    match entropy {
        e if e < 1.0 => "almost constant (padding or zeros)",
        e if e < 4.0 => "low (text, tables or simple data)",
        e if e < 6.5 => "medium (typical machine code or data)",
        e if e < 7.2 => "high (dense data, maybe compressed)",
        _ => "very high (compressed or encrypted)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extremes() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7; 1000]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-5);
        assert!((shannon(&[0, 1, 0, 1]) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn block_split() {
        let mut data = vec![0u8; 512];
        data.extend((0..=255u8).cycle().take(512));
        let b = blocks(&data, 512);
        assert_eq!(b.len(), 2);
        assert!(b[0] < 0.01 && b[1] > 7.9);
        assert_eq!(block_size_for(10, 100), 256);
        assert_eq!(block_size_for(1_000_000, 1000), 1000);
    }
}
