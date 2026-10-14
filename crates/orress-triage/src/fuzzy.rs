//! Fuzzy (similarity) hashes for a sample: TLSH and ssdeep. Unlike cryptographic hashes, these
//! stay close for files that are *similar*, so they're used to cluster variants of a family and
//! to look a sample up in a corpus. Both implementations here are pure Rust.

/// A sample's fuzzy hashes (TLSH needs ~50+ bytes with some variance, so it can be absent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FuzzyHashes {
    pub tlsh: Option<String>,
    pub ssdeep: String,
}

/// Computes the fuzzy hashes of `data`.
pub fn compute(data: &[u8]) -> FuzzyHashes {
    let tlsh = tlsh2::TlshDefaultBuilder::build_from(data)
        .map(|t| String::from_utf8_lossy(&t.hash()).into_owned());
    let ssdeep = fuzzyhash::FuzzyHash::new(data).to_string();
    FuzzyHashes { tlsh, ssdeep }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_both_for_a_real_buffer() {
        // A varied 4 KiB buffer, enough for TLSH.
        let data: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let f = compute(&data);
        assert!(f.tlsh.is_some(), "TLSH should compute for a 4 KiB buffer");
        assert!(f.tlsh.as_ref().unwrap().starts_with('T'));
        assert!(!f.ssdeep.is_empty());
    }

    #[test]
    fn tlsh_absent_for_tiny_input() {
        let f = compute(b"too small");
        assert!(f.tlsh.is_none());
    }
}
