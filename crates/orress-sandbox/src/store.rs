//! Defanged-at-rest storage. A flagged sample is never written to disk as a runnable file: it
//! is XOR-obfuscated behind a magic header, so a double-click or an on-access AV scanner sees
//! inert data. Refang only in memory, right before a gated run.

use std::io;
use std::path::Path;

const MAGIC: &[u8; 4] = b"ODF1";
const KEY: &[u8] = b"ORRESS-infected";

fn xor(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ KEY[i % KEY.len()])
        .collect()
}

/// Obfuscates `data` for storage (magic header + XOR).
pub fn defang(data: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend(xor(data));
    out
}

/// Recovers the original bytes from a defanged blob, or `None` if the header is wrong.
pub fn refang(blob: &[u8]) -> Option<Vec<u8>> {
    blob.strip_prefix(MAGIC.as_slice()).map(xor)
}

/// Writes `data` to `path` in defanged form.
pub fn store(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, defang(data))
}

/// Reads and refangs a defanged file.
pub fn load(path: &Path) -> io::Result<Vec<u8>> {
    let blob = std::fs::read(path)?;
    refang(&blob).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a defanged sample"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let original = b"MZ\x90\x00this is a dangerous payload\xff\xfe";
        let blob = defang(original);
        // The stored blob is not the original (no MZ header at offset 0).
        assert_ne!(&blob[..2], b"MZ");
        assert_eq!(refang(&blob).as_deref(), Some(original.as_slice()));
    }

    #[test]
    fn rejects_foreign_data() {
        assert!(refang(b"not a defanged blob").is_none());
    }
}
