//! Practice programs built into ORRESS. Sources and the build script are in
//! `academy/crackmes/`; adding `crackmeNN.rs` and building it is enough to embed it.

use std::path::{Path, PathBuf};

pub struct Crackme {
    pub name: &'static str,
    pub file_name: &'static str,
    pub bytes: &'static [u8],
    pub source: &'static str,
}

// Every `academy/crackmes/<name>.rs` with a built `bin/<name>.exe` (see `build.rs`).
include!(concat!(env!("OUT_DIR"), "/crackme_files.rs"));

pub fn find(name: &str) -> Option<&'static Crackme> {
    CRACKMES.iter().find(|c| c.name == name)
}

/// Writes the crackme to `dir` (if not already there) and returns its path.
pub fn extract(crackme: &Crackme, dir: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(crackme.file_name);
    let current = std::fs::read(&path).ok();
    if current.as_deref() != Some(crackme.bytes) {
        std::fs::write(&path, crackme.bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crackmes_are_windows_programs() {
        assert!(CRACKMES.len() >= 8);
        for c in CRACKMES {
            assert!(c.bytes.starts_with(b"MZ"), "{} is a PE file", c.name);
            assert!(c.source.contains("fn main"));
        }
    }

    #[test]
    fn extract_writes_once() {
        let dir = std::env::temp_dir().join(format!("orress-crackmes-{}", std::process::id()));
        let path = extract(&CRACKMES[0], &dir).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), CRACKMES[0].bytes);
        assert_eq!(extract(&CRACKMES[0], &dir).unwrap(), path);
        std::fs::remove_dir_all(dir).ok();
    }
}
