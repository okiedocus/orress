//! Practice programs built into ORRESS. Sources and the build script are in
//! `academy/crackmes/`.

use std::path::{Path, PathBuf};

pub struct Crackme {
    pub name: &'static str,
    pub file_name: &'static str,
    pub bytes: &'static [u8],
    pub source: &'static str,
}

pub const CRACKMES: &[Crackme] = &[
    Crackme {
        name: "crackme01",
        file_name: "crackme01.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme01.exe"),
        source: include_str!("../../../academy/crackmes/crackme01.rs"),
    },
    Crackme {
        name: "crackme02",
        file_name: "crackme02.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme02.exe"),
        source: include_str!("../../../academy/crackmes/crackme02.rs"),
    },
    Crackme {
        name: "crackme03",
        file_name: "crackme03.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme03.exe"),
        source: include_str!("../../../academy/crackmes/crackme03.rs"),
    },
    Crackme {
        name: "crackme04",
        file_name: "crackme04.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme04.exe"),
        source: include_str!("../../../academy/crackmes/crackme04.rs"),
    },
    Crackme {
        name: "crackme05",
        file_name: "crackme05.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme05.exe"),
        source: include_str!("../../../academy/crackmes/crackme05.rs"),
    },
    Crackme {
        name: "crackme06",
        file_name: "crackme06.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme06.exe"),
        source: include_str!("../../../academy/crackmes/crackme06.rs"),
    },
    Crackme {
        name: "crackme07",
        file_name: "crackme07.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme07.exe"),
        source: include_str!("../../../academy/crackmes/crackme07.rs"),
    },
    Crackme {
        name: "crackme08",
        file_name: "crackme08.exe",
        bytes: include_bytes!("../../../academy/crackmes/bin/crackme08.exe"),
        source: include_str!("../../../academy/crackmes/crackme08.rs"),
    },
];

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
