//! Your work on a file: renamed functions, comments and bookmarks.
//!
//! Annotations are saved automatically as JSON, one file per analyzed binary, named by
//! the binary's SHA-256. Opening the same file again (from any folder) brings your
//! names and comments back.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const EXTENSION: &str = "orress";
const VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Annotations {
    pub version: u32,
    /// SHA-256 of the file these annotations belong to.
    pub sha256: String,
    /// Path the file was last opened from (informational).
    pub last_path: Option<PathBuf>,
    /// User names by address.
    pub names: BTreeMap<u64, String>,
    /// User comments by address.
    pub comments: BTreeMap<u64, String>,
    pub bookmarks: BTreeSet<u64>,
    /// Patched bytes: file offset -> new value. Applied on top of the original file.
    pub patches: BTreeMap<u64, u8>,
}

impl Annotations {
    pub fn new(sha256: &str, path: &Path) -> Self {
        Self {
            version: VERSION,
            sha256: sha256.to_owned(),
            last_path: Some(path.to_path_buf()),
            ..Self::default()
        }
    }

    pub fn file_for(dir: &Path, sha256: &str) -> PathBuf {
        dir.join(format!("{sha256}.{EXTENSION}"))
    }

    /// Loads annotations from `path`; a missing file is not an error.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Write to a temporary file first so a crash cannot leave half a file behind.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.comments.is_empty()
            && self.bookmarks.is_empty()
            && self.patches.is_empty()
    }
}

/// Checks a user-chosen name: letters, digits, `_`, `@`, `$`, `.`, `:`, and no spaces,
/// so it reads well in the listing.
pub fn validate_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(()); // empty removes the name
    }
    if name.len() > 200 {
        return Err("names can be at most 200 characters".into());
    }
    if name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Err("names cannot start with a digit".into());
    }
    match name
        .chars()
        .find(|c| !(c.is_alphanumeric() || "_@$.:?<>~".contains(*c)))
    {
        Some(c) => Err(format!(
            "`{c}` is not allowed in names; use letters, digits and _"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("orress-annotations-{}", std::process::id()));
        let path = Annotations::file_for(&dir, "abc");
        let mut a = Annotations::new("abc", Path::new("C:/x.exe"));
        a.names.insert(0x401000, "check_password".into());
        a.comments
            .insert(0x401005, "compares with \"s3cret\"".into());
        a.bookmarks.insert(0x401000);
        a.save(&path).unwrap();
        assert_eq!(Annotations::load(&path).unwrap(), Some(a));
        assert_eq!(
            Annotations::load(&dir.join("missing.orress")).unwrap(),
            None
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn name_rules() {
        assert!(validate_name("check_password").is_ok());
        assert!(validate_name("").is_ok());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("1abc").is_err());
    }
}
