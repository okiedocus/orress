//! The extension registry: an index of installable extensions, and install/uninstall against the
//! `extensions/` directory.
//!
//! An index is just data (JSON) — a curated list of extensions with where to fetch each (a git
//! URL). Installing copies a validated extension into the extensions directory; uninstalling
//! removes it. The network fetch ([`install_git`]) shells out to `git`; everything else is
//! offline and unit-tested, with [`install_local`] installing from a directory already on disk.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::load_extension;

/// One installable extension in a registry index.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub author: String,
    /// The git repository to clone the extension from.
    #[serde(default)]
    pub git: Option<String>,
    /// Whether this is a Zed extension (compatible) rather than a native ORRESS one.
    #[serde(default)]
    pub zed: bool,
}

/// A registry index: a list of available extensions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RegistryIndex {
    #[serde(default)]
    pub extensions: Vec<RegistryEntry>,
}

impl RegistryIndex {
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }

    pub fn find(&self, id: &str) -> Option<&RegistryEntry> {
        self.extensions.iter().find(|e| e.id == id)
    }
}

/// An extension found installed in the extensions directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub dir: PathBuf,
}

/// Scans `extensions_dir` for installed extensions (each a subdirectory with an `extension.toml`),
/// sorted by name. Unreadable entries are skipped.
pub fn installed(extensions_dir: &Path) -> Vec<InstalledExtension> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.join("extension.toml").is_file() {
            continue;
        }
        if let Ok(loaded) = load_extension(&dir) {
            let m = loaded.manifest;
            let id = if m.id.is_empty() {
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                m.id
            };
            out.push(InstalledExtension {
                name: if m.name.is_empty() {
                    id.clone()
                } else {
                    m.name
                },
                version: m.version,
                id,
                dir,
            });
        }
    }
    out.sort_by_key(|e| e.name.to_lowercase());
    out
}

/// Whether an extension with `id` is installed.
pub fn is_installed(extensions_dir: &Path, id: &str) -> bool {
    installed(extensions_dir).iter().any(|e| e.id == id)
}

/// Installs the extension in `src` (a directory with an `extension.toml`) into `extensions_dir`,
/// under a folder named by the extension's id. Validates it loads first, replaces any existing
/// install of the same id, and returns the id.
pub fn install_local(src: &Path, extensions_dir: &Path) -> Result<String, String> {
    let loaded = load_extension(src)?;
    let id = {
        let m = &loaded.manifest;
        if m.id.is_empty() {
            src.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            m.id.clone()
        }
    };
    if id.is_empty() || id.contains(['/', '\\', '.']) {
        return Err(format!("invalid extension id `{id}`"));
    }
    let dest = extensions_dir.join(&id);
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| format!("replacing {}: {e}", dest.display()))?;
    }
    std::fs::create_dir_all(extensions_dir).map_err(|e| e.to_string())?;
    copy_dir(src, &dest).map_err(|e| format!("copying into {}: {e}", dest.display()))?;
    Ok(id)
}

/// Clones `git_url` and installs it (a thin wrapper over `git clone` + [`install_local`]). Needs
/// the `git` command on `PATH`; not unit-tested (it reaches the network).
pub fn install_git(git_url: &str, extensions_dir: &Path) -> Result<String, String> {
    validate_git_url(git_url)?;
    let tmp = unique_clone_dir();
    let _ = std::fs::remove_dir_all(&tmp);
    // `--` ends option parsing, so a URL can never be read as a `git clone` flag.
    let status = std::process::Command::new("git")
        .args(["clone", "--depth", "1", "--", git_url])
        .arg(&tmp)
        .status()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("git clone of {git_url} failed"));
    }
    let result = install_local(&tmp, extensions_dir);
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// Rejects a clone URL that could be mistaken for a command-line option (or is empty). The `--`
/// separator already guards `git clone`; this is defence in depth and a clearer error.
fn validate_git_url(git_url: &str) -> Result<(), String> {
    let url = git_url.trim();
    if url.is_empty() {
        return Err("empty git URL".to_string());
    }
    if url.starts_with('-') {
        return Err(format!("invalid git URL `{git_url}`"));
    }
    Ok(())
}

/// A fresh temporary directory path for a clone, unique per process, time and call (so concurrent
/// installs never share or clobber one another's checkout).
fn unique_clone_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "orress_ext_clone_{}_{nanos}_{n}",
        std::process::id()
    ))
}

/// Removes the installed extension `id` from `extensions_dir`.
pub fn uninstall(extensions_dir: &Path, id: &str) -> Result<(), String> {
    if id.is_empty() || id.contains(['/', '\\', '.']) {
        return Err(format!("invalid extension id `{id}`"));
    }
    let dir = extensions_dir.join(id);
    if !dir.exists() {
        return Err(format!("`{id}` is not installed"));
    }
    std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())
}

/// Recursively copies a directory tree.
fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_urls_that_look_like_options_are_rejected() {
        assert!(validate_git_url("--upload-pack=touch /tmp/x").is_err());
        assert!(validate_git_url("-c").is_err());
        assert!(validate_git_url("  ").is_err());
        assert!(validate_git_url("https://github.com/zed-industries/extensions").is_ok());
        assert!(install_git("--upload-pack=x", Path::new(".")).is_err());
    }

    #[test]
    fn clone_dirs_are_unique() {
        assert_ne!(unique_clone_dir(), unique_clone_dir());
    }
}
