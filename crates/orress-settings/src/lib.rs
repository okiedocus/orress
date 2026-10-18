//! User settings, stored as `settings.json` in the platform config directory
//! (on Windows: `%APPDATA%\okiedocus\ORRESS\config\`). A user keymap sits next to it
//! as `keymap.json`, and custom themes go in `themes/*.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Name of the active theme.
    pub theme: String,
    /// UI zoom factor (1.0 = 100%).
    pub ui_scale: f32,
    /// Explain Mode: plain-language tooltips on everything. On by default, because
    /// ORRESS is meant to teach.
    pub explain_mode: bool,
    /// Last opened files, newest first.
    pub recent_files: Vec<PathBuf>,
    /// The open project folder (Zed-style), if any. Restored on startup so the folder tree
    /// reappears. `None` when no folder is open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_root: Option<PathBuf>,
    /// Per-language-server configuration, keyed by server name/id. Mirrors Zed's `lsp` settings
    /// section, so it both configures ORRESS's own LSP client and is handed to Zed language
    /// extensions (via `get-settings`) when they resolve a server. Empty by default.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub lsp: BTreeMap<String, LspServerSettings>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "ORRESS Dark".into(),
            ui_scale: 1.0,
            explain_mode: true,
            recent_files: Vec::new(),
            project_root: None,
            lsp: BTreeMap::new(),
        }
    }
}

/// Per-server LSP configuration, in the same shape Zed uses for `lsp.<server>`: a binary override,
/// server settings (LSP workspace configuration) and initialization options.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LspServerSettings {
    /// Override the server binary (path / arguments / environment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<LspBinarySettings>,
    /// Server-specific settings (sent as the LSP workspace configuration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    /// The LSP `initializationOptions`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_options: Option<serde_json::Value>,
}

/// A language-server binary override (Zed's `lsp.<server>.binary`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LspBinarySettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
}

const MAX_RECENT: usize = 10;

impl Settings {
    pub const MIN_SCALE: f32 = 0.5;
    pub const MAX_SCALE: f32 = 3.0;

    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let mut s: Self = serde_json::from_str(json).context("parsing settings.json")?;
        s.ui_scale = s.ui_scale.clamp(Self::MIN_SCALE, Self::MAX_SCALE);
        Ok(s)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("settings serialize")
    }

    /// Loads settings from `path`. A missing file gives defaults; a broken file gives
    /// defaults plus the error, so the app still starts and can tell the user.
    pub fn load(path: &Path) -> (Self, Option<anyhow::Error>) {
        match std::fs::read_to_string(path) {
            Ok(json) => match Self::from_json(&json) {
                Ok(s) => (s, None),
                Err(e) => (Self::default(), Some(e)),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (
                Self::default(),
                Some(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
            ),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(path, self.to_json()).with_context(|| format!("writing {}", path.display()))
    }

    pub fn push_recent(&mut self, path: PathBuf) {
        self.recent_files.retain(|p| p != &path);
        self.recent_files.insert(0, path);
        self.recent_files.truncate(MAX_RECENT);
    }

    /// The editor settings in the JSON shape a Zed language extension reads via `get-settings`:
    /// `{ "lsp": { "<server>": { "binary": {…}, "settings": {…}, "initialization_options": {…} } } }`.
    /// Handed to the extension host so extensions honour the user's configured server binary,
    /// settings and initialization options (category `"lsp"`, key = the language-server name).
    pub fn zed_extension_settings(&self) -> serde_json::Value {
        serde_json::json!({ "lsp": self.lsp })
    }
}

/// Where ORRESS keeps its configuration files.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
}

impl Paths {
    pub fn from_platform() -> Option<Self> {
        let dirs = directories::ProjectDirs::from("nl", "okiedocus", "ORRESS")?;
        Some(Self {
            config_dir: dirs.config_dir().to_path_buf(),
        })
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    pub fn keymap_file(&self) -> PathBuf {
        self.config_dir.join("keymap.json")
    }

    pub fn themes_dir(&self) -> PathBuf {
        self.config_dir.join("themes")
    }

    /// Imported language-server adapter manifests (`*.json`).
    pub fn lsp_dir(&self) -> PathBuf {
        self.config_dir.join("lsp")
    }

    /// Installed extensions, one directory each (with an `extension.toml`).
    pub fn extensions_dir(&self) -> PathBuf {
        self.config_dir.join("extensions")
    }

    /// Saved annotations (names, comments, bookmarks), one file per analyzed binary.
    pub fn projects_dir(&self) -> PathBuf {
        self.config_dir.join("projects")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_json_fills_defaults_and_clamps() {
        let s = Settings::from_json(r#"{ "ui_scale": 9.0, "explain_mode": false }"#).unwrap();
        assert_eq!(s.ui_scale, Settings::MAX_SCALE);
        assert!(!s.explain_mode);
        assert_eq!(s.theme, "ORRESS Dark");
    }

    #[test]
    fn lsp_settings_round_trip_to_zed_shape() {
        // A user configures one server's binary + init options in settings.json.
        let s = Settings::from_json(
            r#"{ "lsp": { "rust-analyzer": {
                "binary": { "path": "/opt/ra", "arguments": ["--stdio"] },
                "initialization_options": { "cargo": { "allFeatures": true } }
            } } }"#,
        )
        .unwrap();
        let ra = s.lsp.get("rust-analyzer").expect("server configured");
        assert_eq!(ra.binary.as_ref().unwrap().path.as_deref(), Some("/opt/ra"));

        // zed_extension_settings() nests it under "lsp" exactly as a Zed extension reads it: the
        // section at ["lsp"]["rust-analyzer"] carries the binary and init options, and `None`
        // fields (here `settings`) are omitted rather than serialized as null.
        let zed = s.zed_extension_settings();
        let server = &zed["lsp"]["rust-analyzer"];
        assert_eq!(server["binary"]["path"], "/opt/ra");
        assert_eq!(server["binary"]["arguments"][0], "--stdio");
        assert_eq!(
            server["initialization_options"]["cargo"]["allFeatures"],
            true
        );
        assert!(server.get("settings").is_none());

        // No LSP config → an empty `lsp` object (extensions tolerate the absence of a server key).
        assert_eq!(
            Settings::default().zed_extension_settings(),
            serde_json::json!({ "lsp": {} })
        );
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("orress-settings-test-{}", std::process::id()));
        let path = dir.join("settings.json");
        let s = Settings {
            theme: "High Contrast".into(),
            ..Settings::default()
        };
        s.save(&path).unwrap();
        let (loaded, err) = Settings::load(&path);
        assert!(err.is_none());
        assert_eq!(loaded, s);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn broken_file_gives_defaults_and_error() {
        let dir = std::env::temp_dir().join(format!("orress-settings-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "{ not json").unwrap();
        let (s, err) = Settings::load(&path);
        assert_eq!(s, Settings::default());
        assert!(err.is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn recent_files_dedupe_and_cap() {
        let mut s = Settings::default();
        for i in 0..15 {
            s.push_recent(PathBuf::from(format!("f{i}")));
        }
        s.push_recent(PathBuf::from("f10"));
        assert_eq!(s.recent_files.len(), MAX_RECENT);
        assert_eq!(s.recent_files[0], PathBuf::from("f10"));
        assert_eq!(
            s.recent_files
                .iter()
                .filter(|p| p.as_os_str() == "f10")
                .count(),
            1
        );
    }
}
