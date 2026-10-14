//! The ORRESS extension host.
//!
//! Two layers, matching the plan's M12:
//!
//! 1. A **WASM component host** on wasmtime's component model ([`Host`]). This is the runtime a
//!    Zed extension's compiled WASM runs on: the clean-room `zed:extension` WIT world
//!    ([`ZedExtension`]) instantiates and runs real, unmodified Zed extensions (language servers,
//!    context servers, slash commands, debug adapters and locators), alongside ORRESS's own
//!    `orress:extension` world. Guests are sandboxed: file-system host imports are confined to the
//!    extension's directory / the worktree, `run-command` honours the manifest's `process:exec`
//!    capabilities, secrets are withheld from `shell-env`, and a watchdog traps runaway guests.
//!
//! 2. An **extension loader** ([`load_extension`]) that reads a Zed-style `extension.toml` and the
//!    assets ORRESS can use *without* running any WASM — themes (JSON), tree-sitter highlight
//!    queries, and language-server adapters with a static command — and hands them back as ready
//!    ORRESS types. Everything else an extension declares is resolved by running its WASM via the
//!    `resolve_*` / `zed_*` helpers below.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

mod registry;
mod wit;
mod zed;
pub use wit::{ExtensionInfo, RunningExtension};
pub use zed::{
    ContextServerConfig, DapBinary, DapBuildTask, DapConfig, DapRequest, DapRequestKind,
    DapScenario, DapTaskDefinition, DapTaskTemplate, DapTcpTemplate, ExecCapability, ExecPolicy,
    GUEST_TIME_BUDGET, LangServerCommand, SlashCommandCompletion, SlashCommandInfo,
    SlashCommandResult, SlashCommandSection, ZedExtension,
};
// `ZedLanguageServer`, `zed_language_servers`, `resolve_server_command` are defined in this module.
pub use orress_lsp::LspAdapter;
pub use orress_theme::Theme;
pub use registry::{
    InstalledExtension, RegistryEntry, RegistryIndex, install_git, install_local, installed,
    is_installed, uninstall,
};

/// The WASM component host: a wasmtime engine configured for the component model.
pub struct Host {
    engine: Engine,
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide engine every [`Host`] shares: component model on (the crate feature), plus
/// epoch interruption driven by a background ticker thread, so a guest stuck in a loop can be
/// trapped. Sharing it also lets compiled components be cached across calls.
fn shared_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        match Engine::new(&config) {
            Ok(engine) => {
                let ticker = engine.clone();
                let _ = std::thread::Builder::new()
                    .name("orress-ext-epoch".into())
                    .spawn(move || {
                        loop {
                            std::thread::sleep(zed::EPOCH_TICK);
                            ticker.increment_epoch();
                        }
                    });
                engine
            }
            Err(_) => Engine::default(),
        }
    })
}

/// How many epoch ticks one guest call may run on an [`Host::instantiate`]d (`orress:extension`)
/// extension before it traps.
fn guest_budget_ticks() -> u64 {
    (zed::GUEST_TIME_BUDGET.as_millis() / zed::EPOCH_TICK.as_millis().max(1)) as u64
}

impl Host {
    pub fn new() -> Self {
        Self {
            engine: shared_engine().clone(),
        }
    }

    /// Validates and loads a WASM **component** (the format Zed extensions compile to). Returns the
    /// compiled component, ready to instantiate. Rejects core modules and malformed input.
    pub fn load_component(&self, bytes: &[u8]) -> Result<Component, String> {
        Component::new(&self.engine, bytes).map_err(|e| e.to_string())
    }

    /// Loads **and runs** an extension component against the `orress:extension` WIT world: wires
    /// the host imports, instantiates it, and returns a handle to call its exports. This is the
    /// clean-room component host — the same mechanism Zed extensions run on.
    pub fn instantiate(&self, bytes: &[u8]) -> Result<RunningExtension, String> {
        let component = self.load_component(bytes)?;
        let mut linker: Linker<wit::HostState> = Linker::new(&self.engine);
        wit::Extension::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |s| s)
            .map_err(|e| e.to_string())?;
        let mut store = Store::new(&self.engine, wit::HostState::default());
        // Epoch interruption is on: without a deadline the first check would trap.
        store.set_epoch_deadline(guest_budget_ticks());
        let instance = wit::Extension::instantiate(&mut store, &component, &linker)
            .map_err(|e| e.to_string())?;
        Ok(RunningExtension { store, instance })
    }

    /// Instantiates a **Zed** extension component against the clean-room `zed:extension` host
    /// world. The returned handle runs `init-extension` and resolves a language-server command.
    pub fn instantiate_zed(&self, bytes: &[u8], work_dir: &Path) -> Result<ZedExtension, String> {
        zed::instantiate(&self.engine, bytes, work_dir)
    }
}

/// A Zed-style extension manifest (`extension.toml`). Only the fields ORRESS reads are modelled;
/// unknown keys are ignored, so a real Zed manifest parses. ORRESS's own extensions use the same
/// shape, and may put a server `command` directly on a `[language_servers.*]` entry (a Zed
/// extension instead returns that from its WASM, resolved via [`resolve_server_command`]).
#[derive(Debug, Default, Deserialize)]
pub struct ExtensionManifest {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub repository: String,
    /// Zed's extension API schema version (`1` today). Recorded for compatibility gating.
    #[serde(default)]
    pub schema_version: u32,
    /// Tree-sitter grammars the extension ships (name → source). ORRESS can use the grammar's
    /// highlight query over a built-in grammar; loading the extension's own WASM parser waits for
    /// the component host.
    #[serde(default)]
    pub grammars: BTreeMap<String, GrammarSource>,
    /// Language servers the extension provides.
    #[serde(default)]
    pub language_servers: BTreeMap<String, LanguageServerEntry>,
    /// Context (MCP) servers the extension provides (id → entry). The launch command is resolved
    /// from the extension's WASM (`context-server-command`).
    #[serde(default)]
    pub context_servers: BTreeMap<String, ContextServerEntry>,
    /// Slash commands the extension offers in the Assistant (name → entry). Behaviour (completion
    /// and output) comes from the extension's WASM (`run-slash-command`).
    #[serde(default)]
    pub slash_commands: BTreeMap<String, SlashCommandEntry>,
    /// Debug adapters the extension provides (name → entry). The launch binary is resolved from the
    /// extension's WASM (`get-dap-binary`).
    #[serde(default)]
    pub debug_adapters: BTreeMap<String, DebugAdapterEntry>,
    /// Debug locators the extension provides (name → entry). A locator turns a build/run task into a
    /// debug scenario via the extension's WASM (`dap-locator-create-scenario`/`run-dap-locator`).
    #[serde(default)]
    pub debug_locators: BTreeMap<String, DebugLocatorEntry>,
    /// Host capabilities the extension requests (Zed's `capabilities = [{ kind = ... }]`). Only
    /// `process:exec` is enforced (it gates `run-command`); other kinds are recorded.
    #[serde(default)]
    pub capabilities: Vec<ManifestCapability>,
}

/// One entry of a manifest's `capabilities` list, e.g.
/// `{ kind = "process:exec", command = "node", args = ["*"] }`. Unknown keys are ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct ManifestCapability {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

impl ExtensionManifest {
    /// The `process:exec` capabilities this manifest declares — what the extension may run via
    /// `run-command`.
    pub fn exec_capabilities(&self) -> Vec<ExecCapability> {
        self.capabilities
            .iter()
            .filter(|c| c.kind == "process:exec")
            .filter_map(|c| {
                Some(ExecCapability {
                    command: c.command.clone()?,
                    args: c.args.clone(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct GrammarSource {
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub rev: String,
    #[serde(default)]
    pub commit: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct LanguageServerEntry {
    #[serde(default)]
    pub name: String,
    /// The language this server serves (Zed's single-language form)…
    #[serde(default)]
    pub language: String,
    /// …or several (Zed's multi-language form).
    #[serde(default)]
    pub languages: Vec<String>,
    /// An ORRESS extension can name the server binary directly (a Zed extension returns it from
    /// its WASM instead — see [`zed_language_servers`] / [`resolve_server_command`]).
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub root_markers: Vec<String>,
}

impl LanguageServerEntry {
    /// Every language this server serves (merging the single and multi forms).
    fn languages(&self) -> Vec<String> {
        let mut out = self.languages.clone();
        if !self.language.is_empty() && !out.contains(&self.language) {
            out.push(self.language.clone());
        }
        out
    }
}

/// A context-server entry in `extension.toml` (`[context_servers.<id>]`). Zed keeps the launch
/// details in the WASM, so only presence matters here; unknown keys are ignored.
#[derive(Debug, Default, Deserialize)]
pub struct ContextServerEntry {}

/// A slash-command entry in `extension.toml` (`[slash_commands.<name>]`): the metadata shown in the
/// Assistant. The command's behaviour comes from the extension's WASM.
#[derive(Debug, Default, Deserialize)]
pub struct SlashCommandEntry {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub requires_argument: bool,
    #[serde(default)]
    pub tooltip_text: String,
}

/// A debug-adapter entry in `extension.toml` (`[debug_adapters.<name>]`). Zed keeps the launch
/// details in the WASM, so only presence matters here; unknown keys (e.g. `schema_path`) are
/// ignored.
#[derive(Debug, Default, Deserialize)]
pub struct DebugAdapterEntry {}

/// A debug-locator entry in `extension.toml` (`[debug_locators.<name>]`). The behaviour is in the
/// WASM; only presence matters here, and unknown keys are ignored.
#[derive(Debug, Default, Deserialize)]
pub struct DebugLocatorEntry {}

/// A grammar's highlight query, keyed by the language name the extension declares. The caller
/// applies it to a matching built-in grammar via `orress_editor::highlight_with_query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarQuery {
    pub language: String,
    pub highlights: String,
}

/// Everything a loaded extension contributes that ORRESS can use today, plus any non-fatal
/// warnings (an unreadable theme, a server with no command, …).
#[derive(Debug, Default)]
pub struct Loaded {
    pub manifest: ExtensionManifest,
    pub themes: Vec<Theme>,
    pub lsp_adapters: Vec<LspAdapter>,
    pub grammar_queries: Vec<GrammarQuery>,
    pub warnings: Vec<String>,
}

/// Loads an extension directory: its `extension.toml` manifest plus the assets ORRESS can use
/// without running WASM — `themes/*.json` (Zed theme families), `languages/<lang>/highlights.scm`
/// (tree-sitter queries), and any `[language_servers.*]` that names a command (an LSP adapter).
/// Fatal only if the manifest is missing or unparseable; per-asset problems become warnings.
pub fn load_extension(dir: &Path) -> Result<Loaded, String> {
    let manifest_path = dir.join("extension.toml");
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    let manifest: ExtensionManifest =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", manifest_path.display()))?;

    let mut out = Loaded {
        manifest,
        ..Default::default()
    };

    // Themes: every `themes/*.json` is a Zed theme family.
    if let Ok(entries) = std::fs::read_dir(dir.join("themes")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|j| Theme::from_zed_json(&j).map_err(|e| e.to_string()))
            {
                Ok(themes) => out.themes.extend(themes),
                Err(e) => out
                    .warnings
                    .push(format!("theme {} ignored: {e}", path.display())),
            }
        }
    }

    // Grammar highlight queries: `languages/<dir>/highlights.scm`, named by the sibling
    // `config.toml`'s `name` (falling back to the directory name).
    if let Ok(entries) = std::fs::read_dir(dir.join("languages")) {
        for entry in entries.flatten() {
            let lang_dir = entry.path();
            let scm = lang_dir.join("highlights.scm");
            let Ok(highlights) = std::fs::read_to_string(&scm) else {
                continue;
            };
            let language = language_name(&lang_dir);
            out.grammar_queries.push(GrammarQuery {
                language,
                highlights,
            });
        }
    }

    // Language-server adapters: only entries that name a command are usable without running WASM.
    for (id, ls) in &out.manifest.language_servers {
        let Some(command) = ls.command.clone() else {
            out.warnings.push(format!(
                "language server `{id}` needs the extension's WASM to resolve its command (skipped)"
            ));
            continue;
        };
        let languages = ls.languages();
        if languages.is_empty() {
            out.warnings.push(format!(
                "language server `{id}` names no language (skipped)"
            ));
            continue;
        }
        for language in languages {
            out.lsp_adapters.push(LspAdapter {
                language,
                command: command.clone(),
                args: ls.args.clone(),
                language_id: None,
                root_markers: ls.root_markers.clone(),
                key: Some(if ls.name.is_empty() {
                    id.clone()
                } else {
                    ls.name.clone()
                }),
                ..LspAdapter::default()
            });
        }
    }

    Ok(out)
}

/// A language server a Zed extension provides *dynamically* — its launch command comes from the
/// extension's WASM (`language-server-command`), not the manifest. Resolved lazily at server start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZedLanguageServer {
    pub language: String,
    pub server_id: String,
    /// The extension's compiled component (`extension.wasm`).
    pub wasm: std::path::PathBuf,
}

/// Scans installed extensions for Zed language servers whose command is resolved by WASM: a
/// `[language_servers.*]` entry with no static command, in an extension that ships an
/// `extension.wasm`. One entry per served language.
pub fn zed_language_servers(extensions_dir: &Path) -> Vec<ZedLanguageServer> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let wasm = dir.join("extension.wasm");
        if !wasm.is_file() {
            continue;
        }
        let Ok(loaded) = load_extension(&dir) else {
            continue;
        };
        for (id, ls) in &loaded.manifest.language_servers {
            if ls.command.is_some() {
                continue; // static command — a plain adapter, not WASM-resolved
            }
            for language in ls.languages() {
                out.push(ZedLanguageServer {
                    language,
                    server_id: id.clone(),
                    wasm: wasm.clone(),
                });
            }
        }
    }
    out
}

/// A context (MCP) server a Zed extension provides. Its launch command comes from the extension's
/// WASM (`context-server-command`), resolved via [`resolve_context_server_command`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZedContextServer {
    pub server_id: String,
    /// The extension's compiled component (`extension.wasm`).
    pub wasm: std::path::PathBuf,
}

/// Scans installed extensions for context (MCP) servers: each `[context_servers.*]` entry in an
/// extension that ships an `extension.wasm`.
pub fn zed_context_servers(extensions_dir: &Path) -> Vec<ZedContextServer> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let wasm = dir.join("extension.wasm");
        if !wasm.is_file() {
            continue;
        }
        let Ok(loaded) = load_extension(&dir) else {
            continue;
        };
        for id in loaded.manifest.context_servers.keys() {
            out.push(ZedContextServer {
                server_id: id.clone(),
                wasm: wasm.clone(),
            });
        }
    }
    out
}

/// A slash command a Zed extension offers in the Assistant, with the metadata from its manifest.
/// Its behaviour (completion/output) comes from the extension's WASM; run it via
/// [`run_zed_slash_command`] / complete it via [`complete_zed_slash_command`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZedSlashCommand {
    pub command: zed::SlashCommandInfo,
    /// The extension's compiled component (`extension.wasm`).
    pub wasm: std::path::PathBuf,
}

/// Scans installed extensions for Assistant slash commands: each `[slash_commands.*]` entry in an
/// extension that ships an `extension.wasm`.
pub fn zed_slash_commands(extensions_dir: &Path) -> Vec<ZedSlashCommand> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let wasm = dir.join("extension.wasm");
        if !wasm.is_file() {
            continue;
        }
        let Ok(loaded) = load_extension(&dir) else {
            continue;
        };
        for (name, sc) in &loaded.manifest.slash_commands {
            out.push(ZedSlashCommand {
                command: zed::SlashCommandInfo {
                    name: name.clone(),
                    description: sc.description.clone(),
                    tooltip_text: sc.tooltip_text.clone(),
                    requires_argument: sc.requires_argument,
                },
                wasm: wasm.clone(),
            });
        }
    }
    out
}

/// A debug adapter a Zed extension provides. Its launch binary comes from the extension's WASM
/// (`get-dap-binary`), resolved via [`resolve_dap_binary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZedDebugAdapter {
    pub adapter_name: String,
    /// The extension's compiled component (`extension.wasm`).
    pub wasm: std::path::PathBuf,
}

/// Scans installed extensions for debug adapters: each `[debug_adapters.*]` entry in an extension
/// that ships an `extension.wasm`.
pub fn zed_debug_adapters(extensions_dir: &Path) -> Vec<ZedDebugAdapter> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let wasm = dir.join("extension.wasm");
        if !wasm.is_file() {
            continue;
        }
        let Ok(loaded) = load_extension(&dir) else {
            continue;
        };
        for name in loaded.manifest.debug_adapters.keys() {
            out.push(ZedDebugAdapter {
                adapter_name: name.clone(),
                wasm: wasm.clone(),
            });
        }
    }
    out
}

/// A debug locator a Zed extension provides. A locator converts a build/run task into a debug
/// scenario (and resolves it) via the extension's WASM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZedDebugLocator {
    pub locator_name: String,
    /// The extension's compiled component (`extension.wasm`).
    pub wasm: std::path::PathBuf,
}

/// Scans installed extensions for debug locators: each `[debug_locators.*]` entry in an extension
/// that ships an `extension.wasm`.
pub fn zed_debug_locators(extensions_dir: &Path) -> Vec<ZedDebugLocator> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let wasm = dir.join("extension.wasm");
        if !wasm.is_file() {
            continue;
        }
        let Ok(loaded) = load_extension(&dir) else {
            continue;
        };
        for name in loaded.manifest.debug_locators.keys() {
            out.push(ZedDebugLocator {
                locator_name: name.clone(),
                wasm: wasm.clone(),
            });
        }
    }
    out
}

/// Files/directories that mark a project root, for building the worktree a Zed extension sees.
const ROOT_MARKERS: &[&str] = &[
    ".git",
    "Cargo.toml",
    "package.json",
    "tsconfig.json",
    "go.mod",
    "pyproject.toml",
    "setup.py",
    "pom.xml",
    "build.gradle",
    "CMakeLists.txt",
    "compile_commands.json",
    ".clangd",
    "Makefile",
    "pubspec.yaml",
    "Gemfile",
    "composer.json",
];

/// The project root for `path`: the nearest ancestor directory holding a project marker (a VCS or
/// build/manifest file), falling back to the file's own directory. This is the worktree a Zed
/// extension is given when resolving its language-server command, so it can read project files and
/// locate project-local tools.
pub fn project_root(path: &Path) -> std::path::PathBuf {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    let mut dir = Some(start);
    while let Some(d) = dir {
        if ROOT_MARKERS.iter().any(|m| d.join(m).exists()) {
            return d.to_path_buf();
        }
        dir = d.parent();
    }
    start.to_path_buf()
}

/// Compiled components, keyed by `.wasm` path and validated by size + modification time, so
/// repeated `resolve_*` calls do not recompile the same extension (compilation dominates the cost).
type ComponentCache = HashMap<PathBuf, (u64, Option<std::time::SystemTime>, Component)>;

/// Upper bound on cached components (a cache this size is simply cleared and refilled).
const MAX_CACHED_COMPONENTS: usize = 64;

/// The compiled component for `wasm` on the shared engine, from the cache when the file is
/// unchanged.
fn cached_component(wasm: &Path) -> Result<Component, String> {
    static CACHE: OnceLock<Mutex<ComponentCache>> = OnceLock::new();
    let key = std::path::absolute(wasm).unwrap_or_else(|_| wasm.to_path_buf());
    let meta = std::fs::metadata(wasm).map_err(|e| format!("{}: {e}", wasm.display()))?;
    let (len, mtime) = (meta.len(), meta.modified().ok());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some((l, m, component)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key)
        && *l == len
        && *m == mtime
        && mtime.is_some()
    {
        return Ok(component.clone());
    }
    let bytes = std::fs::read(wasm).map_err(|e| format!("{}: {e}", wasm.display()))?;
    let component = Component::new(shared_engine(), &bytes).map_err(|e| e.to_string())?;
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() >= MAX_CACHED_COMPONENTS {
        map.clear();
    }
    map.insert(key, (len, mtime, component.clone()));
    Ok(component)
}

/// The working directory of the extension whose component is `wasm`: its install directory (the
/// folder holding the `.wasm`), made absolute so commands it returns can be resolved from anywhere.
fn extension_work_dir(wasm: &Path) -> PathBuf {
    let dir = match wasm.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf())
}

/// The `run-command` policy for the extension installed in `dir`: the `process:exec` capabilities
/// its `extension.toml` declares (as Zed enforces them). A missing or unreadable manifest grants
/// nothing.
fn manifest_exec_policy(dir: &Path) -> ExecPolicy {
    let caps = std::fs::read_to_string(dir.join("extension.toml"))
        .ok()
        .and_then(|t| toml::from_str::<ExtensionManifest>(&t).ok())
        .map(|m| m.exec_capabilities())
        .unwrap_or_default();
    ExecPolicy::Declared(caps)
}

/// Instantiates the Zed extension compiled at `wasm` (cached), with its install directory as the
/// working directory and its manifest's exec capabilities, hands it `settings`, and runs
/// `init-extension`.
fn start_zed(wasm: &Path, settings: serde_json::Value) -> Result<ZedExtension, String> {
    let component = cached_component(wasm)?;
    // The extension's working directory ($PWD, and the dir it may read/write, e.g. to download a
    // server) is its own install directory — the folder holding its `.wasm`.
    let work_dir = extension_work_dir(wasm);
    let mut ext = zed::instantiate_component(shared_engine(), &component, &work_dir)?;
    ext.set_exec_policy(manifest_exec_policy(&work_dir));
    // Hand the extension the editor's settings so it honours the user's configured binary /
    // settings / init options (read via `get-settings`).
    ext.set_settings(settings);
    ext.init()?;
    Ok(ext)
}

/// Makes a command an extension returned usable from any working directory: a relative path that
/// exists under the extension's `work_dir` (e.g. a server it downloaded there) becomes absolute.
/// Bare names to be found on `PATH` (`node`), absolute paths and anything not under `work_dir`
/// are returned unchanged.
fn absolutize_command(command: &str, work_dir: &Path) -> String {
    if command.is_empty() || Path::new(command).is_absolute() {
        return command.to_string();
    }
    let Some(candidate) = zed::confine(work_dir, command) else {
        return command.to_string();
    };
    let mut candidates = vec![candidate.clone()];
    if cfg!(windows) && candidate.extension().is_none() {
        candidates.push(candidate.with_extension("exe"));
    }
    candidates
        .into_iter()
        .find(|c| c.is_file())
        .map(|c| c.display().to_string())
        .unwrap_or_else(|| command.to_string())
}

/// Runs a Zed extension's WASM to resolve a language server's launch command for `worktree_root`.
/// Returns the command, ready to turn into an [`LspAdapter`]. (Instantiates the component, runs
/// `init-extension`, then `language-server-command`.) A relative command that the extension
/// installed under its own directory is returned as an absolute path, so it can be spawned with the
/// project root as the working directory.
pub fn resolve_server_command(
    wasm: &Path,
    server_id: &str,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<LangServerCommand, String> {
    let mut ext = start_zed(wasm, settings)?;
    let mut cmd = ext.language_server_command(server_id, worktree_root.to_path_buf())?;
    cmd.command = absolutize_command(&cmd.command, ext.work_dir());
    Ok(cmd)
}

/// Everything the native LSP client needs from a Zed extension to run one of its language servers:
/// the launch command (with its environment), plus the `initializationOptions` and workspace
/// configuration the extension provides. See [`resolve_language_server`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedLanguageServer {
    pub command: LangServerCommand,
    /// From `language-server-initialization-options` (`None` when the extension has none or the
    /// export failed — the server still starts, as in Zed).
    pub initialization_options: Option<serde_json::Value>,
    /// From `language-server-workspace-configuration` (same fallback).
    pub workspace_configuration: Option<serde_json::Value>,
}

impl ResolvedLanguageServer {
    /// An [`LspAdapter`] serving `language`, keyed `key` (the server id), that launches this server
    /// with the extension's environment, initialization options and workspace configuration. The
    /// user's `lsp.<server>` settings are merged on top by the LSP manager.
    pub fn into_adapter(self, language: &str, key: &str) -> LspAdapter {
        LspAdapter {
            language: language.to_string(),
            command: self.command.command,
            args: self.command.args,
            key: Some(key.to_string()),
            env: self.command.env.into_iter().collect(),
            initialization_options: self.initialization_options,
            workspace_configuration: self.workspace_configuration,
            ..LspAdapter::default()
        }
    }
}

/// Runs a Zed extension's WASM once to resolve a language server for `worktree_root`: its launch
/// command (as [`resolve_server_command`]) plus its initialization options and workspace
/// configuration, all from the same instance. Only a failing command is an error.
pub fn resolve_language_server(
    wasm: &Path,
    server_id: &str,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<ResolvedLanguageServer, String> {
    let mut ext = start_zed(wasm, settings)?;
    let mut command = ext.language_server_command(server_id, worktree_root.to_path_buf())?;
    command.command = absolutize_command(&command.command, ext.work_dir());
    let initialization_options = ext
        .language_server_initialization_options(server_id, worktree_root.to_path_buf())
        .ok()
        .flatten();
    let workspace_configuration = ext
        .language_server_workspace_configuration(server_id, worktree_root.to_path_buf())
        .ok()
        .flatten();
    Ok(ResolvedLanguageServer {
        command,
        initialization_options,
        workspace_configuration,
    })
}

/// Runs a Zed extension's WASM to get a language server's `initializationOptions`
/// (`language-server-initialization-options`) for `worktree_root`. `None` when the extension has
/// none.
pub fn resolve_server_initialization_options(
    wasm: &Path,
    server_id: &str,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    start_zed(wasm, settings)?
        .language_server_initialization_options(server_id, worktree_root.to_path_buf())
}

/// Runs a Zed extension's WASM to get a language server's workspace configuration (the answer to
/// `workspace/configuration` / `didChangeConfiguration`; `language-server-workspace-configuration`).
pub fn resolve_server_workspace_configuration(
    wasm: &Path,
    server_id: &str,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    start_zed(wasm, settings)?
        .language_server_workspace_configuration(server_id, worktree_root.to_path_buf())
}

/// Runs a Zed extension's WASM to get initialization options it contributes to *another* language
/// server, `target_server_id` (`language-server-additional-initialization-options`).
pub fn resolve_server_additional_initialization_options(
    wasm: &Path,
    server_id: &str,
    target_server_id: &str,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    start_zed(wasm, settings)?.language_server_additional_initialization_options(
        server_id,
        target_server_id,
        worktree_root.to_path_buf(),
    )
}

/// Runs a Zed extension's WASM to get workspace configuration it contributes to *another* language
/// server, `target_server_id` (`language-server-additional-workspace-configuration`).
pub fn resolve_server_additional_workspace_configuration(
    wasm: &Path,
    server_id: &str,
    target_server_id: &str,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    start_zed(wasm, settings)?.language_server_additional_workspace_configuration(
        server_id,
        target_server_id,
        worktree_root.to_path_buf(),
    )
}

/// Runs a Zed extension's WASM to resolve a **context (MCP) server**'s launch command. Any
/// `worktree_roots` are registered so the `project` the extension sees enumerates them.
pub fn resolve_context_server_command(
    wasm: &Path,
    server_id: &str,
    worktree_roots: &[std::path::PathBuf],
    settings: serde_json::Value,
) -> Result<LangServerCommand, String> {
    let mut ext = start_zed(wasm, settings)?;
    for root in worktree_roots {
        ext.add_worktree(root.clone())?;
    }
    let mut cmd = ext.context_server_command(server_id)?;
    cmd.command = absolutize_command(&cmd.command, ext.work_dir());
    Ok(cmd)
}

/// Runs one of a Zed extension's **slash commands** via its WASM, optionally against a worktree,
/// returning the command's output for the Assistant.
pub fn run_zed_slash_command(
    wasm: &Path,
    command: &zed::SlashCommandInfo,
    args: &[String],
    worktree_root: Option<&Path>,
    settings: serde_json::Value,
) -> Result<zed::SlashCommandResult, String> {
    start_zed(wasm, settings)?.run_slash_command(
        command,
        args,
        worktree_root.map(Path::to_path_buf),
    )
}

/// Asks a Zed extension's WASM for **argument completions** for one of its slash commands, given
/// the arguments typed so far.
pub fn complete_zed_slash_command(
    wasm: &Path,
    command: &zed::SlashCommandInfo,
    args: &[String],
    settings: serde_json::Value,
) -> Result<Vec<zed::SlashCommandCompletion>, String> {
    start_zed(wasm, settings)?.complete_slash_command_argument(command, args)
}

/// Runs a Zed extension's WASM to resolve a **debug adapter**'s launch binary (`get-dap-binary`)
/// for a given adapter + config, against `worktree_root`.
pub fn resolve_dap_binary(
    wasm: &Path,
    adapter_name: &str,
    definition: &zed::DapTaskDefinition,
    user_installed_path: Option<String>,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<zed::DapBinary, String> {
    let mut ext = start_zed(wasm, settings)?;
    let mut bin = ext.get_dap_binary(
        adapter_name,
        definition,
        user_installed_path,
        worktree_root.to_path_buf(),
    )?;
    bin.command = bin.command.map(|c| absolutize_command(&c, ext.work_dir()));
    Ok(bin)
}

/// Runs a debug-adapter extension's WASM to translate a high-level [`zed::DapConfig`] into an
/// adapter-specific debug scenario (`dap-config-to-scenario`).
pub fn resolve_dap_scenario(
    wasm: &Path,
    config: &zed::DapConfig,
    settings: serde_json::Value,
) -> Result<zed::DapScenario, String> {
    start_zed(wasm, settings)?.dap_config_to_scenario(config)
}

/// Runs a locator extension's WASM to turn a build/run task into a debug scenario
/// (`dap-locator-create-scenario`). `None` means the locator does not apply to the task.
pub fn create_dap_locator_scenario(
    wasm: &Path,
    locator_name: &str,
    build_task: &zed::DapTaskTemplate,
    resolved_label: &str,
    debug_adapter_name: &str,
    settings: serde_json::Value,
) -> Result<Option<zed::DapScenario>, String> {
    start_zed(wasm, settings)?.dap_locator_create_scenario(
        locator_name,
        build_task,
        resolved_label,
        debug_adapter_name,
    )
}

/// Runs a locator extension's WASM second phase: resolves a built task into a concrete launch/attach
/// request (`run-dap-locator`).
pub fn run_dap_locator(
    wasm: &Path,
    locator_name: &str,
    build_task: &zed::DapTaskTemplate,
    settings: serde_json::Value,
) -> Result<zed::DapRequest, String> {
    start_zed(wasm, settings)?.run_dap_locator(locator_name, build_task)
}

/// A launchable debug target an extension locator produced from a build/run task: the debug adapter
/// to spawn, the concrete launch/attach request, and which locator/scenario produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedDebug {
    /// The debug adapter to spawn (from `get-dap-binary`).
    pub adapter_command: String,
    pub adapter_args: Vec<String>,
    /// Extra environment and working directory for the adapter process (from `get-dap-binary`).
    pub adapter_env: Vec<(String, String)>,
    pub adapter_cwd: Option<String>,
    /// The adapter's JSON configuration for the launch request (from `get-dap-binary`), which
    /// refines the scenario's config.
    pub adapter_configuration: String,
    /// The concrete launch/attach request (from `run-dap-locator`).
    pub request: zed::DapRequest,
    /// The scenario the locator produced (names the adapter, carries the JSON config).
    pub scenario: zed::DapScenario,
    /// The locator that handled the task.
    pub locator_name: String,
}

/// "Debug this task via a locator": tries every installed debug **locator** paired with every
/// installed debug **adapter** to turn `task` into a launchable [`LocatedDebug`]. Returns
/// `Ok(None)` when no locator applies. The pipeline composes three exports —
/// `dap-locator-create-scenario` (does this locator handle the task for that adapter?),
/// `run-dap-locator` (the concrete program to launch), and `get-dap-binary` (the adapter to spawn).
///
/// One misbehaving locator or adapter does not abort the search: a failing pairing is skipped and
/// the next one tried. Only if no pairing succeeds is the last error returned (or `Ok(None)` when
/// none applied and none failed).
///
/// Only extension-provided debug adapters are considered (a native adapter has no WASM to resolve a
/// binary from); if none are installed, this returns `Ok(None)`.
pub fn locate_debug_target(
    extensions_dir: &Path,
    task: &zed::DapTaskTemplate,
    worktree_root: &Path,
    settings: serde_json::Value,
) -> Result<Option<LocatedDebug>, String> {
    let adapters = zed_debug_adapters(extensions_dir);
    let mut last_error: Option<String> = None;
    for loc in zed_debug_locators(extensions_dir) {
        for ad in &adapters {
            let attempt = (|| -> Result<Option<LocatedDebug>, String> {
                let Some(scenario) = create_dap_locator_scenario(
                    &loc.wasm,
                    &loc.locator_name,
                    task,
                    &task.label,
                    &ad.adapter_name,
                    settings.clone(),
                )?
                else {
                    return Ok(None); // this locator does not handle this (task, adapter)
                };
                let request =
                    run_dap_locator(&loc.wasm, &loc.locator_name, task, settings.clone())?;
                let def = zed::DapTaskDefinition {
                    label: scenario.label.clone(),
                    adapter: scenario.adapter.clone(),
                    config: scenario.config.clone(),
                };
                let bin = resolve_dap_binary(
                    &ad.wasm,
                    &ad.adapter_name,
                    &def,
                    None,
                    worktree_root,
                    settings.clone(),
                )?;
                // A TCP-only adapter: our launcher needs a command — try the next pairing.
                let Some(adapter_command) = bin.command else {
                    return Ok(None);
                };
                Ok(Some(LocatedDebug {
                    adapter_command,
                    adapter_args: bin.arguments,
                    adapter_env: bin.env,
                    adapter_cwd: bin.cwd,
                    adapter_configuration: bin.configuration,
                    request,
                    scenario,
                    locator_name: loc.locator_name.clone(),
                }))
            })();
            match attempt {
                Ok(Some(found)) => return Ok(Some(found)),
                Ok(None) => {}
                Err(e) => {
                    last_error = Some(format!(
                        "locator `{}` with adapter `{}`: {e}",
                        loc.locator_name, ad.adapter_name
                    ))
                }
            }
        }
    }
    match last_error {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

/// The language name for a `languages/<dir>`: the `config.toml` `name`, else the directory name.
fn language_name(lang_dir: &Path) -> String {
    #[derive(Deserialize)]
    struct LangConfig {
        #[serde(default)]
        name: String,
    }
    if let Ok(text) = std::fs::read_to_string(lang_dir.join("config.toml"))
        && let Ok(cfg) = toml::from_str::<LangConfig>(&text)
        && !cfg.name.is_empty()
    {
        return cfg.name;
    }
    lang_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
