//! The ORRESS language-server client.
//!
//! A thread-based LSP client (JSON-RPC over the server's stdio) with a manager that keeps one
//! server per language, started on demand. It provides live **diagnostics**, **hover**,
//! **go-to-definition** and **completion** — the features that matter most when writing a
//! solver (source-level debugging lives in `orress-dap`). No async runtime: results arrive on
//! channels the UI polls, which suits egui.
//!
//! Positions: we offer UTF-8 and UTF-16 (`positionEncodings`) and read the encoding the server
//! picks from its `initialize` result (UTF-16 when it names none — pyright and older clangd).
//! [`LspManager::encoding`] reports it; [`position_at_enc`] / [`byte_at_enc`] convert.
//!
//! User settings (`lsp.<server>` in settings.json: binary path/arguments/env, settings,
//! initialization options) apply to every adapter — built-in, imported or extension-provided —
//! matched by server name; see [`LspManager::set_server_settings`]. An adapter may carry its own
//! environment, `initializationOptions` and workspace configuration (e.g. what a Zed extension's
//! WASM returned); the user's settings are deep-merged on top of them, as in Zed.

mod transport;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use transport::{Notify, RpcResult, Transport, normalize_uri};

pub use lsp_types::{
    CompletionItem, CompletionItemKind, Diagnostic, DiagnosticSeverity, Hover, HoverContents,
    Location, MarkedString, MarkupContent, Position, Range, Url,
};

/// How a server counts the `character` of a position: in UTF-8 bytes, UTF-16 code units (the
/// protocol default) or Unicode scalar values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PositionEncoding {
    Utf8,
    #[default]
    Utf16,
    Utf32,
}

/// How to launch a language server for a language.
#[derive(Clone, Debug, Default)]
pub struct ServerSpec {
    /// A key identifying the server instance: the adapter key (usually the language, e.g.
    /// "rust"), plus the workspace root when there is one — so files from two projects get two
    /// servers, each rooted in its own project.
    pub key: String,
    pub command: String,
    pub args: Vec<String>,
    /// Extra environment for the server process.
    pub env: Vec<(String, String)>,
    /// The LSP language id, e.g. "rust" or "python".
    pub language_id: String,
    /// The user's `initializationOptions` for this server, if configured.
    pub initialization_options: Option<Value>,
    /// The user's server settings, the answer to `workspace/configuration`.
    pub settings: Option<Value>,
}

/// The user's configuration for one language server — the `lsp.<server>` section of
/// settings.json, in Zed's shape.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct ServerSettings {
    pub binary: Option<BinarySettings>,
    pub settings: Option<Value>,
    pub initialization_options: Option<Value>,
}

/// A server binary override (`lsp.<server>.binary`).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct BinarySettings {
    pub path: Option<String>,
    pub arguments: Option<Vec<String>>,
    pub env: Option<BTreeMap<String, String>>,
}

/// A language-server **adapter manifest**: how to launch a server for a language, as data. The
/// built-in set covers rust-analyzer, pyright and clangd; the same shape is loaded from JSON files
/// (a single object or an array) so an adapter can be added or overridden without a rebuild — the
/// no-WASM slice of Zed's language-server extensions (Zed ships the equivalent in `extension.toml`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LspAdapter {
    /// The ORRESS language this serves (e.g. `"Rust"`, `"C"`, `"C++"`), matched case-insensitively.
    pub language: String,
    /// The server executable (found on `PATH`).
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// The LSP `languageId` for `didOpen`; defaults to the lowercased language name.
    #[serde(default)]
    pub language_id: Option<String>,
    /// Ancestor files that mark the workspace root (e.g. `["Cargo.toml"]`,
    /// `["compile_commands.json", ".clangd", "CMakeLists.txt"]`). The nearest match is the root; if
    /// none is found the file is analysed standalone (detached).
    #[serde(default)]
    pub root_markers: Vec<String>,
    /// A stable key for the server instance; defaults to the lowercased language name.
    #[serde(default)]
    pub key: Option<String>,
    /// Extra environment for the server process (e.g. a toolchain on `PATH` a Zed extension asked
    /// for). The user's `lsp.<server>.binary.env` wins per variable.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// The adapter's own `initializationOptions` (e.g. from a Zed extension's
    /// `language-server-initialization-options`). The user's `lsp.<server>.initialization_options`
    /// are deep-merged on top.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initialization_options: Option<Value>,
    /// The adapter's own workspace configuration, the base answer to `workspace/configuration`
    /// (e.g. from a Zed extension's `language-server-workspace-configuration`). The user's
    /// `lsp.<server>.settings` are deep-merged on top.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_configuration: Option<Value>,
}

impl LspAdapter {
    /// The server-instance key (explicit, else the lowercased language name).
    pub fn key(&self) -> String {
        self.key
            .clone()
            .unwrap_or_else(|| self.language.to_ascii_lowercase())
    }

    /// The LSP `languageId` (explicit, else the lowercased language name).
    pub fn language_id(&self) -> String {
        self.language_id
            .clone()
            .unwrap_or_else(|| self.language.to_ascii_lowercase())
    }

    /// The nearest ancestor directory of `path` that contains one of `root_markers`, or `None`
    /// (the file is analysed standalone).
    pub fn root_for(&self, path: &Path) -> Option<PathBuf> {
        if self.root_markers.is_empty() {
            return None;
        }
        let mut dir = path.parent();
        while let Some(d) = dir {
            if self.root_markers.iter().any(|m| d.join(m).exists()) {
                return Some(d.to_path_buf());
            }
            dir = d.parent();
        }
        None
    }

    /// The names a user may configure this server under in `lsp.<server>`: its key, its
    /// executable's name (`rust-analyzer`, `clangd`), that name without a `-langserver` suffix
    /// (`pyright`), and the language.
    fn settings_names(&self) -> Vec<String> {
        let mut names = vec![self.key()];
        if let Some(stem) = Path::new(&self.command)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
        {
            if let Some(short) = stem.strip_suffix("-langserver") {
                names.push(short.to_string());
            }
            names.push(stem);
        }
        names.push(self.language.to_ascii_lowercase());
        names
    }

    fn spec(&self) -> ServerSpec {
        ServerSpec {
            key: self.key(),
            command: self.command.clone(),
            args: self.args.clone(),
            env: self
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            language_id: self.language_id(),
            initialization_options: self.initialization_options.clone(),
            settings: self.workspace_configuration.clone(),
        }
    }
}

/// The built-in language-server adapters.
pub fn builtin_adapters() -> Vec<LspAdapter> {
    let a = |language: &str, command: &str, args: &[&str], markers: &[&str]| LspAdapter {
        language: language.into(),
        command: command.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        language_id: None,
        root_markers: markers.iter().map(|s| s.to_string()).collect(),
        ..LspAdapter::default()
    };
    vec![
        a("Rust", "rust-analyzer", &[], &["Cargo.toml"]),
        a(
            "Python",
            "pyright-langserver",
            &["--stdio"],
            &["pyproject.toml", "setup.py", "setup.cfg"],
        ),
        // clangd serves both C and C++ (the grammars added in the tree-sitter step).
        a(
            "C",
            "clangd",
            &[],
            &["compile_commands.json", ".clangd", "CMakeLists.txt"],
        ),
        a(
            "C++",
            "clangd",
            &[],
            &["compile_commands.json", ".clangd", "CMakeLists.txt"],
        ),
        // asm-lsp (cargo install asm-lsp): hover with instruction reference docs, completion and
        // diagnostics for assembly. Launched over stdio; analysed standalone when there is no root.
        LspAdapter {
            language: "Assembly".into(),
            command: "asm-lsp".into(),
            args: Vec::new(),
            language_id: Some("asm".into()),
            root_markers: vec![".asm-lsp.toml".into(), "asm-lsp.toml".into()],
            ..LspAdapter::default()
        },
    ]
}

/// Loads LSP-adapter manifests from a directory of `*.json` files (each a single adapter object or
/// an array of them). Returns the adapters and any per-file parse errors (to surface, not fail on).
pub fn load_adapters(dir: &Path) -> (Vec<LspAdapter>, Vec<String>) {
    let mut adapters = Vec::new();
    let mut errors = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (adapters, errors);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            // Accept either one adapter or an array of them.
            Ok(json) => match serde_json::from_str::<OneOrMany>(&json) {
                Ok(OneOrMany::One(a)) => adapters.push(*a),
                Ok(OneOrMany::Many(v)) => adapters.extend(v),
                Err(e) => errors.push(format!("LSP adapter {} ignored: {e}", path.display())),
            },
            Err(e) => errors.push(format!("LSP adapter {} ignored: {e}", path.display())),
        }
    }
    (adapters, errors)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(Box<LspAdapter>),
    Many(Vec<LspAdapter>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotStarted,
    Starting,
    Ready,
    Failed,
}

struct Server {
    transport: Transport,
    open: HashSet<String>,
    versions: HashMap<String, i32>,
    hashes: HashMap<String, u64>,
}

/// Manages language servers and routes document events to them.
pub struct LspManager {
    servers: HashMap<String, Result<Server, String>>,
    notify: Notify,
    /// Language-server adapters, built-ins first, then any imported ones (which override by
    /// language, since `adapter_for` takes the last match).
    adapters: Vec<LspAdapter>,
    /// The user's per-server settings (`lsp.<server>`), by server name.
    server_settings: HashMap<String, ServerSettings>,
}

/// A pending request result the UI polls.
pub struct Pending {
    rx: std::sync::mpsc::Receiver<RpcResult>,
}

impl Pending {
    /// `None` while still waiting; `Some(result)` once the server replies.
    pub fn poll(&self) -> Option<RpcResult> {
        self.rx.try_recv().ok()
    }
}

impl LspManager {
    pub fn new(notify: Notify) -> Self {
        Self {
            servers: HashMap::new(),
            notify,
            adapters: builtin_adapters(),
            server_settings: HashMap::new(),
        }
    }

    /// Sets the user's per-server configuration from the `lsp` section of settings.json (an
    /// object of `"<server>": { "binary": …, "settings": …, "initialization_options": … }`).
    /// Entries that do not parse are skipped. Applies to servers started from now on.
    pub fn set_server_settings(&mut self, lsp: &Value) {
        self.server_settings = lsp
            .as_object()
            .map(|map| {
                map.iter()
                    .filter_map(|(name, v)| {
                        serde_json::from_value::<ServerSettings>(v.clone())
                            .ok()
                            .map(|s| (name.clone(), s))
                    })
                    .collect()
            })
            .unwrap_or_default();
    }

    /// The user's settings for `adapter`, looked up by its server names.
    fn settings_for(&self, adapter: &LspAdapter) -> Option<&ServerSettings> {
        adapter
            .settings_names()
            .iter()
            .find_map(|name| self.server_settings.get(name))
    }

    /// Registers imported adapters (from manifests). They are appended, so an adapter for a
    /// language already covered by a built-in overrides it.
    pub fn add_adapters(&mut self, more: Vec<LspAdapter>) {
        self.adapters.extend(more);
    }

    /// Replaces all imported adapters: the set becomes the built-ins plus `more`. Used to
    /// re-register after an extension is installed or removed.
    pub fn reset_adapters(&mut self, more: Vec<LspAdapter>) {
        self.adapters = builtin_adapters();
        self.adapters.extend(more);
    }

    /// The adapter serving `language` (case-insensitive), preferring the most recently added.
    pub fn adapter_for(&self, language: &str) -> Option<&LspAdapter> {
        self.adapters
            .iter()
            .rev()
            .find(|a| a.language.eq_ignore_ascii_case(language))
    }

    /// Resolves the launch spec, workspace root and working directory for `language` at `path`,
    /// from the matching adapter. `None` when no adapter serves the language.
    pub fn resolve(
        &self,
        language: &str,
        path: &Path,
    ) -> Option<(ServerSpec, Option<PathBuf>, PathBuf)> {
        let adapter = self.adapter_for(language)?;
        let root = adapter.root_for(path);
        let cwd = root
            .clone()
            .or_else(|| path.parent().map(Path::to_path_buf))?;
        let mut spec = adapter.spec();
        if let Some(user) = self.settings_for(adapter) {
            apply_settings(&mut spec, user);
        }
        // One server per (adapter, project root): a second project's files must not be analysed
        // under the first project's root.
        if let Some(root) = &root {
            spec.key = format!("{}@{}", spec.key, root.display());
        }
        Some((spec, root, cwd))
    }

    /// The position encoding the server for `spec_key` negotiated (UTF-16 until it is ready).
    pub fn encoding(&self, spec_key: &str) -> PositionEncoding {
        match self.servers.get(spec_key) {
            Some(Ok(server)) => server
                .transport
                .inner
                .shared
                .lock()
                .map(|s| s.encoding)
                .unwrap_or_default(),
            _ => PositionEncoding::default(),
        }
    }

    /// Sends `didClose` for every open document `keep` rejects (e.g. files whose editor tab was
    /// closed), so servers stop tracking them.
    pub fn close_documents(&mut self, mut keep: impl FnMut(&Path) -> bool) {
        for server in self.servers.values_mut().flatten() {
            let closing: Vec<String> = server
                .open
                .iter()
                .filter(|uri| {
                    Url::parse(uri)
                        .ok()
                        .and_then(|u| u.to_file_path().ok())
                        .is_some_and(|p| !keep(&p))
                })
                .cloned()
                .collect();
            for uri in closing {
                server.open.remove(&uri);
                server.versions.remove(&uri);
                server.hashes.remove(&uri);
                server.transport.inner.notify_server(
                    "textDocument/didClose",
                    json!({"textDocument": {"uri": uri}}),
                );
            }
        }
    }

    /// Ensures the server for `spec` is running and the document is open and up to date.
    /// `workspace` is the project root (a Cargo project) when the file belongs to one, or
    /// `None` for a standalone file — then the server runs in detached-file mode and only
    /// analyses the open file, rather than indexing `cwd`. `cwd` is where the server runs.
    pub fn sync(
        &mut self,
        spec: &ServerSpec,
        workspace: Option<&Path>,
        cwd: &Path,
        path: &Path,
        text: &str,
    ) {
        let Ok(uri) = Url::from_file_path(path) else {
            return;
        };
        let uri_s = uri.to_string();
        if !self.servers.contains_key(&spec.key) {
            let started = start_server(spec, workspace, cwd, path, &self.notify);
            self.servers.insert(spec.key.clone(), started);
        }
        let Some(Ok(server)) = self.servers.get_mut(&spec.key) else {
            return;
        };
        let hash = hash(text);
        if !server.open.contains(&uri_s) {
            server.open.insert(uri_s.clone());
            server.versions.insert(uri_s.clone(), 1);
            server.hashes.insert(uri_s.clone(), hash);
            server.transport.inner.notify_server(
                "textDocument/didOpen",
                json!({"textDocument": {"uri": uri, "languageId": spec.language_id, "version": 1, "text": text}}),
            );
        } else if server.hashes.get(&uri_s) != Some(&hash) {
            let v = server.versions.entry(uri_s.clone()).or_insert(1);
            *v += 1;
            server.hashes.insert(uri_s.clone(), hash);
            server.transport.inner.notify_server(
                "textDocument/didChange",
                json!({"textDocument": {"uri": uri, "version": *v}, "contentChanges": [{"text": text}]}),
            );
        }
    }

    /// Tells the server the document was saved.
    pub fn did_save(&self, spec_key: &str, path: &Path) {
        if let Some(Ok(server)) = self.servers.get(spec_key)
            && let Ok(uri) = Url::from_file_path(path)
        {
            server.transport.inner.notify_server(
                "textDocument/didSave",
                json!({"textDocument": {"uri": uri}}),
            );
        }
    }

    pub fn status(&self, spec_key: &str) -> Status {
        match self.servers.get(spec_key) {
            None => Status::NotStarted,
            Some(Err(_)) => Status::Failed,
            Some(Ok(server)) => match server.transport.inner.shared.lock() {
                Ok(s) if s.error.is_some() => Status::Failed,
                Ok(s) if s.ready => Status::Ready,
                _ => Status::Starting,
            },
        }
    }

    /// Any error that stopped the server for this language.
    pub fn error(&self, spec_key: &str) -> Option<String> {
        match self.servers.get(spec_key)? {
            Err(e) => Some(e.clone()),
            Ok(server) => server
                .transport
                .inner
                .shared
                .lock()
                .ok()
                .and_then(|s| s.error.clone()),
        }
    }

    /// Current diagnostics for a file.
    pub fn diagnostics(&self, spec_key: &str, path: &Path) -> Vec<Diagnostic> {
        let Some(Ok(server)) = self.servers.get(spec_key) else {
            return Vec::new();
        };
        let Ok(uri) = Url::from_file_path(path) else {
            return Vec::new();
        };
        server
            .transport
            .inner
            .shared
            .lock()
            .ok()
            .and_then(|s| s.diagnostics.get(&normalize_uri(uri.as_ref())).cloned())
            .unwrap_or_default()
    }

    /// Every diagnostic across all servers, as (file path, diagnostic).
    pub fn all_diagnostics(&self) -> Vec<(PathBuf, Diagnostic)> {
        let mut out = Vec::new();
        for server in self.servers.values().flatten() {
            if let Ok(shared) = server.transport.inner.shared.lock() {
                for (uri, diags) in &shared.diagnostics {
                    if diags.is_empty() {
                        continue;
                    }
                    let path = Url::parse(uri).ok().and_then(|u| u.to_file_path().ok());
                    if let Some(path) = path {
                        for d in diags {
                            out.push((path.clone(), d.clone()));
                        }
                    }
                }
            }
        }
        out
    }

    /// A monotone counter that advances whenever any server publishes new data.
    pub fn generation(&self, spec_key: &str) -> u64 {
        match self.servers.get(spec_key) {
            Some(Ok(server)) => server
                .transport
                .inner
                .shared
                .lock()
                .map(|s| s.generation)
                .unwrap_or(0),
            _ => 0,
        }
    }

    pub fn hover(&self, spec_key: &str, path: &Path, pos: Position) -> Option<Pending> {
        self.request(spec_key, "textDocument/hover", path, pos)
    }

    pub fn definition(&self, spec_key: &str, path: &Path, pos: Position) -> Option<Pending> {
        self.request(spec_key, "textDocument/definition", path, pos)
    }

    pub fn completion(&self, spec_key: &str, path: &Path, pos: Position) -> Option<Pending> {
        self.request(spec_key, "textDocument/completion", path, pos)
    }

    fn request(&self, spec_key: &str, method: &str, path: &Path, pos: Position) -> Option<Pending> {
        let Some(Ok(server)) = self.servers.get(spec_key) else {
            return None;
        };
        // Until `initialize` returns the position encoding is unknown, so a position computed
        // now could be wrong; the caller simply asks again on a later frame.
        if !server.transport.inner.shared.lock().is_ok_and(|s| s.ready) {
            return None;
        }
        let uri = Url::from_file_path(path).ok()?;
        let rx = server.transport.inner.request(
            method,
            json!({"textDocument": {"uri": uri}, "position": {"line": pos.line, "character": pos.character}}),
        );
        Some(Pending { rx })
    }
}

fn start_server(
    spec: &ServerSpec,
    workspace: Option<&Path>,
    cwd: &Path,
    doc: &Path,
    notify: &Notify,
) -> Result<Server, String> {
    let child = Command::new(&spec.command)
        .args(&spec.args)
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {} ({e})", spec.command))?;

    // A real workspace gets a rootUri + workspace folder; a standalone file gets neither,
    // so rust-analyzer analyses just the opened file instead of indexing the folder.
    let root_uri = workspace.and_then(|w| Url::from_directory_path(w).ok());
    let folders = match &root_uri {
        Some(uri) => json!([{ "uri": uri, "name": "root" }]),
        None => Value::Null,
    };
    let init_options = init_options(spec.initialization_options.clone(), workspace, doc);
    let init_id = 0i64;
    let init = json!({
        "jsonrpc": "2.0",
        "id": init_id,
        "method": "initialize",
        "params": {
            "processId": std::process::id(),
            "rootUri": root_uri,
            "capabilities": {
                "general": { "positionEncodings": ["utf-8", "utf-16"] },
                "textDocument": {
                    "synchronization": { "didSave": true, "dynamicRegistration": false },
                    "publishDiagnostics": { "relatedInformation": false },
                    "hover": { "contentFormat": ["markdown", "plaintext"] },
                    "definition": { "linkSupport": false },
                    "completion": { "completionItem": { "snippetSupport": false } }
                },
                "workspace": {
                    "configuration": true,
                    "workspaceFolders": true,
                    "applyEdit": false
                }
            },
            "workspaceFolders": folders,
            // For a standalone file (no Cargo workspace) rust-analyzer needs it listed as a
            // detached file, or it reports "failed to discover workspace" and no diagnostics.
            "initializationOptions": init_options
        }
    });
    let transport = Transport::new(
        child,
        init_id,
        Vec::new(),
        spec.settings.clone(),
        Arc::clone(notify),
    );
    // Send initialize immediately (the reader flips `ready` and flushes the rest).
    transport.inner.notify_raw(init);
    Ok(Server {
        transport,
        open: HashSet::new(),
        versions: HashMap::new(),
        hashes: HashMap::new(),
    })
}

/// Layers the user's `lsp.<server>` configuration over an adapter's launch spec: a binary
/// path/arguments override, extra environment, and initialization options and server settings
/// deep-merged over the adapter's own (the user's values win, as in Zed).
fn apply_settings(spec: &mut ServerSpec, user: &ServerSettings) {
    if let Some(binary) = &user.binary {
        if let Some(path) = binary.path.as_ref().filter(|p| !p.is_empty()) {
            spec.command.clone_from(path);
        }
        if let Some(args) = &binary.arguments {
            spec.args.clone_from(args);
        }
        if let Some(env) = &binary.env {
            for (k, v) in env {
                spec.env.retain(|(key, _)| key != k);
                spec.env.push((k.clone(), v.clone()));
            }
        }
    }
    merge_option(
        &mut spec.initialization_options,
        user.initialization_options.as_ref(),
    );
    merge_option(&mut spec.settings, user.settings.as_ref());
}

/// Deep-merges `overlay` (when present) over `base`, or adopts it when `base` is empty.
fn merge_option(base: &mut Option<Value>, overlay: Option<&Value>) {
    let Some(overlay) = overlay else {
        return;
    };
    match base {
        Some(base) => merge_json(base, overlay),
        None => *base = Some(overlay.clone()),
    }
}

/// Deep-merges `overlay` into `base`: objects merge key by key (recursively), anything else —
/// scalars, arrays, mismatched types — is replaced by the overlay's value.
pub fn merge_json(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(key) {
                    Some(existing) => merge_json(existing, value),
                    None => {
                        base.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

/// The `initializationOptions` to send: the user's, plus — for a standalone file (no workspace)
/// — the file listed as a detached file, which rust-analyzer needs to analyse it at all.
fn init_options(user: Option<Value>, workspace: Option<&Path>, doc: &Path) -> Value {
    let mut options = user.unwrap_or_else(|| json!({}));
    if workspace.is_none()
        && let Some(map) = options.as_object_mut()
        && !map.contains_key("detachedFiles")
    {
        map.insert("detachedFiles".into(), json!([doc.to_string_lossy()]));
    }
    options
}

/// The LSP position (line, UTF-8 character) for a byte offset in `text`.
pub fn position_at(text: &str, byte: usize) -> Position {
    position_at_enc(text, byte, PositionEncoding::Utf8)
}

/// The byte offset in `text` for an LSP position whose character is in UTF-8 bytes.
pub fn byte_at(text: &str, pos: Position) -> usize {
    byte_at_enc(text, pos, PositionEncoding::Utf8)
}

/// The LSP position for a byte offset in `text`, with the character counted in `encoding`.
/// An offset inside a character counts from that character's start.
pub fn position_at_enc(text: &str, byte: usize, encoding: PositionEncoding) -> Position {
    let mut byte = byte.min(text.len());
    while !text.is_char_boundary(byte) {
        byte -= 1;
    }
    let before = &text[..byte];
    let line = before.matches('\n').count() as u32;
    let line_start = before.rfind('\n').map_or(0, |p| p + 1);
    let column = &text[line_start..byte];
    let character = match encoding {
        PositionEncoding::Utf8 => column.len(),
        PositionEncoding::Utf16 => column.encode_utf16().count(),
        PositionEncoding::Utf32 => column.chars().count(),
    } as u32;
    Position { line, character }
}

/// The byte offset in `text` for an LSP position whose character is counted in `encoding`.
/// Always a char boundary within the text: a line past the end gives the end of the text, a
/// character past the end of its line gives the line end, and a column inside a character
/// (e.g. half a UTF-16 surrogate pair) gives that character's start.
pub fn byte_at_enc(text: &str, pos: Position, encoding: PositionEncoding) -> usize {
    let mut line_start = 0;
    for _ in 0..pos.line {
        match text[line_start..].find('\n') {
            Some(p) => line_start += p + 1,
            None => return text.len(),
        }
    }
    let line_end = text[line_start..]
        .find('\n')
        .map_or(text.len(), |p| line_start + p);
    let line = &text[line_start..line_end];
    let want = pos.character as usize;
    let mut units = 0usize;
    for (offset, ch) in line.char_indices() {
        let width = match encoding {
            PositionEncoding::Utf8 => ch.len_utf8(),
            PositionEncoding::Utf16 => ch.len_utf16(),
            PositionEncoding::Utf32 => 1,
        };
        if units + width > want {
            return line_start + offset;
        }
        units += width;
    }
    line_end
}

/// Plain text from a hover result, if any.
pub fn hover_text(value: &Value) -> Option<String> {
    let hover: Hover = serde_json::from_value(value.clone()).ok()?;
    let text = match hover.contents {
        HoverContents::Scalar(MarkedString::String(s)) => s,
        HoverContents::Scalar(MarkedString::LanguageString(ls)) => ls.value,
        HoverContents::Markup(MarkupContent { value, .. }) => value,
        HoverContents::Array(items) => items
            .into_iter()
            .map(|m| match m {
                MarkedString::String(s) => s,
                MarkedString::LanguageString(ls) => ls.value,
            })
            .collect::<Vec<_>>()
            .join("\n"),
    };
    (!text.trim().is_empty()).then_some(text)
}

/// The first location from a definition result.
pub fn definition_location(value: &Value) -> Option<Location> {
    // The result is a Location, a Location[] or a LocationLink[].
    if let Ok(loc) = serde_json::from_value::<Location>(value.clone()) {
        return Some(loc);
    }
    if let Ok(locs) = serde_json::from_value::<Vec<Location>>(value.clone()) {
        return locs.into_iter().next();
    }
    if let Some(arr) = value.as_array()
        && let Some(first) = arr.first()
        && let (Some(uri), Some(range)) = (
            first.get("targetUri"),
            first
                .get("targetSelectionRange")
                .or_else(|| first.get("targetRange")),
        )
    {
        let uri: Url = serde_json::from_value(uri.clone()).ok()?;
        let range: Range = serde_json::from_value(range.clone()).ok()?;
        return Some(Location { uri, range });
    }
    None
}

/// The completion items from a completion result (a list or a bare array).
pub fn completion_items(value: &Value) -> Vec<CompletionItem> {
    if let Ok(list) = serde_json::from_value::<lsp_types::CompletionList>(value.clone()) {
        return list.items;
    }
    serde_json::from_value::<Vec<CompletionItem>>(value.clone()).unwrap_or_default()
}

fn hash(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// Finds the nearest ancestor with a `Cargo.toml` (the Rust workspace root).
pub fn cargo_root(path: &Path) -> Option<PathBuf> {
    let mut dir = path.parent();
    while let Some(d) = dir {
        if d.join("Cargo.toml").is_file() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}
