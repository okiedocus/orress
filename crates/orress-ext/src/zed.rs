//! Clean-room host for Zed's extension WIT world (`zed:extension`, `since_v0.6.0`, vendored under
//! `wit/zed`). It implements the host-import surface so a real Zed extension's WASM instantiates
//! and runs: platform/process, the worktree/project/key-value-store resources, and the GitHub,
//! HTTP, Node, file-download and DAP (`resolve-tcp-template`) host imports are all real. Besides
//! the imports, [`ZedExtension`] can drive the extension's exports — language server, context
//! (MCP) server, slash command and the full debug-adapter surface (`get-dap-binary`,
//! launch/attach kind, and the scenario/locator translation). The host also
//! provides a WASI runtime, since real extensions are built for `wasm32-wasip*` and touch
//! `env`/stdio/filesystem on startup.
//!
//! This is the clean-room half of Zed-extension compatibility: no Zed engine code, only the public
//! Apache-2.0 WIT API.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// A worktree the host exposes to an extension (a project folder it can read and probe).
pub struct WorktreeData {
    pub id: u64,
    pub root: PathBuf,
}

/// A project: a set of worktree ids.
pub struct ProjectData {
    pub worktree_ids: Vec<u64>,
}

/// A key-value store the host backs (e.g. for `index-docs`).
#[derive(Default)]
pub struct KeyValueData {
    pub map: BTreeMap<String, String>,
}

/// Backing for an HTTP response stream: the body, yielded once then exhausted.
pub struct HttpStreamData {
    body: Option<Vec<u8>>,
}

wasmtime::component::bindgen!({
    world: "extension",
    path: "wit/zed",
    // Back the host resources with our own types, stored in the `ResourceTable`.
    with: {
        "worktree": WorktreeData,
        "project": ProjectData,
        "key-value-store": KeyValueData,
        "zed:extension/http-client/http-response-stream": HttpStreamData,
    },
});

use zed::extension::{
    common, context_server, dap, github, http_client, lsp, nodejs, platform, process, slash_command,
};

/// The clean-room host state a Zed extension runs against.
///
/// The single [`ResourceTable`] backs both our Zed host resources (worktree/project/key-value) and
/// WASI's own resources (files, streams); [`WasiView`] hands WASI that same table plus the
/// [`WasiCtx`]. Real Zed extensions are WASI components (built for `wasm32-wasip*`) that touch
/// `env`/stdio/filesystem during startup, so the host must provide WASI for them to run at all.
pub struct ZedState {
    table: ResourceTable,
    wasi: WasiCtx,
    /// Editor settings the extension reads via `get-settings` (a JSON object). Top-level keys are
    /// Zed settings categories (e.g. `"lsp"`); an optional `"worktrees"` object keyed by worktree
    /// root path holds per-worktree overrides. Empty by default.
    settings: serde_json::Value,
    /// Worktrees the host has handed to the extension (id → root), in creation order. Lets
    /// `project` enumerate them and `get-settings` resolve a `settings-location`'s worktree.
    worktrees: Vec<(u64, PathBuf)>,
    /// Language-server installation statuses the extension reported (name → status text).
    pub statuses: Vec<(String, String)>,
    /// The extension's working directory. Every path the guest hands to a host import
    /// (`download-file`, `make-file-executable`, npm) is resolved against it and must stay inside.
    work_dir: PathBuf,
    /// Which commands `process::run-command` may spawn.
    exec_policy: ExecPolicy,
    /// When the current export call started, and how much of it was spent inside slow host imports
    /// (network, child processes). Their difference is the time the guest itself ran, which the
    /// epoch watchdog bounds (see [`GUEST_TIME_BUDGET`]).
    call_start: Instant,
    host_time: Duration,
}

/// The longest one export call may spend running guest code (excluding time inside host imports
/// such as downloads), after which the watchdog traps it. Keeps a looping extension from hanging
/// the host.
pub const GUEST_TIME_BUDGET: Duration = Duration::from_secs(30);

/// How often the shared engine's epoch advances (the watchdog's resolution).
pub(crate) const EPOCH_TICK: Duration = Duration::from_millis(50);

/// A `process:exec` capability an extension's manifest grants (Zed's
/// `capabilities = [{ kind = "process:exec", command = "...", args = [...] }]`). `command = "*"`
/// matches any command; in `args`, `"*"` matches any one argument and a trailing `"**"` any
/// remaining arguments; anything else must match exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCapability {
    pub command: String,
    pub args: Vec<String>,
}

impl ExecCapability {
    /// Whether this capability permits running `command` with `args`.
    pub fn allows(&self, command: &str, args: &[String]) -> bool {
        if self.command != "*" && self.command != command {
            return false;
        }
        let mut i = 0;
        for (n, pat) in self.args.iter().enumerate() {
            if pat == "**" && n + 1 == self.args.len() {
                return true;
            }
            match args.get(i) {
                Some(a) if pat == "*" || pat == a => i += 1,
                _ => return false,
            }
        }
        i == args.len()
    }
}

/// What `process::run-command` may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecPolicy {
    /// Anything (the default for a bare `instantiate`, where no manifest is known).
    Unrestricted,
    /// Only commands one of these capabilities allows — the manifest's declared `process:exec`
    /// capabilities, as Zed enforces them. Empty denies every command.
    Declared(Vec<ExecCapability>),
}

impl ExecPolicy {
    fn allows(&self, command: &str, args: &[String]) -> bool {
        match self {
            ExecPolicy::Unrestricted => true,
            ExecPolicy::Declared(caps) => caps.iter().any(|c| c.allows(command, args)),
        }
    }
}

impl ZedState {
    /// Builds host state for an extension whose working directory is `work_dir` — its `$PWD` and
    /// the one directory it may read and write (e.g. to download and run a language server there).
    fn new(work_dir: &Path) -> Self {
        let mut builder = WasiCtxBuilder::new();
        builder
            .inherit_stdio()
            .env("PWD", work_dir.to_string_lossy());
        // Preopen the extension's own directory as `.` so it can manage the files it owns. A
        // missing dir is non-fatal — the extension then simply has no filesystem access.
        let _ = builder.preopened_dir(work_dir, ".", DirPerms::all(), FilePerms::all());
        Self {
            table: ResourceTable::new(),
            wasi: builder.build(),
            settings: serde_json::json!({}),
            worktrees: Vec::new(),
            statuses: Vec::new(),
            work_dir: work_dir.to_path_buf(),
            exec_policy: ExecPolicy::Unrestricted,
            call_start: Instant::now(),
            host_time: Duration::ZERO,
        }
    }

    /// Resolves a path the guest passed to a host import against the extension's working
    /// directory, rejecting anything (absolute elsewhere, `..`) that would land outside it.
    fn guest_path(&self, path: &str) -> Result<PathBuf, String> {
        confine(&self.work_dir, path)
            .ok_or_else(|| format!("path `{path}` is outside the extension's working directory"))
    }

    /// Runs a (potentially slow) host operation, booking its wall time as host time so the guest
    /// watchdog does not count it against the extension.
    fn host_op<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let t = Instant::now();
        let r = f(self);
        self.host_time += t.elapsed();
        r
    }

    /// Registers a worktree rooted at `root`, assigning it the next id, and returns a handle to
    /// pass to an export.
    pub fn add_worktree(&mut self, root: PathBuf) -> wasmtime::Result<Resource<WorktreeData>> {
        let id = self.worktrees.len() as u64;
        self.worktrees.push((id, root.clone()));
        self.table
            .push(WorktreeData { id, root })
            .map_err(Into::into)
    }

    /// Creates a project enumerating every worktree registered so far.
    pub fn add_project(&mut self) -> wasmtime::Result<Resource<ProjectData>> {
        let worktree_ids = self.worktrees.iter().map(|(id, _)| *id).collect();
        self.table
            .push(ProjectData { worktree_ids })
            .map_err(Into::into)
    }
}

impl WasiView for ZedState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

// ---- HTTP + download helpers (used by the http-client, github and nodejs host interfaces). ----

/// A ureq agent honouring a redirect limit.
fn agent(max_redirects: u32) -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(max_redirects).build()
}

/// Performs an HTTP request and returns the response (headers + body).
fn http_fetch(req: &http_client::HttpRequest) -> Result<http_client::HttpResponse, String> {
    use http_client::{HttpMethod, RedirectPolicy};
    let method = match req.method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Patch => "PATCH",
    };
    let redirects = match req.redirect_policy {
        RedirectPolicy::NoFollow => 0,
        RedirectPolicy::FollowLimit(n) => n,
        RedirectPolicy::FollowAll => u32::MAX,
    };
    let mut r = agent(redirects).request(method, &req.url);
    // GitHub (and good manners) require a User-Agent.
    if !req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    {
        r = r.set("User-Agent", "ORRESS");
    }
    for (k, v) in &req.headers {
        r = r.set(k, v);
    }
    let resp = match &req.body {
        Some(body) => r.send_bytes(body),
        None => r.call(),
    }
    .map_err(|e| e.to_string())?;
    let headers = resp
        .headers_names()
        .iter()
        .filter_map(|n| resp.header(n).map(|v| (n.clone(), v.to_string())))
        .collect();
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut body).map_err(|e| e.to_string())?;
    Ok(http_client::HttpResponse { headers, body })
}

/// A simple GET returning the body bytes (sets a User-Agent, follows redirects).
fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let resp = agent(u32::MAX)
        .get(url)
        .set("User-Agent", "ORRESS")
        .call()
        .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut body).map_err(|e| e.to_string())?;
    Ok(body)
}

/// Parses a GitHub release JSON object into the WIT `github-release` (pure — unit tested).
fn github_release_from_json(v: &serde_json::Value) -> Result<github::GithubRelease, String> {
    let version = v
        .get("tag_name")
        .and_then(|t| t.as_str())
        .ok_or("GitHub release JSON has no `tag_name`")?
        .to_string();
    let assets = v
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    Some(github::GithubReleaseAsset {
                        name: a.get("name")?.as_str()?.to_string(),
                        download_url: a.get("browser_download_url")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(github::GithubRelease { version, assets })
}

/// Writes a downloaded payload to `dest`, decompressing by file type (pure — tested). `gzip-tar`
/// and `zip` unpack into `dest` as a directory; `gzip` and `uncompressed` write a single file.
fn write_download(
    bytes: &[u8],
    dest: &std::path::Path,
    file_type: DownloadedFileType,
) -> Result<(), String> {
    use std::io::Read;
    match file_type {
        DownloadedFileType::Uncompressed => std::fs::write(dest, bytes).map_err(|e| e.to_string()),
        DownloadedFileType::Gzip => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(bytes)
                .read_to_end(&mut out)
                .map_err(|e| e.to_string())?;
            std::fs::write(dest, out).map_err(|e| e.to_string())
        }
        DownloadedFileType::GzipTar => {
            let gz = flate2::read::GzDecoder::new(bytes);
            tar::Archive::new(gz)
                .unpack(dest)
                .map_err(|e| e.to_string())
        }
        DownloadedFileType::Zip => unzip_into(bytes, dest),
    }
}

/// Caps on what one downloaded ZIP may expand to (a zip bomb is refused, not unpacked).
const MAX_UNZIP_TOTAL: u64 = 1 << 30; // 1 GiB
const MAX_UNZIP_ENTRIES: usize = 50_000;

/// Extracts a ZIP archive into the directory `dest`, decompressing each file entry. Entries whose
/// path would escape `dest` (zip-slip: `..`, absolute or drive-rooted names) are skipped. The total
/// decompressed size and the entry count are capped; on unix, permission bits recorded by a unix
/// archiver (e.g. a server binary's `+x`) are restored.
fn unzip_into(bytes: &[u8], dest: &std::path::Path) -> Result<(), String> {
    unzip_into_capped(bytes, dest, MAX_UNZIP_TOTAL, MAX_UNZIP_ENTRIES)
}

fn unzip_into_capped(
    bytes: &[u8],
    dest: &std::path::Path,
    max_total: u64,
    max_entries: usize,
) -> Result<(), String> {
    let archive = orress_archive::Archive::open(bytes)?;
    if archive.entries.len() > max_entries {
        return Err(format!(
            "ZIP has {} entries (limit {max_entries})",
            archive.entries.len()
        ));
    }
    let declared: u64 = archive.entries.iter().map(|e| e.uncompressed_size).sum();
    if declared > max_total {
        return Err(format!(
            "ZIP expands to {declared} bytes (limit {max_total})"
        ));
    }
    let modes = zip_unix_modes(bytes);
    let mut total: u64 = 0;
    for entry in &archive.entries {
        if entry.is_dir() {
            continue;
        }
        let Some(rel) = safe_relative(&entry.name) else {
            continue; // unsafe path — skip rather than escape `dest`
        };
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let data = archive.read(entry)?;
        // Declared sizes can lie; count what was actually inflated too.
        total += data.len() as u64;
        if total > max_total {
            return Err(format!("ZIP expands past the {max_total}-byte limit"));
        }
        std::fs::write(&target, data).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        if let Some(&mode) = modes.get(&entry.name) {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode & 0o777));
        }
    }
    #[cfg(not(unix))]
    let _ = modes;
    Ok(())
}

/// Unix permission bits per entry name, from a ZIP's central directory: entries whose "version made
/// by" host is unix (3) carry `st_mode` in the high 16 bits of the external attributes. Entries
/// without one (e.g. from archives made on Windows) are absent. A malformed directory yields what
/// was read so far.
fn zip_unix_modes(bytes: &[u8]) -> std::collections::HashMap<String, u32> {
    let u16_at = |p: usize| {
        bytes
            .get(p..p.checked_add(2)?)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |p: usize| {
        bytes
            .get(p..p.checked_add(4)?)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let mut out = std::collections::HashMap::new();
    if bytes.len() < 22 {
        return out;
    }
    let last = bytes.len() - 22;
    let Some(eocd) = (last.saturating_sub(0xFFFF)..=last)
        .rev()
        .find(|&p| u32_at(p) == Some(0x0605_4b50))
    else {
        return out;
    };
    let (Some(total), Some(cd)) = (u16_at(eocd + 10), u32_at(eocd + 16)) else {
        return out;
    };
    let mut p = cd as usize;
    for _ in 0..total {
        if u32_at(p) != Some(0x0201_4b50) {
            break;
        }
        let (Some(made_by), Some(name_len), Some(extra), Some(comment), Some(attrs)) = (
            u16_at(p + 4),
            u16_at(p + 28),
            u16_at(p + 30),
            u16_at(p + 32),
            u32_at(p + 38),
        ) else {
            break;
        };
        let name_len = name_len as usize;
        let Some(name) = bytes.get(p + 46..p + 46 + name_len) else {
            break;
        };
        let mode = attrs >> 16;
        if made_by >> 8 == 3 && mode != 0 {
            out.insert(String::from_utf8_lossy(name).into_owned(), mode);
        }
        p += 46 + name_len + extra as usize + comment as usize;
    }
    out
}

/// Lexically normalises `path` (drops `.`, resolves `..` against earlier components). `None` if a
/// `..` would climb above the root (or the start of a relative path).
fn normalize_lexically(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                _ => return None,
            },
            other => out.push(other),
        }
    }
    Some(out)
}

/// Joins a guest-supplied `path` onto `base` and normalises it, returning it only if it stays
/// inside `base` (an absolute `path` is accepted only when it already points inside `base`).
pub(crate) fn confine(base: &Path, path: &str) -> Option<PathBuf> {
    let base = normalize_lexically(base)?;
    let joined = normalize_lexically(&base.join(path))?;
    joined.starts_with(&base).then_some(joined)
}

/// Whether an environment variable's name suggests it holds a credential, so it must not be handed
/// to an extension (which also has network access).
fn is_secret_env(name: &str) -> bool {
    const MARKERS: &[&str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASSPHRASE",
        "CREDENTIAL",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "COOKIE",
    ];
    const PREFIXES: &[&str] = &["ANTHROPIC_", "OPENAI_", "AWS_", "AZURE_", "GOOGLE_"];
    let n = name.to_ascii_uppercase();
    MARKERS.iter().any(|m| n.contains(m))
        || n.ends_with("_KEY")
        || n == "KEY"
        || PREFIXES.iter().any(|p| n.starts_with(p))
}

/// A ZIP entry name as a safe relative path, or `None` if it is absolute, drive-rooted, or climbs
/// out with `..`.
fn safe_relative(name: &str) -> Option<std::path::PathBuf> {
    use std::path::Component;
    let normalized = name.replace('\\', "/");
    let path = std::path::Path::new(&normalized);
    let mut out = std::path::PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            // Anything that could escape the destination is rejected outright.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// A command a Zed extension resolved for a language server (from `language-server-command`) or a
/// context server (from `context-server-command`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LangServerCommand {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Setup/installation info for a context (MCP) server, from `context-server-configuration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextServerConfig {
    /// Installation instructions in Markdown.
    pub installation_instructions: String,
    /// A JSON schema for validating the server's settings.
    pub settings_schema: String,
    /// A default settings template (JSON).
    pub default_settings: String,
}

/// A slash command an extension offers for the Assistant (from the extension's manifest/WASM).
/// (Named `…Info` to avoid clashing with the bindgen-generated `SlashCommand` WIT record.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCommandInfo {
    pub name: String,
    pub description: String,
    pub tooltip_text: String,
    pub requires_argument: bool,
}

/// The output of running a slash command (from `run-slash-command`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCommandResult {
    /// The text the command produced (inserted into the Assistant context).
    pub text: String,
    /// Labelled `[start, end)` spans within `text` to show as placeholders.
    pub sections: Vec<SlashCommandSection>,
}

/// A labelled span within a slash command's output text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCommandSection {
    pub range: (u32, u32),
    pub label: String,
}

/// A completion for a slash command's argument (from `complete-slash-command-argument`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCommandCompletion {
    pub label: String,
    pub new_text: String,
    pub run_command: bool,
}

/// Whether a debug session launches a new process or attaches to a running one.
/// (Mirrors the WIT `start-debugging-request-arguments-request`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DapRequestKind {
    Launch,
    Attach,
}

/// A debug session definition passed to `get-dap-binary` (a `debug-task-definition`). Named `Dap…`
/// to avoid the bindgen-generated `DebugTaskDefinition` re-export at the module root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapTaskDefinition {
    pub label: String,
    /// The debug adapter this configuration targets.
    pub adapter: String,
    /// JSON-encoded, adapter-specific configuration.
    pub config: String,
}

/// How ORRESS should launch an extension-provided debug adapter (from `get-dap-binary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapBinary {
    /// The adapter executable (absent when only a TCP connection is used).
    pub command: Option<String>,
    pub arguments: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    /// If set, connect to the adapter over TCP instead of stdio.
    pub tcp: Option<std::net::SocketAddrV4>,
    /// The JSON configuration for the DAP launch/attach request, and which kind it is.
    pub configuration: String,
    pub request: DapRequestKind,
}

/// What to debug — launch a new process or attach to a running one (the WIT `debug-request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DapRequest {
    Launch {
        program: String,
        cwd: Option<String>,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },
    Attach {
        process_id: Option<u32>,
    },
}

/// A high-level, adapter-agnostic debug configuration (the WIT `debug-config`), the input to
/// `dap-config-to-scenario`. `Dap…` named to avoid the bindgen root `DebugConfig` re-export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapConfig {
    pub label: String,
    pub adapter: String,
    pub request: DapRequest,
    pub stop_on_entry: Option<bool>,
}

/// A command template (the WIT `task-template`; also used for build and resolved tasks).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DapTaskTemplate {
    pub label: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
}

/// A build step a debug scenario runs first (the WIT `build-task-definition`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DapBuildTask {
    ByName(String),
    Template {
        locator_name: Option<String>,
        template: DapTaskTemplate,
    },
}

/// A TCP connection template on a scenario (the WIT `tcp-arguments-template`; `host` is a packed
/// IPv4). All fields optional — the user may specify none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DapTcpTemplate {
    pub port: Option<u16>,
    pub host: Option<u32>,
    pub timeout: Option<u64>,
}

/// A user-facing debug scenario (the WIT `debug-scenario`), produced by the scenario/locator
/// exports. `Dap…` named to avoid the bindgen root `DebugScenario` re-export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapScenario {
    pub label: String,
    pub adapter: String,
    /// An optional build step to run before debugging.
    pub build: Option<DapBuildTask>,
    /// JSON-encoded adapter configuration.
    pub config: String,
    pub tcp: Option<DapTcpTemplate>,
}

/// A running Zed extension: its WASM instantiated against the clean-room host.
///
/// We hold the raw component `Instance` rather than the bindgen-generated `Extension` wrapper, and
/// resolve the handful of exports we call by name. This is deliberate: the `zed:extension` package
/// is *unversioned* — newer API versions only add imports/exports (e.g. `since_v0.6.0` added the
/// `dap` interface and five `dap-*` exports). The generated `Extension::instantiate` eagerly binds
/// *every* export the world declares, so it rejects an older extension that lacks the newest ones.
/// By instantiating against the (superset) host linker and looking up only `init-extension` and
/// `language-server-command` — core exports present in every version since v0.0.1 — one host runs
/// extensions built against any API version, old or new. See `wit/zed/NOTICE.md`.
pub struct ZedExtension {
    store: wasmtime::Store<ZedState>,
    instance: wasmtime::component::Instance,
}

/// Instantiates a Zed extension component against the clean-room host world, with `work_dir` as the
/// extension's working directory (its `$PWD` and the one directory it may read/write).
///
/// The host linker provides the full `since_v0.6.0` import surface plus WASI; a component that
/// imports only an older subset — or no WASI at all — still satisfies it (extra host imports are
/// ignored), so this accepts extensions built against any `zed_extension_api` version and either a
/// `wasm32-wasip*` or a `wasm32-unknown-unknown` target.
pub fn instantiate(
    engine: &wasmtime::Engine,
    bytes: &[u8],
    work_dir: &Path,
) -> Result<ZedExtension, String> {
    let component =
        wasmtime::component::Component::new(engine, bytes).map_err(|e| e.to_string())?;
    instantiate_component(engine, &component, work_dir)
}

/// [`instantiate`] from an already-compiled component (so callers can cache compilation).
///
/// When `engine` has epoch interruption enabled (the shared engine does, with a ticker thread
/// advancing it), every export call is watched: guest code that runs longer than
/// [`GUEST_TIME_BUDGET`] (time spent in host imports such as downloads does not count) traps with an
/// error instead of hanging the host.
pub fn instantiate_component(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    work_dir: &Path,
) -> Result<ZedExtension, String> {
    let mut linker = wasmtime::component::Linker::<ZedState>::new(engine);
    // `add_to_linker` is the import half of the generated world; it is independent of which exports
    // a given extension provides, so it serves old and new extensions alike.
    Extension::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |s| s)
        .map_err(|e| e.to_string())?;
    // Real Zed extensions are WASI reactors; provide WASI so their std startup (env/stdio/fs) runs.
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(|e| e.to_string())?;
    let mut store = wasmtime::Store::new(engine, ZedState::new(work_dir));
    // The watchdog: each epoch tick past the deadline lands here; trap once the guest itself (not
    // host imports) has run for longer than the budget, otherwise check again next tick.
    store.epoch_deadline_callback(|ctx| {
        let st = ctx.data();
        let guest = st.call_start.elapsed().saturating_sub(st.host_time);
        if guest > GUEST_TIME_BUDGET {
            Err(wasmtime::Error::msg(format!(
                "extension ran for more than {}s without returning (watchdog)",
                GUEST_TIME_BUDGET.as_secs()
            )))
        } else {
            Ok(wasmtime::UpdateDeadline::Continue(1))
        }
    });
    arm_store(&mut store);
    let instance = linker
        .instantiate(&mut store, component)
        .map_err(|e| e.to_string())?;
    Ok(ZedExtension { store, instance })
}

/// Starts a fresh watchdog window for the next guest call.
fn arm_store(store: &mut wasmtime::Store<ZedState>) {
    let st = store.data_mut();
    st.call_start = Instant::now();
    st.host_time = Duration::ZERO;
    store.set_epoch_deadline(1);
}

impl ZedExtension {
    /// Starts a fresh watchdog window before calling an export.
    fn arm(&mut self) {
        arm_store(&mut self.store);
    }

    /// Restricts which commands the extension may run via `process::run-command` (by default a bare
    /// instantiation is unrestricted; the crate-level helpers apply the manifest's declared
    /// `process:exec` capabilities).
    pub fn set_exec_policy(&mut self, policy: ExecPolicy) {
        self.store.data_mut().exec_policy = policy;
    }

    /// The extension's working directory (its `$PWD`).
    pub fn work_dir(&self) -> &Path {
        &self.store.data().work_dir
    }

    /// Asks the extension for a language server's `initializationOptions`
    /// (`language-server-initialization-options`), as JSON. `None` when the extension provides
    /// none (or predates the export).
    pub fn language_server_initialization_options(
        &mut self,
        language_server_id: &str,
        root: PathBuf,
    ) -> Result<Option<serde_json::Value>, String> {
        self.lsp_json_export(
            "language-server-initialization-options",
            language_server_id,
            None,
            root,
        )
    }

    /// Asks the extension for a language server's `workspace/configuration` settings
    /// (`language-server-workspace-configuration`), as JSON.
    pub fn language_server_workspace_configuration(
        &mut self,
        language_server_id: &str,
        root: PathBuf,
    ) -> Result<Option<serde_json::Value>, String> {
        self.lsp_json_export(
            "language-server-workspace-configuration",
            language_server_id,
            None,
            root,
        )
    }

    /// Asks the extension for initialization options it contributes to *another* language server
    /// (`language-server-additional-initialization-options`).
    pub fn language_server_additional_initialization_options(
        &mut self,
        language_server_id: &str,
        target_language_server_id: &str,
        root: PathBuf,
    ) -> Result<Option<serde_json::Value>, String> {
        self.lsp_json_export(
            "language-server-additional-initialization-options",
            language_server_id,
            Some(target_language_server_id),
            root,
        )
    }

    /// Asks the extension for workspace configuration it contributes to *another* language server
    /// (`language-server-additional-workspace-configuration`).
    pub fn language_server_additional_workspace_configuration(
        &mut self,
        language_server_id: &str,
        target_language_server_id: &str,
        root: PathBuf,
    ) -> Result<Option<serde_json::Value>, String> {
        self.lsp_json_export(
            "language-server-additional-workspace-configuration",
            language_server_id,
            Some(target_language_server_id),
            root,
        )
    }

    /// Calls one of the `language-server-*` exports that return `result<option<string>, string>`
    /// (a JSON document). An extension that does not export it yields `Ok(None)`.
    fn lsp_json_export(
        &mut self,
        export: &str,
        language_server_id: &str,
        target_language_server_id: Option<&str>,
        root: PathBuf,
    ) -> Result<Option<serde_json::Value>, String> {
        if self
            .instance
            .get_export_index(&mut self.store, None, export)
            .is_none()
        {
            return Ok(None);
        }
        let worktree = self
            .store
            .data_mut()
            .add_worktree(root)
            .map_err(|e| e.to_string())?;
        let result = match target_language_server_id {
            None => {
                let func = self
                    .instance
                    .get_typed_func::<(&str, Resource<WorktreeData>), (Result<Option<String>, String>,)>(
                        &mut self.store,
                        export,
                    )
                    .map_err(|e| e.to_string())?;
                self.arm();
                let (result,) = func
                    .call(&mut self.store, (language_server_id, worktree))
                    .map_err(|e| e.to_string())?;
                func.post_return(&mut self.store)
                    .map_err(|e| e.to_string())?;
                result
            }
            Some(target) => {
                let func = self
                    .instance
                    .get_typed_func::<(&str, &str, Resource<WorktreeData>), (Result<Option<String>, String>,)>(
                        &mut self.store,
                        export,
                    )
                    .map_err(|e| e.to_string())?;
                self.arm();
                let (result,) = func
                    .call(&mut self.store, (language_server_id, target, worktree))
                    .map_err(|e| e.to_string())?;
                func.post_return(&mut self.store)
                    .map_err(|e| e.to_string())?;
                result
            }
        };
        match result? {
            None => Ok(None),
            Some(text) if text.trim().is_empty() => Ok(None),
            Some(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| format!("{export} returned invalid JSON: {e}")),
        }
    }

    /// Sets the editor settings the extension reads via `get-settings` (a JSON object; see
    /// `ZedState::settings`). Call before running exports. The host serves `settings[category]`,
    /// optionally narrowed by `key`, with `settings["worktrees"][<root>]` overriding per worktree.
    pub fn set_settings(&mut self, settings: serde_json::Value) {
        self.store.data_mut().settings = settings;
    }

    /// Runs the extension's `init-extension` export.
    pub fn init(&mut self) -> Result<(), String> {
        let func = self
            .instance
            .get_typed_func::<(), ()>(&mut self.store, "init-extension")
            .map_err(|e| e.to_string())?;
        self.arm();
        func.call(&mut self.store, ()).map_err(|e| e.to_string())?;
        func.post_return(&mut self.store).map_err(|e| e.to_string())
    }

    /// Asks the extension how to launch a language server, giving it a worktree rooted at `root`.
    pub fn language_server_command(
        &mut self,
        language_server_id: &str,
        root: PathBuf,
    ) -> Result<LangServerCommand, String> {
        let worktree = self
            .store
            .data_mut()
            .add_worktree(root)
            .map_err(|e| e.to_string())?;
        let func = self
            .instance
            .get_typed_func::<(&str, Resource<WorktreeData>), (Result<process::Command, String>,)>(
                &mut self.store,
                "language-server-command",
            )
            .map_err(|e| e.to_string())?;
        // Outer `?`: a host/trap error (to String). Inner `?`: the extension's own error (String).
        self.arm();
        let (result,) = func
            .call(&mut self.store, (language_server_id, worktree))
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        let cmd = result?;
        Ok(LangServerCommand {
            command: cmd.command,
            args: cmd.args,
            env: cmd.env,
        })
    }

    /// Registers a worktree (project folder) the extension can see. Call before
    /// `context_server_command` so the `project` it receives enumerates this worktree.
    pub fn add_worktree(&mut self, root: PathBuf) -> Result<(), String> {
        self.store
            .data_mut()
            .add_worktree(root)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Asks the extension how to launch a **context (MCP) server** by id, giving it a project
    /// spanning the host's worktrees. Returns the launch command (same shape as a language server).
    pub fn context_server_command(
        &mut self,
        context_server_id: &str,
    ) -> Result<LangServerCommand, String> {
        let project = self
            .store
            .data_mut()
            .add_project()
            .map_err(|e| e.to_string())?;
        let func = self
            .instance
            .get_typed_func::<(&str, Resource<ProjectData>), (Result<process::Command, String>,)>(
                &mut self.store,
                "context-server-command",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(&mut self.store, (context_server_id, project))
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        let cmd = result?;
        Ok(LangServerCommand {
            command: cmd.command,
            args: cmd.args,
            env: cmd.env,
        })
    }

    /// Asks the extension for a context server's setup/installation configuration, if it provides
    /// one (`context-server-configuration`).
    pub fn context_server_configuration(
        &mut self,
        context_server_id: &str,
    ) -> Result<Option<ContextServerConfig>, String> {
        let project = self
            .store
            .data_mut()
            .add_project()
            .map_err(|e| e.to_string())?;
        let func = self
            .instance
            .get_typed_func::<(&str, Resource<ProjectData>), (Result<Option<context_server::ContextServerConfiguration>, String>,)>(
                &mut self.store,
                "context-server-configuration",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(&mut self.store, (context_server_id, project))
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(result?.map(|c| ContextServerConfig {
            installation_instructions: c.installation_instructions,
            settings_schema: c.settings_schema,
            default_settings: c.default_settings,
        }))
    }

    /// Runs one of the extension's **slash commands** (`run-slash-command`), optionally against a
    /// worktree rooted at `worktree_root`, and returns its output.
    pub fn run_slash_command(
        &mut self,
        command: &SlashCommandInfo,
        args: &[String],
        worktree_root: Option<PathBuf>,
    ) -> Result<SlashCommandResult, String> {
        let worktree = match worktree_root {
            Some(root) => Some(
                self.store
                    .data_mut()
                    .add_worktree(root)
                    .map_err(|e| e.to_string())?,
            ),
            None => None,
        };
        let func = self
            .instance
            .get_typed_func::<(
                slash_command::SlashCommand,
                Vec<String>,
                Option<Resource<WorktreeData>>,
            ), (Result<slash_command::SlashCommandOutput, String>,)>(
                &mut self.store,
                "run-slash-command",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(
                &mut self.store,
                (into_wit_command(command), args.to_vec(), worktree),
            )
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        let out = result?;
        Ok(SlashCommandResult {
            text: out.text,
            sections: out
                .sections
                .into_iter()
                .map(|s| SlashCommandSection {
                    range: (s.range.start, s.range.end),
                    label: s.label,
                })
                .collect(),
        })
    }

    /// Asks the extension for argument completions for one of its slash commands
    /// (`complete-slash-command-argument`).
    pub fn complete_slash_command_argument(
        &mut self,
        command: &SlashCommandInfo,
        args: &[String],
    ) -> Result<Vec<SlashCommandCompletion>, String> {
        let func = self
            .instance
            .get_typed_func::<(slash_command::SlashCommand, Vec<String>), (Result<Vec<slash_command::SlashCommandArgumentCompletion>, String>,)>(
                &mut self.store,
                "complete-slash-command-argument",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(&mut self.store, (into_wit_command(command), args.to_vec()))
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(result?
            .into_iter()
            .map(|c| SlashCommandCompletion {
                label: c.label,
                new_text: c.new_text,
                run_command: c.run_command,
            })
            .collect())
    }

    /// Asks a **debug-adapter** extension whether a config should launch or attach
    /// (`dap-request-kind`). `config_json` is the adapter-specific JSON configuration.
    pub fn dap_request_kind(
        &mut self,
        adapter_name: &str,
        config_json: &str,
    ) -> Result<DapRequestKind, String> {
        let func = self
            .instance
            .get_typed_func::<(&str, &str), (Result<dap::StartDebuggingRequestArgumentsRequest, String>,)>(
                &mut self.store,
                "dap-request-kind",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(&mut self.store, (adapter_name, config_json))
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(into_request_kind(result?))
    }

    /// Asks a **debug-adapter** extension how to launch its adapter (`get-dap-binary`), giving it a
    /// worktree rooted at `worktree_root` and the user's configured adapter path, if any.
    pub fn get_dap_binary(
        &mut self,
        adapter_name: &str,
        definition: &DapTaskDefinition,
        user_installed_path: Option<String>,
        worktree_root: PathBuf,
    ) -> Result<DapBinary, String> {
        let worktree = self
            .store
            .data_mut()
            .add_worktree(worktree_root)
            .map_err(|e| e.to_string())?;
        let config = dap::DebugTaskDefinition {
            label: definition.label.clone(),
            adapter: definition.adapter.clone(),
            config: definition.config.clone(),
            tcp_connection: None,
        };
        let func = self
            .instance
            .get_typed_func::<(
                &str,
                dap::DebugTaskDefinition,
                Option<String>,
                Resource<WorktreeData>,
            ), (Result<dap::DebugAdapterBinary, String>,)>(
                &mut self.store, "get-dap-binary"
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(
                &mut self.store,
                (adapter_name, config, user_installed_path, worktree),
            )
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        let bin = result?;
        Ok(DapBinary {
            command: bin.command,
            arguments: bin.arguments,
            env: bin.envs,
            cwd: bin.cwd,
            tcp: bin
                .connection
                .map(|c| std::net::SocketAddrV4::new(std::net::Ipv4Addr::from(c.host), c.port)),
            configuration: bin.request_args.configuration,
            request: into_request_kind(bin.request_args.request),
        })
    }

    /// Translates a high-level [`DapConfig`] into an adapter-specific debug scenario
    /// (`dap-config-to-scenario`).
    pub fn dap_config_to_scenario(&mut self, config: &DapConfig) -> Result<DapScenario, String> {
        let func = self
            .instance
            .get_typed_func::<(dap::DebugConfig,), (Result<dap::DebugScenario, String>,)>(
                &mut self.store,
                "dap-config-to-scenario",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(&mut self.store, (lower_debug_config(config),))
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(lift_scenario(result?))
    }

    /// Asks a locator to turn a build task into a debug scenario (`dap-locator-create-scenario`).
    /// Returns `None` if the named locator does not apply.
    pub fn dap_locator_create_scenario(
        &mut self,
        locator_name: &str,
        build_task: &DapTaskTemplate,
        resolved_label: &str,
        debug_adapter_name: &str,
    ) -> Result<Option<DapScenario>, String> {
        let func = self
            .instance
            .get_typed_func::<(&str, dap::TaskTemplate, &str, &str), (Option<dap::DebugScenario>,)>(
                &mut self.store,
                "dap-locator-create-scenario",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(
                &mut self.store,
                (
                    locator_name,
                    lower_task_template(build_task),
                    resolved_label,
                    debug_adapter_name,
                ),
            )
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(result.map(lift_scenario))
    }

    /// Runs a locator's second phase: resolves a (built) task into a concrete launch/attach request
    /// (`run-dap-locator`).
    pub fn run_dap_locator(
        &mut self,
        locator_name: &str,
        build_task: &DapTaskTemplate,
    ) -> Result<DapRequest, String> {
        let func = self
            .instance
            .get_typed_func::<(&str, dap::TaskTemplate), (Result<dap::DebugRequest, String>,)>(
                &mut self.store,
                "run-dap-locator",
            )
            .map_err(|e| e.to_string())?;
        self.arm();
        let (result,) = func
            .call(
                &mut self.store,
                (locator_name, lower_task_template(build_task)),
            )
            .map_err(|e| e.to_string())?;
        func.post_return(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(lift_request(result?))
    }

    /// The installation statuses the extension reported during the calls above.
    pub fn statuses(&self) -> &[(String, String)] {
        &self.store.data().statuses
    }
}

// --- DAP scenario/locator lowering + lifting between ORRESS and WIT types. ------------------
fn lower_request(r: &DapRequest) -> dap::DebugRequest {
    match r {
        DapRequest::Launch {
            program,
            cwd,
            args,
            env,
        } => dap::DebugRequest::Launch(dap::LaunchRequest {
            program: program.clone(),
            cwd: cwd.clone(),
            args: args.clone(),
            envs: env.clone(),
        }),
        DapRequest::Attach { process_id } => dap::DebugRequest::Attach(dap::AttachRequest {
            process_id: *process_id,
        }),
    }
}

fn lower_task_template(t: &DapTaskTemplate) -> dap::TaskTemplate {
    dap::TaskTemplate {
        label: t.label.clone(),
        command: t.command.clone(),
        args: t.args.clone(),
        env: t.env.clone(),
        cwd: t.cwd.clone(),
    }
}

fn lower_debug_config(c: &DapConfig) -> dap::DebugConfig {
    dap::DebugConfig {
        label: c.label.clone(),
        adapter: c.adapter.clone(),
        request: lower_request(&c.request),
        stop_on_entry: c.stop_on_entry,
    }
}

fn lift_request(r: dap::DebugRequest) -> DapRequest {
    match r {
        dap::DebugRequest::Launch(l) => DapRequest::Launch {
            program: l.program,
            cwd: l.cwd,
            args: l.args,
            env: l.envs,
        },
        dap::DebugRequest::Attach(a) => DapRequest::Attach {
            process_id: a.process_id,
        },
    }
}

fn lift_task_template(t: dap::TaskTemplate) -> DapTaskTemplate {
    DapTaskTemplate {
        label: t.label,
        command: t.command,
        args: t.args,
        env: t.env,
        cwd: t.cwd,
    }
}

fn lift_build_task(b: dap::BuildTaskDefinition) -> DapBuildTask {
    match b {
        dap::BuildTaskDefinition::ByName(name) => DapBuildTask::ByName(name),
        dap::BuildTaskDefinition::Template(p) => DapBuildTask::Template {
            locator_name: p.locator_name,
            template: lift_task_template(p.template),
        },
    }
}

fn lift_scenario(s: dap::DebugScenario) -> DapScenario {
    DapScenario {
        label: s.label,
        adapter: s.adapter,
        build: s.build.map(lift_build_task),
        config: s.config,
        tcp: s.tcp_connection.map(|t| DapTcpTemplate {
            port: t.port,
            host: t.host,
            timeout: t.timeout,
        }),
    }
}

/// Maps the WIT launch/attach enum to the ORRESS one.
fn into_request_kind(r: dap::StartDebuggingRequestArgumentsRequest) -> DapRequestKind {
    match r {
        dap::StartDebuggingRequestArgumentsRequest::Launch => DapRequestKind::Launch,
        dap::StartDebuggingRequestArgumentsRequest::Attach => DapRequestKind::Attach,
    }
}

/// Lowers an ORRESS [`SlashCommandInfo`] into the WIT record the exports take.
fn into_wit_command(c: &SlashCommandInfo) -> slash_command::SlashCommand {
    slash_command::SlashCommand {
        name: c.name.clone(),
        description: c.description.clone(),
        tooltip_text: c.tooltip_text.clone(),
        requires_argument: c.requires_argument,
    }
}

// --- Marker interfaces (only define types; no host functions). ------------------------------
impl common::Host for ZedState {}
impl lsp::Host for ZedState {}
impl slash_command::Host for ZedState {}
impl context_server::Host for ZedState {}

// --- Platform: real. ------------------------------------------------------------------------
impl platform::Host for ZedState {
    fn current_platform(&mut self) -> (platform::Os, platform::Architecture) {
        let os = if cfg!(target_os = "macos") {
            platform::Os::Mac
        } else if cfg!(target_os = "windows") {
            platform::Os::Windows
        } else {
            platform::Os::Linux
        };
        let arch = if cfg!(target_arch = "aarch64") {
            platform::Architecture::Aarch64
        } else if cfg!(target_arch = "x86") {
            platform::Architecture::X86
        } else {
            platform::Architecture::X8664
        };
        (os, arch)
    }
}

// --- Process: real (run a child process and collect output). --------------------------------
impl process::Host for ZedState {
    fn run_command(&mut self, command: process::Command) -> Result<process::Output, String> {
        if !self.exec_policy.allows(&command.command, &command.args) {
            return Err(format!(
                "capability for process:exec {} {:?} was not listed in the extension manifest",
                command.command, command.args
            ));
        }
        // Run in the extension's own directory (its `$PWD`), so relative paths agree with the guest.
        let work_dir = self.work_dir.clone();
        let out = self
            .host_op(|_| {
                let mut cmd = std::process::Command::new(&command.command);
                cmd.args(&command.args).envs(command.env);
                if work_dir.is_dir() {
                    cmd.current_dir(&work_dir);
                }
                cmd.output()
            })
            .map_err(|e| e.to_string())?;
        Ok(process::Output {
            status: out.status.code(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

// --- GitHub: query the public releases API. --------------------------------------------------
impl github::Host for ZedState {
    fn latest_github_release(
        &mut self,
        repo: String,
        options: github::GithubReleaseOptions,
    ) -> Result<github::GithubRelease, String> {
        // The `/releases/latest` endpoint excludes pre-releases; when pre-releases are wanted, list
        // all and take the first matching one.
        if options.pre_release {
            let url = format!("https://api.github.com/repos/{repo}/releases?per_page=10");
            let body = self.host_op(|_| http_get(&url))?;
            let list: serde_json::Value =
                serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            let arr = list
                .as_array()
                .ok_or("GitHub releases JSON is not an array")?;
            for entry in arr {
                let release = github_release_from_json(entry)?;
                if !options.require_assets || !release.assets.is_empty() {
                    return Ok(release);
                }
            }
            Err(format!("no matching release for `{repo}`"))
        } else {
            let url = format!("https://api.github.com/repos/{repo}/releases/latest");
            let body = self.host_op(|_| http_get(&url))?;
            let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            github_release_from_json(&v)
        }
    }

    fn github_release_by_tag_name(
        &mut self,
        repo: String,
        tag: String,
    ) -> Result<github::GithubRelease, String> {
        let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
        let body = self.host_op(|_| http_get(&url))?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        github_release_from_json(&v)
    }
}

// --- HTTP client: real requests via ureq. ----------------------------------------------------
impl http_client::Host for ZedState {
    fn fetch(
        &mut self,
        req: http_client::HttpRequest,
    ) -> Result<http_client::HttpResponse, String> {
        self.host_op(|_| http_fetch(&req))
    }

    fn fetch_stream(
        &mut self,
        req: http_client::HttpRequest,
    ) -> Result<Resource<HttpStreamData>, String> {
        // Buffer the whole body and hand it back as a single stream chunk.
        let body = self.host_op(|_| http_fetch(&req))?.body;
        self.table
            .push(HttpStreamData { body: Some(body) })
            .map_err(|e| e.to_string())
    }
}

impl http_client::HostHttpResponseStream for ZedState {
    fn next_chunk(&mut self, self_: Resource<HttpStreamData>) -> Result<Option<Vec<u8>>, String> {
        let stream = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
        Ok(stream.body.take())
    }
    fn drop(&mut self, rep: Resource<HttpStreamData>) -> wasmtime::Result<()> {
        self.table.delete(rep).map(|_| ()).map_err(Into::into)
    }
}

// --- Node.js / npm: use the installed `node`/`npm` and the npm registry. ----------------------
impl nodejs::Host for ZedState {
    fn node_binary_path(&mut self) -> Result<String, String> {
        which_on_path("node").ok_or_else(|| "`node` was not found on PATH".to_string())
    }

    fn npm_package_latest_version(&mut self, package_name: String) -> Result<String, String> {
        let url = format!("https://registry.npmjs.org/{package_name}/latest");
        let body = self.host_op(|_| http_get(&url))?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        v.get("version")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("no version for npm package `{package_name}`"))
    }

    fn npm_package_installed_version(
        &mut self,
        package_name: String,
    ) -> Result<Option<String>, String> {
        // Reads `node_modules/<pkg>/package.json` in the extension's working directory (where
        // `npm-install-package` installs). A name that would escape it is rejected.
        validate_npm_name(&package_name)?;
        let path = self.guest_path(&format!("node_modules/{package_name}/package.json"))?;
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("version")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                })),
            Err(_) => Ok(None),
        }
    }

    fn npm_install_package(&mut self, package_name: String, version: String) -> Result<(), String> {
        validate_npm_name(&package_name)?;
        if version.starts_with('-') || version.chars().any(char::is_whitespace) {
            return Err(format!("invalid npm version `{version}`"));
        }
        let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
        // Install into the extension's own directory (its `node_modules`), never the process CWD.
        let work_dir = self.work_dir.clone();
        std::fs::create_dir_all(&work_dir).map_err(|e| e.to_string())?;
        let status = self
            .host_op(|_| {
                std::process::Command::new(npm)
                    .args(["install", "--no-save", &format!("{package_name}@{version}")])
                    .current_dir(&work_dir)
                    .status()
            })
            .map_err(|e| format!("could not run npm: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("npm install of {package_name}@{version} failed"))
        }
    }
}

// --- DAP: resolve a TCP connection template for a debug adapter. ----------------------------
impl dap::Host for ZedState {
    /// Fills in a debug adapter's TCP connection: a `none` host defaults to loopback, and a `none`
    /// port is allocated from the OS (bind to port 0, then release it so the adapter can claim it).
    /// `host` is an IPv4 address packed into a `u32`, matching the WIT `tcp-arguments` shape.
    fn resolve_tcp_template(
        &mut self,
        template: dap::TcpArgumentsTemplate,
    ) -> Result<dap::TcpArguments, String> {
        use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
        let host = template
            .host
            .unwrap_or_else(|| u32::from(Ipv4Addr::LOCALHOST));
        let ip = Ipv4Addr::from(host);
        let port = match template.port {
            Some(p) => p,
            None => {
                let listener =
                    TcpListener::bind(SocketAddrV4::new(ip, 0)).map_err(|e| e.to_string())?;
                listener.local_addr().map_err(|e| e.to_string())?.port()
            }
        };
        Ok(dap::TcpArguments {
            host,
            port,
            timeout: template.timeout,
        })
    }
}

// --- World-level imports. -------------------------------------------------------------------
impl ExtensionImports for ZedState {
    /// Serves the editor settings for `category` (e.g. `"lsp"`), optionally narrowed to `key` (e.g.
    /// a language-server name), as a JSON string. A `settings-location` selects per-worktree
    /// overrides (`settings["worktrees"][<worktree root path>][category]`), which win over the
    /// global section. Missing settings serialize to `{}` (section) or `null` (key) — both of which
    /// Zed extensions tolerate. This matches how `zed_extension_api`'s `LspSettings::for_worktree`
    /// reads a server's config (category `"lsp"`, key = the server name).
    fn get_settings(
        &mut self,
        path: Option<SettingsLocation>,
        category: String,
        key: Option<String>,
    ) -> Result<String, String> {
        let worktree_override = path.as_ref().and_then(|loc| {
            self.settings
                .get("worktrees")
                .and_then(|w| w.get(&loc.path))
                .and_then(|wt| wt.get(&category))
        });
        let section = worktree_override
            .or_else(|| self.settings.get(&category))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let value = match &key {
            Some(k) => section.get(k).cloned().unwrap_or(serde_json::Value::Null),
            None => section,
        };
        serde_json::to_string(&value).map_err(|e| e.to_string())
    }
    fn download_file(
        &mut self,
        url: String,
        file_path: String,
        file_type: DownloadedFileType,
    ) -> Result<(), String> {
        let dest = self.guest_path(&file_path)?;
        let bytes = self.host_op(|_| http_get(&url))?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        self.host_op(|_| write_download(&bytes, &dest, file_type))
    }

    fn make_file_executable(&mut self, filepath: String) -> Result<(), String> {
        let filepath = self.guest_path(&filepath)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&filepath)
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_mode(perms.mode() | 0o111); // +x for user/group/other
            std::fs::set_permissions(&filepath, perms).map_err(|e| e.to_string())
        }
        #[cfg(not(unix))]
        {
            // On Windows, executability is by extension; nothing to set.
            let _ = filepath;
            Ok(())
        }
    }
    fn set_language_server_installation_status(
        &mut self,
        language_server_name: String,
        status: LanguageServerInstallationStatus,
    ) {
        self.statuses
            .push((language_server_name, format!("{status:?}")));
    }
}

// --- Resources: worktree, project, key-value store. -----------------------------------------
impl HostWorktree for ZedState {
    fn id(&mut self, self_: Resource<WorktreeData>) -> u64 {
        self.table.get(&self_).map(|w| w.id).unwrap_or(0)
    }
    fn root_path(&mut self, self_: Resource<WorktreeData>) -> String {
        self.table
            .get(&self_)
            .map(|w| w.root.display().to_string())
            .unwrap_or_default()
    }
    fn read_text_file(
        &mut self,
        self_: Resource<WorktreeData>,
        path: String,
    ) -> Result<String, String> {
        let root = self
            .table
            .get(&self_)
            .map_err(|e| e.to_string())?
            .root
            .clone();
        // Confined to the worktree: no absolute paths elsewhere, no climbing out with `..`.
        let full = confine(&root, &path)
            .ok_or_else(|| format!("path `{path}` is outside the worktree"))?;
        std::fs::read_to_string(full).map_err(|e| e.to_string())
    }
    fn which(&mut self, _self_: Resource<WorktreeData>, binary_name: String) -> Option<String> {
        which_on_path(&binary_name)
    }
    /// The host environment minus anything that looks like a credential (API keys, tokens,
    /// passwords): extensions have network access, so secrets must not reach them.
    fn shell_env(&mut self, _self_: Resource<WorktreeData>) -> Vec<(String, String)> {
        std::env::vars()
            .filter(|(k, _)| !is_secret_env(k))
            .collect()
    }
    fn drop(&mut self, rep: Resource<WorktreeData>) -> wasmtime::Result<()> {
        self.table.delete(rep).map(|_| ()).map_err(Into::into)
    }
}

impl HostProject for ZedState {
    fn worktree_ids(&mut self, self_: Resource<ProjectData>) -> Vec<u64> {
        self.table
            .get(&self_)
            .map(|p| p.worktree_ids.clone())
            .unwrap_or_default()
    }
    fn drop(&mut self, rep: Resource<ProjectData>) -> wasmtime::Result<()> {
        self.table.delete(rep).map(|_| ()).map_err(Into::into)
    }
}

impl HostKeyValueStore for ZedState {
    fn insert(
        &mut self,
        self_: Resource<KeyValueData>,
        key: String,
        value: String,
    ) -> Result<(), String> {
        let kv = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
        kv.map.insert(key, value);
        Ok(())
    }
    fn drop(&mut self, rep: Resource<KeyValueData>) -> wasmtime::Result<()> {
        self.table.delete(rep).map(|_| ()).map_err(Into::into)
    }
}

/// Validates an npm package name before it is used in a path or on a command line: no option-like
/// or path-escaping names (scoped `@scope/name` is fine).
fn validate_npm_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && !name.starts_with(['-', '.', '/', '\\'])
        && !name.contains('\\')
        && !name.chars().any(char::is_whitespace)
        && name.split('/').all(|part| !part.is_empty() && part != "..")
        && name.matches('/').count() <= usize::from(name.starts_with('@'));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid npm package name `{name}`"))
    }
}

/// Finds `binary` on `PATH` (the worktree `which` host function). On Windows a name that already
/// has an extension is tried as given first (so `node.exe` works), then with each `PATHEXT`
/// extension. (An extensionless name is not tried bare there: npm ships an extensionless `npm` shell
/// script next to `npm.cmd`, which Windows cannot run.)
fn which_on_path(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        let has_ext = Path::new(binary).extension().is_some();
        has_ext
            .then(String::new)
            .into_iter()
            .chain(
                std::env::var("PATHEXT")
                    .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
                    .split(';')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            )
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let candidate = dir.join(format!("{binary}{ext}"));
            if candidate.is_file() {
                return Some(candidate.display().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    // The world-level trait methods come in via the glob; `dap::Host` lives in a submodule, so
    // bring it in explicitly to call `resolve_tcp_template` on `ZedState`.
    use super::dap::Host as _;

    /// Host state with no WASI filesystem needed (the settings/dap/worktree logic is pure).
    fn state() -> ZedState {
        ZedState::new(&std::env::temp_dir())
    }

    #[test]
    fn get_settings_resolves_category_key_and_worktree_overrides() {
        let mut st = state();
        st.settings = serde_json::json!({
            "lsp": { "rust-analyzer": { "binary": { "path": "ra" } } },
            "worktrees": {
                "/proj": { "lsp": { "rust-analyzer": { "binary": { "path": "ra-proj" } } } }
            }
        });

        // A whole category.
        let lsp = st.get_settings(None, "lsp".into(), None).unwrap();
        assert!(lsp.contains("rust-analyzer") && lsp.contains("\"path\":\"ra\""));
        // Narrowed to a key (the `LspSettings::for_worktree` shape).
        let ra = st
            .get_settings(None, "lsp".into(), Some("rust-analyzer".into()))
            .unwrap();
        assert_eq!(ra, r#"{"binary":{"path":"ra"}}"#);
        // A per-worktree override wins for that worktree's root path.
        let loc = SettingsLocation {
            worktree_id: 0,
            path: "/proj".into(),
        };
        let ra_proj = st
            .get_settings(Some(loc), "lsp".into(), Some("rust-analyzer".into()))
            .unwrap();
        assert_eq!(ra_proj, r#"{"binary":{"path":"ra-proj"}}"#);
        // Missing category → `{}`; missing key → `null`.
        assert_eq!(st.get_settings(None, "nope".into(), None).unwrap(), "{}");
        assert_eq!(
            st.get_settings(None, "lsp".into(), Some("gopls".into()))
                .unwrap(),
            "null"
        );
    }

    #[test]
    fn resolve_tcp_template_defaults_host_and_allocates_a_port() {
        use std::net::Ipv4Addr;
        let mut st = state();

        // No host/port: loopback, and an OS-allocated (nonzero) port; timeout passes through.
        let r = st
            .resolve_tcp_template(dap::TcpArgumentsTemplate {
                port: None,
                host: None,
                timeout: Some(5),
            })
            .unwrap();
        assert_eq!(r.host, u32::from(Ipv4Addr::LOCALHOST));
        assert_ne!(r.port, 0);
        assert_eq!(r.timeout, Some(5));

        // An explicit host/port is echoed back verbatim.
        let r2 = st
            .resolve_tcp_template(dap::TcpArgumentsTemplate {
                port: Some(12345),
                host: Some(u32::from(Ipv4Addr::new(10, 0, 0, 1))),
                timeout: None,
            })
            .unwrap();
        assert_eq!(r2.port, 12345);
        assert_eq!(r2.host, u32::from(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(r2.timeout, None);
    }

    #[test]
    fn worktrees_get_sequential_ids_and_a_project_enumerates_them() {
        let mut st = state();
        let _w0 = st.add_worktree(PathBuf::from("/a")).unwrap();
        let _w1 = st.add_worktree(PathBuf::from("/b")).unwrap();
        let project = st.add_project().unwrap();
        assert_eq!(st.worktree_ids(project), vec![0, 1]);
    }

    #[test]
    fn parses_a_github_release() {
        let json = serde_json::json!({
            "tag_name": "v1.2.3",
            "assets": [
                { "name": "server-linux.tar.gz", "browser_download_url": "https://x/a.tar.gz" },
                { "name": "server-mac.gz", "browser_download_url": "https://x/b.gz" },
                { "name": "missing-url" }
            ]
        });
        let r = github_release_from_json(&json).unwrap();
        assert_eq!(r.version, "v1.2.3");
        // The asset without a download URL is dropped.
        assert_eq!(r.assets.len(), 2);
        assert_eq!(r.assets[0].name, "server-linux.tar.gz");
        assert_eq!(r.assets[1].download_url, "https://x/b.gz");
        assert!(github_release_from_json(&serde_json::json!({})).is_err());
    }

    /// Builds a minimal STORED (uncompressed) ZIP — enough for `orress-archive` to read back.
    fn make_stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        for (name, data) in files {
            let offset = out.len() as u32;
            let n = name.as_bytes();
            // Local file header.
            out.extend(le32(0x0403_4b50));
            out.extend(le16(20)); // version needed
            out.extend(le16(0)); // flags
            out.extend(le16(0)); // method: store
            out.extend(le16(0)); // time
            out.extend(le16(0)); // date
            out.extend(le32(0)); // crc (unchecked by the reader)
            out.extend(le32(data.len() as u32)); // compressed size
            out.extend(le32(data.len() as u32)); // uncompressed size
            out.extend(le16(n.len() as u16));
            out.extend(le16(0)); // extra len
            out.extend_from_slice(n);
            out.extend_from_slice(data);
            // Central directory record.
            central.extend(le32(0x0201_4b50));
            central.extend(le16(20)); // version made by
            central.extend(le16(20)); // version needed
            central.extend(le16(0)); // flags
            central.extend(le16(0)); // method
            central.extend(le16(0)); // time
            central.extend(le16(0)); // date
            central.extend(le32(0)); // crc
            central.extend(le32(data.len() as u32));
            central.extend(le32(data.len() as u32));
            central.extend(le16(n.len() as u16));
            central.extend(le16(0)); // extra
            central.extend(le16(0)); // comment
            central.extend(le16(0)); // disk start
            central.extend(le16(0)); // internal attrs
            central.extend(le32(0)); // external attrs
            central.extend(le32(offset)); // local header offset
            central.extend_from_slice(n);
        }
        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        // End of central directory.
        out.extend(le32(0x0605_4b50));
        out.extend(le16(0)); // disk
        out.extend(le16(0)); // cd start disk
        out.extend(le16(files.len() as u16)); // entries this disk
        out.extend(le16(files.len() as u16)); // total entries
        out.extend(le32(cd_size));
        out.extend(le32(cd_offset));
        out.extend(le16(0)); // comment len
        out
    }

    #[test]
    fn safe_relative_rejects_escapes() {
        assert!(safe_relative("bin/server").is_some());
        assert!(safe_relative("a\\b\\c").is_some()); // backslashes normalised
        assert!(safe_relative("../evil").is_none());
        assert!(safe_relative("/etc/passwd").is_none());
        assert!(safe_relative("a/../../b").is_none());
        assert!(safe_relative("").is_none());
    }

    #[test]
    fn writes_downloads_zip_and_skips_zip_slip() {
        let zip = make_stored_zip(&[
            ("bin/server", b"ELF binary"),
            ("readme.txt", b"hi"),
            ("../escape.txt", b"evil"),
        ]);
        let dir = std::env::temp_dir().join(format!("orress_unzip_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_download(&zip, &dir, DownloadedFileType::Zip).unwrap();
        assert_eq!(
            std::fs::read(dir.join("bin/server")).unwrap(),
            b"ELF binary"
        );
        assert_eq!(std::fs::read(dir.join("readme.txt")).unwrap(), b"hi");
        // The zip-slip entry is dropped, not written outside `dir`.
        assert!(!dir.parent().unwrap().join("escape.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_downloads_uncompressed_and_gzip() {
        use std::io::Write;
        let data = b"a language server binary";
        let dir = std::env::temp_dir().join(format!("orress_dl_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Uncompressed: written verbatim.
        let raw = dir.join("raw.bin");
        write_download(data, &raw, DownloadedFileType::Uncompressed).unwrap();
        assert_eq!(std::fs::read(&raw).unwrap(), data);

        // Gzip: decompressed on write.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        let gz = enc.finish().unwrap();
        let out = dir.join("out.bin");
        write_download(&gz, &out, DownloadedFileType::Gzip).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);

        // Bytes that are not a ZIP, declared as one → a clear error, not a panic.
        assert!(write_download(data, &dir.join("z"), DownloadedFileType::Zip).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unzip_caps_total_size_and_entry_count() {
        let zip = make_stored_zip(&[("a", b"0123456789"), ("b", b"0123456789")]);
        let dir = std::env::temp_dir().join(format!("orress_unzip_cap_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(unzip_into_capped(&zip, &dir, 15, 100).is_err(), "size cap");
        assert!(unzip_into_capped(&zip, &dir, 1000, 1).is_err(), "entry cap");
        assert!(unzip_into_capped(&zip, &dir, 20, 2).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_unix_modes_from_the_central_directory() {
        let mut zip = make_stored_zip(&[("bin/server", b"x")]);
        // Patch the central record: made-by host 3 (unix), external attrs = 0o100755 << 16.
        let cd = zip
            .windows(4)
            .position(|w| w == 0x0201_4b50u32.to_le_bytes())
            .unwrap();
        zip[cd + 5] = 3;
        zip[cd + 38..cd + 42].copy_from_slice(&((0o100_755u32) << 16).to_le_bytes());
        let modes = zip_unix_modes(&zip);
        assert_eq!(modes.get("bin/server").map(|m| m & 0o777), Some(0o755));
        // A non-unix archive records nothing.
        assert!(zip_unix_modes(&make_stored_zip(&[("a", b"x")])).is_empty());
    }

    #[test]
    fn guest_paths_are_confined_to_their_base() {
        let base = Path::new("/ext/work");
        assert_eq!(
            confine(base, "bin/server"),
            Some(PathBuf::from("/ext/work/bin/server"))
        );
        assert_eq!(
            confine(base, "./a/../b"),
            Some(PathBuf::from("/ext/work/b"))
        );
        assert_eq!(confine(base, "../escape"), None);
        assert_eq!(confine(base, "a/../../escape"), None);
        assert_eq!(confine(base, "/etc/passwd"), None);
        // An absolute path already inside the base is fine.
        assert_eq!(
            confine(base, "/ext/work/x"),
            Some(PathBuf::from("/ext/work/x"))
        );
    }

    #[test]
    fn host_imports_reject_paths_outside_their_roots() {
        let work = std::env::temp_dir().join(format!("orress_zed_conf_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join("proj")).unwrap();
        std::fs::write(work.join("proj").join("ok.txt"), "fine").unwrap();
        std::fs::write(work.join("secret.txt"), "nope").unwrap();
        let mut st = ZedState::new(&work.join("ext"));

        // Worktree reads stay inside the worktree.
        let wt = st.add_worktree(work.join("proj")).unwrap();
        let wt_rep = wt.rep();
        assert_eq!(
            st.read_text_file(Resource::new_borrow(wt_rep), "ok.txt".into())
                .unwrap(),
            "fine"
        );
        assert!(
            st.read_text_file(Resource::new_borrow(wt_rep), "../secret.txt".into())
                .is_err()
        );
        let abs = work.join("secret.txt").display().to_string();
        assert!(
            st.read_text_file(Resource::new_borrow(wt_rep), abs)
                .is_err()
        );

        // Downloads / chmod / npm stay inside the extension's work dir (rejected before any I/O).
        assert!(
            st.download_file(
                "http://127.0.0.1:1/x".into(),
                "../evil".into(),
                DownloadedFileType::Uncompressed
            )
            .unwrap_err()
            .contains("outside")
        );
        assert!(st.make_file_executable("../../evil".into()).is_err());
        use super::nodejs::Host as _;
        assert!(st.npm_package_installed_version("../../x".into()).is_err());
        assert_eq!(
            st.npm_package_installed_version("@scope/pkg".into()),
            Ok(None)
        );
        assert!(st.npm_install_package("--foo".into(), "1".into()).is_err());
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn exec_capabilities_match_like_zed() {
        let cap = ExecCapability {
            command: "echo".into(),
            args: vec!["hello".into(), "*".into()],
        };
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(cap.allows("echo", &a(&["hello", "world"])));
        assert!(!cap.allows("echo", &a(&["hello"])));
        assert!(!cap.allows("echo", &a(&["bye", "x"])));
        assert!(!cap.allows("rm", &a(&["hello", "x"])));
        let any = ExecCapability {
            command: "*".into(),
            args: vec!["**".into()],
        };
        assert!(any.allows("anything", &a(&[])));
        assert!(any.allows("anything", &a(&["a", "b"])));

        // The host refuses commands the manifest did not declare.
        use super::process::Host as _;
        let mut st = state();
        st.exec_policy = ExecPolicy::Declared(vec![]);
        let err = st
            .run_command(process::Command {
                command: "echo".into(),
                args: vec!["hi".into()],
                env: vec![],
            })
            .unwrap_err();
        assert!(err.contains("not listed"), "{err}");
    }

    #[test]
    fn secret_env_vars_are_withheld() {
        for k in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "MY_SECRET",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "SIGNING_KEY",
        ] {
            assert!(is_secret_env(k), "{k} should be filtered");
        }
        for k in [
            "PATH",
            "HOME",
            "USERPROFILE",
            "LANG",
            "CARGO_HOME",
            "KEYBOARD",
        ] {
            assert!(!is_secret_env(k), "{k} should pass");
        }
    }

    #[test]
    fn npm_names_are_validated() {
        assert!(validate_npm_name("typescript").is_ok());
        assert!(validate_npm_name("@vue/language-server").is_ok());
        assert!(validate_npm_name("../x").is_err());
        assert!(validate_npm_name("a/b").is_err());
        assert!(validate_npm_name("@a/../b").is_err());
        assert!(validate_npm_name("-g").is_err());
        assert!(validate_npm_name("").is_err());
    }
}
