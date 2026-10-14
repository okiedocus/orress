//! A Debug Adapter Protocol (DAP) client for source-level debugging of programs you write
//! in ORRESS (via an adapter such as `lldb-dap`). Like the LSP client it is thread-based
//! with Content-Length framing and no async runtime — the UI polls shared state.
//!
//! The transport runs the whole launch handshake and event loop on its thread
//! (initialize -> launch -> setBreakpoints -> configurationDone, then stop/continue/output
//! events; on each stop it fetches the call stack and the top frame's variables). This
//! module is the thin public surface: launch and the step controls.

mod transport;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use transport::Transport;

pub use transport::Notify;

/// Where the debuggee is in its life cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Starting,
    Running,
    Stopped,
    Exited,
    Failed,
}

/// One stack frame.
#[derive(Clone, Debug, Default)]
pub struct Frame {
    pub id: i64,
    pub name: String,
    pub source: Option<PathBuf>,
    pub line: u32,
}

/// One variable (name = value).
#[derive(Clone, Debug)]
pub struct Variable {
    pub name: String,
    pub value: String,
    pub ty: Option<String>,
}

/// A snapshot of the debug session for the UI.
#[derive(Clone, Debug, Default)]
pub struct DapState {
    pub status: Option<Status>,
    pub stop_reason: Option<String>,
    pub frames: Vec<Frame>,
    pub variables: Vec<Variable>,
    pub output: Vec<String>,
    pub last_error: Option<String>,
    /// The current stopped source file and line.
    pub current: Option<(PathBuf, u32)>,
    pub generation: u64,
}

impl DapState {
    pub fn is_stopped(&self) -> bool {
        self.status == Some(Status::Stopped)
    }
    pub fn is_alive(&self) -> bool {
        matches!(
            self.status,
            Some(Status::Starting | Status::Running | Status::Stopped)
        )
    }
}

/// How to start a debug session: the adapter process to spawn and the `launch` request to send.
#[derive(Clone, Debug)]
pub struct LaunchConfig {
    /// The adapter executable (e.g. "lldb-dap") and its arguments.
    pub adapter: String,
    pub adapter_args: Vec<String>,
    /// Extra environment and working directory for the adapter process itself.
    pub adapter_env: Vec<(String, String)>,
    pub adapter_cwd: Option<PathBuf>,
    /// The `adapterID` sent in `initialize` (e.g. "lldb", "CodeLLDB", "debugpy").
    pub adapter_id: String,
    /// The raw `launch` request arguments, passed through as given (adapter-specific keys such
    /// as `program`, `cwd`, `args`, `env`, `type`, `stopOnEntry`, …).
    pub launch_arguments: serde_json::Value,
}

impl LaunchConfig {
    /// The plain lldb-style launch of `program` (in `cwd`) under `adapter`.
    pub fn lldb(
        adapter: &str,
        adapter_args: &[String],
        program: &Path,
        cwd: Option<&Path>,
    ) -> Self {
        let mut args = serde_json::json!({
            "name": "orress",
            "type": "lldb",
            "request": "launch",
            "program": program.to_string_lossy(),
            "stopOnEntry": false,
        });
        if let Some(cwd) = cwd {
            args["cwd"] = serde_json::json!(cwd.to_string_lossy());
        }
        Self {
            adapter: adapter.to_string(),
            adapter_args: adapter_args.to_vec(),
            adapter_env: Vec::new(),
            adapter_cwd: None,
            adapter_id: "lldb".into(),
            launch_arguments: args,
        }
    }
}

/// A running (or finished) source-debug session.
pub struct DapSession {
    tx: Transport,
}

impl DapSession {
    /// Launches `program` under the adapter at `adapter` (e.g. "lldb-dap"), stopping at the
    /// given source breakpoints (1-based line numbers per file).
    pub fn launch(
        adapter: &str,
        adapter_args: &[String],
        program: &Path,
        cwd: Option<&Path>,
        breakpoints: HashMap<PathBuf, Vec<u32>>,
        notify: Notify,
    ) -> std::io::Result<Self> {
        Self::launch_with(
            LaunchConfig::lldb(adapter, adapter_args, program, cwd),
            breakpoints,
            notify,
        )
    }

    /// Launches a session from a full [`LaunchConfig`] (adapter id, raw launch arguments, the
    /// adapter's own environment and working directory), stopping at the given breakpoints.
    pub fn launch_with(
        config: LaunchConfig,
        breakpoints: HashMap<PathBuf, Vec<u32>>,
        notify: Notify,
    ) -> std::io::Result<Self> {
        Ok(Self {
            tx: Transport::start(config, breakpoints, notify)?,
        })
    }

    /// Replaces the breakpoints of one source file (1-based lines). Sent to the adapter at once
    /// when the session is configured; before that they are sent with the initial set.
    pub fn set_breakpoints(&self, source: &Path, lines: Vec<u32>) {
        self.tx.set_breakpoints(source, lines);
    }

    pub fn state(&self) -> DapState {
        self.tx.state()
    }

    pub fn resume(&self) {
        self.tx.control("continue");
    }
    pub fn step_over(&self) {
        self.tx.control("next");
    }
    pub fn step_in(&self) {
        self.tx.control("stepIn");
    }
    pub fn step_out(&self) {
        self.tx.control("stepOut");
    }
    pub fn pause(&self) {
        self.tx.control("pause");
    }
    pub fn stop(&self) {
        self.tx.terminate();
    }
}

pub(crate) fn parse_frames_body(body: &serde_json::Value) -> Vec<Frame> {
    body.get("stackFrames")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|f| Frame {
                    id: f.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                    name: f
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    source: f
                        .get("source")
                        .and_then(|s| s.get("path"))
                        .and_then(|v| v.as_str())
                        .map(PathBuf::from),
                    line: f.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_variables_body(body: &serde_json::Value) -> Vec<Variable> {
    body.get("variables")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| Variable {
                    name: v
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    value: v
                        .get("value")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    ty: v.get("type").and_then(|x| x.as_str()).map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Finds a DAP adapter: `lldb-dap` on PATH, or the LLVM install on Windows.
pub fn find_adapter() -> Option<(String, Vec<String>)> {
    for cand in ["lldb-dap", "lldb-vscode"] {
        if which(cand) {
            return Some((cand.to_string(), Vec::new()));
        }
    }
    if cfg!(windows) {
        let p = "C:/Program Files/LLVM/bin/lldb-dap.exe";
        if Path::new(p).exists() {
            return Some((p.to_string(), Vec::new()));
        }
    }
    None
}

fn which(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
