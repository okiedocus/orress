//! DAP JSON framing, a background reader thread, and the protocol state machine. All the
//! sequencing (initialize -> launch, the `initialized` event -> setBreakpoints, a `stopped`
//! event -> stackTrace -> scopes -> variables) runs on the reader thread.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::{DapState, LaunchConfig, Status, parse_frames_body, parse_variables_body};

pub type Notify = Arc<dyn Fn() + Send + Sync>;

struct Shared {
    state: DapState,
    thread_id: i64,
    /// Whether the initial breakpoints and `configurationDone` have been sent, after which a
    /// breakpoint change goes straight to the adapter.
    configured: bool,
}

struct Inner {
    writer: Mutex<ChildStdin>,
    next_seq: AtomicI64,
    pending: Mutex<HashMap<i64, String>>,
    shared: Mutex<Shared>,
    notify: Notify,
    /// The `launch` request arguments, sent as given.
    launch_arguments: Value,
    /// Breakpoints per source file; updated live by [`Transport::set_breakpoints`].
    breakpoints: Mutex<HashMap<PathBuf, Vec<u32>>>,
}

impl Inner {
    fn bump(&self, f: impl FnOnce(&mut DapState)) {
        {
            let mut s = self.shared.lock().expect("dap state");
            f(&mut s.state);
            s.state.generation += 1;
        }
        (self.notify)();
    }

    fn send(&self, msg: &Value) {
        if std::env::var("ORRESS_DAP_DEBUG").is_ok() {
            eprintln!(
                "[dap] -> {} {}",
                msg.get("command").and_then(|v| v.as_str()).unwrap_or(""),
                msg
            );
        }
        if let Ok(mut w) = self.writer.lock() {
            let _ = write_message(&mut *w, msg);
        }
    }

    fn request(&self, command: &str, arguments: Value) -> i64 {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut p) = self.pending.lock() {
            p.insert(seq, command.to_string());
        }
        self.send(
            &json!({ "seq": seq, "type": "request", "command": command, "arguments": arguments }),
        );
        seq
    }

    fn launch_program(&self) {
        self.request("launch", self.launch_arguments.clone());
    }

    fn send_breakpoints(&self, src: &std::path::Path, lines: &[u32]) {
        self.request(
            "setBreakpoints",
            json!({
                "source": { "path": src.to_string_lossy(), "name": src.file_name().map(|n| n.to_string_lossy()) },
                "breakpoints": lines.iter().map(|l| json!({ "line": l })).collect::<Vec<_>>(),
                "lines": lines,
            }),
        );
    }

    fn set_breakpoints(&self) {
        let all = self
            .breakpoints
            .lock()
            .map(|b| b.clone())
            .unwrap_or_default();
        for (src, lines) in &all {
            self.send_breakpoints(src, lines);
        }
        if let Ok(mut s) = self.shared.lock() {
            s.configured = true;
        }
        self.request("configurationDone", json!({}));
    }
}

pub struct Transport {
    inner: Arc<Inner>,
    /// The adapter process (taken on drop, to be reaped off the UI thread).
    child: Option<Child>,
    _reader: std::thread::JoinHandle<()>,
}

impl Transport {
    pub fn start(
        config: LaunchConfig,
        breakpoints: HashMap<PathBuf, Vec<u32>>,
        notify: Notify,
    ) -> std::io::Result<Self> {
        let adapter = config.adapter.as_str();
        let mut cmd = Command::new(adapter);
        cmd.args(&config.adapter_args)
            .envs(config.adapter_env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(cwd) = &config.adapter_cwd {
            cmd.current_dir(cwd);
        }
        // The adapter may need its own directory on PATH to find its shared libraries
        // (e.g. lldb-dap needs liblldb next to it).
        if let Some(dir) = std::path::Path::new(adapter)
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
        {
            let mut paths = vec![dir.to_path_buf()];
            if let Some(existing) = std::env::var_os("PATH") {
                paths.extend(std::env::split_paths(&existing));
            }
            if let Ok(joined) = std::env::join_paths(paths) {
                cmd.env("PATH", joined);
            }
        }
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("adapter stdin");
        let stdout = child.stdout.take().expect("adapter stdout");
        let inner = Arc::new(Inner {
            writer: Mutex::new(stdin),
            next_seq: AtomicI64::new(1),
            pending: Mutex::new(HashMap::new()),
            shared: Mutex::new(Shared {
                state: DapState {
                    status: Some(Status::Starting),
                    ..DapState::default()
                },
                thread_id: 0,
                configured: false,
            }),
            notify,
            launch_arguments: config.launch_arguments,
            breakpoints: Mutex::new(breakpoints),
        });
        let reader_inner = Arc::clone(&inner);
        let reader = std::thread::Builder::new()
            .name("orress-dap-read".into())
            .spawn(move || read_loop(BufReader::new(stdout), &reader_inner))
            .expect("spawn dap reader");

        // Kick off the handshake.
        inner.request(
            "initialize",
            json!({
                "clientID": "orress",
                "adapterID": config.adapter_id,
                "linesStartAt1": true,
                "columnsStartAt1": true,
                "pathFormat": "path",
                "supportsRunInTerminalRequest": false,
            }),
        );

        Ok(Self {
            inner,
            child: Some(child),
            _reader: reader,
        })
    }

    /// Replaces one file's breakpoints; sends them right away once the session is configured
    /// (before that, the `initialized` event sends the whole updated set).
    pub fn set_breakpoints(&self, source: &std::path::Path, lines: Vec<u32>) {
        if let Ok(mut b) = self.inner.breakpoints.lock() {
            b.insert(source.to_path_buf(), lines.clone());
        }
        let configured = self.inner.shared.lock().is_ok_and(|s| s.configured);
        let alive = self.state().is_alive();
        if configured && alive {
            self.inner.send_breakpoints(source, &lines);
        }
    }

    pub fn state(&self) -> DapState {
        self.inner.shared.lock().expect("dap state").state.clone()
    }

    pub fn control(&self, command: &str) {
        let tid = self.inner.shared.lock().map(|s| s.thread_id).unwrap_or(0);
        self.inner.request(command, json!({ "threadId": tid }));
        if matches!(command, "continue" | "next" | "stepIn" | "stepOut") {
            self.inner.bump(|s| s.status = Some(Status::Running));
        }
    }

    pub fn terminate(&self) {
        self.inner.request("terminate", json!({}));
        self.inner
            .request("disconnect", json!({ "terminateDebuggee": true }));
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.inner
            .request("disconnect", json!({ "terminateDebuggee": true }));
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Reap it (no zombie on Unix) without blocking the UI thread on the wait.
            let _ = std::thread::Builder::new()
                .name("orress-dap-reap".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

fn read_loop(mut reader: impl BufRead, inner: &Arc<Inner>) {
    loop {
        match read_message(&mut reader) {
            Ok(Some(msg)) => {
                if std::env::var("ORRESS_DAP_DEBUG").is_ok() {
                    let kind = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let what = msg
                        .get("event")
                        .or_else(|| msg.get("command"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    eprintln!(
                        "[dap] <- {kind} {what} success={:?} msg={}",
                        msg.get("success"),
                        serde_json::to_string(&msg)
                            .unwrap_or_default()
                            .chars()
                            .take(240)
                            .collect::<String>()
                    );
                }
                handle(&msg, inner)
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    inner.bump(|s| match s.status {
        // Exiting before we ever got going means the adapter itself failed to start.
        Some(Status::Starting) => {
            s.status = Some(Status::Failed);
            s.last_error = Some(
                "the debug adapter exited before starting — is it installed and working?".into(),
            );
        }
        Some(Status::Exited) => {}
        _ => s.status = Some(Status::Exited),
    });
}

fn handle(msg: &Value, inner: &Arc<Inner>) {
    match msg.get("type").and_then(Value::as_str) {
        Some("response") => {
            let req_seq = msg.get("request_seq").and_then(Value::as_i64).unwrap_or(-1);
            let command = inner
                .pending
                .lock()
                .ok()
                .and_then(|mut p| p.remove(&req_seq))
                .or_else(|| {
                    msg.get("command")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let body = msg.get("body").cloned().unwrap_or(Value::Null);
            let success = msg.get("success").and_then(Value::as_bool).unwrap_or(false);
            if !success {
                let err = msg
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("request failed");
                if matches!(command.as_str(), "launch" | "initialize") {
                    inner.bump(|s| {
                        s.status = Some(Status::Failed);
                        s.last_error = Some(format!("{command}: {err}"));
                    });
                }
                return;
            }
            handle_response(&command, &body, inner);
        }
        Some("event") => handle_event(msg, inner),
        _ => {}
    }
}

fn handle_response(command: &str, body: &Value, inner: &Arc<Inner>) {
    match command {
        "initialize" => inner.launch_program(),
        "stackTrace" => {
            let frames = parse_frames_body(body);
            let current = frames
                .first()
                .and_then(|f| f.source.clone().map(|p| (p, f.line)));
            let top = frames.first().map(|f| f.id);
            inner.bump(|s| {
                s.frames = frames;
                s.current = current;
            });
            if let Some(id) = top {
                inner.request("scopes", json!({ "frameId": id }));
            }
        }
        "scopes" => {
            let reference = body
                .get("scopes")
                .and_then(Value::as_array)
                .and_then(|scopes| {
                    scopes
                        .iter()
                        .find(|s| s.get("name").and_then(Value::as_str) == Some("Locals"))
                        .or_else(|| scopes.first())
                })
                .and_then(|s| s.get("variablesReference"))
                .and_then(Value::as_i64);
            if let Some(reference) = reference {
                inner.request("variables", json!({ "variablesReference": reference }));
            } else {
                inner.bump(|s| s.status = Some(Status::Stopped));
            }
        }
        "variables" => {
            let vars = parse_variables_body(body);
            inner.bump(|s| {
                s.variables = vars;
                s.status = Some(Status::Stopped);
            });
        }
        _ => {}
    }
}

fn handle_event(msg: &Value, inner: &Arc<Inner>) {
    let event = msg.get("event").and_then(Value::as_str).unwrap_or("");
    let body = msg.get("body").cloned().unwrap_or(Value::Null);
    match event {
        "initialized" => inner.set_breakpoints(),
        "stopped" => {
            let tid = body.get("threadId").and_then(Value::as_i64).unwrap_or(0);
            let reason = body
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("stopped")
                .to_string();
            {
                let mut s = inner.shared.lock().expect("dap state");
                s.thread_id = tid;
                s.state.stop_reason = Some(reason);
            }
            inner.request(
                "stackTrace",
                json!({ "threadId": tid, "startFrame": 0, "levels": 40 }),
            );
        }
        "continued" => inner.bump(|s| s.status = Some(Status::Running)),
        "output" => {
            if let Some(text) = body.get("output").and_then(Value::as_str) {
                let text = text.to_string();
                inner.bump(|s| s.output.push(text));
            }
        }
        "terminated" | "exited" => inner.bump(|s| s.status = Some(Status::Exited)),
        _ => {}
    }
}

fn write_message(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(v)?;
    write!(w, "Content-Length: {}\r\n\r\n", body.len())?;
    w.write_all(&body)?;
    w.flush()
}

fn read_message(reader: &mut impl BufRead) -> std::io::Result<Option<Value>> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Content-Length:") {
            content_length = v.trim().parse().ok();
        }
    }
    let len = content_length.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing Content-Length")
    })?;
    let mut buf = vec![0u8; len];
    std::io::Read::read_exact(reader, &mut buf)?;
    Ok(Some(serde_json::from_slice(&buf)?))
}
