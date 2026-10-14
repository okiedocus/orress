//! JSON-RPC over a language server's stdio: Content-Length framing, a background reader
//! thread, request/response correlation and notification dispatch. No async runtime — the
//! UI polls results through channels, which fits egui.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::PositionEncoding;

pub type Notify = Arc<dyn Fn() + Send + Sync>;

/// A response to a request: `Ok(result)` or `Err(error object)`.
pub type RpcResult = Result<Value, Value>;

/// Shared state the reader thread writes and the UI reads.
#[derive(Default)]
pub struct Shared {
    /// Diagnostics by document URI.
    pub diagnostics: HashMap<String, Vec<lsp_types::Diagnostic>>,
    /// Whether `initialize` has completed.
    pub ready: bool,
    /// A fatal transport error, if any.
    pub error: Option<String>,
    /// Whether the server has gone away (exited, crashed or failed `initialize`). Requests made
    /// after that fail at once instead of waiting forever.
    pub dead: bool,
    /// The position encoding negotiated in `initialize` (UTF-16, the LSP default, until then).
    pub encoding: PositionEncoding,
    /// Bumps on every change, so the UI can tell when to refresh.
    pub generation: u64,
}

pub struct Inner {
    stdin: Mutex<ChildStdin>,
    next_id: AtomicI64,
    pending: Mutex<HashMap<i64, Sender<RpcResult>>>,
    /// Notifications queued until the server is initialized.
    queue: Mutex<Vec<Value>>,
    pub shared: Mutex<Shared>,
    pub notify: Notify,
    /// The id of the `initialize` request, handled specially by the reader.
    init_id: i64,
    /// The `initialized` + initial didOpen messages to send once initialize returns.
    on_ready: Mutex<Vec<Value>>,
    /// The user's settings for this server (`lsp.<server>.settings`), the answer to the server's
    /// `workspace/configuration` requests.
    settings: Option<Value>,
}

impl Inner {
    fn bump(&self) {
        if let Ok(mut s) = self.shared.lock() {
            s.generation += 1;
        }
        (self.notify)();
    }

    fn write(&self, msg: &Value) {
        if let Ok(mut stdin) = self.stdin.lock() {
            let _ = write_message(&mut *stdin, msg);
        }
    }

    /// Writes a message directly, bypassing the ready-queue (used for `initialize`).
    pub fn notify_raw(&self, msg: Value) {
        self.write(&msg);
    }

    /// Sends a notification, queuing it until the server is ready.
    pub fn notify_server(&self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        let ready = self.shared.lock().map(|s| s.ready).unwrap_or(false);
        if ready {
            self.write(&msg);
        } else if let Ok(mut q) = self.queue.lock() {
            q.push(msg);
        }
    }

    /// Sends a request; its result arrives on the returned receiver. If the server is gone, the
    /// receiver gets an error straight away.
    pub fn request(&self, method: &str, params: Value) -> std::sync::mpsc::Receiver<RpcResult> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = std::sync::mpsc::channel();
        if self.shared.lock().map(|s| s.dead).unwrap_or(true) {
            let _ = tx.send(Err(
                json!({"message": "the language server is not running"}),
            ));
            return rx;
        }
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        // Requests also wait for readiness (except initialize, sent directly at startup).
        let ready = self.shared.lock().map(|s| s.ready).unwrap_or(false);
        if ready || id == self.init_id {
            self.write(&msg);
        } else if let Ok(mut q) = self.queue.lock() {
            q.push(msg);
        }
        rx
    }

    /// Marks the server gone and fails every request still waiting for a reply, so callers
    /// polling a [`crate::Pending`] see an error instead of waiting forever.
    fn fail_pending(&self, why: &str) {
        if let Ok(mut s) = self.shared.lock() {
            s.dead = true;
        }
        let waiting: Vec<Sender<RpcResult>> = self
            .pending
            .lock()
            .map(|mut p| p.drain().map(|(_, tx)| tx).collect())
            .unwrap_or_default();
        for tx in waiting {
            let _ = tx.send(Err(json!({ "message": why })));
        }
    }
}

pub struct Transport {
    pub inner: Arc<Inner>,
    /// The server process (taken on drop, to be reaped off the UI thread).
    child: Option<Child>,
    _reader: std::thread::JoinHandle<()>,
}

impl Transport {
    /// Starts the reader thread over `child`'s stdout. `init_id` is the id used for the
    /// `initialize` request; `on_ready` are messages to flush once it returns; `settings` answers
    /// the server's `workspace/configuration` requests.
    pub fn new(
        mut child: Child,
        init_id: i64,
        on_ready: Vec<Value>,
        settings: Option<Value>,
        notify: Notify,
    ) -> Self {
        let stdin = child.stdin.take().expect("server stdin");
        let stdout = child.stdout.take().expect("server stdout");
        let inner = Arc::new(Inner {
            stdin: Mutex::new(stdin),
            next_id: AtomicI64::new(init_id + 1),
            pending: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
            shared: Mutex::new(Shared::default()),
            notify,
            init_id,
            on_ready: Mutex::new(on_ready),
            settings,
        });
        let reader_inner = Arc::clone(&inner);
        let reader = std::thread::Builder::new()
            .name("orress-lsp-read".into())
            .spawn(move || read_loop(BufReader::new(stdout), &reader_inner))
            .expect("spawn lsp reader");
        Self {
            inner,
            child: Some(child),
            _reader: reader,
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // Best-effort graceful shutdown, then kill.
        self.inner
            .write(&json!({"jsonrpc":"2.0","id":-1,"method":"shutdown","params":null}));
        self.inner
            .write(&json!({"jsonrpc":"2.0","method":"exit","params":null}));
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Reap it (no zombie on Unix) without blocking the UI thread on the wait.
            let _ = std::thread::Builder::new()
                .name("orress-lsp-reap".into())
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
                if std::env::var("ORRESS_LSP_DEBUG").is_ok() {
                    let m = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    if m == "window/showMessage"
                        || m == "textDocument/publishDiagnostics"
                        || m == "window/logMessage"
                    {
                        eprintln!(
                            "[lsp] <- {m}: {}",
                            msg.get("params")
                                .map(|p| p.to_string())
                                .unwrap_or_default()
                                .chars()
                                .take(300)
                                .collect::<String>()
                        );
                    } else {
                        eprintln!(
                            "[lsp] <- id={:?} method={:?}",
                            msg.get("id"),
                            msg.get("method")
                        );
                    }
                }
                handle(&msg, inner);
            }
            Ok(None) => {
                // EOF: the server exited. If it never became ready, surface that.
                if let Ok(mut s) = inner.shared.lock()
                    && !s.ready
                    && s.error.is_none()
                {
                    s.error = Some(
                        "the language server exited before it was ready (is it installed?)".into(),
                    );
                }
                inner.fail_pending("the language server exited");
                inner.bump();
                break;
            }
            Err(e) => {
                if let Ok(mut s) = inner.shared.lock() {
                    s.error = Some(e.to_string());
                }
                inner.fail_pending(&format!("the language server connection failed: {e}"));
                inner.bump();
                break;
            }
        }
    }
}

fn handle(msg: &Value, inner: &Arc<Inner>) {
    // A response to one of our requests.
    if let Some(id) = msg.get("id").and_then(Value::as_i64)
        && (msg.get("result").is_some() || msg.get("error").is_some())
        && msg.get("method").is_none()
    {
        if id == inner.init_id {
            match msg.get("error") {
                // A failed `initialize` leaves the server unusable: report it, don't proceed.
                Some(err) => {
                    let text = err
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error");
                    if let Ok(mut s) = inner.shared.lock() {
                        s.error = Some(format!("the language server failed to initialize: {text}"));
                    }
                    inner.fail_pending("the language server failed to initialize");
                    inner.bump();
                }
                None => on_initialized(inner, msg.get("result").unwrap_or(&Value::Null)),
            }
            return;
        }
        let result: RpcResult = match msg.get("error") {
            Some(e) => Err(e.clone()),
            None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
        };
        if let Ok(mut p) = inner.pending.lock()
            && let Some(tx) = p.remove(&id)
        {
            let _ = tx.send(result);
        }
        inner.bump();
        return;
    }

    // A request from the server to us: reply so it does not stall.
    if let (Some(id), Some(method)) = (msg.get("id"), msg.get("method").and_then(Value::as_str)) {
        let result = match method {
            "workspace/configuration" => {
                // One config object per requested item, from the user's settings for this server.
                let items = msg
                    .get("params")
                    .and_then(|p| p.get("items"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                Value::Array(
                    items
                        .iter()
                        .map(|item| {
                            configuration_for(
                                inner.settings.as_ref(),
                                item.get("section").and_then(Value::as_str),
                            )
                        })
                        .collect(),
                )
            }
            // We never apply server-initiated edits, and must say so rather than reply null.
            "workspace/applyEdit" => json!({ "applied": false }),
            _ => Value::Null, // registerCapability, workDoneProgress/create, …
        };
        inner.write(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
        return;
    }

    // A notification from the server.
    if let Some(method) = msg.get("method").and_then(Value::as_str)
        && method == "textDocument/publishDiagnostics"
        && let Some(params) = msg.get("params")
        && let Ok(pdp) =
            serde_json::from_value::<lsp_types::PublishDiagnosticsParams>(params.clone())
    {
        if let Ok(mut s) = inner.shared.lock() {
            s.diagnostics
                .insert(normalize_uri(pdp.uri.as_ref()), pdp.diagnostics);
        }
        inner.bump();
    }
    // Other notifications ($/progress, window/logMessage, …) are ignored.
}

/// The answer to one `workspace/configuration` item: the value at `section` (a dotted path such
/// as `python.analysis`) in the user's settings for this server. A section the settings do not
/// nest under is answered with the whole settings object (users often write a server's settings
/// without the server-name wrapper, e.g. `lsp.rust-analyzer.settings = { "check": … }`).
pub(crate) fn configuration_for(settings: Option<&Value>, section: Option<&str>) -> Value {
    let Some(settings) = settings else {
        return Value::Null;
    };
    let Some(section) = section.filter(|s| !s.is_empty()) else {
        return settings.clone();
    };
    let mut node = settings;
    for part in section.split('.') {
        match node.get(part) {
            Some(next) => node = next,
            None => return settings.clone(),
        }
    }
    node.clone()
}

/// The position encoding the server picked in its `initialize` result (UTF-16 when it names
/// none, as the protocol specifies).
pub(crate) fn negotiated_encoding(result: &Value) -> PositionEncoding {
    match result
        .get("capabilities")
        .and_then(|c| c.get("positionEncoding"))
        .and_then(Value::as_str)
    {
        Some("utf-8") => PositionEncoding::Utf8,
        Some("utf-32") => PositionEncoding::Utf32,
        _ => PositionEncoding::Utf16,
    }
}

fn on_initialized(inner: &Arc<Inner>, result: &Value) {
    if std::env::var("ORRESS_LSP_DEBUG").is_ok() {
        eprintln!("[lsp] on_initialized");
    }
    inner.write(&json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    if let Ok(mut s) = inner.shared.lock() {
        s.ready = true;
        s.encoding = negotiated_encoding(result);
    }
    // Flush the didOpen queued at startup, then anything queued while initializing.
    let ready_msgs = inner
        .on_ready
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_default();
    for m in ready_msgs {
        inner.write(&m);
    }
    let queued = inner
        .queue
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_default();
    for m in queued {
        inner.write(&m);
    }
    inner.bump();
}

/// Normalises a document URI for map keys. Windows paths are case-insensitive and
/// rust-analyzer lower-cases the drive letter, so fold case there.
pub fn normalize_uri(uri: &str) -> String {
    if cfg!(windows) {
        uri.to_lowercase()
    } else {
        uri.to_string()
    }
}

fn write_message(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(v)?;
    write!(w, "Content-Length: {}\r\n\r\n", body.len())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one framed message; `Ok(None)` on EOF.
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
    reader.read_exact(&mut buf)?;
    let value = serde_json::from_slice(&buf)?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({"jsonrpc":"2.0","id":1,"method":"hi"})).unwrap();
        let text = String::from_utf8(buf.clone()).unwrap();
        assert!(text.starts_with("Content-Length: "));
        let mut cur = Cursor::new(buf);
        let msg = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(msg["id"], 1);
        assert_eq!(msg["method"], "hi");
    }

    #[test]
    fn eof_returns_none() {
        let mut cur = Cursor::new(Vec::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn configuration_sections_resolve_from_settings() {
        let settings = json!({ "python": { "analysis": { "typeCheckingMode": "strict" } } });
        assert_eq!(
            configuration_for(Some(&settings), Some("python.analysis")),
            json!({ "typeCheckingMode": "strict" })
        );
        // A section the settings do not nest under gets the whole object.
        assert_eq!(
            configuration_for(Some(&settings), Some("rust-analyzer")),
            settings
        );
        assert_eq!(configuration_for(None, Some("python")), Value::Null);
    }

    #[test]
    fn pending_requests_fail_when_the_server_exits() {
        use std::process::{Command, Stdio};
        // `rustc --version` stands in for a server that prints something and exits at once.
        let child = Command::new("rustc")
            .arg("--version")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("rustc runs");
        let transport = Transport::new(child, 0, Vec::new(), None, Arc::new(|| {}));
        let rx = transport.inner.request("textDocument/hover", json!({}));
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the request is answered, not left hanging");
        assert!(result.is_err());
    }

    #[test]
    fn encoding_defaults_to_utf16() {
        assert_eq!(negotiated_encoding(&json!({})), PositionEncoding::Utf16);
        assert_eq!(
            negotiated_encoding(&json!({"capabilities": {"positionEncoding": "utf-8"}})),
            PositionEncoding::Utf8
        );
    }

    #[test]
    fn reads_two_messages() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({"n":1})).unwrap();
        write_message(&mut buf, &json!({"n":2})).unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_message(&mut cur).unwrap().unwrap()["n"], 1);
        assert_eq!(read_message(&mut cur).unwrap().unwrap()["n"], 2);
        assert!(read_message(&mut cur).unwrap().is_none());
    }
}
