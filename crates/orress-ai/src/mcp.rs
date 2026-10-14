//! A minimal MCP (Model Context Protocol) client over stdio, so ORRESS's HTTP model backends
//! (Claude API and OpenAI-compatible) can offer an extension's MCP server as tool sources. The
//! Claude-CLI backend gets MCP from the CLI instead, so this is only used by the HTTP loops.
//!
//! MCP's stdio transport is newline-delimited JSON-RPC 2.0: one JSON message per line. Servers log
//! to stderr, so stdout carries only protocol messages.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::McpServer;

const PROTOCOL_VERSION: &str = "2024-11-05";
/// A safety bound on the tool-call loop, so a model that keeps asking for tools cannot spin forever.
pub const MAX_TOOL_ITERATIONS: usize = 8;

/// A tool an MCP server exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    /// The JSON Schema for the tool's arguments (passed straight to the model as the tool's schema).
    pub input_schema: Value,
}

/// Converts a tool to the Anthropic Messages API `tools` entry.
pub fn to_anthropic_tool(t: &McpTool) -> Value {
    json!({ "name": t.name, "description": t.description, "input_schema": t.input_schema })
}

/// Converts a tool to the OpenAI Chat-Completions `tools` entry.
pub fn to_openai_tool(t: &McpTool) -> Value {
    json!({
        "type": "function",
        "function": { "name": t.name, "description": t.description, "parameters": t.input_schema }
    })
}

/// Newline-delimited JSON-RPC write.
fn write_message(w: &mut impl Write, msg: &Value) -> Result<(), String> {
    let mut line = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    line.push(b'\n');
    w.write_all(&line).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

/// Reads one newline-delimited JSON-RPC message; `Ok(None)` at EOF. Blank lines are skipped.
fn read_message(r: &mut impl BufRead) -> Result<Option<Value>, String> {
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return serde_json::from_str(trimmed)
            .map(Some)
            .map_err(|e| format!("bad MCP JSON: {e}"));
    }
}

/// Parses a `tools/list` result into tools.
fn parse_tools(result: &Value) -> Vec<McpTool> {
    result
        .get("tools")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    Some(McpTool {
                        name: t.get("name")?.as_str()?.to_string(),
                        description: t
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        input_schema: t
                            .get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| json!({ "type": "object" })),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Extracts the text content from a `tools/call` result (joining text blocks).
fn result_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// How long to wait for a server to answer one request before giving up on it (a hung server must
/// not hang the query forever).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Reads messages from `stdout` on a background thread, forwarding each (or a read error) to the
/// returned channel; the channel closes at EOF. This lets [`Server::request`] wait with a timeout.
fn spawn_reader(stdout: impl Read + Send + 'static) -> Receiver<Result<Value, String>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_message(&mut reader) {
                Ok(Some(msg)) => {
                    if tx.send(Ok(msg)).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    // A malformed line is reported but does not end the stream.
                    if tx.send(Err(e)).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// A single connected MCP server process and its framed stdio.
struct Server {
    child: Option<Child>,
    stdin: Box<dyn Write + Send>,
    incoming: Receiver<Result<Value, String>>,
    next_id: i64,
    timeout: Duration,
}

impl Server {
    /// Sends a request and returns its `result`. While waiting it answers requests the server
    /// sends us (`ping` → `{}`, anything else → "method not found") and skips notifications, and it
    /// gives up after the request timeout.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        write_message(
            &mut self.stdin,
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let msg = match self.incoming.recv_timeout(remaining) {
                Ok(Ok(msg)) => msg,
                Ok(Err(_)) => continue, // an unparseable line; keep waiting for our answer
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "the MCP server did not answer `{method}` within {}s",
                        self.timeout.as_secs()
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("the MCP server closed the connection".into());
                }
            };
            // A request from the server to us (it has both a method and an id): answer it.
            if let (Some(m), Some(req_id)) =
                (msg.get("method").and_then(Value::as_str), msg.get("id"))
            {
                let reply = server_request_reply(m, req_id.clone());
                write_message(&mut self.stdin, &reply)?;
                continue;
            }
            if msg.get("id").and_then(Value::as_i64) == Some(id) {
                if let Some(err) = msg.get("error") {
                    return Err(format!("MCP error: {err}"));
                }
                return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
            }
            // Notifications and stray responses are ignored.
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        write_message(
            &mut self.stdin,
            &json!({ "jsonrpc": "2.0", "method": method, "params": params }),
        )
    }
}

/// Our reply to a request the server sent us: `ping` succeeds with `{}`; we offer no other client
/// capabilities (sampling, roots, …), so everything else is "method not found".
fn server_request_reply(method: &str, id: Value) -> Value {
    if method == "ping" {
        json!({ "jsonrpc": "2.0", "id": id, "result": {} })
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") }
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawns one MCP server and performs the handshake, returning it with its tools.
fn connect_one(s: &McpServer) -> Result<(Server, Vec<McpTool>), String> {
    let mut child = Command::new(&s.command)
        .args(&s.args)
        .envs(s.env.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start MCP server `{}`: {e}", s.name))?;
    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout: ChildStdout = child.stdout.take().ok_or("no stdout")?;
    let mut server = Server {
        child: Some(child),
        stdin: Box::new(stdin),
        incoming: spawn_reader(stdout),
        next_id: 1,
        timeout: REQUEST_TIMEOUT,
    };
    server.request(
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "ORRESS", "version": env!("CARGO_PKG_VERSION") }
        }),
    )?;
    server.notify("notifications/initialized", json!({}))?;
    let tools = parse_tools(&server.request("tools/list", json!({}))?);
    Ok((server, tools))
}

/// A set of connected MCP servers and the tools they expose, routing a tool call to its owner.
/// Best-effort: a server that fails to start or handshake is skipped rather than failing the query.
pub struct McpSession {
    servers: Vec<Server>,
    /// Tool name → index into `servers`.
    owner: HashMap<String, usize>,
    tools: Vec<McpTool>,
}

impl McpSession {
    pub fn connect(servers: &[McpServer]) -> Self {
        let mut session = McpSession {
            servers: Vec::new(),
            owner: HashMap::new(),
            tools: Vec::new(),
        };
        for s in servers {
            if let Ok((server, tools)) = connect_one(s) {
                let idx = session.servers.len();
                for t in &tools {
                    session.owner.insert(t.name.clone(), idx);
                }
                session.tools.extend(tools);
                session.servers.push(server);
            }
        }
        session
    }

    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Calls a tool by name, returning its text output.
    pub fn call(&mut self, name: &str, arguments: Value) -> Result<String, String> {
        let idx = *self
            .owner
            .get(name)
            .ok_or_else(|| format!("no MCP tool named `{name}`"))?;
        let result = self.servers[idx].request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )?;
        Ok(result_text(&result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn framing_round_trips_and_skips_blank_lines() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({ "id": 1, "method": "ping" })).unwrap();
        assert!(buf.ends_with(b"\n"));
        // A blank line before the next message is skipped.
        let mut stream = Cursor::new([&buf[..], b"\n", b"{\"id\":2}\n"].concat());
        assert_eq!(
            read_message(&mut stream).unwrap().unwrap()["method"],
            "ping"
        );
        assert_eq!(read_message(&mut stream).unwrap().unwrap()["id"], 2);
        assert!(read_message(&mut stream).unwrap().is_none()); // EOF
    }

    #[test]
    fn parses_tools_and_call_results() {
        let listed = json!({
            "tools": [
                { "name": "search", "description": "Search docs",
                  "inputSchema": { "type": "object", "properties": { "q": { "type": "string" } } } },
                { "name": "noschema" }
            ]
        });
        let tools = parse_tools(&listed);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "search");
        assert_eq!(tools[0].input_schema["properties"]["q"]["type"], "string");
        // A tool with no inputSchema still gets a valid object schema.
        assert_eq!(tools[1].input_schema, json!({ "type": "object" }));

        let result = json!({ "content": [ { "type": "text", "text": "hello" }, { "type": "text", "text": "world" } ] });
        assert_eq!(result_text(&result), "hello\nworld");
    }

    /// A writer that records what the client sent.
    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn fake_server(script: &str, timeout: Duration) -> (Server, Sink) {
        let sink = Sink::default();
        let server = Server {
            child: None,
            stdin: Box::new(sink.clone()),
            incoming: spawn_reader(Cursor::new(script.as_bytes().to_vec())),
            next_id: 1,
            timeout,
        };
        (server, sink)
    }

    #[test]
    fn answers_server_requests_while_waiting_for_a_response() {
        let script = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"s2\",\"method\":\"sampling/createMessage\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n",
        );
        let (mut server, sink) = fake_server(script, Duration::from_secs(5));
        assert_eq!(
            server.request("tools/list", json!({})).unwrap(),
            json!({ "ok": true })
        );
        let sent = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<Value> = sent
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Our request, then the ping reply, then the method-not-found error.
        assert_eq!(lines[0]["method"], "tools/list");
        assert_eq!(
            lines[1],
            json!({ "jsonrpc": "2.0", "id": "s1", "result": {} })
        );
        assert_eq!(lines[2]["id"], "s2");
        assert_eq!(lines[2]["error"]["code"], -32601);
    }

    #[test]
    fn a_silent_or_closed_server_errors_instead_of_hanging() {
        // EOF with no answer → closed.
        let (mut server, _) = fake_server("", Duration::from_secs(5));
        assert!(
            server
                .request("x", json!({}))
                .unwrap_err()
                .contains("closed")
        );

        // A server that never answers → timeout (the reader stays open).
        let (tx, rx) = channel();
        let mut server = Server {
            child: None,
            stdin: Box::new(Sink::default()),
            incoming: rx,
            next_id: 1,
            timeout: Duration::from_millis(50),
        };
        let err = server.request("x", json!({})).unwrap_err();
        assert!(err.contains("did not answer"), "{err}");
        drop(tx);
    }

    #[test]
    fn tool_schema_conversions_match_each_api() {
        let t = McpTool {
            name: "search".into(),
            description: "Search".into(),
            input_schema: json!({ "type": "object" }),
        };
        let a = to_anthropic_tool(&t);
        assert_eq!(a["name"], "search");
        assert_eq!(a["input_schema"]["type"], "object");

        let o = to_openai_tool(&t);
        assert_eq!(o["type"], "function");
        assert_eq!(o["function"]["name"], "search");
        assert_eq!(o["function"]["parameters"]["type"], "object");
    }
}
