//! A tiny mock DAP adapter used only by tests: it speaks enough of the protocol to drive
//! the client through a full stop (initialize -> launch -> initialized -> breakpoints ->
//! stopped -> stackTrace -> scopes -> variables), with canned data.

use std::io::{BufRead, BufReader, Write};

use serde_json::{Value, json};

fn main() {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = std::io::stdout();
    let mut seq = 1i64;
    let send = |out: &mut std::io::Stdout, v: Value| {
        let body = serde_json::to_vec(&v).unwrap();
        let _ = write!(out, "Content-Length: {}\r\n\r\n", body.len());
        let _ = out.write_all(&body);
        let _ = out.flush();
    };
    let next = |seq: &mut i64| {
        let s = *seq;
        *seq += 1;
        s
    };

    while let Some(msg) = read_message(&mut reader) {
        let command = msg
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let req_seq = msg.get("seq").and_then(Value::as_i64).unwrap_or(0);
        let resp = |seq: &mut i64, body: Value| json!({ "seq": next(seq), "type": "response", "request_seq": req_seq, "success": true, "command": command, "body": body });
        match command.as_str() {
            "initialize" => {
                send(
                    &mut out,
                    resp(
                        &mut seq,
                        json!({ "supportsConfigurationDoneRequest": true }),
                    ),
                );
            }
            "launch" => {
                send(&mut out, resp(&mut seq, Value::Null));
                // Ask for configuration.
                send(
                    &mut out,
                    json!({ "seq": next(&mut seq), "type": "event", "event": "initialized", "body": {} }),
                );
            }
            "setBreakpoints" => {
                send(
                    &mut out,
                    resp(
                        &mut seq,
                        json!({ "breakpoints": [{ "verified": true, "line": 3 }] }),
                    ),
                );
            }
            "configurationDone" => {
                send(&mut out, resp(&mut seq, Value::Null));
                // Now "hit" the breakpoint.
                send(
                    &mut out,
                    json!({ "seq": next(&mut seq), "type": "event", "event": "stopped", "body": { "reason": "breakpoint", "threadId": 1 } }),
                );
            }
            "stackTrace" => {
                send(
                    &mut out,
                    resp(
                        &mut seq,
                        json!({ "stackFrames": [{ "id": 1000, "name": "main", "line": 3, "source": { "path": "/tmp/demo.rs" } }], "totalFrames": 1 }),
                    ),
                );
            }
            "scopes" => {
                send(
                    &mut out,
                    resp(
                        &mut seq,
                        json!({ "scopes": [{ "name": "Locals", "variablesReference": 2000 }] }),
                    ),
                );
            }
            "variables" => {
                send(
                    &mut out,
                    resp(
                        &mut seq,
                        json!({ "variables": [{ "name": "a", "value": "41", "type": "i32" }] }),
                    ),
                );
            }
            "continue" | "next" | "stepIn" | "stepOut" | "pause" => {
                send(
                    &mut out,
                    resp(&mut seq, json!({ "allThreadsContinued": true })),
                );
            }
            "terminate" => send(&mut out, resp(&mut seq, Value::Null)),
            "disconnect" => {
                send(&mut out, resp(&mut seq, Value::Null));
                break;
            }
            _ => send(&mut out, resp(&mut seq, Value::Null)),
        }
    }
}

fn read_message(reader: &mut impl BufRead) -> Option<Value> {
    let mut len = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Content-Length:") {
            len = v.trim().parse().ok();
        }
    }
    let mut buf = vec![0u8; len?];
    std::io::Read::read_exact(reader, &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}
