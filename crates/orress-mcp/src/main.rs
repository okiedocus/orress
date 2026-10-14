//! The ORRESS MCP server binary: a newline-delimited JSON-RPC 2.0 loop over stdio. Point an MCP
//! client (e.g. Claude Code) at this program to let an agent drive ORRESS's analysis engines.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => orress_mcp::dispatch(&req),
            Err(e) => Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32700, "message": format!("parse error: {e}") }
            })),
        };
        if let Some(resp) = resp {
            let _ = writeln!(stdout, "{resp}");
            let _ = stdout.flush();
        }
    }
}
