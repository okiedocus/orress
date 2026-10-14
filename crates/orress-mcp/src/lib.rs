//! An MCP (Model Context Protocol) server that exposes ORRESS's analysis engines to external
//! agents — Claude Code and the like — over stdio JSON-RPC. It lets an agent drive ORRESS: triage
//! a file, pull its strings, disassemble managed/bytecode formats, deobfuscate JavaScript and list
//! archive contents, all through the same pure-Rust engines the GUI uses.
//!
//! The transport is newline-delimited JSON-RPC 2.0 (the MCP stdio transport). [`dispatch`] handles
//! one message and returns the response (or `None` for a notification), so it is easy to test.

use serde_json::{Value, json};

pub mod tools;

/// Handles one JSON-RPC message, returning the response value (or `None` for a notification).
pub fn dispatch(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    match method {
        "initialize" => reply(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "orress-mcp", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "ping" => reply(id, json!({})),
        "tools/list" => reply(id, json!({ "tools": tool_schemas() })),
        "tools/call" => {
            let params = req.get("params");
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let empty = json!({});
            let args = params.and_then(|p| p.get("arguments")).unwrap_or(&empty);
            // A panic inside an engine (malformed input tripping a bug) must not kill the server;
            // report it as a tool error instead.
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_tool(name, args)))
                    .unwrap_or_else(|panic| {
                        Err(format!(
                            "tool `{name}` panicked: {}",
                            panic_message(panic.as_ref())
                        ))
                    });
            match outcome {
                Ok(text) => reply(id, json!({ "content": [{ "type": "text", "text": text }] })),
                Err(e) => reply(
                    id,
                    json!({ "content": [{ "type": "text", "text": format!("error: {e}") }], "isError": true }),
                ),
            }
        }
        // Notifications (no id) are silently accepted.
        _ if id.is_none() => None,
        _ => error(id, -32601, &format!("method not found: {method}")),
    }
}

/// The message of a caught panic payload (a `&str` or `String`), or a generic note.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

fn reply(id: Option<Value>, result: Value) -> Option<Value> {
    Some(json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result }))
}

fn error(id: Option<Value>, code: i64, message: &str) -> Option<Value> {
    Some(
        json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "error": { "code": code, "message": message } }),
    )
}

fn run_tool(name: &str, args: &Value) -> Result<String, String> {
    // The diff tool takes two paths rather than one.
    if name == "binary_diff" {
        let a = args
            .get("path_a")
            .and_then(Value::as_str)
            .ok_or("missing required 'path_a'")?;
        let b = args
            .get("path_b")
            .and_then(Value::as_str)
            .ok_or("missing required 'path_b'")?;
        return tools::binary_diff(a, b);
    }
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or("missing required 'path' argument")?;
    match name {
        "triage" => tools::triage(path),
        "strings" => {
            let min = args.get("min_length").and_then(Value::as_u64).unwrap_or(5) as usize;
            tools::strings(path, min)
        }
        "disassemble" => tools::disassemble(path),
        "detect_vm" => tools::detect_vm(path),
        "deobfuscate_js" => tools::deobfuscate_js(path),
        "archive_list" => tools::archive_list(path),
        other => Err(format!("unknown tool: {other}")),
    }
}

/// The tool definitions advertised via `tools/list`.
fn tool_schemas() -> Value {
    let path_arg = json!({
        "type": "object",
        "properties": { "path": { "type": "string", "description": "Path to the file to analyze" } },
        "required": ["path"]
    });
    json!([
        { "name": "triage", "description": "Static triage of a file: format, architecture, hashes, protections, imports by behaviour (MITRE ATT&CK) and defanged IOCs, as Markdown.", "inputSchema": path_arg },
        { "name": "strings", "description": "Printable ASCII strings in a file.", "inputSchema": {
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Path to the file" },
                "min_length": { "type": "integer", "description": "Minimum run length (default 5)" }
            },
            "required": ["path"]
        }},
        { "name": "disassemble", "description": "Auto-detects and disassembles a managed/bytecode file: WebAssembly (WAT), Python .pyc, Java .class, .NET (IL) or Android .dex.", "inputSchema": path_arg },
        { "name": "detect_vm", "description": "Flags functions that look like a VM interpreter (bytecode dispatch loop) — the signature of VM-based obfuscation (VMProtect/Themida/custom CTF VMs).", "inputSchema": path_arg },
        { "name": "deobfuscate_js", "description": "Deobfuscates JavaScript (escapes, fromCharCode, atob, string arrays), beautifies it and lists its strings.", "inputSchema": path_arg },
        { "name": "archive_list", "description": "Lists the entries of a ZIP/JAR/APK and a JAR's Main-Class.", "inputSchema": path_arg },
        { "name": "binary_diff", "description": "BinDiff-style comparison of two native binaries: identical / changed / added / removed functions (patch diffing, malware-variant comparison).", "inputSchema": {
            "type": "object",
            "properties": {
                "path_a": { "type": "string", "description": "Path to the first (older) binary" },
                "path_b": { "type": "string", "description": "Path to the second (newer) binary" }
            },
            "required": ["path_a", "path_b"]
        }}
    ])
}

#[cfg(test)]
mod tests;
