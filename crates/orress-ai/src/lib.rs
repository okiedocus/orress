//! AI assistant backends for ORRESS — bring your own model.
//!
//! Four providers are supported so anyone can use their own subscription or a local model:
//!
//! - **Claude plan (CLI)** — shells out to the installed `claude` CLI (`claude -p`), which runs on
//!   whatever account Claude Code is signed into, *including a Claude Pro/Max plan* — no API key.
//! - **Claude API** — the Anthropic Messages API with an `x-api-key` (or `ANTHROPIC_API_KEY`).
//! - **OpenAI-compatible** — the Chat Completions protocol: OpenAI itself, Azure OpenAI, or any
//!   local server that speaks it (Ollama, LM Studio, llama.cpp, vLLM, …) via its base URL.
//! - **Offline** — no model; the caller answers from static analysis only.
//!
//! The HTTP providers use a blocking `ureq` client (rustls); callers run [`ask`] on a background
//! thread. Keys come from the config or, if blank, the matching environment variable.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod mcp;

/// Which backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    /// The `claude` CLI (`claude -p`) on the signed-in Claude plan/account.
    ClaudeCli,
    /// The Anthropic Messages API (key).
    ClaudeApi,
    /// Any OpenAI Chat-Completions-compatible endpoint (OpenAI, Azure, Ollama, LM Studio, …).
    OpenAi,
    /// No model — answer from static analysis only.
    Offline,
}

impl Provider {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClaudeCli => "Claude plan (CLI)",
            Self::ClaudeApi => "Claude API (key)",
            Self::OpenAi => "OpenAI-compatible / local",
            Self::Offline => "Offline (static only)",
        }
    }
    /// Default endpoint base for the HTTP providers.
    pub fn default_base(self) -> &'static str {
        match self {
            Self::ClaudeApi => "https://api.anthropic.com",
            Self::OpenAi => "https://api.openai.com/v1",
            _ => "",
        }
    }
    /// Environment variable consulted when no key is configured.
    pub fn key_env(self) -> &'static str {
        match self {
            Self::ClaudeApi => "ANTHROPIC_API_KEY",
            Self::OpenAi => "OPENAI_API_KEY",
            _ => "",
        }
    }
}

/// The assistant configuration. The API key is persisted only when `remember_key` is set (it is
/// then written to `ai.json` in plaintext); otherwise it is session-only and falls back to the
/// provider's environment variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub provider: Provider,
    pub model: String,
    pub base_url: String,
    /// Save the API key to disk (plaintext). Off → key is session-only / from the environment.
    #[serde(default)]
    pub remember_key: bool,
    #[serde(default)]
    pub api_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider: Provider::ClaudeCli,
            model: String::new(),
            base_url: String::new(),
            remember_key: false,
            api_key: String::new(),
        }
    }
}

impl Config {
    fn base(&self) -> String {
        if self.base_url.trim().is_empty() {
            self.provider.default_base().to_string()
        } else {
            self.base_url.trim().trim_end_matches('/').to_string()
        }
    }
    /// The API key: the configured one, else the provider's environment variable.
    fn key(&self) -> Option<String> {
        if !self.api_key.trim().is_empty() {
            return Some(self.api_key.trim().to_string());
        }
        let env = self.provider.key_env();
        (!env.is_empty()).then(|| std::env::var(env).ok()).flatten()
    }
}

/// The Claude API model used when none is configured (the current Opus).
pub const DEFAULT_CLAUDE_MODEL: &str = "claude-opus-5-5";

/// The output-token cap for Claude API requests. Current models think before answering and the
/// thinking counts against this cap, so it must leave room for both (1024 truncated answers).
const MAX_TOKENS: u32 = 16_000;

/// The default system prompt: a focused RE assistant that answers from the provided context.
pub const SYSTEM_PROMPT: &str = "You are a reverse-engineering assistant embedded in ORRESS, a \
    reverse-engineering IDE for CTF and malware analysis. Answer the user's question about the \
    binary using only the analysis context provided in the message. Be concise and concrete, \
    prefer bullet points, cite the specific strings/APIs/addresses you reason from, and suggest \
    the next step in ORRESS. Do not ask to run tools; everything you need is in the message.";

/// Whether the `claude` CLI is available (for the Claude-plan backend).
pub fn claude_available() -> bool {
    claude_binary().is_some()
}

fn claude_binary() -> Option<String> {
    for name in ["claude", "claude.cmd", "claude.exe"] {
        if Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return Some(name.to_string());
        }
    }
    None
}

/// An MCP (Model Context Protocol) server the model may use as a tool source, resolved from a Zed
/// context-server extension (its `context-server-command`). Only the `claude` CLI backend wires
/// these in; the HTTP backends ignore them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Builds the `--mcp-config` JSON the `claude` CLI expects:
/// `{ "mcpServers": { "<name>": { "command", "args", "env" } } }`. Pure, so it is unit-tested.
pub fn mcp_config_json(servers: &[McpServer]) -> String {
    let mut map = serde_json::Map::new();
    for s in servers {
        let env: serde_json::Map<String, Value> = s
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        map.insert(
            s.name.clone(),
            json!({ "command": s.command, "args": s.args, "env": Value::Object(env) }),
        );
    }
    json!({ "mcpServers": Value::Object(map) }).to_string()
}

/// Sends a query to the configured backend and returns the answer. Blocks (HTTP or a subprocess),
/// so run it on a background thread. `Offline` is not a model and returns an error here. `mcp` lists
/// MCP servers the model may use (honoured only by the `claude` CLI backend).
pub fn ask(cfg: &Config, system: &str, user: &str, mcp: &[McpServer]) -> Result<String, String> {
    match cfg.provider {
        Provider::ClaudeCli => {
            let model = (!cfg.model.trim().is_empty()).then(|| cfg.model.trim());
            ask_claude(model, system, user, mcp)
        }
        Provider::ClaudeApi => {
            let key = cfg
                .key()
                .ok_or("no Anthropic API key (set it, or ANTHROPIC_API_KEY)")?;
            anthropic(
                &cfg.base(),
                &key,
                model_or(cfg, DEFAULT_CLAUDE_MODEL),
                system,
                user,
                mcp,
            )
        }
        Provider::OpenAi => openai(
            &cfg.base(),
            cfg.key(),
            model_or(cfg, "gpt-4o-mini"),
            system,
            user,
            mcp,
        ),
        Provider::Offline => Err("the Offline backend has no model".into()),
    }
}

fn model_or<'a>(cfg: &'a Config, default: &'a str) -> &'a str {
    if cfg.model.trim().is_empty() {
        default
    } else {
        cfg.model.trim()
    }
}

/// Runs the `claude` CLI headless, feeding the prompt on stdin. When `mcp` is non-empty the model
/// is given those MCP servers as tool sources (via a temporary `--mcp-config` file) and allowed
/// several turns so it can call a tool and then answer; with no MCP servers a single turn is used.
pub fn ask_claude(
    model: Option<&str>,
    system: &str,
    user: &str,
    mcp: &[McpServer],
) -> Result<String, String> {
    let bin = claude_binary().ok_or("the `claude` CLI was not found on PATH")?;
    let mut cmd = Command::new(bin);
    cmd.arg("-p").arg("--output-format").arg("text");
    // MCP servers need a multi-turn loop (call a tool, then answer); otherwise one turn suffices.
    let mcp_config = if mcp.is_empty() {
        cmd.arg("--max-turns").arg("1");
        None
    } else {
        let path = write_private_temp(&mcp_config_json(mcp))
            .map_err(|e| format!("could not write the MCP config: {e}"))?;
        let allowed = mcp
            .iter()
            .map(|s| format!("mcp__{}", s.name))
            .collect::<Vec<_>>()
            .join(",");
        cmd.arg("--max-turns")
            .arg("12")
            .arg("--mcp-config")
            .arg(&path);
        cmd.arg("--allowedTools").arg(allowed);
        Some(path)
    };
    cmd.arg("--append-system-prompt").arg(system);
    if let Some(m) = model {
        cmd.arg("--model").arg(m);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let result = run_claude(&mut cmd, user);
    if let Some(path) = mcp_config {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Writes `contents` (which may carry secrets, e.g. MCP server env vars) to a fresh temp file only
/// the current user can read, and returns its path. The name is unique per process, time and call,
/// and the file is created exclusively, so concurrent queries never share or clobber one. The
/// caller deletes it after use.
fn write_private_temp(contents: &str) -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "orress-mcp-{}-{nanos}-{n}.json",
        std::process::id()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    // On Windows the per-user temp directory is already private to the user.
    let mut file = opts.open(&path)?;
    if let Err(e) = file.write_all(contents.as_bytes()) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Spawns `cmd`, writes `user` to its stdin, and returns its trimmed stdout (or an error).
fn run_claude(cmd: &mut Command, user: &str) -> Result<String, String> {
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not start claude: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(user.as_bytes())
        .map_err(|e| format!("could not send the prompt: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("claude did not finish: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "claude failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(600))
        .build()
}

/// Returns the parsed JSON body of a response, or a readable error.
fn send(resp: Result<ureq::Response, ureq::Error>) -> Result<Value, String> {
    match resp {
        Ok(r) => r.into_json().map_err(|e| format!("bad JSON response: {e}")),
        Err(ureq::Error::Status(code, r)) => {
            let body: String = r
                .into_string()
                .unwrap_or_default()
                .chars()
                .take(400)
                .collect();
            Err(format!("HTTP {code}: {body}"))
        }
        Err(e) => Err(format!("request failed: {e}")),
    }
}

/// The Anthropic Messages API, with an MCP tool-use loop: discovered tools are offered to the
/// model, and when it emits `tool_use` blocks ORRESS runs them against the MCP servers and feeds
/// the `tool_result`s back, until the model answers (bounded by [`mcp::MAX_TOOL_ITERATIONS`]).
fn anthropic(
    base: &str,
    key: &str,
    model: &str,
    system: &str,
    user: &str,
    mcp: &[McpServer],
) -> Result<String, String> {
    let url = format!("{base}/v1/messages");
    let mut session = mcp::McpSession::connect(mcp);
    let tools: Vec<Value> = session.tools().iter().map(mcp::to_anthropic_tool).collect();
    let mut messages = vec![json!({ "role": "user", "content": user })];

    for _ in 0..mcp::MAX_TOOL_ITERATIONS {
        let mut body = json!({ "model": model, "max_tokens": MAX_TOKENS, "system": system, "messages": messages });
        if !tools.is_empty() {
            body["tools"] = Value::Array(tools.clone());
        }
        let resp = agent()
            .post(&url)
            .set("x-api-key", key)
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_json(body);
        let v = send(resp)?;

        let content = v["content"].as_array().cloned().unwrap_or_default();
        let tool_uses: Vec<&Value> = content.iter().filter(|b| b["type"] == "tool_use").collect();
        if tool_uses.is_empty() || v["stop_reason"] != "tool_use" {
            return parse_anthropic_response(&v);
        }
        // Echo the assistant turn, then answer each tool call with a tool_result.
        messages.push(json!({ "role": "assistant", "content": content }));
        let results: Vec<Value> = tool_uses
            .iter()
            .map(|tu| {
                let (text, is_error) =
                    match session.call(tu["name"].as_str().unwrap_or(""), tu["input"].clone()) {
                        Ok(text) => (text, false),
                        Err(e) => (e, true),
                    };
                json!({ "type": "tool_result", "tool_use_id": tu["id"], "content": text, "is_error": is_error })
            })
            .collect();
        messages.push(json!({ "role": "user", "content": results }));
    }
    Err("the model kept requesting tools without answering".into())
}

/// Any OpenAI Chat-Completions-compatible endpoint, with the same MCP tool-use loop (OpenAI
/// `tools`/`tool_calls` shape).
fn openai(
    base: &str,
    key: Option<String>,
    model: &str,
    system: &str,
    user: &str,
    mcp: &[McpServer],
) -> Result<String, String> {
    let url = format!("{base}/chat/completions");
    let mut session = mcp::McpSession::connect(mcp);
    let tools: Vec<Value> = session.tools().iter().map(mcp::to_openai_tool).collect();
    let mut messages = vec![
        json!({ "role": "system", "content": system }),
        json!({ "role": "user", "content": user }),
    ];

    for _ in 0..mcp::MAX_TOOL_ITERATIONS {
        let mut body = json!({ "model": model, "messages": messages, "stream": false });
        if !tools.is_empty() {
            body["tools"] = Value::Array(tools.clone());
        }
        let mut req = agent().post(&url).set("content-type", "application/json");
        if let Some(k) = &key {
            req = req.set("authorization", &format!("Bearer {k}"));
        }
        let v = send(req.send_json(body))?;

        let message = v["choices"][0]["message"].clone();
        let tool_calls = message["tool_calls"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if tool_calls.is_empty() {
            return parse_openai_response(&v);
        }
        messages.push(message);
        for tc in &tool_calls {
            let name = tc["function"]["name"].as_str().unwrap_or("");
            let args: Value = tc["function"]["arguments"]
                .as_str()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| json!({}));
            let text = session.call(name, args).unwrap_or_else(|e| e);
            messages.push(json!({ "role": "tool", "tool_call_id": tc["id"], "content": text }));
        }
    }
    Err("the model kept requesting tools without answering".into())
}

pub fn build_openai_body(model: &str, system: &str, user: &str) -> Value {
    json!({
        "model": model,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user }
        ],
        "stream": false
    })
}

pub fn build_anthropic_body(model: &str, system: &str, user: &str) -> Value {
    json!({
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": system,
        "messages": [ { "role": "user", "content": user } ]
    })
}

pub fn parse_openai_response(v: &Value) -> Result<String, String> {
    v["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.trim().to_string())
        .ok_or_else(|| format!("unexpected OpenAI response: {v}"))
}

pub fn parse_anthropic_response(v: &Value) -> Result<String, String> {
    if let Some(arr) = v["content"].as_array() {
        let text: String = arr
            .iter()
            .filter(|p| p["type"] == "text")
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("");
        if !text.is_empty() {
            return Ok(text.trim().to_string());
        }
    }
    Err(format!("unexpected Anthropic response: {v}"))
}

/// Builds the user prompt from a question and an analysis-context block.
pub fn build_prompt(question: &str, context: &str) -> String {
    format!("# Analysis context (from ORRESS)\n{context}\n\n# Question\n{question}\n")
}

/// The form of the config actually written to disk: the API key is cleared unless `remember_key`.
fn persisted(cfg: &Config) -> Config {
    let mut c = cfg.clone();
    if !c.remember_key {
        c.api_key.clear();
    }
    c
}

/// The persisted JSON for `cfg` — used both to save and to detect changes worth saving.
pub fn config_json(cfg: &Config) -> String {
    serde_json::to_string_pretty(&persisted(cfg)).unwrap_or_default()
}

/// Loads a persisted config. A missing or broken file gives the default.
pub fn load_config(path: &std::path::Path) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persists the config (the API key only when `remember_key` is set).
pub fn save_config(path: &std::path::Path, cfg: &Config) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, config_json(cfg))
}

#[cfg(test)]
mod tests;
