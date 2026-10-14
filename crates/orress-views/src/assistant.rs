//! The AI assistant panel — bring your own model. It answers questions about the open binary
//! through one of four backends: the **Claude plan** (via the `claude` CLI, no API key), the
//! **Claude API** (key), any **OpenAI-compatible** endpoint (OpenAI, Azure, or a local server like
//! Ollama/LM Studio), or **Offline** (static analysis only, nothing leaves the machine).
//!
//! The non-secret config (provider, model, base URL) is persisted to `ai.json` in the config dir;
//! the API key is session-only or taken from an environment variable. Sending context to a model
//! is opt-in, and the exact context (a summary, never raw bytes) is shown first.
//!
//! Installed Zed extensions extend the assistant: their **slash commands** (`/<name> …`) run
//! locally through the extension host and their output becomes the answer, and their **context
//! (MCP) servers** can be offered to any model backend as tool sources — the Claude CLI via its own
//! MCP config, the HTTP backends (Claude API, OpenAI-compatible) via ORRESS's built-in MCP client.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use egui::{RichText, Ui};
use orress_ai::{Config, Provider, SYSTEM_PROMPT};
use orress_project::DocStore;
use orress_triage::hints::Challenge;
use orress_ui::muted;

/// Cap on how much analysis context is assembled for a prompt.
const MAX_CONTEXT: usize = 8_000;

/// Persistent UI state for the AI assistant tab.
pub struct AssistantView {
    cfg: Config,
    loaded: bool,
    /// The last persisted JSON, to detect edits worth saving.
    saved_json: String,
    consent: bool,
    question: String,
    result: Arc<Mutex<Option<Result<String, String>>>>,
    running: Arc<AtomicBool>,
    claude_ok: Option<bool>,
    /// Slash commands and context (MCP) servers discovered from installed Zed extensions.
    slash: Vec<orress_ext::ZedSlashCommand>,
    servers: Vec<orress_ext::ZedContextServer>,
    discovered: bool,
    /// Let Claude use the discovered MCP servers as tools (Claude-CLI backend only).
    use_mcp: bool,
    /// Error from the last attempt to save `ai.json`.
    save_error: Option<String>,
    /// Context built for the current file: ((path, SHA-256), context, classification).
    /// Triage and hints are too slow to redo every frame.
    context: Option<((PathBuf, String), String, Challenge)>,
    /// SHA-256 of the file the consent and answer belong to.
    file_sha: String,
    /// Bumped when the file changes, so an answer still in flight for the old file is dropped.
    epoch: Arc<AtomicU64>,
}

impl Default for AssistantView {
    fn default() -> Self {
        Self {
            cfg: Config::default(),
            loaded: false,
            saved_json: String::new(),
            consent: false,
            question: String::new(),
            result: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            claude_ok: None,
            slash: Vec::new(),
            servers: Vec::new(),
            discovered: false,
            use_mcp: false,
            save_error: None,
            context: None,
            file_sha: String::new(),
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }
}

fn ai_file() -> Option<PathBuf> {
    orress_settings::Paths::from_platform().map(|p| p.config_dir.join("ai.json"))
}

pub fn assistant_view(ui: &mut Ui, view: &mut AssistantView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Assistant", ui.max_rect());
    if !view.loaded {
        if let Some(f) = ai_file() {
            view.cfg = orress_ai::load_config(&f);
        }
        view.saved_json = orress_ai::config_json(&view.cfg);
        view.loaded = true;
    }

    // Discover the slash commands and context (MCP) servers that installed Zed extensions provide,
    // once the app has told us where the extensions live.
    if !view.discovered
        && let Some(dir) = crate::extensions::extensions_dir(ui.ctx())
    {
        view.slash = orress_ext::zed_slash_commands(&dir);
        view.servers = orress_ext::zed_context_servers(&dir);
        view.discovered = true;
    }

    ui.horizontal(|ui| {
        ui.label(RichText::new("AI assistant").strong());
        ui.label(muted("bring your own model · explain · graded help"));
    });
    ui.separator();

    let claude_ok = *view
        .claude_ok
        .get_or_insert_with(orress_ai::claude_available);
    backend_config(ui, view, claude_ok);

    // Persist the config when it changes (the key only if "Remember key" is on).
    let now = orress_ai::config_json(&view.cfg);
    if now != view.saved_json {
        if let Some(f) = ai_file() {
            view.save_error = orress_ai::save_config(&f, &view.cfg)
                .err()
                .map(|e| format!("could not save {}: {e}", f.display()));
        }
        view.saved_json = now;
    }
    if let Some(e) = &view.save_error {
        ui.colored_label(ui.visuals().error_fg_color, e);
    }

    ui.add_space(4.0);
    let Some(doc) = docs.active() else {
        ui.label(muted("Open a binary, then ask the assistant about it."));
        return;
    };
    let Some(analysis) = doc.analysis() else {
        ui.label(muted(
            "Analysis is still running… the assistant needs it to answer.",
        ));
        return;
    };
    // Consent and the answer belong to one file: switching files starts over.
    if view.file_sha != analysis.info.hashes.sha256 {
        view.file_sha.clone_from(&analysis.info.hashes.sha256);
        view.consent = false;
        view.epoch.fetch_add(1, Ordering::SeqCst);
        *lock(&view.result) = None;
    }
    let key = (doc.path.clone(), analysis.info.hashes.sha256.clone());
    if view.context.as_ref().is_none_or(|(k, ..)| *k != key) {
        view.context = build_context(doc).map(|(c, ch)| (key, c, ch));
    }
    let Some((_, context, challenge)) = view.context.clone() else {
        ui.label(muted(
            "Analysis is still running… the assistant needs it to answer.",
        ));
        return;
    };
    // The worktree an extension slash command / context server runs against.
    let worktree = orress_ext::project_root(&doc.path);

    let offline = view.cfg.provider == Provider::Offline;
    if !offline {
        ui.checkbox(
            &mut view.consent,
            "Send the analysis summary below to the model",
        )
        .on_hover_text("Only the summary shown here is sent — never the raw file bytes.");
    }
    egui::CollapsingHeader::new("Context that will be used")
        .id_salt("ai-context")
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(160.0)
                .id_salt("ai-ctx-scroll")
                .show(ui, |ui| {
                    ui.label(RichText::new(&context).monospace().weak());
                });
        });
    ui.add_space(4.0);

    // Slash commands provided by installed extensions: click to insert `/<name> `, then Ask runs it.
    if !view.slash.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(muted("Slash commands:"));
            let cmds: Vec<(String, String)> = view
                .slash
                .iter()
                .map(|c| (c.command.name.clone(), c.command.description.clone()))
                .collect();
            for (name, desc) in cmds {
                let resp = ui.small_button(format!("/{name}"));
                let resp = if desc.is_empty() {
                    resp
                } else {
                    resp.on_hover_text(desc)
                };
                if resp.clicked() {
                    view.question = format!("/{name} ");
                }
            }
        });
    }
    // Context (MCP) servers provided by installed extensions. Every model backend can use them —
    // the Claude CLI via its own MCP config, the HTTP backends via ORRESS's built-in MCP client.
    if !view.servers.is_empty() {
        let ids: Vec<String> = view.servers.iter().map(|s| s.server_id.clone()).collect();
        if view.cfg.provider == Provider::Offline {
            ui.label(muted(format!(
                "{} MCP server(s) available — switch to a model backend to use them.",
                ids.len()
            )));
        } else {
            ui.checkbox(
                &mut view.use_mcp,
                format!("Let the model use {} MCP server(s)", ids.len()),
            )
            .on_hover_text(format!("Context servers: {}", ids.join(", ")));
        }
    }

    let running = view.running.load(Ordering::SeqCst);
    let usable = offline || (view.cfg.provider != Provider::ClaudeCli) || claude_ok;
    let can_send = !running && usable && (offline || view.consent);

    ui.horizontal_wrapped(|ui| {
        for (label, q) in [
            (
                "Explain this file",
                "Explain what this program does and how its check works.",
            ),
            (
                "Suggest next steps",
                "What should I do next in ORRESS to solve this?",
            ),
            (
                "Where's the flag/key?",
                "Where is the flag or key, and how is the input validated?",
            ),
        ] {
            if ui.add_enabled(can_send, egui::Button::new(label)).clicked() {
                view.question = q.to_string();
                submit(
                    view,
                    ui.ctx().clone(),
                    &context,
                    &challenge,
                    worktree.clone(),
                );
            }
        }
    });
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut view.question)
                .hint_text("Ask about this binary…  (or /command for an extension)")
                .desired_width(ui.available_width() - 60.0),
        );
        // A slash command runs a local extension (no model, no consent needed); a plain question
        // needs a usable backend and consent.
        let is_slash = parse_slash(view.question.trim()).is_some();
        let ok = !running && !view.question.trim().is_empty() && (is_slash || can_send);
        if ui.add_enabled(ok, egui::Button::new("Ask")).clicked() {
            submit(
                view,
                ui.ctx().clone(),
                &context,
                &challenge,
                worktree.clone(),
            );
        }
    });
    if !offline && !view.consent {
        ui.label(muted("Tick the consent box to send context to the model."));
    }

    ui.add_space(6.0);
    ui.separator();
    if running {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted("asking…"));
        });
        return;
    }
    if let Some(result) = lock(&view.result).as_ref() {
        match result {
            Ok(text) => {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .id_salt("ai-answer")
                    .show(ui, |ui| {
                        let mut buf = text.as_str();
                        ui.add(
                            egui::TextEdit::multiline(&mut buf)
                                .desired_width(f32::INFINITY)
                                .desired_rows(16),
                        );
                    });
            }
            Err(e) => {
                ui.colored_label(ui.visuals().error_fg_color, format!("AI error: {e}"));
            }
        }
    }
}

/// The backend picker and provider-specific configuration.
fn backend_config(ui: &mut Ui, view: &mut AssistantView, claude_ok: bool) {
    ui.horizontal(|ui| {
        ui.label("Backend:");
        egui::ComboBox::from_id_salt("ai-provider")
            .selected_text(view.cfg.provider.label())
            .show_ui(ui, |ui| {
                for p in [
                    Provider::ClaudeCli,
                    Provider::ClaudeApi,
                    Provider::OpenAi,
                    Provider::Offline,
                ] {
                    ui.selectable_value(&mut view.cfg.provider, p, p.label());
                }
            });
    });

    match view.cfg.provider {
        Provider::ClaudeCli => {
            if !claude_ok {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    "The `claude` CLI was not found — install Claude Code and sign in to use your Claude plan.",
                );
            } else {
                ui.label(muted(
                    "Runs `claude -p` on your signed-in Claude plan (Pro/Max or API) — no API key.",
                ));
            }
            model_field(ui, &mut view.cfg.model, "default (your Claude Code model)");
        }
        Provider::ClaudeApi => {
            model_field(ui, &mut view.cfg.model, "claude-opus-4-20250514");
            base_field(ui, &mut view.cfg.base_url, "https://api.anthropic.com");
            key_field(
                ui,
                &mut view.cfg.api_key,
                &mut view.cfg.remember_key,
                "ANTHROPIC_API_KEY",
            );
        }
        Provider::OpenAi => {
            ui.label(muted("OpenAI, Azure, or a local server (Ollama: http://localhost:11434/v1, LM Studio, …)."));
            model_field(ui, &mut view.cfg.model, "gpt-4o-mini (or e.g. llama3.1)");
            base_field(ui, &mut view.cfg.base_url, "https://api.openai.com/v1");
            key_field(
                ui,
                &mut view.cfg.api_key,
                &mut view.cfg.remember_key,
                "OPENAI_API_KEY",
            );
        }
        Provider::Offline => {
            ui.label(muted(
                "Answers from ORRESS's static analysis only — nothing leaves the machine.",
            ));
        }
    }
}

fn model_field(ui: &mut Ui, model: &mut String, hint: &str) {
    ui.horizontal(|ui| {
        ui.label(muted("Model:"));
        ui.add(
            egui::TextEdit::singleline(model)
                .hint_text(hint)
                .desired_width(240.0),
        );
    });
}

fn base_field(ui: &mut Ui, base: &mut String, hint: &str) {
    ui.horizontal(|ui| {
        ui.label(muted("Base URL:"));
        ui.add(
            egui::TextEdit::singleline(base)
                .hint_text(hint)
                .desired_width(240.0),
        );
    });
}

fn key_field(ui: &mut Ui, key: &mut String, remember: &mut bool, env: &str) {
    ui.horizontal(|ui| {
        ui.label(muted("API key:"));
        ui.add(
            egui::TextEdit::singleline(key)
                .password(true)
                .hint_text(format!("or ${env}"))
                .desired_width(240.0),
        );
    });
    ui.checkbox(remember, "Remember key").on_hover_text(
        "Saves the key to ai.json in plaintext, so you don't re-enter it each session.",
    );
    if *remember {
        ui.label(muted("Saved in ai.json (plaintext) in the config folder."));
    } else {
        ui.label(muted(format!("Not saved — session only, or set ${env}.")));
    }
}

/// Parses a leading slash command: `/name arg1 arg2` → `("name", ["arg1", "arg2"])`. Returns
/// `None` for input that is not a slash command (empty, or not starting with `/name`).
fn parse_slash(input: &str) -> Option<(String, Vec<String>)> {
    let rest = input.trim().strip_prefix('/')?;
    let mut parts = rest.split_whitespace();
    let name = parts.next()?.to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, parts.map(str::to_string).collect()))
}

/// Dispatches the input: a `/command` runs an extension slash command; anything else is a model
/// question.
fn submit(
    view: &mut AssistantView,
    ctx: egui::Context,
    context: &str,
    challenge: &Challenge,
    worktree: PathBuf,
) {
    if let Some((name, args)) = parse_slash(view.question.trim()) {
        run_slash_command(view, ctx, &name, args, worktree);
    } else {
        ask(view, ctx, context, challenge, worktree);
    }
}

/// Runs an extension's slash command on a background thread; its output becomes the answer.
fn run_slash_command(
    view: &mut AssistantView,
    ctx: egui::Context,
    name: &str,
    args: Vec<String>,
    worktree: PathBuf,
) {
    let Some(sc) = view.slash.iter().find(|c| c.command.name == name).cloned() else {
        let available: Vec<String> = view
            .slash
            .iter()
            .map(|c| format!("/{}", c.command.name))
            .collect();
        *lock(&view.result) = Some(Err(format!(
            "unknown slash command /{name}. Available: {}",
            if available.is_empty() {
                "(none installed)".to_string()
            } else {
                available.join(", ")
            }
        )));
        return;
    };
    let result = Arc::clone(&view.result);
    let running = Arc::clone(&view.running);
    *lock(&result) = None;
    running.store(true, Ordering::SeqCst);
    let epoch = Arc::clone(&view.epoch);
    let started = epoch.load(Ordering::SeqCst);
    std::thread::spawn(move || {
        let r = orress_ext::run_zed_slash_command(
            &sc.wasm,
            &sc.command,
            &args,
            Some(worktree.as_path()),
            serde_json::json!({}),
        )
        .map(|o| o.text);
        if epoch.load(Ordering::SeqCst) == started {
            *lock(&result) = Some(r);
        }
        running.store(false, Ordering::SeqCst);
        ctx.request_repaint();
    });
}

/// Resolves each discovered context server's launch command (running its WASM) into an
/// [`orress_ai::McpServer`]. Servers that fail to resolve are skipped.
fn resolve_mcp(
    servers: &[orress_ext::ZedContextServer],
    worktree: &std::path::Path,
) -> Vec<orress_ai::McpServer> {
    let roots = [worktree.to_path_buf()];
    servers
        .iter()
        .filter_map(|s| {
            let cmd = orress_ext::resolve_context_server_command(
                &s.wasm,
                &s.server_id,
                &roots,
                serde_json::json!({}),
            )
            .ok()?;
            Some(orress_ai::McpServer {
                name: s.server_id.clone(),
                command: cmd.command,
                args: cmd.args,
                env: cmd.env,
            })
        })
        .collect()
}

/// Starts a model query: Offline answers locally; the others run on a background thread. When MCP
/// is enabled (Claude-CLI backend), the discovered context servers are resolved and passed through.
fn ask(
    view: &mut AssistantView,
    ctx: egui::Context,
    context: &str,
    challenge: &Challenge,
    worktree: PathBuf,
) {
    if view.cfg.provider == Provider::Offline {
        *lock(&view.result) = Some(Ok(offline_answer(challenge)));
        return;
    }
    let prompt = orress_ai::build_prompt(view.question.trim(), context);
    let cfg = view.cfg.clone();
    let result = Arc::clone(&view.result);
    let running = Arc::clone(&view.running);
    let mcp_servers = if view.use_mcp && cfg.provider != Provider::Offline {
        view.servers.clone()
    } else {
        Vec::new()
    };
    *lock(&result) = None;
    running.store(true, Ordering::SeqCst);
    let epoch = Arc::clone(&view.epoch);
    let started = epoch.load(Ordering::SeqCst);
    std::thread::spawn(move || {
        let mcp = resolve_mcp(&mcp_servers, &worktree);
        let r = orress_ai::ask(&cfg, SYSTEM_PROMPT, &prompt, &mcp);
        if epoch.load(Ordering::SeqCst) == started {
            *lock(&result) = Some(r);
        }
        running.store(false, Ordering::SeqCst);
        ctx.request_repaint();
    });
}

/// The offline answer: the challenge classification plus every graded hint, from static analysis.
fn offline_answer(c: &Challenge) -> String {
    let mut out = format!("{}\n\nGraded hints:\n", c.summary);
    for h in &c.hints {
        let _ = writeln!(out, "  [{}] {}", h.level.label(), h.text);
    }
    if !c.techniques.is_empty() {
        let _ = writeln!(out, "\nSuggested techniques: {}", c.techniques.join(", "));
    }
    out.push_str(
        "\n(Offline mode — from ORRESS's static analysis only; nothing was sent anywhere.)",
    );
    out
}

/// Locks the shared answer, recovering it if a worker panicked while holding the lock.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Builds the compact analysis context (never the raw bytes) and the challenge classification.
fn build_context(doc: &orress_project::Document) -> Option<(String, Challenge)> {
    let analysis = doc.analysis()?;
    let bytes = doc.bytes()?;
    let strings: Vec<&str> = analysis.strings.iter().map(|s| s.text.as_str()).collect();
    let report = orress_triage::build(&analysis.info, &strings, bytes);
    let challenge = orress_triage::hints::analyze(&report, &analysis.info, &strings);

    let mut c = String::new();
    let _ = writeln!(c, "file: {}", doc.file_name());
    let _ = writeln!(
        c,
        "format: {} ({})",
        analysis.info.format.name(),
        analysis.info.arch
    );
    let _ = writeln!(
        c,
        "size: {} bytes · entropy {:.2}/8",
        analysis.info.size, analysis.info.entropy
    );
    let _ = writeln!(c, "classification: {}", challenge.summary);
    if !report.flags.is_empty() {
        let _ = writeln!(c, "risk flags: {}", report.flags.join("; "));
    }
    if !report.capabilities.is_empty() {
        let caps: Vec<String> = report
            .capabilities
            .iter()
            .map(|x| x.name.to_string())
            .collect();
        let _ = writeln!(c, "capabilities: {}", caps.join(", "));
    }
    for b in &report.behaviors {
        let _ = writeln!(c, "imports[{}]: {}", b.category.name(), b.apis.join(", "));
    }
    if !report.iocs.is_empty() {
        let iocs: Vec<&str> = report
            .iocs
            .iter()
            .take(15)
            .map(|i| i.value.as_str())
            .collect();
        let _ = writeln!(c, "indicators: {}", iocs.join(", "));
    }
    let top: Vec<&str> = strings
        .iter()
        .filter(|s| s.len() >= 5)
        .take(40)
        .copied()
        .collect();
    if !top.is_empty() {
        let _ = writeln!(c, "strings (sample):\n{}", top.join("\n"));
    }
    if c.len() > MAX_CONTEXT {
        c.truncate(crate::code::floor_char_boundary(&c, MAX_CONTEXT));
        c.push_str("\n… (truncated)");
    }
    Some((c, challenge))
}

#[cfg(test)]
mod tests {
    use super::parse_slash;

    #[test]
    fn parses_slash_commands() {
        assert_eq!(parse_slash("/greet"), Some(("greet".to_string(), vec![])));
        assert_eq!(
            parse_slash("  /file  src/main.rs  --line 3 "),
            Some((
                "file".to_string(),
                vec!["src/main.rs".into(), "--line".into(), "3".into()]
            ))
        );
        // Not slash commands.
        assert_eq!(parse_slash("explain this"), None);
        assert_eq!(parse_slash(""), None);
        assert_eq!(parse_slash("/"), None);
        assert_eq!(parse_slash("/   "), None);
    }
}
