//! The code editor view and the run console that streams task output.
//!
//! The editor is built on egui's `TextEdit` (so editing, selection and undo come for free)
//! with a tree-sitter highlighting layouter (`orress-editor`) and a language-server client
//! (`orress-lsp`) for diagnostics and hover. Files live in a `String` — fine for solver
//! scripts and crackmes; a `ropey` rope behind a custom widget is the eventual upgrade.
//! `RunConsole` runs build/run tasks in a background thread and streams output to the panel.

use std::collections::{BTreeSet, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egui::text::{CCursor, LayoutJob};
use egui::{Align, Color32, FontId, Key, RichText, Stroke, TextFormat, Ui};
use orress_editor::{Buffer, Language, Tok, tasks_for};
use orress_lsp::{CompletionItem, DiagnosticSeverity, LspManager, ServerSpec, Status};
use orress_project::Document;
use orress_ui::muted;

use crate::code;
use crate::code_editor::{MultiCursor, code_editor};

/// A request to open another file at a line (from go-to-definition across files).
#[derive(Clone, Debug)]
pub struct GotoFile {
    pub path: PathBuf,
    pub line: u32,
}

/// A save requested from outside the editor (the File menu), applied to the focused editor tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveRequest {
    /// Save to the current file, prompting for a path only when the buffer is untitled.
    Save,
    /// Always prompt for a new path (Save As), adopting it.
    SaveAs,
}

/// An open completion popup.
struct Completion {
    /// All items the server returned.
    items: Vec<CompletionItem>,
    /// Items matching the current prefix (recomputed each frame), with their index in `items`.
    filtered: Vec<usize>,
    selected: usize,
    /// Byte offset where the word being completed starts.
    anchor: usize,
    /// Byte offset of the caret (end of the word), updated each frame.
    caret: usize,
}

/// A diagnostic reduced to a byte range in the current text plus whether it is an error.
#[derive(Clone, Copy)]
struct DiagSpan {
    start: usize,
    end: usize,
    error: bool,
}

/// A resolved language server: its launch spec, workspace root (None = standalone) and the
/// directory to run it in.
type ResolvedServer = (ServerSpec, Option<PathBuf>, PathBuf);

/// Which language server (if any) handles a file, its workspace root (None = standalone) and the
/// directory to run it in. Resolved from the LSP manager's adapter manifests (built-in plus any
/// imported); on a miss, from a **Zed extension** that serves the language — its WASM resolves the
/// launch command on a worker thread (once, then cached as an adapter). While that runs, or if it
/// failed, the second value says so for the status bar.
fn server_spec(
    lsp: &mut LspManager,
    ctx: &egui::Context,
    path: &Path,
    lang: Language,
) -> (Option<ResolvedServer>, Option<ZedLs>) {
    if let Some(spec) = lsp.resolve(lang.name(), path) {
        return (Some(spec), None);
    }
    let zed = resolve_zed_language_server(lsp, ctx, path, lang);
    (lsp.resolve(lang.name(), path), zed)
}

fn lsp_settings_id() -> egui::Id {
    egui::Id::new("orress::zed_lsp_settings")
}

/// The app stores the editor's LSP settings, in Zed's `{ "lsp": { … } }` shape, here so a Zed
/// language extension can be handed them (via `get-settings`) when it resolves a server command.
/// See [`orress_settings::Settings::zed_extension_settings`].
pub fn set_lsp_settings(ctx: &egui::Context, settings: serde_json::Value) {
    ctx.data_mut(|d| d.insert_temp(lsp_settings_id(), settings));
}

pub(crate) fn lsp_settings(ctx: &egui::Context) -> serde_json::Value {
    ctx.data(|d| d.get_temp::<serde_json::Value>(lsp_settings_id()))
        .unwrap_or_else(|| serde_json::json!({}))
}

fn grammar_queries_id() -> egui::Id {
    egui::Id::new("orress::grammar_queries")
}

/// Imported highlight queries by language — only those over a grammar ORRESS bundles.
type GrammarQueries = Arc<std::collections::HashMap<Language, Arc<str>>>;

/// The app hands the editor the grammar highlight queries installed extensions ship
/// (`languages/<lang>/highlights.scm`). Those for a language with a bundled tree-sitter grammar
/// (Rust, Python, C, C++) replace its built-in query; others are ignored until extension grammars
/// (WASM parsers) can be loaded. A later query for the same language wins.
pub fn set_grammar_queries(ctx: &egui::Context, queries: &[orress_ext::GrammarQuery]) {
    let map: std::collections::HashMap<Language, Arc<str>> = queries
        .iter()
        .filter_map(|q| {
            let lang = Language::from_name(&q.language)?;
            orress_editor::has_grammar(lang).then(|| (lang, Arc::from(q.highlights.as_str())))
        })
        .collect();
    ctx.data_mut(|d| d.insert_temp::<GrammarQueries>(grammar_queries_id(), Arc::new(map)));
}

/// The imported highlight query for `lang`, if an extension provides one.
fn grammar_query(ctx: &egui::Context, lang: Language) -> Option<Arc<str>> {
    ctx.data(|d| d.get_temp::<GrammarQueries>(grammar_queries_id()))
        .and_then(|m| m.get(&lang).cloned())
}

/// Where a Zed extension's language-server resolution for one language stands (for the status
/// bar).
#[derive(Clone, Debug, PartialEq, Eq)]
enum ZedLs {
    /// The extension's WASM is still running on a worker thread.
    Resolving,
    /// It failed; the error.
    Failed(String),
}

/// The worker's result slot for a Zed language-server resolution.
type ZedLsSlot = Arc<Mutex<Option<Result<orress_ext::ResolvedLanguageServer, String>>>>;

/// The per-(extension, language) resolution state kept in egui's temp data.
#[derive(Clone)]
enum ZedLsJob {
    Running(ZedLsSlot),
    /// Finished: `None` when the adapter was registered, else the error. Not retried this session.
    Done(Option<String>),
}

/// On an LSP miss, tries a Zed extension that serves `lang`. Its WASM (which may download a server
/// and is only bounded by the 30 s watchdog) runs once per (extension, language) on a worker thread
/// — never on the UI thread — to resolve the server command, initialization options and workspace
/// configuration; when it finishes the result is registered as an adapter for the normal path to
/// pick up. Returns the resolution's state while it is pending or after it failed.
fn resolve_zed_language_server(
    lsp: &mut LspManager,
    ctx: &egui::Context,
    path: &Path,
    lang: Language,
) -> Option<ZedLs> {
    let dir = crate::extensions::extensions_dir(ctx)?;
    let server = orress_ext::zed_language_servers(&dir)
        .into_iter()
        .find(|s| s.language.eq_ignore_ascii_case(lang.name()))?;
    let id = egui::Id::new(("orress::zed_ls", server.wasm.clone(), lang.name()));
    match ctx.data(|d| d.get_temp::<ZedLsJob>(id)) {
        None => {
            // The worktree the extension sees is the file's project root, not just its directory.
            let root = orress_ext::project_root(path);
            let settings = lsp_settings(ctx);
            let slot: ZedLsSlot = Arc::new(Mutex::new(None));
            let (out, repaint) = (Arc::clone(&slot), ctx.clone());
            let (wasm, server_id) = (server.wasm.clone(), server.server_id.clone());
            let spawned = std::thread::Builder::new()
                .name("orress-zed-ls".into())
                .spawn(move || {
                    let result =
                        orress_ext::resolve_language_server(&wasm, &server_id, &root, settings);
                    if let Ok(mut s) = out.lock() {
                        *s = Some(result);
                    }
                    repaint.request_repaint();
                });
            let job = match spawned {
                Ok(_) => ZedLsJob::Running(slot),
                Err(e) => ZedLsJob::Done(Some(format!("could not start the resolver: {e}"))),
            };
            let state = match &job {
                ZedLsJob::Running(_) => ZedLs::Resolving,
                ZedLsJob::Done(e) => ZedLs::Failed(e.clone().unwrap_or_default()),
            };
            ctx.data_mut(|d| d.insert_temp(id, job));
            Some(state)
        }
        Some(ZedLsJob::Running(slot)) => {
            let result = match slot.lock() {
                Ok(mut s) => s.take(),
                Err(_) => Some(Err("the resolver panicked".to_string())),
            };
            match result {
                None => Some(ZedLs::Resolving),
                Some(Ok(resolved)) => {
                    lsp.add_adapters(vec![resolved.into_adapter(lang.name(), &server.server_id)]);
                    ctx.data_mut(|d| d.insert_temp(id, ZedLsJob::Done(None)));
                    None
                }
                Some(Err(e)) => {
                    let e = format!("extension `{}`: {e}", server.server_id);
                    ctx.data_mut(|d| d.insert_temp(id, ZedLsJob::Done(Some(e.clone()))));
                    Some(ZedLs::Failed(e))
                }
            }
        }
        Some(ZedLsJob::Done(err)) => err.map(ZedLs::Failed),
    }
}

/// Per-tab editor state; created lazily from the tab's optional path.
#[derive(Default)]
pub struct EditorState {
    buffer: Option<Buffer>,
    /// Status message (save/load errors or confirmations).
    message: Option<String>,
    /// Cached highlight tokens, keyed by a hash of the text, so tree-sitter only re-parses
    /// when the text changes rather than every frame.
    hl_cache: Option<(u64, std::sync::Arc<Vec<orress_editor::Token>>)>,
    /// A pending hover request and the byte offset it was made for.
    hover: Option<(usize, orress_lsp::Pending)>,
    /// The last hover text to show, and the byte offset it is for.
    hover_shown: Option<(usize, String)>,
    /// A pending go-to-definition request.
    pending_def: Option<orress_lsp::Pending>,
    /// A pending completion request and the anchor byte it was made for.
    pending_completion: Option<(usize, orress_lsp::Pending)>,
    /// The open completion popup, if any.
    completion: Option<Completion>,
    /// A caret char index to apply on the next frame (after accepting a completion).
    set_caret: Option<usize>,
    /// Multi-cursor editing state (carets, selections, undo/redo).
    mc: MultiCursor,
    /// Assembler (for `.asm` buffers): the last listing, the problems found, and the text hash
    /// they were produced for (so they clear once the buffer is edited).
    asm_listing: Option<String>,
    asm_diags: Vec<orress_asm::Diagnostic>,
    asm_for_hash: Option<u64>,
}

fn text_hash(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// The highlight tokens for `text`, re-highlighting only when the text (or the imported highlight
/// `query` in use) changed. With a `query` (a Zed grammar extension's `highlights.scm`) the bundled
/// grammar is highlighted with it — the compiled query is cached in `orress-editor` — falling back
/// to the built-in query if it does not compile.
fn cached_tokens(
    cache: &mut Option<(u64, std::sync::Arc<Vec<orress_editor::Token>>)>,
    text: &str,
    lang: Language,
    query: Option<&str>,
) -> std::sync::Arc<Vec<orress_editor::Token>> {
    let hash = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut h);
        query.hash(&mut h);
        h.finish()
    };
    if let Some((h, toks)) = cache
        && *h == hash
    {
        return std::sync::Arc::clone(toks);
    }
    let toks = std::sync::Arc::new(match query {
        Some(q) => orress_editor::highlight_with_query(text, lang, q),
        None => orress_editor::highlight(text, lang),
    });
    *cache = Some((hash, std::sync::Arc::clone(&toks)));
    toks
}

impl EditorState {
    /// A pre-filled, named editor over generated text (e.g. a decompiler port opened for
    /// editing). The buffer has no path yet, so the tab shows `name` and Save prompts for one.
    pub fn scratch(name: &str, text: &str) -> Self {
        Self {
            buffer: Some(Buffer::scratch(name, text)),
            ..Self::default()
        }
    }

    /// Initializes the buffer from the path on first use.
    fn ensure(&mut self, path: &Option<PathBuf>) {
        if self.buffer.is_none() {
            let mut err = None;
            let buffer = match path {
                Some(p) => Buffer::open(p).unwrap_or_else(|e| {
                    err = Some(format!("Could not open {}: {e}", p.display()));
                    Buffer::untitled()
                }),
                None => Buffer::untitled(),
            };
            self.buffer = Some(buffer);
            if err.is_some() {
                self.message = err;
            }
        }
    }

    /// The tab title (file name, `*` when unsaved).
    pub fn title(&self) -> Option<String> {
        self.buffer.as_ref().map(Buffer::title)
    }

    /// Whether the buffer has changes that are not on disk. (A tab that was never shown has no
    /// buffer yet, so nothing to lose.)
    pub fn is_dirty(&self) -> bool {
        self.buffer.as_ref().is_some_and(Buffer::is_dirty)
    }

    /// Saves unsaved changes, asking for a file name when the buffer is untitled. `Ok(true)`
    /// when nothing is left unsaved, `Ok(false)` when the user cancelled the file dialog.
    /// `path` (the tab's) adopts a newly chosen file.
    pub fn save_interactive(&mut self, path: &mut Option<PathBuf>) -> Result<bool, String> {
        let Some(buffer) = self.buffer.as_mut() else {
            return Ok(true);
        };
        if !buffer.is_dirty() {
            return Ok(true);
        }
        match save(buffer, path, false) {
            None => Ok(false),
            Some(msg) if buffer.is_dirty() => Err(msg),
            Some(msg) => {
                self.message = Some(msg);
                Ok(true)
            }
        }
    }
}

fn color(kind: Tok, c: &orress_theme::SyntaxColors, text: Color32) -> Color32 {
    match kind {
        Tok::Keyword => c.keyword.0,
        Tok::Type => c.type_name.0,
        Tok::Function => c.function.0,
        Tok::Macro => c.function.0,
        Tok::Attribute => c.label.0,
        Tok::String => c.string.0,
        Tok::Char => c.string.0,
        Tok::Number => c.immediate.0,
        Tok::Comment => c.comment.0,
        Tok::Lifetime => c.label.0,
        #[allow(unreachable_patterns)]
        _ => text,
    }
}

/// Builds the layout job for `text`, merging token colours with diagnostic underlines.
fn build_job(
    text: &str,
    tokens: &[orress_editor::Token],
    diags: &[DiagSpan],
    font: &FontId,
    colors: &orress_theme::SyntaxColors,
    default: Color32,
) -> LayoutJob {
    let mut job = LayoutJob::default();
    job.wrap.max_width = f32::INFINITY; // code does not wrap; the view scrolls horizontally
    let len = text.len();

    // Boundaries at every token and diagnostic edge, so each emitted run is uniform.
    let mut points: BTreeSet<usize> = BTreeSet::from([0, len]);
    for t in tokens {
        points.insert(t.start.min(len));
        points.insert(t.end.min(len));
    }
    for d in diags {
        points.insert(d.start.min(len));
        points.insert(d.end.min(len));
    }
    let points: Vec<usize> = points
        .into_iter()
        .filter(|p| text.is_char_boundary(*p))
        .collect();

    for w in points.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b {
            continue;
        }
        let col = tokens
            .iter()
            .find(|t| t.start <= a && a < t.end)
            .map_or(default, |t| color(t.kind, colors, default));
        let mut fmt = TextFormat::simple(font.clone(), col);
        if let Some(d) = diags.iter().find(|d| d.start <= a && a < d.end) {
            let c = if d.error {
                Color32::from_rgb(230, 70, 70)
            } else {
                Color32::from_rgb(220, 180, 60)
            };
            fmt.underline = Stroke::new(1.0, c);
        }
        job.append(&text[a..b], 0.0, fmt);
    }
    job
}

/// Draws the editor. `nav` collects cross-file go-to-definition requests for the app.
#[allow(clippy::too_many_arguments)]
pub fn editor_view(
    ui: &mut Ui,
    path: &mut Option<PathBuf>,
    state: &mut EditorState,
    console: &mut RunConsole,
    lsp: &mut LspManager,
    nav: &mut Vec<GotoFile>,
    source_dbg: &mut crate::SourceDebug,
    save_cmd: Option<SaveRequest>,
    active_binary: Option<&mut Document>,
) {
    state.ensure(path);
    let mut hl_cache = std::mem::take(&mut state.hl_cache);
    let mut hover = std::mem::take(&mut state.hover);
    let mut hover_shown = std::mem::take(&mut state.hover_shown);
    let mut pending_def = std::mem::take(&mut state.pending_def);
    let mut pending_completion = std::mem::take(&mut state.pending_completion);
    let mut completion = std::mem::take(&mut state.completion);
    let mut set_caret = std::mem::take(&mut state.set_caret);
    let mut mc = std::mem::take(&mut state.mc);
    let mut asm_listing = std::mem::take(&mut state.asm_listing);
    let mut asm_diags = std::mem::take(&mut state.asm_diags);
    let mut asm_for_hash = state.asm_for_hash;
    let buffer = state.buffer.as_mut().expect("buffer");
    let colors = code::syntax(ui.ctx());
    let font = FontId::monospace(13.0);
    let lang = buffer.language;
    // The buffer is a rope; the editor widget edits it in place. Everything else here (LSP,
    // tree-sitter, egui layout) needs a contiguous `&str`, so materialize one per frame and
    // refresh it after an edit. This per-frame O(n) matches egui's full-text galley layout.
    let mut text = buffer.text.to_string();

    // A cross-file definition landing: the app stored the target line for this file.
    let mut goto_byte: Option<usize> = None;
    if let Some(p) = &buffer.path {
        let key = egui::Id::new(("orress-goto", p));
        if let Some(line) = ui.ctx().data_mut(|d| d.remove_temp::<u32>(key)) {
            goto_byte = Some(byte_of_line(&text, line));
        }
    }

    // Completion popup keyboard handling, before the TextEdit sees the keys.
    if let Some(c) = &mut completion {
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Escape)) {
            completion = None;
        } else if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::ArrowDown)) {
            c.selected = (c.selected + 1).min(c.filtered.len().saturating_sub(1));
        } else if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::ArrowUp)) {
            c.selected = c.selected.saturating_sub(1);
        } else if ui.input_mut(|i| {
            i.consume_key(egui::Modifiers::NONE, Key::Enter)
                || i.consume_key(egui::Modifiers::NONE, Key::Tab)
        }) {
            if let Some(&idx) = c.filtered.get(c.selected) {
                let item = &c.items[idx];
                let insert = item
                    .insert_text
                    .clone()
                    .unwrap_or_else(|| item.label.clone());
                let (a, caret) = (c.anchor.min(text.len()), c.caret.min(text.len()));
                if a <= caret && text.is_char_boundary(a) && text.is_char_boundary(caret) {
                    // Apply the completion to the rope (char indices), then refresh `text`.
                    let ca = buffer.text.byte_to_char(a);
                    let ccaret = buffer.text.byte_to_char(caret);
                    buffer.text.remove(ca..ccaret);
                    buffer.text.insert(ca, &insert);
                    set_caret = Some(ca + insert.chars().count());
                    text = buffer.text.to_string();
                }
            }
            completion = None;
        }
    }

    // Language server: sync the document, collect diagnostics and status.
    let (server, zed_ls) = match buffer.path.as_ref() {
        Some(p) => {
            let (spec, zed) = server_spec(lsp, ui.ctx(), p, lang);
            (spec.map(|(s, cargo, cwd)| (s, cargo, cwd, p.clone())), zed)
        }
        None => (None, None),
    };
    let mut diags: Vec<DiagSpan> = Vec::new();
    let mut lsp_diags = Vec::new();
    // How the server counts columns (UTF-8 or UTF-16), for every position sent or received.
    let enc = server
        .as_ref()
        .map(|(spec, ..)| lsp.encoding(&spec.key))
        .unwrap_or_default();
    if let Some((spec, cargo, cwd, p)) = &server {
        lsp.sync(spec, cargo.as_deref(), cwd, p, &text);
        lsp_diags = lsp.diagnostics(&spec.key, p);
        diags = lsp_diags
            .iter()
            .map(|d| DiagSpan {
                start: orress_lsp::byte_at_enc(&text, d.range.start, enc),
                end: orress_lsp::byte_at_enc(&text, d.range.end, enc),
                error: d.severity != Some(DiagnosticSeverity::WARNING)
                    && d.severity != Some(DiagnosticSeverity::INFORMATION)
                    && d.severity != Some(DiagnosticSeverity::HINT),
            })
            .collect();
    }

    // Toolbar: language, LSP status, run tasks, save.
    let mut do_save = false;
    let mut start_debug = false;
    let mut run_task = None;
    let mut debug_task: Option<orress_editor::Task> = None;
    // Assembler controls are offered for `.asm` buffers. The target architecture follows the
    // active binary (so patches encode correctly); a standalone .asm defaults to x86-64.
    let is_asm = matches!(lang, Language::Asm);
    let bin_arch = active_binary
        .as_deref()
        .and_then(Document::program)
        .and_then(|p| asm_arch_for(p.isa));
    let patch_ok = is_asm && bin_arch.is_some();
    let asm_arch = bin_arch.unwrap_or(orress_asm::Arch::X64);
    let mut do_assemble = false;
    let mut do_patch = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new(buffer.language.name()).weak());
        if let Some((spec, _, _, _)) = &server {
            ui.separator();
            lsp_status_label(ui, lsp, &spec.key, lsp_diags.len());
        } else if let Some(zed) = &zed_ls {
            ui.separator();
            zed_ls_label(ui, zed);
        }
        ui.separator();
        let tasks = path
            .as_ref()
            .map(|p| tasks_for(p, buffer.language))
            .unwrap_or_default();
        ui.add_enabled_ui(!tasks.is_empty() && !console.is_running(), |ui| {
            ui.menu_button("▶ Run", |ui| {
                for t in &tasks {
                    if ui.button(&t.label).clicked() {
                        run_task = Some(t.clone());
                        ui.close();
                    }
                }
            })
            .response
            .on_hover_text("Build and run this file");
        });
        // Debug a task via an extension-provided locator + debug adapter.
        ui.add_enabled_ui(!tasks.is_empty() && !source_dbg.is_active(), |ui| {
            ui.menu_button("🐞 Debug task", |ui| {
                for t in &tasks {
                    if ui.button(&t.label).clicked() {
                        debug_task = Some(t.clone());
                        ui.close();
                    }
                }
            })
            .response
            .on_hover_text("Debug this task via an installed debug-adapter extension (locator)");
        });
        if console.is_running() && ui.button("⏹ Stop").clicked() {
            console.stop();
        }
        // Source debugging (Rust files): compile with -g and run under a DAP adapter.
        if matches!(lang, Language::Rust) && buffer.path.is_some() {
            if source_dbg.is_active() {
                if ui.button("⏹ Debug").clicked() {
                    source_dbg.stop();
                }
            } else if ui
                .button("🐞 Debug")
                .on_hover_text("Compile with debug info and run under the source debugger. Set breakpoints with F9.")
                .clicked()
            {
                start_debug = true;
            }
        }
        if ui.button("Save").on_hover_text("Ctrl+S").clicked() {
            do_save = true;
        }
        if is_asm {
            ui.separator();
            if ui
                .button("⚙ Assemble")
                .on_hover_text(format!(
                    "Assemble this {} source and show the bytes",
                    asm_arch.label()
                ))
                .clicked()
            {
                do_assemble = true;
            }
            ui.add_enabled_ui(patch_ok, |ui| {
                ui.button("⬇ Patch binary")
                    .on_hover_text(
                        "Assemble and write the bytes into the active binary at its cursor. \
                         The file on disk is untouched — save a patched copy to keep it.",
                    )
                    .clicked()
                    .then(|| do_patch = true);
            });
        }
    });
    if let Some(msg) = &state.message {
        ui.colored_label(ui.visuals().weak_text_color(), msg);
    }

    // Assembler (.asm buffers): run on request, surface the listing, and underline problems.
    if is_asm && (do_assemble || do_patch) {
        let base = active_binary
            .as_deref()
            .and_then(Document::cursor_address)
            .unwrap_or(0);
        match orress_asm::assemble(&text, asm_arch, base) {
            Ok(out) => {
                asm_diags.clear();
                asm_listing = Some(format_listing(&out));
                if do_patch {
                    if let Some(doc) = active_binary {
                        let off = doc.cursor;
                        state.message = Some(match doc.patch(off, &out.bytes) {
                            Ok(()) => format!(
                                "Patched {} byte(s) at offset {off:#x}. Save a patched copy to run it.",
                                out.bytes.len()
                            ),
                            Err(e) => format!("Patch failed: {e}"),
                        });
                    }
                } else {
                    state.message = Some(format!(
                        "Assembled {} byte(s) at {base:#x}.",
                        out.bytes.len()
                    ));
                }
            }
            Err(problems) => {
                let n = problems.len();
                asm_diags = problems;
                asm_listing = None;
                let s = if n == 1 { "" } else { "s" };
                state.message = Some(format!(
                    "{n} assembler problem{s} — see the underlined line{s}."
                ));
            }
        }
        asm_for_hash = Some(text_hash(&text));
    }
    // Drop stale assembler results once the buffer has been edited since they were produced.
    if asm_for_hash.is_some_and(|h| h != text_hash(&text)) {
        asm_diags.clear();
        asm_listing = None;
        asm_for_hash = None;
    }
    // Merge assembler problems into the diagnostics the editor underlines (whole offending line).
    for d in &asm_diags {
        if d.line == 0 {
            continue;
        }
        let start = byte_of_line(&text, d.line as u32 - 1);
        let end = text[start..].find('\n').map_or(text.len(), |p| start + p);
        diags.push(DiagSpan {
            start,
            end,
            error: true,
        });
    }
    if let Some(listing) = &asm_listing {
        egui::CollapsingHeader::new("Assembled bytes")
            .default_open(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(listing).monospace())
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                    });
            });
    }
    ui.separator();

    // The editor itself, with syntax highlighting and diagnostic underlines. The highlight
    // job is built once per frame and handed to the multi-cursor editor widget.
    let query = grammar_query(ui.ctx(), lang);
    let tokens = cached_tokens(&mut hl_cache, &text, lang, query.as_deref());
    let job = build_job(
        &text,
        &tokens,
        &diags,
        &font,
        &colors,
        ui.visuals().text_color(),
    );
    let editor_area = ui.available_rect_before_wrap();
    // A line-number gutter beside the editor, scrolling vertically with it.
    let line_count = text.lines().count().max(1) + usize::from(text.ends_with('\n'));
    let gutter_w = (line_count.to_string().len().max(2) + 1) as f32 * char_w(ui, &font);
    let gutter_color = ui.visuals().weak_text_color();
    let out = egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let nums: String = (1..=line_count).map(|n| format!("{n}\n")).collect();
                ui.add_sized(
                    [gutter_w, 0.0],
                    egui::Label::new(RichText::new(nums).font(font.clone()).color(gutter_color))
                        .selectable(false),
                );
                egui::ScrollArea::horizontal()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        code_editor(ui, &mut buffer.text, &mut mc, job, "orress-editor")
                    })
                    .inner
            })
            .inner
        })
        .inner;
    // A Copy/Cut inside the editor leaves its text here; push it to the OS clipboard.
    if let Some(clip) = crate::code_editor::take_clipboard() {
        ui.ctx().copy_text(clip);
    }
    // The widget may have edited the rope; refresh the materialized string for the logic below.
    if out.changed {
        text = buffer.text.to_string();
    }
    let response = &out.response;

    // Ctrl+S saves (when the editor has focus). Matched exactly and consumed, so Ctrl+Shift+S is
    // left for Save As and the key does not also reach the app's shortcuts.
    if response.has_focus()
        && ui.input_mut(|i| consume_exact(i, egui::Modifiers::COMMAND, egui::Key::S))
    {
        do_save = true;
    }
    // A save requested from the File menu (this is the focused editor). "Save As" forces the
    // path dialog even when the buffer already has a file.
    let mut force_dialog = false;
    match save_cmd {
        Some(SaveRequest::Save) => do_save = true,
        Some(SaveRequest::SaveAs) => {
            do_save = true;
            force_dialog = true;
        }
        None => {}
    }

    // Hover: ask the language server about the symbol under the pointer.
    if let Some((spec, _, _, p)) = &server {
        let byte = response.hover_pos().map(|pos| {
            char_byte(
                &text,
                out.galley.cursor_from_pos(pos - out.galley_pos).index.0,
            )
        });
        if let Some(byte) = byte {
            let already = hover.as_ref().map(|(b, _)| *b) == Some(byte)
                || hover_shown.as_ref().map(|(b, _)| *b) == Some(byte);
            if !already
                && let Some(pending) =
                    lsp.hover(&spec.key, p, orress_lsp::position_at_enc(&text, byte, enc))
            {
                hover = Some((byte, pending));
            }
        }
        if let Some((b, pending)) = &hover
            && let Some(result) = pending.poll()
        {
            hover_shown = result
                .ok()
                .and_then(|v| orress_lsp::hover_text(&v))
                .map(|t| (*b, t));
            hover = None;
        }
        if let (Some(byte), Some((hb, text))) = (byte, &hover_shown)
            && *hb == byte
            && !text.is_empty()
        {
            response.show_tooltip_ui(|ui| {
                ui.set_max_width(520.0);
                ui.set_max_height(260.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(RichText::new(text.trim()).monospace());
                });
            });
        }
    }

    // The primary caret's byte offset (for definition and completion at the cursor).
    let caret_byte = char_byte(&text, out.primary_char);

    // F9 toggles a source breakpoint on the caret's line.
    if response.has_focus()
        && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::F9))
        && let Some(p) = buffer.path.clone()
    {
        let line = (text[..caret_byte.min(text.len())].matches('\n').count() + 1) as u32;
        source_dbg.toggle_breakpoint(&p, line);
    }

    if let Some((spec, _, _, p)) = &server {
        // Go to definition: F12 at the caret, or Ctrl+click on a symbol.
        let mut def_byte = None;
        if response.has_focus() && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::F12))
        {
            def_byte = Some(caret_byte);
        }
        if response.clicked() && ui.input(|i| i.modifiers.command) {
            def_byte = response.interact_pointer_pos().map(|pos| {
                char_byte(
                    &text,
                    out.galley.cursor_from_pos(pos - out.galley_pos).index.0,
                )
            });
        }
        if let Some(byte) = def_byte {
            pending_def =
                lsp.definition(&spec.key, p, orress_lsp::position_at_enc(&text, byte, enc));
        }
        if let Some(pending) = &pending_def
            && let Some(Ok(value)) = pending.poll()
        {
            if let Some(loc) = orress_lsp::definition_location(&value) {
                let same_file = orress_lsp::Url::from_file_path(p).map(|u| norm(u.as_ref()))
                    == Ok(norm(loc.uri.as_ref()));
                if same_file {
                    goto_byte = Some(orress_lsp::byte_at_enc(&text, loc.range.start, enc));
                } else if let Ok(target) = loc.uri.to_file_path() {
                    nav.push(GotoFile {
                        path: target,
                        line: loc.range.start.line,
                    });
                }
            }
            pending_def = None;
        }

        // Completion: Ctrl+Space, or after typing `.` / `:`.
        let mut want_completion = false;
        if response.has_focus()
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::Space))
        {
            want_completion = true;
        }
        if out.changed
            && caret_byte > 0
            && matches!(text.as_bytes().get(caret_byte - 1), Some(b'.') | Some(b':'))
        {
            want_completion = true;
        }
        if want_completion
            && let Some(pend) = lsp.completion(
                &spec.key,
                p,
                orress_lsp::position_at_enc(&text, caret_byte, enc),
            )
        {
            pending_completion = Some((word_start(&text, caret_byte), pend));
        }
        if let Some((anchor, pending)) = &pending_completion
            && let Some(Ok(value)) = pending.poll()
        {
            let items = orress_lsp::completion_items(&value);
            if !items.is_empty() {
                completion = Some(Completion {
                    items,
                    filtered: Vec::new(),
                    selected: 0,
                    anchor: *anchor,
                    caret: caret_byte,
                });
            }
            pending_completion = None;
        }

        // Keep the popup filtered to the current prefix, and draw it.
        if let Some(c) = &mut completion {
            c.caret = caret_byte;
            if c.caret < c.anchor
                || !text.is_char_boundary(c.anchor)
                || !text.is_char_boundary(c.caret.min(text.len()))
            {
                completion = None;
            } else {
                let prefix = text[c.anchor..c.caret.min(text.len())].to_ascii_lowercase();
                c.filtered = c
                    .items
                    .iter()
                    .enumerate()
                    .filter(|(_, it)| {
                        let hay = it
                            .filter_text
                            .as_deref()
                            .unwrap_or(&it.label)
                            .to_ascii_lowercase();
                        prefix.is_empty() || hay.contains(&prefix)
                    })
                    .map(|(i, _)| i)
                    .take(50)
                    .collect();
                if c.filtered.is_empty() {
                    completion = None;
                } else {
                    c.selected = c.selected.min(c.filtered.len() - 1);
                    let caret_rect = out.galley.pos_from_cursor(CCursor::new(
                        text[..c.caret.min(text.len())].chars().count(),
                    ));
                    let at = out.galley_pos + caret_rect.left_bottom().to_vec2();
                    draw_completion(ui, c, at);
                }
            }
        }
    }

    // Apply a pending caret move (after accepting a completion) or a goto target.
    if let Some(char_idx) = set_caret.take() {
        mc.set_single(char_idx);
        response.request_focus();
    }
    if let Some(byte) = goto_byte {
        let char_idx = text[..byte.min(text.len())].chars().count();
        mc.set_single(char_idx);
        let rect = out
            .galley
            .pos_from_cursor(CCursor::new(char_idx))
            .translate(out.galley_pos.to_vec2());
        ui.scroll_to_rect(rect, Some(Align::Center));
        response.request_focus();
    }

    // Run and Debug act on the file on disk, so unsaved edits are saved first. If that fails,
    // say so and do not run a stale file.
    if (run_task.is_some() || start_debug || debug_task.is_some())
        && buffer.path.is_some()
        && buffer.is_dirty()
    {
        match buffer.save() {
            Ok(()) => {
                if let Some((spec, _, _, p)) = &server {
                    lsp.did_save(&spec.key, p);
                }
            }
            Err(e) => {
                state.message = Some(format!("Save failed, so nothing was run: {e}"));
                run_task = None;
                start_debug = false;
                debug_task = None;
            }
        }
    }
    let run_now = run_task;
    let save_msg = do_save.then(|| save(buffer, path, force_dialog));
    if let Some(msg) = save_msg {
        state.message = msg;
    }
    if let Some(task) = run_now {
        console.run(task, repaint(ui));
    }
    if start_debug && let Some(p) = buffer.path.clone() {
        let ext_dir = crate::extensions::extensions_dir(ui.ctx());
        source_dbg.start(&p, ext_dir, lsp_settings(ui.ctx()), repaint(ui));
    }
    if let Some(task) = debug_task {
        let ext_dir = crate::extensions::extensions_dir(ui.ctx());
        let worktree = buffer
            .path
            .as_ref()
            .map(|p| orress_ext::project_root(p))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        source_dbg.debug_task(
            &task,
            ext_dir,
            &worktree,
            lsp_settings(ui.ctx()),
            repaint(ui),
        );
    }

    // Breakpoint dots in the gutter and the stopped line (while debugging).
    if let Some(p) = &buffer.path {
        let row_h = ui.fonts_mut(|f| f.row_height(&FontId::monospace(13.0)));
        let painter = ui.painter_at(editor_area);
        if let Some(line) = source_dbg.current_line(p) {
            let y0 = editor_from_line(out.galley_pos.y, line, row_h);
            let rect = egui::Rect::from_min_max(
                egui::Pos2::new(editor_area.left(), y0),
                egui::Pos2::new(editor_area.right(), y0 + row_h),
            );
            painter.rect_filled(
                rect,
                0.0,
                Color32::from_rgb(70, 130, 60).gamma_multiply(0.4),
            );
            ui.ctx().request_repaint();
        }
        if let Some(bps) = source_dbg.breakpoints(p) {
            for &line in bps {
                let y = editor_from_line(out.galley_pos.y, line, row_h) + row_h * 0.5;
                painter.circle_filled(
                    egui::Pos2::new(out.galley_pos.x - 9.0, y),
                    3.5,
                    Color32::from_rgb(220, 60, 60),
                );
            }
        }
    }

    state.hl_cache = hl_cache;
    state.hover = hover;
    state.hover_shown = hover_shown;
    state.pending_def = pending_def;
    state.pending_completion = pending_completion;
    state.completion = completion;
    state.set_caret = set_caret;
    state.mc = mc;
    state.asm_listing = asm_listing;
    state.asm_diags = asm_diags;
    state.asm_for_hash = asm_for_hash;
}

/// The assembler architecture for a binary's ISA, or `None` if the assembler can't target it.
fn asm_arch_for(isa: orress_arch::Isa) -> Option<orress_asm::Arch> {
    match isa {
        orress_arch::Isa::X64 => Some(orress_asm::Arch::X64),
        orress_arch::Isa::Arm64 => Some(orress_asm::Arch::Arm64),
        _ => None,
    }
}

/// Format an assembler result as an `address  bytes  source` listing.
fn format_listing(out: &orress_asm::Assembled) -> String {
    let mut s = String::new();
    for l in &out.lines {
        if l.bytes.is_empty() {
            continue;
        }
        let hex: String = l.bytes.iter().map(|b| format!("{b:02x} ")).collect();
        s.push_str(&format!(
            "{:08x}  {:<24} {}\n",
            l.address,
            hex.trim_end(),
            l.source
        ));
    }
    s
}

/// Consumes a key press whose modifiers are exactly `modifiers` (unlike `consume_key`, which
/// ignores extra Shift/Alt — so Ctrl+S would also swallow Ctrl+Shift+S).
fn consume_exact(input: &mut egui::InputState, modifiers: egui::Modifiers, key: Key) -> bool {
    let before = input.events.len();
    input.events.retain(|e| {
        !matches!(
            e,
            egui::Event::Key { key: k, pressed: true, modifiers: m, .. }
                if *k == key && m.matches_exact(modifiers)
        )
    });
    input.events.len() != before
}

fn char_byte(text: &str, char_idx: usize) -> usize {
    text.char_indices()
        .nth(char_idx)
        .map_or(text.len(), |(b, _)| b)
}

/// Screen y of a 1-based source line in the editor's galley.
fn editor_from_line(galley_y: f32, line: u32, row_h: f32) -> f32 {
    galley_y + line.saturating_sub(1) as f32 * row_h
}

fn char_w(ui: &Ui, font: &FontId) -> f32 {
    ui.fonts_mut(|f| f.glyph_width(font, '0'))
}

/// Normalises a URI for comparison (case-insensitive on Windows).
fn norm(uri: &str) -> String {
    if cfg!(windows) {
        uri.to_lowercase()
    } else {
        uri.to_string()
    }
}

/// The byte offset of the start of `line` (0-based) in `text`.
fn byte_of_line(text: &str, line: u32) -> usize {
    let mut start = 0;
    for _ in 0..line {
        match text[start..].find('\n') {
            Some(p) => start += p + 1,
            None => return text.len(),
        }
    }
    start
}

/// The byte offset where the identifier ending at `byte` begins.
fn word_start(text: &str, byte: usize) -> usize {
    let bytes = text.as_bytes();
    let mut a = byte.min(text.len());
    while a > 0 && (bytes[a - 1].is_ascii_alphanumeric() || bytes[a - 1] == b'_') {
        a -= 1;
    }
    a
}

/// Draws the completion popup anchored at `at` (screen coordinates).
fn draw_completion(ui: &mut Ui, c: &Completion, at: egui::Pos2) {
    let area = egui::Area::new(ui.id().with("orress-completion"))
        .order(egui::Order::Foreground)
        .fixed_pos(at + egui::vec2(0.0, 2.0));
    area.show(ui.ctx(), |ui| {
        egui::Frame::popup(ui.style()).show(ui, |ui| {
            ui.set_max_width(420.0);
            ui.set_max_height(220.0);
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (row, &idx) in c.filtered.iter().enumerate() {
                    let item = &c.items[idx];
                    let selected = row == c.selected;
                    let kind = completion_kind(item.kind);
                    let mut text = format!("{kind} {}", item.label);
                    if let Some(detail) = &item.detail {
                        text.push_str(&format!("   {}", detail.lines().next().unwrap_or("")));
                    }
                    let label = egui::RichText::new(text).monospace();
                    let label = if selected { label.strong() } else { label };
                    let resp = ui.selectable_label(selected, label);
                    if selected {
                        resp.scroll_to_me(None);
                    }
                }
            });
        });
    });
}

fn completion_kind(kind: Option<orress_lsp::CompletionItemKind>) -> &'static str {
    use orress_lsp::CompletionItemKind as K;
    match kind {
        Some(K::METHOD | K::FUNCTION) => "ƒn",
        Some(K::FIELD | K::PROPERTY) => " .",
        Some(K::VARIABLE) => "var",
        Some(K::STRUCT | K::CLASS | K::INTERFACE | K::ENUM) => "ty",
        Some(K::MODULE) => "mod",
        Some(K::KEYWORD) => "kw",
        Some(K::CONSTANT) => "const",
        _ => "·",
    }
}

fn lsp_status_label(ui: &mut Ui, lsp: &LspManager, key: &str, diag_count: usize) {
    let (text, color, hint) = match lsp.status(key) {
        Status::NotStarted => (
            "LSP: —".to_string(),
            ui.visuals().weak_text_color(),
            String::new(),
        ),
        Status::Starting => (
            "LSP: starting…".to_string(),
            ui.visuals().weak_text_color(),
            "the language server is starting and indexing".into(),
        ),
        Status::Ready => {
            let d = if diag_count == 0 {
                "no problems".to_string()
            } else {
                format!("{diag_count} problem(s)")
            };
            (
                format!("LSP: ready · {d}"),
                ui.visuals().text_color(),
                "language server connected (hover a symbol for its type)".into(),
            )
        }
        Status::Failed => (
            "LSP: unavailable".to_string(),
            ui.visuals().warn_fg_color,
            lsp.error(key).unwrap_or_else(|| {
                "the language server could not start — is it installed and on PATH?".into()
            }),
        ),
    };
    let r = ui.label(RichText::new(text).weak().color(color));
    if !hint.is_empty() {
        r.on_hover_text(hint);
    }
}

/// The status-bar label for a Zed extension's language server that is still being resolved, or
/// whose resolution failed.
fn zed_ls_label(ui: &mut Ui, zed: &ZedLs) {
    match zed {
        ZedLs::Resolving => {
            ui.label(
                RichText::new("LSP: resolving language server…")
                    .weak()
                    .color(ui.visuals().weak_text_color()),
            )
            .on_hover_text("a Zed extension is resolving (and possibly downloading) the server");
        }
        ZedLs::Failed(e) => {
            ui.label(
                RichText::new("LSP: unavailable")
                    .weak()
                    .color(ui.visuals().warn_fg_color),
            )
            .on_hover_text(e.as_str());
        }
    }
}

/// The bottom "Problems" panel: diagnostics across all open files.
pub fn problems_panel(ui: &mut Ui, lsp: &LspManager) {
    let mut diags = lsp.all_diagnostics();
    diags.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.range.start.line.cmp(&b.1.range.start.line))
    });
    if diags.is_empty() {
        ui.label(muted("No problems. When a language server reports errors or warnings, they appear here and underlined in the editor."));
        return;
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (path, d) in &diags {
                let file = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let is_err = !matches!(
                    d.severity,
                    Some(
                        DiagnosticSeverity::WARNING
                            | DiagnosticSeverity::INFORMATION
                            | DiagnosticSeverity::HINT
                    )
                );
                let color = if is_err {
                    ui.visuals().error_fg_color
                } else {
                    ui.visuals().warn_fg_color
                };
                let line = d.range.start.line + 1;
                let msg = d.message.lines().next().unwrap_or("").trim();
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(if is_err { "●" } else { "▲" }).color(color));
                    ui.label(RichText::new(format!("{file}:{line}")).monospace().weak());
                    ui.label(msg);
                });
            }
        });
}

/// Saves the buffer. Asks for a path when the buffer is untitled, or when `force_dialog` is set
/// (Save As). Returns a status message.
fn save(buffer: &mut Buffer, path: &mut Option<PathBuf>, force_dialog: bool) -> Option<String> {
    let result = if buffer.path.is_some() && !force_dialog {
        buffer.save()
    } else {
        let p = rfd::FileDialog::new()
            .set_title(if force_dialog {
                "Save file as"
            } else {
                "Save file"
            })
            .set_file_name(buffer.suggested_name())
            .save_file()?;
        buffer.save_as(&p)
    };
    Some(match result {
        Ok(()) => {
            *path = buffer.path.clone();
            buffer
                .path
                .as_ref()
                .map_or_else(|| "Saved.".into(), |p| format!("Saved {}", p.display()))
        }
        Err(e) => format!("Save failed: {e}"),
    })
}

fn repaint(ui: &Ui) -> Arc<dyn Fn() + Send + Sync> {
    let ctx = ui.ctx().clone();
    Arc::new(move || ctx.request_repaint())
}

// ---------------------------------------------------------------------------
// Run console
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunStatus {
    Idle,
    Running,
    Done(i32),
    Failed,
}

/// The most output lines the console keeps; older ones are dropped (a chatty program would
/// otherwise grow memory without bound).
const MAX_LINES: usize = 20_000;

struct ConsoleLine {
    text: String,
    err: bool,
}

#[derive(Default)]
struct ConsoleInner {
    lines: VecDeque<ConsoleLine>,
    /// How many of the oldest lines were dropped to stay within [`MAX_LINES`].
    dropped: usize,
    label: String,
    status_done: Option<i32>,
    running: bool,
    failed: bool,
}

/// Runs build/run tasks in the background and collects their output. Owned by the app and
/// shared with the editor (to launch) and the bottom panel (to display).
#[derive(Default)]
pub struct RunConsole {
    inner: Arc<Mutex<ConsoleInner>>,
    cancel: Arc<AtomicBool>,
    /// The running step's process, so Stop can kill it at once (even when it prints nothing).
    child: Arc<Mutex<Option<Child>>>,
    /// Bumped on every run, so output still trickling in from a stopped run is dropped.
    generation: Arc<AtomicU64>,
}

impl RunConsole {
    pub fn is_running(&self) -> bool {
        self.inner.lock().map(|c| c.running).unwrap_or(false)
    }

    pub fn status(&self) -> RunStatus {
        let c = self.inner.lock().expect("console");
        if c.running {
            RunStatus::Running
        } else if c.failed {
            RunStatus::Failed
        } else {
            c.status_done.map_or(RunStatus::Idle, RunStatus::Done)
        }
    }

    pub fn label(&self) -> String {
        self.inner
            .lock()
            .map(|c| c.label.clone())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut c) = self.inner.lock() {
            c.lines.clear();
            c.dropped = 0;
            c.status_done = None;
            c.failed = false;
        }
    }

    /// Stops the running task: kills its current process right away.
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Ok(mut slot) = self.child.lock()
            && let Some(child) = slot.as_mut()
        {
            let _ = child.kill();
        }
    }

    /// Runs a task's steps in sequence on a background thread.
    pub fn run(&self, task: orress_editor::Task, notify: Arc<dyn Fn() + Send + Sync>) {
        if self.is_running() {
            return;
        }
        self.cancel.store(false, Ordering::SeqCst);
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut c = self.inner.lock().expect("console");
            c.lines.clear();
            c.dropped = 0;
            c.label = task.label.clone();
            c.running = true;
            c.failed = false;
            c.status_done = None;
        }
        let run = Run {
            inner: Arc::clone(&self.inner),
            cancel: Arc::clone(&self.cancel),
            child: Arc::clone(&self.child),
            generation: Arc::clone(&self.generation),
            this_run: generation,
            notify,
        };
        std::thread::Builder::new()
            .name("orress-run".into())
            .spawn(move || run.task(&task))
            .expect("spawn run thread");
    }
}

type Shared = Arc<Mutex<ConsoleInner>>;
type Notify = Arc<dyn Fn() + Send + Sync>;

/// Everything a run's threads share.
#[derive(Clone)]
struct Run {
    inner: Shared,
    cancel: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    generation: Arc<AtomicU64>,
    /// This run's generation; output arriving after a newer run started is dropped.
    this_run: u64,
    notify: Notify,
}

impl Run {
    fn push(&self, text: String, err: bool) {
        if self.generation.load(Ordering::SeqCst) != self.this_run {
            return;
        }
        if let Ok(mut c) = self.inner.lock() {
            if c.lines.len() >= MAX_LINES {
                c.lines.pop_front();
                c.dropped += 1;
            }
            c.lines.push_back(ConsoleLine { text, err });
        }
        (self.notify)();
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Streams one pipe into the console on its own thread, counting it done at EOF.
    fn stream(
        &self,
        pipe: impl std::io::Read + Send + 'static,
        err: bool,
        done: &Arc<AtomicUsize>,
    ) {
        let run = self.clone();
        let done = Arc::clone(done);
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                run.push(line, err);
            }
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    fn task(&self, task: &orress_editor::Task) {
        use std::process::{Command, Stdio};

        let mut failed = false;
        for step in &task.steps {
            if self.cancelled() {
                break;
            }
            self.push(format!("$ {} {}", step.program, step.args.join(" ")), false);
            let spawned = Command::new(&step.program)
                .args(&step.args)
                .current_dir(&step.cwd)
                // No console input: a program waiting on stdin would otherwise hang the run.
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            let mut child = match spawned {
                Ok(c) => c,
                Err(e) => {
                    self.push(format!("could not start {}: {e}", step.program), true);
                    failed = true;
                    break;
                }
            };
            // Both pipes are read on helper threads; this thread only waits for the process, so
            // Stop (which kills it through the shared slot) takes effect immediately.
            let done = Arc::new(AtomicUsize::new(0));
            let mut readers = 0;
            if let Some(out) = child.stdout.take() {
                self.stream(out, false, &done);
                readers += 1;
            }
            if let Some(err) = child.stderr.take() {
                self.stream(err, true, &done);
                readers += 1;
            }
            if let Ok(mut slot) = self.child.lock() {
                *slot = Some(child);
            }
            let status = self.wait();
            // Let the readers drain what the process wrote. Bounded: a child it started may keep
            // the pipes open after it exits; its later output is dropped with the generation.
            let deadline = Instant::now() + Duration::from_secs(2);
            while done.load(Ordering::SeqCst) < readers && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            match status {
                Ok(s) if s.success() => {}
                Ok(_) if self.cancelled() => {
                    self.push("[stopped]".into(), true);
                    failed = true;
                    break;
                }
                Ok(s) => {
                    self.push(
                        format!("[exited with code {}]", s.code().unwrap_or(-1)),
                        true,
                    );
                    failed = true;
                    break;
                }
                Err(e) => {
                    self.push(format!("[error: {e}]"), true);
                    failed = true;
                    break;
                }
            }
        }
        if let Ok(mut c) = self.inner.lock() {
            c.running = false;
            c.failed = failed || self.cancelled();
            c.status_done = Some(if c.failed { 1 } else { 0 });
        }
        (self.notify)();
    }

    /// Waits for the process in the shared slot to exit (polling, so the slot stays free for
    /// Stop to kill it), then clears the slot.
    fn wait(&self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            {
                let mut slot = self
                    .child
                    .lock()
                    .map_err(|_| std::io::Error::other("console lock poisoned"))?;
                let Some(child) = slot.as_mut() else {
                    return Err(std::io::Error::other("the process went missing"));
                };
                if let Some(status) = child.try_wait()? {
                    *slot = None;
                    return Ok(status);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The bottom "Terminal / Output" panel: the run console's output.
pub fn run_panel(ui: &mut Ui, console: &mut RunConsole) {
    ui.horizontal(|ui| {
        let (label, color) = match console.status() {
            RunStatus::Idle => ("ready".to_string(), ui.visuals().weak_text_color()),
            RunStatus::Running => (
                format!("running: {}", console.label()),
                ui.visuals().text_color(),
            ),
            RunStatus::Done(0) => (
                format!("{} — done", console.label()),
                ui.visuals().text_color(),
            ),
            RunStatus::Done(c) => (
                format!("{} — exited {c}", console.label()),
                ui.visuals().warn_fg_color,
            ),
            RunStatus::Failed => (
                format!("{} — failed", console.label()),
                ui.visuals().error_fg_color,
            ),
        };
        ui.colored_label(color, label);
        if console.is_running() {
            if ui.small_button("⏹ Stop").clicked() {
                console.stop();
            }
        } else if ui.small_button("Clear").clicked() {
            console.clear();
        }
        let dropped = console.inner.lock().map(|c| c.dropped).unwrap_or(0);
        if dropped > 0 {
            ui.label(muted(format!("({dropped} earlier lines dropped)")));
        }
    });
    ui.separator();
    let font = FontId::monospace(12.0);
    let row_h = ui.fonts_mut(|f| f.row_height(&font));
    let inner = console.inner.lock().expect("console");
    if inner.lines.is_empty() {
        ui.label(muted(
            "Run a file from the editor (▶ Run). Output appears here.",
        ));
        return;
    }
    // Only the visible rows are laid out, so a long log costs nothing per frame.
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show_rows(ui, row_h, inner.lines.len(), |ui, rows| {
            for line in inner.lines.range(rows) {
                let col = if line.err {
                    ui.visuals().warn_fg_color
                } else {
                    ui.visuals().text_color()
                };
                ui.add(
                    egui::Label::new(RichText::new(&line.text).font(font.clone()).color(col))
                        .wrap_mode(egui::TextWrapMode::Extend),
                );
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_idle(console: &RunConsole) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while console.is_running() {
            assert!(Instant::now() < deadline, "the run did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn output_is_capped() {
        let console = RunConsole::default();
        let run = Run {
            inner: Arc::clone(&console.inner),
            cancel: Arc::clone(&console.cancel),
            child: Arc::clone(&console.child),
            generation: Arc::clone(&console.generation),
            this_run: 0,
            notify: Arc::new(|| {}),
        };
        for i in 0..MAX_LINES + 5 {
            run.push(format!("line {i}"), false);
        }
        let c = console.inner.lock().unwrap();
        assert_eq!(c.lines.len(), MAX_LINES);
        assert_eq!(c.dropped, 5);
        assert_eq!(c.lines.front().unwrap().text, "line 5");
    }

    #[test]
    fn stop_kills_a_silent_process() {
        // A process that runs for a long time without printing anything.
        let (program, args): (&str, Vec<String>) = if cfg!(windows) {
            (
                "powershell",
                vec![
                    "-NoProfile".into(),
                    "-Command".into(),
                    "Start-Sleep 30".into(),
                ],
            )
        } else {
            ("sleep", vec!["30".into()])
        };
        let console = RunConsole::default();
        console.run(
            orress_editor::Task {
                label: "sleep".into(),
                steps: vec![orress_editor::Command {
                    program: program.into(),
                    args,
                    cwd: std::env::temp_dir(),
                }],
            },
            Arc::new(|| {}),
        );
        // Wait until the process is in the slot, then stop it.
        let deadline = Instant::now() + Duration::from_secs(20);
        while console.child.lock().unwrap().is_none() && console.is_running() {
            assert!(Instant::now() < deadline, "the process did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let started = Instant::now();
        console.stop();
        wait_idle(&console);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "stop took too long"
        );
        assert_eq!(console.status(), RunStatus::Failed);
        // It was started and then stopped (not a failed launch).
        let c = console.inner.lock().unwrap();
        assert!(
            c.lines.iter().any(|l| l.text == "[stopped]"),
            "output: {:?}",
            c.lines.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }
}
