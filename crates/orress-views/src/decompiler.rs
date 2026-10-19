//! Decompiler panel: the function under the cursor as Rust-style pseudocode.
//!
//! It follows the cursor of the active file: move through the disassembly and the
//! panel shows (and highlights) the matching line. Clicking a line moves the
//! disassembly there; clicking a function name goes to that function. Ctrl+F searches
//! the function's code; a right click shows what can be done with a line or name.

use std::sync::{Arc, Weak};

use egui::text::LayoutJob;
use egui::{Align, Color32, FontId, RichText, Sense, Ui};
use orress_analysis::Program;
use orress_decompiler::{Output, TokKind};
use orress_project::{DocStore, Document};
use orress_ui::{ExplainExt as _, muted};

use crate::edit::{self, EditPopup};
use crate::find::{self, FindInput, FindStep};
use crate::{ViewCommand, ViewRequest, code, menu};

type Cached = Arc<Result<Output, String>>;
type PortCached = Arc<Result<String, String>>;

/// How many decompiled functions (per mode) are kept.
const CACHE_ENTRIES: usize = 16;

/// One cached result, for `func` in a specific analysis. The `Weak` pins the identity of
/// the program without keeping it alive: a patch makes a new program, so its functions are
/// decompiled again, while renames (applied when drawing) reuse the result.
#[derive(Clone)]
struct Entry<T> {
    program: Weak<Program>,
    func: u64,
    /// The document's annotation generation the result was built at, so applying or editing
    /// a type (which bumps the generation) re-decompiles instead of reusing a stale result.
    generation: u64,
    value: Arc<T>,
}

/// Recently decompiled functions, most recently used last, bounded so browsing many
/// functions or files does not pile results up in memory.
#[derive(Clone, Default)]
struct DecompCache {
    pseudo: Vec<Entry<Result<Output, String>>>,
    port: Vec<Entry<Result<String, String>>>,
    /// The highlighted port text, for the port result it was built from and the colours.
    port_job: Option<(
        PortCached,
        Color32,
        orress_theme::SyntaxColors,
        Arc<LayoutJob>,
    )>,
}

fn cache_id() -> egui::Id {
    egui::Id::new("orress::decompiler_cache")
}

/// The cached value for (`program`, `func`), moved to the most-recent end.
fn lookup<T>(
    entries: &mut Vec<Entry<T>>,
    program: &Arc<Program>,
    func: u64,
    generation: u64,
) -> Option<Arc<T>> {
    let weak = Arc::downgrade(program);
    let i = entries.iter().position(|e| {
        e.func == func && e.generation == generation && Weak::ptr_eq(&e.program, &weak)
    })?;
    let e = entries.remove(i);
    let value = Arc::clone(&e.value);
    entries.push(e);
    Some(value)
}

fn remember<T>(
    entries: &mut Vec<Entry<T>>,
    program: &Arc<Program>,
    func: u64,
    generation: u64,
    value: &Arc<T>,
) {
    // Results for programs that no longer exist (an older patch level, a closed file) go first.
    entries.retain(|e| e.program.strong_count() > 0);
    if entries.len() >= CACHE_ENTRIES {
        entries.remove(0);
    }
    entries.push(Entry {
        program: Arc::downgrade(program),
        func,
        generation,
        value: Arc::clone(value),
    });
}

const EXPLAIN: &str = "The decompiler turns the machine code of a function back into readable code. \
    ORRESS writes it as Rust: `if`, `while` and `loop` instead of jumps, parameters (a1, a2 ...) \
    instead of registers, `&[u8]` for a buffer with its length, `bool` for yes/no results. \
    It is a reconstruction, not the original source: names, types and some details are lost when \
    a program is compiled. Values the decompiler cannot type are shown as read::<u32>(address). \
    When in doubt, the disassembly is the truth.";

fn color(kind: TokKind, syntax: &orress_theme::SyntaxColors, text: Color32) -> Color32 {
    match kind {
        TokKind::Keyword => syntax.keyword.0,
        TokKind::Type => syntax.type_name.0,
        TokKind::Function => syntax.function.0,
        TokKind::Param => syntax.label.0,
        TokKind::Variable => syntax.register.0,
        TokKind::Number => syntax.immediate.0,
        TokKind::Str => syntax.string.0,
        TokKind::Comment => syntax.comment.0,
        TokKind::Punct => text,
    }
}

/// Sanitises a function label into a file-name stem (alphanumerics and `_` kept, the rest
/// replaced), so a name like `main+0x1a` becomes a usable `main_0x1a.rs`.
fn file_stem(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() { "function".into() } else { s }
}

/// The Copy / Open-in-editor buttons shared by both decompiler modes. `code` is the text they
/// act on; `name` is the function label used to name the editor buffer (which can then be saved
/// with File ▸ Save As). `code` is the text to act on.
fn code_actions(ui: &mut Ui, requests: &mut Vec<ViewRequest>, name: &str, code: &str) {
    if ui
        .small_button("Copy")
        .on_hover_text("Copy the code")
        .clicked()
    {
        ui.ctx().copy_text(code.to_string());
    }
    if ui
        .small_button("Open in editor")
        .on_hover_text("Open this code in a new editor tab (then save it with File ▸ Save As)")
        .clicked()
    {
        requests.push(ViewRequest::OpenInEditor {
            name: format!("{}.rs", file_stem(name)),
            contents: code.to_string(),
        });
    }
}

/// Per-panel state that lives between frames: the find bar, the right-click target and a
/// rename/comment popup.
#[derive(Clone, Default)]
struct PanelState {
    find: FindInput,
    /// Index of the current match in this frame's match list.
    current: Option<usize>,
    /// What the matches belong to: (function, Rust port mode, query). When it changes the
    /// current match starts over.
    matched: Option<(u64, bool, String)>,
    /// The right-clicked line and the address under the pointer.
    menu: Option<(usize, Option<u64>)>,
    popup: Option<EditPopup>,
    /// The open "set prototype" editor, if any.
    proto: Option<crate::prototype::ProtoDraft>,
}

fn state_id() -> egui::Id {
    egui::Id::new("orress::decompiler_panel")
}

/// Something picked in the right-click menu, done after the code is drawn.
enum MenuAction {
    GoTo(u64),
    Rename(u64),
    Comment(u64),
    Xrefs(u64),
    Mode(bool),
    Find,
}

const FIND_EXPLAIN: &str = "Search the decompiled code of this function, ignoring upper/lower \
    case: a variable (a1), a function name, a number (0x5a), a keyword (while). F3 finds the \
    next match, Shift+F3 the previous one. To search the whole program, use Find in the \
    Disassembly view.";

pub fn decompiler_panel(
    ui: &mut Ui,
    docs: &mut DocStore,
    requests: &mut Vec<ViewRequest>,
    commands: Vec<ViewCommand>,
) {
    let mut state: PanelState = ui
        .ctx()
        .data(|d| d.get_temp(state_id()))
        .unwrap_or_default();
    let mut step = None;
    for command in commands {
        match command {
            ViewCommand::FindNext if state.find.needle().is_some() => step = Some(FindStep::Next),
            ViewCommand::FindPrevious if state.find.needle().is_some() => {
                step = Some(FindStep::Previous);
            }
            ViewCommand::Find | ViewCommand::FindNext | ViewCommand::FindPrevious => {
                state.find.show();
            }
            _ => {}
        }
    }
    panel(ui, docs, requests, &mut state, step);
    ui.ctx().data_mut(|d| d.insert_temp(state_id(), state));
}

fn panel(
    ui: &mut Ui,
    docs: &mut DocStore,
    requests: &mut Vec<ViewRequest>,
    state: &mut PanelState,
    mut step: Option<FindStep>,
) {
    let Some(doc) = docs.active_mut() else {
        ui.label(
            "Open a program and put the cursor in a function: its decompiled code appears here.",
        );
        return;
    };
    let Some(program) = doc.program().cloned() else {
        ui.label(muted("Waiting for the disassembly…"));
        return;
    };
    let Some(format) = doc.analysis().map(|a| a.info.format) else {
        return;
    };
    let cursor = program.memory.address_of(doc.cursor);
    let Some(func) = cursor
        .and_then(|a| program.function_containing(a))
        .map(|f| f.entry)
    else {
        ui.label("Put the cursor inside a function in the disassembly (Ctrl+D) to decompile it.");
        return;
    };

    // Decompiling is quick, but not free: keep the result until the code changes (a patch
    // makes a new program) or a type is applied/edited (which bumps the generation). Names are
    // not part of the output; renames apply when drawing.
    let generation = doc.generation;
    let hints = build_hints(doc);
    let cached: Option<Cached> = ui.ctx().data_mut(|d| {
        lookup(
            &mut d.get_temp_mut_or_default::<DecompCache>(cache_id()).pseudo,
            &program,
            func,
            generation,
        )
    });
    let result = cached.unwrap_or_else(|| {
        let conv = orress_decompiler::convention(format);
        let r = Arc::new(
            orress_decompiler::decompile_with(&program, func, conv, &hints)
                .map_err(|e| e.to_string()),
        );
        ui.ctx().data_mut(|d| {
            let cache = d.get_temp_mut_or_default::<DecompCache>(cache_id());
            remember(&mut cache.pseudo, &program, func, generation, &r);
        });
        r
    });

    let name = code::describe_address(doc, &program, func);
    let mode_id = egui::Id::new("orress::decompiler_mode");
    let mut port_mode: bool = ui.ctx().data(|d| d.get_temp(mode_id)).unwrap_or(false);
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("Decompiled: {name}")).strong())
            .explain("Decompiler", EXPLAIN);
        ui.label(muted(format!("(0x{func:x})")));
        ui.separator();
        if ui.selectable_label(!port_mode, "Pseudocode").clicked() {
            port_mode = false;
        }
        if ui
            .selectable_label(port_mode, "Rust port")
            .on_hover_text("A compilable Rust scaffold for porting — un-lifted instructions kept as inline asm")
            .clicked()
        {
            port_mode = true;
        }
        ui.separator();
        if ui
            .selectable_label(state.find.open, "Find…")
            .on_hover_text("Search this function's code (Ctrl+F)")
            .clicked()
        {
            if state.find.open {
                state.find.open = false;
            } else {
                state.find.show();
            }
        }
        ui.separator();
        let has_proto = doc.annotations.func_prototypes.contains_key(&func);
        let label = if has_proto {
            "Prototype ✎"
        } else {
            "Set prototype…"
        };
        if ui
            .selectable_label(state.proto.is_some(), label)
            .on_hover_text("Pin this function's return type and parameter names/types")
            .clicked()
        {
            state.proto = if state.proto.is_some() {
                None
            } else {
                Some(crate::prototype::ProtoDraft::load(doc, func))
            };
        }
    });
    crate::prototype::window(ui, &mut state.proto, doc, &name);
    if state.find.open {
        let bar = find::bar(ui, &mut state.find, "e.g. a1, while, 0x5a", FIND_EXPLAIN);
        if bar.changed {
            state.current = None;
        }
        step = bar.step.or(step);
    }
    let needle = state.find.open.then(|| state.find.needle()).flatten();
    let key = (func, port_mode, needle.clone().unwrap_or_default());
    if state.matched.as_ref() != Some(&key) {
        state.matched = Some(key);
        state.current = None;
        if step.is_none() {
            state.find.status = None;
        }
    }

    let mut action: Option<MenuAction> = None;

    // --- Rust port mode: a compilable scaffold rather than reading pseudocode. -----
    if port_mode {
        #[cfg(feature = "compile-check")]
        let pkey = egui::Id::new(("orress::port", &doc.path, func));
        let pcached: Option<PortCached> = ui.ctx().data_mut(|d| {
            lookup(
                &mut d.get_temp_mut_or_default::<DecompCache>(cache_id()).port,
                &program,
                func,
                generation,
            )
        });
        let pres = pcached.unwrap_or_else(|| {
            let conv = orress_decompiler::convention(format);
            let r =
                Arc::new(orress_decompiler::port(&program, func, conv).map_err(|e| e.to_string()));
            ui.ctx().data_mut(|d| {
                let cache = d.get_temp_mut_or_default::<DecompCache>(cache_id());
                remember(&mut cache.port, &program, func, generation, &r);
            });
            r
        });
        ui.horizontal(|ui| {
            ui.label(muted(
                "Best-effort compilable Rust — review before porting.",
            ));
            if let Ok(s) = &*pres {
                code_actions(ui, requests, &name, s);
            }
            #[cfg(feature = "compile-check")]
            if let Ok(s) = &*pres {
                port_compile_check(ui, pkey, s);
            }
        });
        ui.separator();
        match &*pres {
            Ok(s) => {
                // Colour the port with the same tree-sitter highlighter and theme as the code
                // editor, so the tab reads like the IDE editor (and like the pseudocode tab).
                // Highlighting parses the whole text, so it is redone only when the text or
                // the colours change.
                let syntax = code::syntax(ui.ctx());
                let default = ui.visuals().text_color();
                let cached_job = ui.ctx().data(|d| {
                    d.get_temp::<DecompCache>(cache_id())
                        .and_then(|c| c.port_job)
                        .filter(|(p, c, sx, _)| {
                            Arc::ptr_eq(p, &pres) && *c == default && *sx == syntax
                        })
                        .map(|(.., job)| job)
                });
                let job = cached_job.unwrap_or_else(|| {
                    let job = Arc::new(code::highlight_job(
                        s,
                        orress_editor::Language::Rust,
                        &syntax,
                        FontId::monospace(13.0),
                        default,
                    ));
                    ui.ctx().data_mut(|d| {
                        d.get_temp_mut_or_default::<DecompCache>(cache_id())
                            .port_job =
                            Some((Arc::clone(&pres), default, syntax.clone(), Arc::clone(&job)));
                    });
                    job
                });
                let starts = needle
                    .as_deref()
                    .map(|n| find::matches(s, n))
                    .unwrap_or_default();
                let stepped = step.is_some();
                if let (Some(step), Some(n)) = (step, needle.as_deref()) {
                    state.current = find::step_index(starts.len(), state.current, step);
                    state.find.status = Some(match state.current {
                        Some(i) => Ok(format!("{} of {} in this function", i + 1, starts.len())),
                        None => Err(format!("`{n}` is not in this function")),
                    });
                }
                let len = needle.as_ref().map_or(0, String::len);
                let job = if starts.is_empty() {
                    (*job).clone()
                } else {
                    mark_matches(&job, &starts, len, state.current)
                };
                let galley = ui.fonts_mut(|f| f.layout_job(job));
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .id_salt("port-scroll")
                    .show(ui, |ui| {
                        let response =
                            ui.add(egui::Label::new(Arc::clone(&galley)).selectable(true));
                        if stepped && let Some(i) = state.current {
                            let char_index = s[..starts[i]].chars().count();
                            let at = galley
                                .pos_from_cursor(egui::text::CCursor::new(char_index))
                                .translate(response.rect.min.to_vec2());
                            ui.scroll_to_rect(at, Some(Align::Center));
                        }
                        response.context_menu(|ui| {
                            ui.set_min_width(220.0);
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                            menu::copy_item(ui, "Copy the code", s.clone());
                            if ui.button("Open in editor").clicked() {
                                requests.push(ViewRequest::OpenInEditor {
                                    name: format!("{}.rs", file_stem(&name)),
                                    contents: s.clone(),
                                });
                                ui.close();
                            }
                            if ui.button("Show pseudocode").clicked() {
                                action = Some(MenuAction::Mode(false));
                                ui.close();
                            }
                            if ui
                                .add(egui::Button::new("Find…").shortcut_text("Ctrl+F"))
                                .clicked()
                            {
                                action = Some(MenuAction::Find);
                                ui.close();
                            }
                            menu::views_and_commands(ui, requests);
                        });
                    });
            }
            Err(e) => {
                ui.label(e.as_str());
            }
        }
        apply(ui, doc, requests, state, action, &mut port_mode);
        ui.ctx().data_mut(|d| d.insert_temp(mode_id, port_mode));
        return;
    }

    let out = match &*result {
        Ok(out) => out,
        Err(e) => {
            ui.label(e.as_str());
            ui.ctx().data_mut(|d| d.insert_temp(mode_id, port_mode));
            return;
        }
    };
    ui.horizontal(|ui| {
        code_actions(ui, requests, &name, &out.text());
        ui.label(muted(
            "Pseudocode reconstructed from the machine code. Names and types are best guesses.",
        ))
        .note("Decompiler", EXPLAIN);
    });
    ui.separator();

    // The text of each line as drawn (with the user's names), for searching.
    let line_text = |line: &orress_decompiler::Line| -> String {
        line.spans
            .iter()
            .map(|span| match (span.kind, span.target) {
                (TokKind::Function, Some(a)) => doc.name_of(a).unwrap_or_else(|| span.text.clone()),
                _ => span.text.clone(),
            })
            .collect()
    };
    let hits: Vec<usize> = match needle.as_deref() {
        Some(n) => out
            .lines
            .iter()
            .enumerate()
            .filter(|(_, l)| line_text(l).to_ascii_lowercase().contains(n))
            .map(|(i, _)| i)
            .collect(),
        None => Vec::new(),
    };
    let stepped = step.is_some();
    if let (Some(step), Some(n)) = (step, needle.as_deref()) {
        state.current = find::step_index(hits.len(), state.current, step);
        state.find.status = Some(match state.current {
            Some(i) => Ok(format!(
                "line {} · {} of {} matching lines in this function",
                hits[i] + 1,
                i + 1,
                hits.len()
            )),
            None => Err(format!("`{n}` is not in this function")),
        });
    }
    let current_hit = state.current.and_then(|i| hits.get(i).copied());

    let current = cursor.and_then(|a| out.line_for(a));
    // Scroll to the current line only when the cursor moved.
    let moved_key = egui::Id::new("orress::decompiler_cursor");
    let moved = ui.ctx().data(|d| d.get_temp::<Option<u64>>(moved_key)) != Some(cursor);
    ui.ctx().data_mut(|d| d.insert_temp(moved_key, cursor));

    let syntax = code::syntax(ui.ctx());
    let text = ui.visuals().text_color();
    let font = FontId::monospace(13.0);
    let highlight = ui.visuals().selection.bg_fill.gamma_multiply(0.35);
    let found = Color32::from_rgb(230, 180, 40);
    let mut go: Option<u64> = None;
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 1.0);
            for (i, line) in out.lines.iter().enumerate() {
                let mut targets: Vec<(egui::Rect, u64)> = Vec::new();
                let row = ui.horizontal(|ui| {
                    ui.label(RichText::new("    ".repeat(line.indent)).font(font.clone()));
                    for span in &line.spans {
                        // User renames win over the analysis' names.
                        let shown = match (span.kind, span.target) {
                            (TokKind::Function, Some(a)) => {
                                doc.name_of(a).unwrap_or_else(|| span.text.clone())
                            }
                            _ => span.text.clone(),
                        };
                        let rich = RichText::new(shown)
                            .font(font.clone())
                            .color(color(span.kind, &syntax, text));
                        let r = ui.add(egui::Label::new(rich).selectable(false));
                        if let Some(a) = span.target {
                            targets.push((r.rect, a));
                        }
                    }
                });
                let rect = row
                    .response
                    .rect
                    .with_max_x(ui.clip_rect().right().max(row.response.rect.right()));
                if Some(i) == current {
                    ui.painter().rect_filled(rect, 2.0, highlight);
                    if moved && !stepped {
                        // Only scroll vertically: keep the start of the line in view.
                        let left =
                            egui::Rect::from_min_size(rect.min, egui::vec2(1.0, rect.height()));
                        ui.scroll_to_rect(left, Some(Align::Center));
                    }
                }
                if hits.binary_search(&i).is_ok() {
                    let strength = if Some(i) == current_hit { 0.45 } else { 0.18 };
                    ui.painter()
                        .rect_filled(rect, 2.0, found.gamma_multiply(strength));
                    if stepped && Some(i) == current_hit {
                        let left =
                            egui::Rect::from_min_size(rect.min, egui::vec2(1.0, rect.height()));
                        ui.scroll_to_rect(left, Some(Align::Center));
                    }
                }
                // One click area per line; a click on a name goes to that name instead.
                let r = ui.interact(rect, ui.id().with(("line", i)), Sense::click());
                let pointer = r.hover_pos();
                let on_target = pointer
                    .and_then(|p| targets.iter().find(|(t, _)| t.contains(p)).map(|(_, a)| *a));
                if r.secondary_clicked() {
                    state.menu = Some((i, on_target));
                }
                if let Some(a) = on_target {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    if r.clicked() {
                        go = Some(a);
                    }
                } else if r.clicked() {
                    go = line.addr;
                }
                r.context_menu(|ui| {
                    if let Some((at, target)) = state.menu
                        && at == i
                    {
                        let text = line_text(line);
                        let picked =
                            line_menu(ui, doc, &program, requests, func, line, target, &text);
                        if picked.is_some() {
                            action = picked;
                        }
                    }
                });
                if let Some(a) = on_target {
                    r.on_hover_text(format!("Go to 0x{a:x}"));
                }
            }
        });
    if let Some(a) = go {
        doc.navigate_to_address(a);
    }
    apply(ui, doc, requests, state, action, &mut port_mode);
    ui.ctx().data_mut(|d| d.insert_temp(mode_id, port_mode));
}

/// The right-click menu of a pseudocode line. `target` is the function or address under
/// the pointer.
#[allow(clippy::too_many_arguments)]
fn line_menu(
    ui: &mut Ui,
    doc: &Document,
    program: &Program,
    requests: &mut Vec<ViewRequest>,
    func: u64,
    line: &orress_decompiler::Line,
    target: Option<u64>,
    text: &str,
) -> Option<MenuAction> {
    ui.set_min_width(220.0);
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
    let mut action = None;
    let mut pick = |ui: &mut Ui, label: String, a: MenuAction| {
        if ui.button(label).clicked() {
            action = Some(a);
            ui.close();
        }
    };
    if let Some(a) = target {
        let name = code::describe_address(doc, program, a);
        pick(ui, format!("Go to {name}"), MenuAction::GoTo(a));
        pick(ui, format!("Rename {name}…"), MenuAction::Rename(a));
        pick(
            ui,
            format!("Cross-references to {name}"),
            MenuAction::Xrefs(a),
        );
        ui.separator();
    }
    if let Some(addr) = line.addr {
        pick(
            ui,
            format!("Show in disassembly (0x{addr:x})"),
            MenuAction::GoTo(addr),
        );
        pick(ui, "Comment…".into(), MenuAction::Comment(addr));
    }
    if target != Some(func) {
        let name = code::describe_address(doc, program, func);
        pick(ui, format!("Rename {name}…"), MenuAction::Rename(func));
        pick(
            ui,
            format!("Cross-references to {name}"),
            MenuAction::Xrefs(func),
        );
    }
    ui.menu_button("Copy", |ui| {
        menu::copy_item(ui, "Line", text.trim().to_owned());
        if let Some(addr) = line.addr {
            menu::copy_item(ui, "Address", format!("0x{addr:x}"));
        }
        menu::copy_item(
            ui,
            "Function name",
            code::describe_address(doc, program, func),
        );
    });
    ui.separator();
    pick(ui, "Show Rust port".into(), MenuAction::Mode(true));
    if ui
        .add(egui::Button::new("Find…").shortcut_text("Ctrl+F"))
        .clicked()
    {
        action = Some(MenuAction::Find);
        ui.close();
    }
    if ui.button("Show in graph").clicked() {
        requests.push(ViewRequest::RunAction("view::Graph".into()));
        ui.close();
    }
    menu::views_and_commands(ui, requests);
    action
}

/// Does what was picked in a right-click menu, and shows the rename/comment popup.
fn apply(
    ui: &mut Ui,
    doc: &mut Document,
    requests: &mut Vec<ViewRequest>,
    state: &mut PanelState,
    action: Option<MenuAction>,
    port_mode: &mut bool,
) {
    match action {
        Some(MenuAction::GoTo(a)) => {
            if !doc.navigate_to_address(a) {
                requests.push(ViewRequest::Message(format!(
                    "0x{a:x} is not inside the file."
                )));
            }
        }
        Some(MenuAction::Rename(a)) => state.popup = Some(EditPopup::rename(doc, a)),
        Some(MenuAction::Comment(a)) => state.popup = Some(EditPopup::comment(doc, a)),
        Some(MenuAction::Xrefs(a)) => {
            doc.xref_target = Some(a);
            requests.push(ViewRequest::ShowXrefs);
        }
        Some(MenuAction::Mode(port)) => *port_mode = port,
        Some(MenuAction::Find) => state.find.show(),
        None => {}
    }
    if let Some(popup) = &mut state.popup
        && !edit::show(ui, doc, popup)
    {
        state.popup = None;
    }
}

/// `job` with the matches (byte offsets `starts`, each `len` long) given a background; the
/// `current` one stronger.
fn mark_matches(
    job: &LayoutJob,
    starts: &[usize],
    len: usize,
    current: Option<usize>,
) -> LayoutJob {
    let found = Color32::from_rgb(230, 180, 40);
    let mut out = job.clone();
    out.sections.clear();
    for section in &job.sections {
        let (start, end): (usize, usize) = (
            section.byte_range.start.into(),
            section.byte_range.end.into(),
        );
        let mut cuts = vec![start, end];
        for &m in starts {
            for b in [m, m + len] {
                if b > start && b < end {
                    cuts.push(b);
                }
            }
        }
        cuts.sort_unstable();
        cuts.dedup();
        for (k, w) in cuts.windows(2).enumerate() {
            let mut format = section.format.clone();
            // The match this piece belongs to: the last one starting at or before it.
            let i = starts.partition_point(|&m| m <= w[0]);
            if i > 0 && w[1] <= starts[i - 1] + len {
                let strength = if current == Some(i - 1) { 0.6 } else { 0.25 };
                format.background = found.gamma_multiply(strength);
            }
            out.sections.push(egui::text::LayoutSection {
                leading_space: if k == 0 { section.leading_space } else { 0.0 },
                byte_range: w[0].into()..w[1].into(),
                format,
            });
        }
    }
    out
}

/// The Rust-port "does this compile?" affordance (behind the `compile-check` feature): a
/// button that runs `rustc` over the scaffold, then a ✓ / ✗ badge with the diagnostics.
#[cfg(feature = "compile-check")]
fn port_compile_check(ui: &mut egui::Ui, pkey: egui::Id, src: &str) {
    use orress_decompiler::compile::{CompileStatus, check_source};

    let key = pkey.with("compile");
    let cached: Option<std::sync::Arc<(CompileStatus, String)>> =
        ui.ctx().data(|d| d.get_temp(key));
    if ui
        .small_button("Check compiles")
        .on_hover_text("Run rustc over this scaffold")
        .clicked()
    {
        let r = check_source(src);
        ui.ctx()
            .data_mut(|d| d.insert_temp(key, std::sync::Arc::new((r.status, r.diagnostics))));
    }
    if let Some(r) = cached {
        let (status, diags) = &*r;
        match status {
            CompileStatus::Compiles => {
                ui.colored_label(egui::Color32::from_rgb(0x4c, 0xaf, 0x50), "✓ compiles");
            }
            CompileStatus::Errors => {
                ui.colored_label(egui::Color32::from_rgb(0xe5, 0x73, 0x73), "✗ errors")
                    .on_hover_text(diags.as_str());
            }
            CompileStatus::ToolMissing => {
                ui.label(muted("rustc not found"))
                    .on_hover_text(diags.as_str());
            }
        }
    }
}

/// Builds decompiler type hints from the document's type catalog and function prototypes:
/// user struct layouts (to name recovered struct parameters and their fields) and lowered
/// prototypes (to override a function's signature).
fn build_hints(doc: &Document) -> orress_decompiler::types::TypeHints {
    use orress_decompiler::types as dt;
    use orress_project::types::UserType;

    let catalog = doc.type_catalog();
    let mut structs = Vec::new();
    for ty in catalog.types.values() {
        if let UserType::Struct { name, .. } = ty
            && let Some(laid) = catalog.layout(ty)
        {
            let fields = laid
                .iter()
                .filter(|f| f.count == 1)
                .filter_map(|f| {
                    let (w, signed) = scalar_width(&catalog, &f.ty)?;
                    Some((
                        f.offset,
                        orress_decompiler::ir::Width(w),
                        signed,
                        f.path.clone(),
                    ))
                })
                .collect();
            structs.push(dt::StructDef {
                name: name.clone(),
                fields,
            });
        }
    }

    let mut prototypes = std::collections::BTreeMap::new();
    for (&addr, proto) in &doc.annotations.func_prototypes {
        let params = proto
            .params
            .iter()
            .map(|(_, t)| {
                lower_ty(&catalog, t).unwrap_or(dt::Ty::Int(orress_decompiler::ir::Width(8), false))
            })
            .collect();
        let ret = proto.ret.as_ref().and_then(|t| lower_ty(&catalog, t));
        prototypes.insert(addr, dt::Proto { ret, params });
    }

    dt::TypeHints {
        structs,
        prototypes,
    }
}

/// The integer byte-width and signedness of a scalar field type, or `None` for a type that
/// is not a fixed-width scalar (a nested struct, say) and so cannot name a recovered field.
fn scalar_width(
    catalog: &orress_project::TypeCatalog,
    ty: &orress_project::TypeRef,
) -> Option<(u8, bool)> {
    use orress_project::types::{Prim, TypeRef};
    match ty {
        TypeRef::Prim(Prim::U8 | Prim::Char | Prim::Bool) => Some((1, false)),
        TypeRef::Prim(Prim::I8) => Some((1, true)),
        TypeRef::Prim(Prim::U16) => Some((2, false)),
        TypeRef::Prim(Prim::I16) => Some((2, true)),
        TypeRef::Prim(Prim::U32) => Some((4, false)),
        TypeRef::Prim(Prim::I32) => Some((4, true)),
        TypeRef::Prim(Prim::U64) => Some((8, false)),
        TypeRef::Prim(Prim::I64) => Some((8, true)),
        TypeRef::Pointer(_) => Some((catalog.pointer_size as u8, false)),
        _ => None,
    }
}

/// Lowers a user type reference into a decompiler [`Ty`] for a function prototype.
fn lower_ty(
    catalog: &orress_project::TypeCatalog,
    ty: &orress_project::TypeRef,
) -> Option<orress_decompiler::types::Ty> {
    use orress_decompiler::types as dt;
    use orress_project::types::{Prim, TypeRef, UserType};

    match ty {
        TypeRef::Prim(Prim::F32) => Some(dt::Ty::Float(orress_decompiler::ir::Width(4))),
        TypeRef::Prim(Prim::F64) => Some(dt::Ty::Float(orress_decompiler::ir::Width(8))),
        TypeRef::Prim(Prim::Bool) => Some(dt::Ty::Bool),
        TypeRef::Prim(Prim::Void) => None,
        TypeRef::Prim(_) => {
            let (w, signed) = scalar_width(catalog, ty)?;
            Some(dt::Ty::Int(orress_decompiler::ir::Width(w), signed))
        }
        TypeRef::Pointer(inner) => match inner.as_ref() {
            // A pointer to a user struct becomes a named struct parameter.
            TypeRef::Named(name) => {
                let user = catalog.types.get(name)?;
                let fields = catalog
                    .layout(user)?
                    .iter()
                    .filter(|f| f.count == 1)
                    .filter_map(|f| {
                        let (w, signed) = scalar_width(catalog, &f.ty)?;
                        Some((
                            f.offset,
                            f.path.clone(),
                            dt::Field {
                                offset: f.offset,
                                width: orress_decompiler::ir::Width(w),
                                signed,
                            },
                        ))
                    })
                    .collect::<Vec<_>>();
                let field_names = fields.iter().map(|(o, n, _)| (*o, n.clone())).collect();
                let layout = dt::StructLayout {
                    name: name.clone(),
                    fields: fields.into_iter().map(|(_, _, f)| f).collect(),
                    field_names,
                };
                let mutable = matches!(user, UserType::Struct { .. });
                Some(dt::Ty::Struct(layout, mutable))
            }
            // A pointer to a scalar becomes a reference of that width.
            other => {
                let (w, _) = scalar_width(catalog, other)?;
                Some(dt::Ty::Ref(orress_decompiler::ir::Width(w), false))
            }
        },
        TypeRef::Named(_) => None,
    }
}
