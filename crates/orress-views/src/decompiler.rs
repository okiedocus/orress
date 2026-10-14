//! Decompiler panel: the function under the cursor as Rust-style pseudocode.
//!
//! It follows the cursor of the active file: move through the disassembly and the
//! panel shows (and highlights) the matching line. Clicking a line moves the
//! disassembly there; clicking a function name goes to that function.

use std::sync::{Arc, Weak};

use egui::text::LayoutJob;
use egui::{Align, Color32, FontId, RichText, Sense, Ui};
use orress_analysis::Program;
use orress_decompiler::{Output, TokKind};
use orress_project::DocStore;
use orress_ui::{ExplainExt as _, muted};

use crate::{ViewRequest, code};

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
fn lookup<T>(entries: &mut Vec<Entry<T>>, program: &Arc<Program>, func: u64) -> Option<Arc<T>> {
    let weak = Arc::downgrade(program);
    let i = entries
        .iter()
        .position(|e| e.func == func && Weak::ptr_eq(&e.program, &weak))?;
    let e = entries.remove(i);
    let value = Arc::clone(&e.value);
    entries.push(e);
    Some(value)
}

fn remember<T>(entries: &mut Vec<Entry<T>>, program: &Arc<Program>, func: u64, value: &Arc<T>) {
    // Results for programs that no longer exist (an older patch level, a closed file) go first.
    entries.retain(|e| e.program.strong_count() > 0);
    if entries.len() >= CACHE_ENTRIES {
        entries.remove(0);
    }
    entries.push(Entry {
        program: Arc::downgrade(program),
        func,
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

pub fn decompiler_panel(ui: &mut Ui, docs: &mut DocStore, requests: &mut Vec<ViewRequest>) {
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
    // makes a new program). Names are not part of the output; renames apply when drawing.
    let cached: Option<Cached> = ui.ctx().data_mut(|d| {
        lookup(
            &mut d.get_temp_mut_or_default::<DecompCache>(cache_id()).pseudo,
            &program,
            func,
        )
    });
    let result = cached.unwrap_or_else(|| {
        let conv = orress_decompiler::convention(format);
        let r =
            Arc::new(orress_decompiler::decompile(&program, func, conv).map_err(|e| e.to_string()));
        ui.ctx().data_mut(|d| {
            let cache = d.get_temp_mut_or_default::<DecompCache>(cache_id());
            remember(&mut cache.pseudo, &program, func, &r);
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
    });
    ui.ctx().data_mut(|d| d.insert_temp(mode_id, port_mode));

    // --- Rust port mode: a compilable scaffold rather than reading pseudocode. -----
    if port_mode {
        #[cfg(feature = "compile-check")]
        let pkey = egui::Id::new(("orress::port", &doc.path, func));
        let pcached: Option<PortCached> = ui.ctx().data_mut(|d| {
            lookup(
                &mut d.get_temp_mut_or_default::<DecompCache>(cache_id()).port,
                &program,
                func,
            )
        });
        let pres = pcached.unwrap_or_else(|| {
            let conv = orress_decompiler::convention(format);
            let r =
                Arc::new(orress_decompiler::port(&program, func, conv).map_err(|e| e.to_string()));
            ui.ctx().data_mut(|d| {
                let cache = d.get_temp_mut_or_default::<DecompCache>(cache_id());
                remember(&mut cache.port, &program, func, &r);
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
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .id_salt("port-scroll")
                    .show(ui, |ui| {
                        ui.add(egui::Label::new((*job).clone()).selectable(true));
                    });
            }
            Err(e) => {
                ui.label(e.as_str());
            }
        }
        return;
    }

    let out = match &*result {
        Ok(out) => out,
        Err(e) => {
            ui.label(e.as_str());
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

    let current = cursor.and_then(|a| out.line_for(a));
    // Scroll to the current line only when the cursor moved.
    let moved_key = egui::Id::new("orress::decompiler_cursor");
    let moved = ui.ctx().data(|d| d.get_temp::<Option<u64>>(moved_key)) != Some(cursor);
    ui.ctx().data_mut(|d| d.insert_temp(moved_key, cursor));

    let syntax = code::syntax(ui.ctx());
    let text = ui.visuals().text_color();
    let font = FontId::monospace(13.0);
    let highlight = ui.visuals().selection.bg_fill.gamma_multiply(0.35);
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
                    if moved {
                        // Only scroll vertically: keep the start of the line in view.
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
                if let Some(a) = on_target {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    if r.clicked() {
                        go = Some(a);
                    }
                    r.on_hover_text(format!("Go to 0x{a:x}"));
                } else if r.clicked() {
                    go = line.addr;
                }
            }
        });
    if let Some(a) = go {
        doc.navigate_to_address(a);
    }
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
