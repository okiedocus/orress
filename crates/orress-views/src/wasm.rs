//! The WebAssembly view: a structured overview of an open `.wasm` module (imports, exports,
//! functions with signatures, memories, globals) and its WAT disassembly, powered by the
//! pure-Rust `orress-wasm` loader. Parsing is cached per file so switching panels is instant.

use std::path::PathBuf;

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_ui::muted;
use orress_wasm::{WasmModule, is_wasm};

/// WAT larger than this is truncated in the display (the file can still be huge; the panel stays
/// responsive). Typical CTF/malware wasm is far smaller.
const MAX_WAT_SHOWN: usize = 800_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Panel {
    Overview,
    Disassembly,
}

/// Persistent UI state for the WASM tab.
pub struct WasmView {
    /// (path, byte length) of the parsed file, so we re-parse when the file changes.
    key: Option<(PathBuf, usize, u64)>,
    module: Option<WasmModule>,
    wat: Option<Result<String, String>>,
    panel: Panel,
}

impl Default for WasmView {
    fn default() -> Self {
        Self {
            key: None,
            module: None,
            wat: None,
            panel: Panel::Overview,
        }
    }
}

pub fn wasm_view(ui: &mut Ui, view: &mut WasmView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Wasm", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("WebAssembly").strong());
        ui.label(muted(
            "module overview · WAT disassembly (pure-Rust wasm-tools)",
        ));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a .wasm file to inspect it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };
    if !is_wasm(bytes) {
        ui.label(muted(format!(
            "{} is not a WebAssembly module (it does not start with the \\0asm magic).",
            doc.file_name()
        )));
        return;
    }

    // (Re)parse when the active file changes.
    let key = (doc.path.clone(), bytes.len(), doc.generation);
    if view.key.as_ref() != Some(&key) {
        view.module = Some(orress_wasm::parse(bytes));
        view.wat = Some(orress_wasm::disassemble(bytes));
        view.key = Some(key);
    }
    let Some(module) = &view.module else { return };

    ui.horizontal(|ui| {
        ui.selectable_value(&mut view.panel, Panel::Overview, "Overview");
        ui.selectable_value(&mut view.panel, Panel::Disassembly, "Disassembly (WAT)");
        ui.separator();
        ui.label(muted(format!("wasm v{}", module.version)));
    });
    if module.is_component {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            "This is a WebAssembly component, not a core module — the overview may be incomplete.",
        );
    }
    if let Some(e) = &module.parse_error {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!("Parsing stopped early: {e} (showing what was read)"),
        );
    }
    ui.add_space(4.0);

    match view.panel {
        Panel::Overview => overview(ui, module),
        Panel::Disassembly => disassembly(ui, view.wat.as_ref()),
    }
}

fn overview(ui: &mut Ui, m: &WasmModule) {
    ui.label(RichText::new(m.summary()).strong());
    if let Some(s) = m.start_func {
        ui.label(muted(format!("start function: {s}")));
    }
    ui.add_space(6.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Imports
            if !m.imports.is_empty() {
                section(ui, &format!("Imports ({})", m.imports.len()));
                for imp in &m.imports {
                    let sig = match &imp.kind {
                        orress_wasm::ImportKind::Func(ti) => {
                            m.types.get(*ti as usize).map(|t| t.signature())
                        }
                        _ => None,
                    };
                    let line = match sig {
                        Some(s) => {
                            format!("  {} · {}.{}  {s}", imp.kind.label(), imp.module, imp.name)
                        }
                        None => format!("  {} · {}.{}", imp.kind.label(), imp.module, imp.name),
                    };
                    ui.label(RichText::new(line).monospace());
                }
                ui.add_space(6.0);
            }

            // Exports
            if !m.exports.is_empty() {
                section(ui, &format!("Exports ({})", m.exports.len()));
                for e in &m.exports {
                    ui.label(
                        RichText::new(format!("  {} · {} [{}]", e.kind, e.name, e.index))
                            .monospace(),
                    );
                }
                ui.add_space(6.0);
            }

            // Functions
            if !m.functions.is_empty() {
                section(ui, &format!("Defined functions ({})", m.functions.len()));
                egui::Grid::new("wasm-funcs")
                    .striped(true)
                    .num_columns(5)
                    .spacing([14.0, 3.0])
                    .show(ui, |ui| {
                        for h in ["#", "name", "signature", "locals/ops", "bytes"] {
                            ui.label(RichText::new(h).strong());
                        }
                        ui.end_row();
                        for f in &m.functions {
                            ui.label(RichText::new(f.index.to_string()).monospace());
                            ui.label(
                                RichText::new(f.name.clone().unwrap_or_else(|| "—".into()))
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new(
                                    f.sig.as_ref().map(|s| s.signature()).unwrap_or_default(),
                                )
                                .monospace()
                                .weak(),
                            );
                            ui.label(
                                RichText::new(format!("{} / {}", f.locals, f.ops)).monospace(),
                            );
                            ui.label(RichText::new(f.size.to_string()).monospace());
                            ui.end_row();
                        }
                    });
                ui.add_space(6.0);
            }

            // Memories & globals
            if !m.memories.is_empty() {
                section(ui, &format!("Memories ({})", m.memories.len()));
                for mem in &m.memories {
                    let max = mem
                        .max_pages
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "∞".into());
                    let flags = [
                        mem.memory64.then_some("memory64"),
                        mem.shared.then_some("shared"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ");
                    let suffix = if flags.is_empty() {
                        String::new()
                    } else {
                        format!("  ({flags})")
                    };
                    ui.label(
                        RichText::new(format!(
                            "  {} … {} pages (×64 KiB){suffix}",
                            mem.min_pages, max
                        ))
                        .monospace(),
                    );
                }
                ui.add_space(6.0);
            }
            if !m.globals.is_empty() {
                section(ui, &format!("Globals ({})", m.globals.len()));
                for (i, g) in m.globals.iter().enumerate() {
                    let mu = if g.mutable { "mut " } else { "" };
                    ui.label(RichText::new(format!("  [{i}] {mu}{}", g.ty)).monospace());
                }
                ui.add_space(6.0);
            }

            // Misc
            let mut misc = Vec::new();
            if m.table_count > 0 {
                misc.push(format!("{} table(s)", m.table_count));
            }
            if m.data_segments > 0 {
                misc.push(format!("{} data segment(s)", m.data_segments));
            }
            if !misc.is_empty() {
                ui.label(muted(misc.join(" · ")));
            }
            if !m.custom_sections.is_empty() {
                section(ui, "Custom sections");
                for (name, len) in &m.custom_sections {
                    ui.label(
                        RichText::new(format!("  {name} ({len} bytes)"))
                            .monospace()
                            .weak(),
                    );
                }
            }
        });
}

fn disassembly(ui: &mut Ui, wat: Option<&Result<String, String>>) {
    match wat {
        None => {
            ui.label(muted("No disassembly."));
        }
        Some(Err(e)) => {
            ui.colored_label(
                ui.visuals().error_fg_color,
                format!("Could not disassemble: {e}"),
            );
        }
        Some(Ok(text)) => {
            let shown = if text.len() > MAX_WAT_SHOWN {
                ui.label(muted(format!(
                    "WAT is {} bytes; showing the first {}.",
                    text.len(),
                    MAX_WAT_SHOWN
                )));
                &text[..crate::code::floor_char_boundary(text, MAX_WAT_SHOWN)]
            } else {
                text.as_str()
            };
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // A read-only, selectable code view (copy with Ctrl+C).
                    let mut buf = shown;
                    ui.add(
                        egui::TextEdit::multiline(&mut buf)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                });
        }
    }
}

fn section(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).strong().underline());
}
