//! The IL panel: the function under the cursor shown as the decompiler's lifted, simplified
//! intermediate representation — the stage between raw assembly and structured pseudocode.
//! Read-only and teaching-oriented; the printing lives in `orress_decompiler::il`.

use std::sync::{Arc, Weak};

use egui::{Color32, FontId, RichText, Ui};
use orress_analysis::Program;
use orress_decompiler::{Output, TokKind};
use orress_project::DocStore;
use orress_ui::muted;

use crate::{ViewRequest, code};

type Cached = Arc<Result<Output, String>>;

/// One cached IL result, pinned to a program (a patch makes a new program) and its annotation
/// generation.
#[derive(Clone)]
struct Entry {
    program: Weak<Program>,
    func: u64,
    value: Cached,
}

fn cache_id() -> egui::Id {
    egui::Id::new("orress::il_cache")
}

const EXPLAIN: &str = "The IL view shows the decompiler's intermediate representation: machine \
    code lifted into simple statements and expressions, in basic blocks, before it is \
    structured into if/while and printed as Rust. It is a window on how decompilation works — \
    registers become variables, flags become comparisons, and each line keeps the address it \
    came from. The decompiler tab shows the finished, readable result.";

/// Maps a token kind to a theme colour (mirrors the decompiler view).
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

pub fn il_panel(ui: &mut Ui, docs: &mut DocStore, _requests: &mut [ViewRequest]) {
    let Some(doc) = docs.active_mut() else {
        ui.label(muted(
            "Open a program and put the cursor in a function to see its lifted IR.",
        ));
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
        ui.label(muted(
            "Put the cursor inside a function in the disassembly to lift it.",
        ));
        return;
    };

    // Reuse the last result for this (program, function); patches make a new program.
    let cached: Option<Cached> = ui.ctx().data_mut(|d| {
        let e = d.get_temp::<Entry>(cache_id());
        e.filter(|e| e.func == func && Weak::ptr_eq(&e.program, &Arc::downgrade(&program)))
            .map(|e| e.value)
    });
    let out = cached.unwrap_or_else(|| {
        let conv = orress_decompiler::convention(format);
        let r = Arc::new(orress_decompiler::il(&program, func, conv).map_err(|e| e.to_string()));
        ui.ctx().data_mut(|d| {
            d.insert_temp(
                cache_id(),
                Entry {
                    program: Arc::downgrade(&program),
                    func,
                    value: Arc::clone(&r),
                },
            );
        });
        r
    });

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "Lifted IR: {}",
                code::describe_address(doc, &program, func)
            ))
            .strong(),
        )
        .on_hover_text(EXPLAIN);
        ui.label(muted(format!("(0x{func:x})")));
    });
    ui.separator();

    let output = match &*out {
        Ok(o) => o,
        Err(e) => {
            ui.label(muted(format!("Cannot lift this function: {e}")));
            return;
        }
    };

    let syntax = code::syntax(ui.ctx());
    let text = ui.visuals().text_color();
    let font = FontId::monospace(13.0);
    let mut go: Option<u64> = None;
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 1.0);
            for line in &output.lines {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("    ".repeat(line.indent)).font(font.clone()));
                    for span in &line.spans {
                        let rich = RichText::new(span.text.clone())
                            .font(font.clone())
                            .color(color(span.kind, &syntax, text));
                        // Block labels / call targets are clickable to navigate the disassembly.
                        if let Some(addr) = span.target {
                            if ui
                                .add(egui::Label::new(rich).sense(egui::Sense::click()))
                                .on_hover_text(format!("Go to 0x{addr:x}"))
                                .clicked()
                            {
                                go = Some(addr);
                            }
                        } else {
                            ui.add(egui::Label::new(rich).selectable(true));
                        }
                    }
                });
            }
        });
    if let Some(addr) = go {
        doc.navigate_to_address(addr);
    }
}
