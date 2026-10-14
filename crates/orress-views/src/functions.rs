//! Functions list.

use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use orress_analysis::FunctionKind;
use orress_project::Document;
use orress_ui::{ExplainExt as _, muted};

use crate::{DocView, ViewCtx, ViewRequest};

#[derive(Default)]
pub struct FunctionsState {
    filter: String,
    show_thunks: bool,
    cache: Option<(String, u64, Vec<u64>)>,
}

pub fn functions(
    ui: &mut Ui,
    doc: &mut Document,
    state: &mut FunctionsState,
    cx: &mut ViewCtx<'_>,
) {
    let Some(program) = crate::program_or_message(ui, doc) else {
        return;
    };
    ui.label(muted(
        "Every function ORRESS found by following calls from the entry point and known \
         symbols. Names like sub_401000 are generated: rename them (N in the disassembly) as \
         you understand what they do. Callers: how many places call it.",
    ));
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .hint_text("Filter by name…")
                .desired_width(220.0),
        );
        ui.checkbox(&mut state.show_thunks, "Show import stubs")
            .explain(
                "Import stubs",
                "Tiny functions that only jump to a library function (PLT entries on Linux, \
             import thunks on Windows). Hidden by default because they all look the same.",
            );
        if let Some(main) = program.main
            && ui
                .button("Go to main")
                .explain(
                    "main",
                    "Jump to the program's own main function, past the start-up code.",
                )
                .clicked()
        {
            doc.navigate_to_address(main);
            cx.requests
                .push(ViewRequest::Open(doc.path.clone(), DocView::Disassembly));
        }
    });

    let key = format!("{}{}", state.filter, state.show_thunks);
    if state
        .cache
        .as_ref()
        .is_none_or(|(k, g, _)| *k != key || *g != doc.generation)
    {
        let filter = state.filter.to_lowercase();
        let list = program
            .functions
            .values()
            .filter(|f| state.show_thunks || f.kind != FunctionKind::Thunk)
            .filter(|f| {
                filter.is_empty()
                    || doc
                        .name_of(f.entry)
                        .is_some_and(|n| n.to_lowercase().contains(&filter))
            })
            .map(|f| f.entry)
            .collect();
        state.cache = Some((key, doc.generation, list));
    }
    let Some((_, _, list)) = &state.cache else {
        return;
    };
    ui.label(muted(format!(
        "{} of {} functions",
        list.len(),
        program.functions.len()
    )));

    let wide = program.isa.pointer_size() == 8;
    let current = program
        .memory
        .address_of(doc.cursor)
        .and_then(|a| program.function_containing(a))
        .map(|f| f.entry);
    let mut clicked = None;
    TableBuilder::new(ui)
        .id_salt("functions")
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(200.0))
        .column(Column::auto().at_least(if wide { 150.0 } else { 90.0 }))
        .columns(Column::auto().at_least(60.0), 3)
        .column(Column::remainder())
        .header(20.0, |mut h| {
            for (name, explain) in [
                ("Name", "The function's name: from the file's symbols, found by ORRESS (main), yours, or generated."),
                ("Address", "Where the function starts in memory."),
                ("Size", "Bytes of code."),
                ("Blocks", "Basic blocks: more blocks means more branches and loops."),
                ("Callers", "How many places call this function. Small functions with many callers are often helpers like strlen."),
                ("", ""),
            ] {
                h.col(|ui| {
                    ui.label(RichText::new(name).strong()).explain(name, explain);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, list.len(), |mut row| {
                let entry = list[row.index()];
                let Some(f) = program.functions.get(&entry) else {
                    return;
                };
                row.set_selected(current == Some(entry));
                let name = doc.name_of(entry).unwrap_or_else(|| format!("sub_{entry:x}"));
                let user = doc.annotations.names.contains_key(&entry);
                row.col(|ui| {
                    let text = RichText::new(name).monospace();
                    ui.label(if user { text.strong() } else { text });
                });
                row.col(|ui| {
                    ui.label(RichText::new(crate::fmt_addr(entry, wide)).monospace());
                });
                row.col(|ui| {
                    ui.label(f.size().to_string());
                });
                row.col(|ui| {
                    ui.label(f.blocks.len().to_string());
                });
                row.col(|ui| {
                    ui.label(program.xrefs(entry).len().to_string());
                });
                row.col(|ui| {
                    if program.main == Some(entry) {
                        ui.label(RichText::new("main").small().color(ui.visuals().hyperlink_color));
                    } else if f.kind == FunctionKind::Thunk {
                        ui.label(muted("import stub"));
                    }
                });
                if row.response().clicked() {
                    clicked = Some(entry);
                }
            });
        });
    if let Some(entry) = clicked {
        doc.navigate_to_address(entry);
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Disassembly));
    }
}
