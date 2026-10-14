//! Imports and exports.

use std::collections::BTreeMap;

use egui::{RichText, Ui};
use orress_loaders::apis;
use orress_project::Document;
use orress_ui::{ExplainExt as _, muted};

#[derive(Default)]
pub struct ImportsState {
    filter: String,
    interesting_only: bool,
}

pub fn imports(
    ui: &mut Ui,
    doc: &mut Document,
    state: &mut ImportsState,
    cx: &mut crate::ViewCtx<'_>,
) {
    let Some(analysis) = doc.analysis().cloned() else {
        return;
    };
    let info = &analysis.info;
    ui.label(muted(
        "Imports are functions from other libraries that this program calls, such as strcmp \
         or CreateFileW. They tell you what the program can do before you read any code. \
         Hover a function for an explanation.",
    ));
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .hint_text("Filter…")
                .desired_width(220.0),
        );
        ui.checkbox(&mut state.interesting_only, "Only functions ORRESS knows")
            .explain(
                "Known functions",
                "Show only functions in ORRESS's knowledge base: input, comparison, crypto, \
             anti-debugging, network, injection and similar. A quick way to spot behavior.",
            );
    });
    ui.add_space(4.0);

    let filter = state.filter.to_lowercase();
    let mut groups: BTreeMap<&str, Vec<&orress_loaders::Import>> = BTreeMap::new();
    for import in &info.imports {
        let known = apis::lookup(&import.name);
        if state.interesting_only && known.is_none() {
            continue;
        }
        if !filter.is_empty()
            && !import.name.to_lowercase().contains(&filter)
            && !import.library.to_lowercase().contains(&filter)
        {
            continue;
        }
        let lib = if import.library.is_empty() {
            "(shared libraries)"
        } else {
            import.library.as_str()
        };
        groups.entry(lib).or_default().push(import);
    }

    let program = doc.program().cloned();
    let slots: std::collections::HashMap<&str, u64> = info
        .import_slots
        .iter()
        .map(|s| (s.name.as_str(), s.address))
        .collect();
    let mut follow = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("Imports ({})", info.imports.len()))
                    .strong()
                    .size(15.0),
            );
            if info.imports.is_empty() {
                ui.label(muted(
                    "No imports. Either the program is statically linked (all library code is \
                 inside it), or a packer hides them.",
                ));
            }
            let open_all = !filter.is_empty() || state.interesting_only || groups.len() <= 3;
            for (lib, list) in &groups {
                egui::CollapsingHeader::new(format!("{lib} ({})", list.len()))
                    .id_salt(lib)
                    .default_open(true)
                    .open(open_all.then_some(true))
                    .show(ui, |ui| {
                        for import in list {
                            ui.horizontal(|ui| {
                                let name = RichText::new(&import.name).monospace();
                                match apis::lookup(&import.name) {
                                    Some(api) => {
                                        let color = if api.category.suspicious() {
                                            ui.visuals().warn_fg_color
                                        } else {
                                            ui.visuals().hyperlink_color
                                        };
                                        ui.label(name).explain(&import.name, api.explain);
                                        ui.label(
                                            RichText::new(api.category.name()).small().color(color),
                                        );
                                    }
                                    None => {
                                        ui.label(name);
                                    }
                                }
                                let callers = program
                                    .as_ref()
                                    .zip(slots.get(import.name.as_str()))
                                    .map(|(p, &slot)| import_callers(p, slot))
                                    .unwrap_or_default();
                                if let Some(&first) = callers.first()
                                    && ui
                                        .link(RichText::new(format!("{} »", callers.len())).small())
                                        .on_hover_text("Number of places that call it. Click to go to the first one.")
                                        .clicked()
                                {
                                    follow = Some(first);
                                }
                            });
                        }
                    });
            }

            ui.add_space(10.0);
            ui.label(
                RichText::new(format!("Exports ({})", info.exports.len()))
                    .strong()
                    .size(15.0),
            );
            if info.exports.is_empty() {
                ui.label(muted(
                    "No exports. Normal for programs; libraries (DLLs) export functions.",
                ));
            }
            let wide = info.bits == Some(64);
            egui::Grid::new("exports")
                .striped(true)
                .num_columns(2)
                .show(ui, |ui| {
                    for e in info
                        .exports
                        .iter()
                        .filter(|e| filter.is_empty() || e.name.to_lowercase().contains(&filter))
                        .take(5_000)
                    {
                        ui.monospace(crate::fmt_addr(e.address, wide));
                        ui.monospace(&e.name);
                        ui.end_row();
                    }
                });
        });
    if let Some(from) = follow {
        doc.navigate_to_address(from);
        cx.requests.push(crate::ViewRequest::Open(
            doc.path.clone(),
            crate::DocView::Disassembly,
        ));
    }
}

/// Instructions that call an import: direct uses of its slot, and calls to stubs (PLT
/// entries, thunks) that jump through the slot.
fn import_callers(program: &orress_analysis::Program, slot: u64) -> Vec<u64> {
    let mut out = Vec::new();
    for xref in program.xrefs(slot) {
        match program.functions.get(&xref.from) {
            Some(f) if f.kind == orress_analysis::FunctionKind::Thunk => {
                out.extend(program.xrefs(f.entry).iter().map(|x| x.from));
            }
            _ => out.push(xref.from),
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}
