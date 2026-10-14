//! Cross-references panel: who uses an address.
//!
//! It follows the function under the cursor until a target is pinned (X in the disassembly,
//! or the Pin button); "Follow cursor" unpins it again.

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_ui::muted;

use crate::{DocView, ViewRequest, code};

pub fn xrefs_panel(ui: &mut Ui, docs: &mut DocStore, requests: &mut Vec<ViewRequest>) {
    let Some(doc) = docs.active_mut() else {
        ui.label(
            "Open a file, put the cursor on a function or address in the disassembly and press X.",
        );
        return;
    };
    let Some(program) = doc.program().cloned() else {
        ui.label(muted("Waiting for the disassembly…"));
        return;
    };
    // A pinned target (X in the disassembly), else the function under the cursor.
    let pinned = doc.xref_target.is_some();
    let target = doc.xref_target.or_else(|| {
        let addr = program.memory.address_of(doc.cursor)?;
        program.function_containing(addr).map(|f| f.entry)
    });
    let Some(target) = target else {
        ui.label("Put the cursor on code, or press X on an address in the disassembly.");
        return;
    };
    let name = code::describe_address(doc, &program, target);
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("References to {name}")).strong());
        ui.label(muted(format!("(0x{target:x})")));
        if pinned {
            if ui
                .small_button("Follow cursor")
                .on_hover_text("Unpin: show references to the function under the cursor again")
                .clicked()
            {
                doc.xref_target = None;
            }
        } else if ui
            .small_button("📌 Pin")
            .on_hover_text("Keep showing this target while the cursor moves")
            .clicked()
        {
            doc.xref_target = Some(target);
        }
    });
    ui.label(muted(
        "Every place in the code that calls, jumps to or reads this address. Following \
         references is how you find, for example, the code that prints \"Wrong password\".",
    ));
    let refs = program.xrefs(target).to_vec();
    if refs.is_empty() {
        ui.label(
            "No references found. It may be called indirectly (through a pointer) or not at all.",
        );
        return;
    }
    let mut go = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("xrefs")
                .striped(true)
                .num_columns(4)
                .spacing([12.0, 3.0])
                .show(ui, |ui| {
                    for h in ["From", "In", "Kind", "Instruction"] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for xref in &refs {
                        if ui
                            .link(RichText::new(format!("0x{:x}", xref.from)).monospace())
                            .clicked()
                        {
                            go = Some(xref.from);
                        }
                        ui.label(
                            RichText::new(code::describe_address(doc, &program, xref.from))
                                .monospace(),
                        );
                        ui.label(xref.kind.label());
                        let text = program
                            .decode(xref.from)
                            .map(|i| i.text())
                            .unwrap_or_default();
                        ui.label(RichText::new(text).monospace().weak());
                        ui.end_row();
                    }
                });
        });
    if let Some(from) = go {
        doc.navigate_to_address(from);
        requests.push(ViewRequest::Open(doc.path.clone(), DocView::Disassembly));
    }
}
