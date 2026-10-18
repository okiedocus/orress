//! The Gadgets panel: list the ROP gadgets in the open binary and filter them, for building
//! return-oriented chains. The finder lives in `orress-pwn`; this is the egui front end.

use std::path::PathBuf;

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_pwn::Gadget;
use orress_ui::muted;

/// Persistent UI state for the Gadgets tab.
#[derive(Default)]
pub struct GadgetsView {
    /// The file (path + generation) the cache belongs to; a new file or a patch re-scans.
    doc: Option<(PathBuf, u64)>,
    gadgets: Vec<Gadget>,
    filter: String,
}

impl GadgetsView {
    fn ensure(&mut self, doc: &orress_project::Document) {
        let key = (doc.path.clone(), doc.generation);
        if self.doc.as_ref() == Some(&key) {
            return;
        }
        self.gadgets = scan(doc);
        self.doc = Some(key);
    }
}

pub fn gadgets_view(ui: &mut Ui, view: &mut GadgetsView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Gadgets", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Gadgets").strong());
        ui.label(muted("ROP gadgets · filter and copy for your chain"));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a binary to find its ROP gadgets."));
        return;
    };
    if doc.program().is_none() {
        ui.label(muted(
            "Analysis is still running (or this file has no code).",
        ));
        return;
    }
    view.ensure(doc);

    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(
            egui::TextEdit::singleline(&mut view.filter)
                .hint_text("pop rdi ; ret")
                .desired_width(260.0),
        );
        if ui.button("Clear").clicked() {
            view.filter.clear();
        }
    });

    let needle = view.filter.to_lowercase();
    let matches: Vec<usize> = view
        .gadgets
        .iter()
        .enumerate()
        .filter(|(_, g)| needle.is_empty() || g.text.to_lowercase().contains(&needle))
        .map(|(i, _)| i)
        .collect();
    ui.label(muted(format!(
        "{} gadget{} ({} shown)",
        view.gadgets.len(),
        if view.gadgets.len() == 1 { "" } else { "s" },
        matches.len()
    )));
    ui.separator();

    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, row_h, matches.len(), |ui, range| {
            for &i in &matches[range] {
                let g = &view.gadgets[i];
                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new(format!("{:#x}", g.addr)).monospace())
                        .on_hover_text("Copy address")
                        .clicked()
                    {
                        ui.ctx().copy_text(format!("{:#x}", g.addr));
                    }
                    ui.label(RichText::new(&g.text).monospace());
                });
            }
        });
}

/// Scans the open binary's executable sections for gadgets.
fn scan(doc: &orress_project::Document) -> Vec<Gadget> {
    let (Some(analysis), Some(program), Some(bytes)) = (doc.analysis(), doc.program(), doc.bytes())
    else {
        return Vec::new();
    };
    let sections: Vec<(u64, &[u8])> = analysis
        .info
        .sections
        .iter()
        .filter(|s| s.perms.execute)
        .filter_map(|s| Some((s.address, bytes.get(s.file_range()?)?)))
        .collect();
    orress_pwn::find_gadgets(&sections, program.isa, 6)
}
