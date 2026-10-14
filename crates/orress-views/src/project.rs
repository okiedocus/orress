//! Project overview (left dock): open files and their views.

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_ui::{ExplainExt as _, muted};

use crate::{DocView, ViewRequest};

pub fn project_tree(ui: &mut Ui, docs: &DocStore, requests: &mut Vec<ViewRequest>) {
    if docs.iter().next().is_none() {
        ui.heading("Project");
        ui.label("No files open. Use File > Open (Ctrl+O) or drop a file on the window.");
        return;
    }
    for doc in docs.iter() {
        let active = docs.active.as_deref() == Some(doc.path.as_path());
        let title = RichText::new(doc.file_name());
        egui::CollapsingHeader::new(if active { title.strong() } else { title })
            .id_salt(&doc.path)
            .default_open(true)
            .show(ui, |ui| {
                match (doc.data(), doc.analysis()) {
                    (None, _) => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(muted("reading…"));
                        });
                    }
                    (Some(Err(e)), _) => {
                        ui.colored_label(ui.visuals().error_fg_color, e);
                        return;
                    }
                    (Some(Ok(_)), None) => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(muted("analyzing…"));
                        });
                    }
                    (Some(Ok(_)), Some(a)) => {
                        ui.label(muted(format!("{} · {}", a.info.format.name(), a.info.arch)));
                    }
                }
                for view in DocView::ALL {
                    let mut label = view.name().to_owned();
                    if let Some(a) = doc.analysis() {
                        match view {
                            DocView::Sections => label += &format!(" ({})", a.info.sections.len()),
                            DocView::Imports => label += &format!(" ({})", a.info.imports.len()),
                            DocView::Strings => label += &format!(" ({})", a.strings.len()),
                            DocView::Functions => {
                                if let Some(p) = doc.program() {
                                    label += &format!(" ({})", p.functions.len());
                                }
                            }
                            _ => {}
                        }
                    }
                    let response = ui
                        .selectable_label(false, label)
                        .explain(view.name(), view.explain());
                    orress_ui::spotlight::mark(
                        ui.ctx(),
                        &format!("tree.{}", view.name()),
                        response.rect,
                    );
                    if response.clicked() {
                        requests.push(ViewRequest::Open(doc.path.clone(), view));
                    }
                }
            });
    }
}
