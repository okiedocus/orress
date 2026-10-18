//! The Resources view: list everything inside the open executable — native Win32 resources,
//! embedded files, sections and overlay — and extract a selection into the project folder.
//! The extraction engine is `orress-resources`; this is the egui front end.

use std::path::{Path, PathBuf};

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_resources::{Resource, ResourceKind};
use orress_ui::muted;

use crate::ViewRequest;

/// Persistent UI state for the Resources tab.
#[derive(Default)]
pub struct ResourcesView {
    /// The file the cache belongs to (path + generation), so a new file or a patch re-scans.
    doc: Option<(PathBuf, u64)>,
    items: Vec<Resource>,
    selected: Vec<bool>,
}

impl ResourcesView {
    fn ensure(&mut self, path: &Path, generation: u64, bytes: &[u8]) {
        if self
            .doc
            .as_ref()
            .is_some_and(|(p, g)| p == path && *g == generation)
        {
            return;
        }
        self.items = orress_resources::extract(bytes);
        self.selected = vec![false; self.items.len()];
        self.doc = Some((path.to_path_buf(), generation));
    }
}

pub fn resources_view(
    ui: &mut Ui,
    view: &mut ResourcesView,
    docs: &DocStore,
    project_root: Option<&Path>,
    requests: &mut Vec<ViewRequest>,
) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Resources", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Resources").strong());
        ui.label(muted(
            "icons · manifest · version · embedded files · sections · overlay",
        ));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open an executable to pull its resources out of it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };
    let path = doc.path.clone();
    view.ensure(&path, doc.generation, bytes);

    if view.items.is_empty() {
        ui.label(muted(format!(
            "Nothing extractable found in {}.",
            doc.file_name()
        )));
        return;
    }

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());

    // Controls.
    ui.horizontal_wrapped(|ui| {
        if ui.button("Select all").clicked() {
            view.selected.iter_mut().for_each(|s| *s = true);
        }
        if ui.button("Select none").clicked() {
            view.selected.iter_mut().for_each(|s| *s = false);
        }
        let any = view.selected.iter().any(|&s| s);
        ui.separator();
        if ui
            .add_enabled(any, egui::Button::new("Extract selected"))
            .clicked()
        {
            let chosen: Vec<Resource> = view
                .items
                .iter()
                .zip(&view.selected)
                .filter(|&(_, &s)| s)
                .map(|(r, _)| r.clone())
                .collect();
            extract_to_project(ui, &chosen, &stem, project_root, requests);
        }
        if ui.button("Extract all").clicked() {
            let all = view.items.clone();
            extract_to_project(ui, &all, &stem, project_root, requests);
        }
    });
    match project_root {
        Some(root) => ui.label(muted(format!(
            "Extracts into {}",
            root.join("extracted").join(&stem).display()
        ))),
        None => ui.label(muted(
            "No project folder open — extracting will ask for one (and adopt it as the project).",
        )),
    };
    ui.separator();

    // The list, grouped by kind.
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for kind in [
                ResourceKind::Resource,
                ResourceKind::Embedded,
                ResourceKind::Overlay,
                ResourceKind::Section,
            ] {
                let indices: Vec<usize> = view
                    .items
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.kind == kind)
                    .map(|(i, _)| i)
                    .collect();
                if indices.is_empty() {
                    continue;
                }
                ui.add_space(4.0);
                ui.label(RichText::new(group_title(kind, indices.len())).strong());
                for i in indices {
                    let r = &view.items[i];
                    let detail = match r.offset {
                        Some(o) => {
                            format!("{}  ·  {}  ·  0x{o:x}", r.ext, human_size(r.data.len()))
                        }
                        None => format!("{}  ·  {}", r.ext, human_size(r.data.len())),
                    };
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut view.selected[i], "");
                        ui.label(&r.name);
                        ui.label(muted(detail));
                    });
                }
            }
        });
}

/// Writes `chosen` to `<project>/extracted/<stem>/`; with no project open, asks for a folder and
/// adopts it as the project root first.
fn extract_to_project(
    ui: &Ui,
    chosen: &[Resource],
    stem: &str,
    project_root: Option<&Path>,
    requests: &mut Vec<ViewRequest>,
) {
    if chosen.is_empty() {
        return;
    }
    let root = match project_root {
        Some(r) => r.to_path_buf(),
        None => {
            let Some(dir) = rfd::FileDialog::new()
                .set_title("Choose a project folder for the extracted files")
                .pick_folder()
            else {
                return;
            };
            requests.push(ViewRequest::SetProjectRoot(dir.clone()));
            dir
        }
    };
    let dest = root.join("extracted").join(stem);
    match orress_resources::write_all(chosen, &dest) {
        Ok(paths) => {
            requests.push(ViewRequest::Message(format!(
                "Extracted {} file{} to {}",
                paths.len(),
                if paths.len() == 1 { "" } else { "s" },
                dest.display()
            )));
        }
        Err(e) => requests.push(ViewRequest::Message(format!("Extraction failed: {e}"))),
    }
    // The folder tree re-reads on its next frame / Refresh.
    ui.ctx().request_repaint();
}

fn group_title(kind: ResourceKind, n: usize) -> String {
    let name = match kind {
        ResourceKind::Resource => "Native resources",
        ResourceKind::Embedded => "Embedded files",
        ResourceKind::Overlay => "Overlay",
        ResourceKind::Section => "Sections",
    };
    format!("{name} ({n})")
}

fn human_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
