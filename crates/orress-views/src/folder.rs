//! The project folder tree (left dock, top section): a Zed-style view of a folder on disk.
//! Clicking a file opens it the usual way (source to the editor, binaries to analysis); the
//! right-click menu reveals a path in the OS, makes a notes file, or extracts an executable's
//! resources into the project.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use egui::{RichText, Ui};
use orress_project::DocStore;

use crate::ViewRequest;

/// At most this many entries are listed per directory (a guard against pathological folders).
const MAX_ENTRIES: usize = 5000;

/// One entry in a directory listing.
#[derive(Clone)]
struct Entry {
    name: String,
    path: PathBuf,
    is_dir: bool,
}

/// Cached directory listings, so the tree does not `read_dir` every frame. Cleared when the
/// project root changes or the user presses Refresh.
#[derive(Clone, Default)]
struct FolderCache {
    root: Option<PathBuf>,
    dirs: std::collections::HashMap<PathBuf, Arc<Result<Vec<Entry>, String>>>,
}

fn cache_id() -> egui::Id {
    egui::Id::new("orress::folder_cache")
}

/// Reads (and caches) the sorted listing of `dir`: directories first, then files, each
/// alphabetical and case-insensitive.
fn listing(cache: &mut FolderCache, dir: &Path) -> Arc<Result<Vec<Entry>, String>> {
    if let Some(hit) = cache.dirs.get(dir) {
        return Arc::clone(hit);
    }
    let result = read_dir_sorted(dir);
    let arc = Arc::new(result);
    cache.dirs.insert(dir.to_path_buf(), Arc::clone(&arc));
    arc
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<Entry>, String> {
    let mut entries: Vec<Entry> = Vec::new();
    let read = std::fs::read_dir(dir).map_err(|e| format!("{e}"))?;
    for item in read.take(MAX_ENTRIES).flatten() {
        let path = item.path();
        let is_dir = item.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let name = item.file_name().to_string_lossy().into_owned();
        entries.push(Entry { name, path, is_dir });
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

/// Draws the folder tree for `root`.
pub fn folder_tree(ui: &mut Ui, root: &Path, docs: &DocStore, requests: &mut Vec<ViewRequest>) {
    let mut cache = ui
        .data_mut(|d| d.get_temp::<FolderCache>(cache_id()))
        .unwrap_or_default();
    // Reset when the project root changes.
    if cache.root.as_deref() != Some(root) {
        cache = FolderCache {
            root: Some(root.to_path_buf()),
            dirs: Default::default(),
        };
    }

    ui.horizontal(|ui| {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.display().to_string());
        ui.label(RichText::new(name).strong());
        if ui.small_button("⟳").on_hover_text("Refresh").clicked() {
            cache.dirs.clear();
        }
    });
    ui.add_space(2.0);

    let active = docs.active.as_deref().map(Path::to_path_buf);
    render_dir(ui, root, &mut cache, requests, active.as_deref());

    ui.data_mut(|d| d.insert_temp(cache_id(), cache));
}

fn render_dir(
    ui: &mut Ui,
    dir: &Path,
    cache: &mut FolderCache,
    requests: &mut Vec<ViewRequest>,
    active: Option<&Path>,
) {
    let entries = listing(cache, dir);
    match entries.as_ref() {
        Err(e) => {
            ui.colored_label(ui.visuals().warn_fg_color, e.as_str());
        }
        Ok(entries) => {
            for entry in entries.iter() {
                if entry.is_dir {
                    let path = entry.path.clone();
                    let header = egui::CollapsingHeader::new(&entry.name)
                        .id_salt(&entry.path)
                        .show(ui, |ui| {
                            render_dir(ui, &path, cache, requests, active);
                        });
                    header
                        .header_response
                        .context_menu(|ui| dir_menu(ui, &entry.path, requests));
                } else {
                    let is_active = active == Some(entry.path.as_path());
                    let label = if is_active {
                        RichText::new(&entry.name).strong()
                    } else {
                        RichText::new(&entry.name)
                    };
                    let response = ui.selectable_label(is_active, label);
                    if response.clicked() {
                        requests.push(ViewRequest::OpenPath(entry.path.clone()));
                    }
                    response.context_menu(|ui| file_menu(ui, &entry.path, requests));
                }
            }
        }
    }
}

fn file_menu(ui: &mut Ui, path: &Path, requests: &mut Vec<ViewRequest>) {
    if ui.button("Open").clicked() {
        requests.push(ViewRequest::OpenPath(path.to_path_buf()));
        ui.close();
    }
    if is_executable(path) && ui.button("Extract resources…").clicked() {
        requests.push(ViewRequest::ExtractResources(path.to_path_buf()));
        ui.close();
    }
    if ui.button("Reveal in file manager").clicked() {
        requests.push(ViewRequest::RevealInOs(path.to_path_buf()));
        ui.close();
    }
}

fn dir_menu(ui: &mut Ui, dir: &Path, requests: &mut Vec<ViewRequest>) {
    if ui.button("New notes file…").clicked() {
        requests.push(ViewRequest::NewNotesFile(dir.to_path_buf()));
        ui.close();
    }
    if ui.button("Reveal in file manager").clicked() {
        requests.push(ViewRequest::RevealInOs(dir.to_path_buf()));
        ui.close();
    }
}

/// Whether a path looks like a Windows executable image (used only to offer resource extraction;
/// the extractor itself validates the bytes).
fn is_executable(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(
            "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "efi" | "mui" | "node" | "drv" | "ax"
                | "tsp"
        )
    )
}
