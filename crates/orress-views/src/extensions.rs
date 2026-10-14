//! The Extensions panel: see installed extensions, install new ones (from a git URL or a local
//! directory) and uninstall them. Install/uninstall are performed by the app (which owns the
//! extensions directory and re-registers themes and language servers afterwards); the panel emits
//! [`ViewRequest`]s and reads the installed set straight from disk.

use std::path::PathBuf;
use std::sync::Arc;

use egui::{Id, RichText, Ui};
use orress_ui::muted;

use crate::ViewRequest;

fn dir_id() -> Id {
    Id::new("orress::extensions_dir")
}

fn cache_id() -> Id {
    Id::new("orress::extensions_installed")
}

/// The app stores the extensions directory here so the panel can scan it.
pub fn set_extensions_dir(ctx: &egui::Context, dir: PathBuf) {
    ctx.data_mut(|d| d.insert_temp(dir_id(), dir));
    refresh_extensions(ctx);
}

/// Forgets the cached list of installed extensions, so the panel re-reads the manifests from
/// disk the next time it is drawn. The app calls this after an install or uninstall.
pub fn refresh_extensions(ctx: &egui::Context) {
    ctx.data_mut(|d| d.remove_temp::<Arc<Vec<orress_ext::InstalledExtension>>>(cache_id()));
}

/// The installed extensions, read from disk once and then cached (scanning every manifest each
/// frame would hit the disk at the frame rate).
fn installed(
    ctx: &egui::Context,
    dir: &std::path::Path,
) -> Arc<Vec<orress_ext::InstalledExtension>> {
    if let Some(list) = ctx.data(|d| d.get_temp(cache_id())) {
        return list;
    }
    let list = Arc::new(orress_ext::installed(dir));
    ctx.data_mut(|d| d.insert_temp(cache_id(), Arc::clone(&list)));
    list
}

pub(crate) fn extensions_dir(ctx: &egui::Context) -> Option<PathBuf> {
    ctx.data(|d| d.get_temp::<PathBuf>(dir_id()))
}

/// Draws the Extensions panel.
pub fn extensions_panel(ui: &mut Ui, requests: &mut Vec<ViewRequest>) {
    ui.heading("Extensions");
    ui.label(muted(
        "Install ORRESS or Zed-compatible extensions: themes, tree-sitter grammars and \
         language-server adapters. Theme and server changes apply as the extension loads.",
    ));
    ui.separator();

    let Some(dir) = extensions_dir(ui.ctx()) else {
        ui.label(muted(
            "No config directory, so extensions cannot be managed here.",
        ));
        return;
    };

    // Install from a git URL or a local path.
    let src_id = Id::new("orress::ext_install_src");
    let mut src: String = ui.data(|d| d.get_temp(src_id).unwrap_or_default());
    ui.horizontal(|ui| {
        ui.label("Install from:");
        let edit = ui.add(
            egui::TextEdit::singleline(&mut src)
                .hint_text("git URL or local directory path")
                .desired_width(360.0),
        );
        if edit.changed() {
            ui.data_mut(|d| d.insert_temp(src_id, src.clone()));
        }
        let trimmed = src.trim().to_string();
        if ui
            .add_enabled(!trimmed.is_empty(), egui::Button::new("Install"))
            .clicked()
        {
            requests.push(ViewRequest::InstallExtension(trimmed));
            ui.data_mut(|d| d.insert_temp(src_id, String::new()));
        }
    });
    ui.add_space(8.0);

    let installed = installed(ui.ctx(), &dir);
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("Installed ({})", installed.len())).strong());
        if ui
            .small_button("Refresh")
            .on_hover_text("Re-read the extensions folder (e.g. after copying one in by hand)")
            .clicked()
        {
            refresh_extensions(ui.ctx());
        }
    });
    if installed.is_empty() {
        ui.label(muted("Nothing installed yet."));
    }
    for ext in installed.iter() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&ext.name).strong());
            if !ext.version.is_empty() {
                ui.label(muted(format!("v{}", ext.version)));
            }
            ui.label(muted(format!("({})", ext.id)));
            if ui.small_button("Uninstall").clicked() {
                requests.push(ViewRequest::UninstallExtension(ext.id.clone()));
            }
        });
    }

    ui.add_space(6.0);
    ui.label(muted(format!("Directory: {}", dir.display())));
}
