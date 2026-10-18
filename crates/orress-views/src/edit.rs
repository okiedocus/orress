//! Small popups for renaming and commenting, shared by the code views.

use egui::{Key, RichText, Ui};
use orress_project::Document;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditKind {
    Rename,
    Comment,
}

#[derive(Clone)]
pub struct EditPopup {
    pub kind: EditKind,
    pub addr: u64,
    pub text: String,
    pub error: Option<String>,
    focus: bool,
}

impl EditPopup {
    pub fn rename(doc: &Document, addr: u64) -> Self {
        Self {
            kind: EditKind::Rename,
            addr,
            text: doc
                .annotations
                .names
                .get(&addr)
                .cloned()
                .or_else(|| doc.name_of(addr))
                .unwrap_or_default(),
            error: None,
            focus: true,
        }
    }

    pub fn comment(doc: &Document, addr: u64) -> Self {
        Self {
            kind: EditKind::Comment,
            addr,
            text: doc
                .annotations
                .comments
                .get(&addr)
                .cloned()
                .unwrap_or_default(),
            error: None,
            focus: true,
        }
    }
}

/// Shows the popup; returns `false` when it should close.
pub fn show(ui: &mut Ui, doc: &mut Document, popup: &mut EditPopup) -> bool {
    let mut keep = true;
    let title = match popup.kind {
        EditKind::Rename => format!("Rename 0x{:x}", popup.addr),
        EditKind::Comment => format!("Comment at 0x{:x}", popup.addr),
    };
    egui::Window::new(title)
        .id(ui.id().with("edit_popup"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_TOP, [0.0, 120.0])
        .show(ui.ctx(), |ui| {
            let hint = match popup.kind {
                EditKind::Rename => {
                    "Give it a name that says what it does, e.g. check_password. Leave empty to \
                     restore the original name."
                }
                EditKind::Comment => "Write a note for this line. Leave empty to remove it.",
            };
            ui.label(RichText::new(hint).weak());
            let edit = ui.add(egui::TextEdit::singleline(&mut popup.text).desired_width(360.0));
            if popup.focus {
                edit.request_focus();
                popup.focus = false;
            }
            if let Some(e) = &popup.error {
                ui.colored_label(ui.visuals().warn_fg_color, e);
            }
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            let escape = ui.input(|i| i.key_pressed(Key::Escape));
            ui.horizontal(|ui| {
                if ui.button("OK").clicked() || enter {
                    match popup.kind {
                        EditKind::Rename => match doc.rename(popup.addr, &popup.text) {
                            Ok(()) => keep = false,
                            Err(e) => {
                                popup.error = Some(e);
                                popup.focus = true;
                            }
                        },
                        EditKind::Comment => {
                            doc.set_comment(popup.addr, &popup.text);
                            keep = false;
                        }
                    }
                }
                if ui.button("Cancel").clicked() || escape {
                    keep = false;
                }
            });
        });
    keep
}
