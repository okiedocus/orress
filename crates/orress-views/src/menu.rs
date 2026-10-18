//! Right-click menus. Each code view adds its own actions for what was clicked, then the
//! shared part: every view that can be opened, and every command of the app, grouped like
//! the command palette. The app publishes its command list with [`set_commands`].

use std::sync::Arc;

use egui::{Context, Ui};
use orress_ui::ExplainExt as _;

use crate::ViewRequest;

/// One app command, as the menus show it.
#[derive(Clone, Debug)]
pub struct CommandEntry {
    /// Action id, e.g. `view::Decompiler`.
    pub id: String,
    pub title: String,
    pub explain: String,
    /// Shortcut label, e.g. `Ctrl+D`, if any.
    pub shortcut: Option<String>,
}

fn commands_id() -> egui::Id {
    egui::Id::new("orress::menu_commands")
}

/// Publishes the app's commands for the right-click menus.
pub fn set_commands(ctx: &Context, commands: Vec<CommandEntry>) {
    ctx.data_mut(|d| d.insert_temp(commands_id(), Arc::new(commands)));
}

fn commands(ctx: &Context) -> Arc<Vec<CommandEntry>> {
    ctx.data(|d| d.get_temp::<Arc<Vec<CommandEntry>>>(commands_id()))
        .unwrap_or_default()
}

/// File views, in the order of the View menu.
const FILE_VIEWS: &[&str] = &[
    "file::Info",
    "file::Functions",
    "view::Disassembly",
    "view::Graph",
    "view::Decompiler",
    "file::Strings",
    "file::Imports",
    "file::Sections",
    "file::Hex",
    "view::Xrefs",
];

/// `view::` commands that change the look instead of opening a view.
const NOT_VIEWS: &[&str] = &[
    "view::ZoomIn",
    "view::ZoomOut",
    "view::ZoomReset",
    "view::ToggleExplainMode",
];

/// A menu item that runs the command `id`; nothing if the app has no such command.
pub(crate) fn command(ui: &mut Ui, requests: &mut Vec<ViewRequest>, id: &str) {
    let all = commands(ui.ctx());
    if let Some(c) = all.iter().find(|c| c.id == id) {
        item(ui, requests, c);
    }
}

fn item(ui: &mut Ui, requests: &mut Vec<ViewRequest>, c: &CommandEntry) {
    let button =
        egui::Button::new(c.title.as_str()).shortcut_text(c.shortcut.clone().unwrap_or_default());
    if ui.add(button).explain(&c.title, &c.explain).clicked() {
        requests.push(ViewRequest::RunAction(c.id.clone()));
        ui.close();
    }
}

/// "Open view" and "All commands" submenus, shared by every right-click menu.
pub(crate) fn views_and_commands(ui: &mut Ui, requests: &mut Vec<ViewRequest>) {
    let all = commands(ui.ctx());
    if all.is_empty() {
        return;
    }
    ui.separator();
    ui.menu_button("Open view", |ui| {
        for id in FILE_VIEWS {
            if let Some(c) = all.iter().find(|c| c.id == *id) {
                item(ui, requests, c);
            }
        }
        ui.separator();
        let mut tools: Vec<&CommandEntry> = all
            .iter()
            .filter(|c| {
                c.id.starts_with("view::")
                    && !FILE_VIEWS.contains(&c.id.as_str())
                    && !NOT_VIEWS.contains(&c.id.as_str())
            })
            .collect();
        tools.sort_by(|a, b| a.title.cmp(&b.title));
        for c in tools {
            item(ui, requests, c);
        }
    });
    ui.menu_button("All commands", |ui| {
        let mut groups: Vec<&str> = Vec::new();
        for c in all.iter() {
            let group = namespace(&c.id);
            if !groups.contains(&group) {
                groups.push(group);
            }
        }
        for group in groups {
            ui.menu_button(group_title(group), |ui| {
                egui::ScrollArea::vertical()
                    .max_height(480.0)
                    .show(ui, |ui| {
                        for c in all.iter().filter(|c| namespace(&c.id) == group) {
                            item(ui, requests, c);
                        }
                    });
            });
        }
    });
}

fn namespace(id: &str) -> &str {
    id.split_once("::").map_or(id, |(ns, _)| ns)
}

/// `command_palette` -> `Command palette`.
fn group_title(namespace: &str) -> String {
    let words = namespace.replace('_', " ");
    let mut chars = words.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Copy items shared by the code views.
pub(crate) fn copy_item(ui: &mut Ui, label: &str, text: String) {
    if ui.button(label).clicked() {
        ui.ctx().copy_text(text);
        ui.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_by_namespace() {
        assert_eq!(namespace("view::Graph"), "view");
        assert_eq!(group_title("command_palette"), "Command palette");
        assert_eq!(group_title("hex"), "Hex");
    }
}
