//! The .NET view: open a managed PE and browse its metadata — types (with their methods), the
//! assembly/module names, the metadata-table overview, and the `#US` user strings (the string
//! literals in the IL) — powered by the pure-Rust `orress-dotnet` loader. Cached per file.

use std::path::PathBuf;

use egui::{RichText, Ui};
use orress_dotnet::DotNet;
use orress_project::DocStore;
use orress_ui::muted;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Types,
    Strings,
}

/// Persistent UI state for the .NET tab.
pub struct DotNetView {
    key: Option<(PathBuf, usize, u64)>,
    dn: Option<Result<DotNet, String>>,
    selected: usize,
    method_sel: usize,
    mode: Mode,
}

impl Default for DotNetView {
    fn default() -> Self {
        Self {
            key: None,
            dn: None,
            selected: 0,
            method_sel: 0,
            mode: Mode::Types,
        }
    }
}

pub fn dotnet_view(ui: &mut Ui, view: &mut DotNetView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.DotNet", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new(".NET assembly").strong());
        ui.label(muted("CLI metadata · types & methods · user strings"));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a .NET executable (.exe/.dll) to inspect it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };
    if !orress_dotnet::is_dotnet(bytes) {
        ui.label(muted(format!(
            "{} is not a .NET assembly (no CLI header in the PE).",
            doc.file_name()
        )));
        return;
    }

    let key = (doc.path.clone(), bytes.len(), doc.generation);
    if view.key.as_ref() != Some(&key) {
        view.dn = Some(orress_dotnet::parse(bytes));
        // A patch or rename re-parses; only another file resets the selection (it is
        // clamped to the new contents below).
        if view.key.as_ref().map(|k| &k.0) != Some(&key.0) {
            view.selected = 0;
        }
        view.key = Some(key);
    }

    let dn = match view.dn.as_ref().unwrap() {
        Ok(d) => d,
        Err(e) => {
            ui.colored_label(ui.visuals().error_fg_color, format!("Could not parse: {e}"));
            return;
        }
    };

    ui.horizontal(|ui| {
        let name = dn
            .assembly_name
            .clone()
            .unwrap_or_else(|| dn.module_name.clone());
        ui.label(RichText::new(name).strong().monospace());
        ui.label(muted(format!(
            "{} · module {}",
            dn.runtime_version, dn.module_name
        )));
    });
    ui.label(muted(format!(
        "{} types · {} user strings · tables: {}",
        dn.types.len(),
        dn.user_strings.len(),
        dn.table_rows
            .iter()
            .map(|(n, c)| format!("{n} {c}"))
            .collect::<Vec<_>>()
            .join(", ")
    )));
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.selectable_value(&mut view.mode, Mode::Types, "Types");
        ui.selectable_value(&mut view.mode, Mode::Strings, "User strings");
    });
    ui.add_space(4.0);

    match view.mode {
        Mode::Strings => strings_panel(ui, &dn.user_strings),
        Mode::Types => types_panel(ui, dn, bytes, &mut view.selected, &mut view.method_sel),
    }
}

fn types_panel(
    ui: &mut Ui,
    dn: &DotNet,
    data: &[u8],
    selected: &mut usize,
    method_sel: &mut usize,
) {
    if dn.types.is_empty() {
        ui.label(muted("No types."));
        return;
    }
    if *selected >= dn.types.len() {
        *selected = 0;
    }
    let before = *selected;
    ui.horizontal_top(|ui| {
        // Type list.
        ui.vertical(|ui| {
            ui.set_width(240.0);
            egui::ScrollArea::vertical()
                .id_salt("dn-types")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (i, t) in dn.types.iter().enumerate() {
                        let label = format!("{} ({})", t.full_name(), t.methods.len());
                        if ui
                            .selectable_label(*selected == i, RichText::new(label).monospace())
                            .clicked()
                        {
                            *selected = i;
                        }
                    }
                });
        });
        if *selected != before {
            *method_sel = 0;
        }
        ui.separator();
        // Method list for the selected type.
        let Some(t) = dn.types.get(*selected) else {
            return;
        };
        ui.vertical(|ui| {
            ui.set_width(220.0);
            ui.label(RichText::new(t.full_name()).strong().monospace());
            if *method_sel >= t.methods.len() {
                *method_sel = 0;
            }
            egui::ScrollArea::vertical()
                .id_salt("dn-methods")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (i, m) in t.methods.iter().enumerate() {
                        let label = format!("{}{}", m.name, m.signature);
                        if ui
                            .selectable_label(*method_sel == i, RichText::new(label).monospace())
                            .clicked()
                        {
                            *method_sel = i;
                        }
                    }
                });
        });
        ui.separator();
        // IL of the selected method.
        ui.vertical(|ui| {
            let Some(m) = t.methods.get(*method_sel) else {
                return;
            };
            ui.label(
                RichText::new(format!("{}{}", m.name, m.signature))
                    .strong()
                    .monospace(),
            );
            match dn.disassemble(data, m.rva) {
                Ok(il) => {
                    egui::ScrollArea::vertical()
                        .id_salt("dn-il")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for ins in &il {
                                let mark = if ins.is_branch_target { ">>" } else { "  " };
                                let line = format!(
                                    "{mark} IL_{:04x}: {:<14} {}",
                                    ins.offset, ins.opcode, ins.operand
                                );
                                let text = RichText::new(line).monospace();
                                ui.label(if ins.is_branch_target {
                                    text.color(ui.visuals().hyperlink_color)
                                } else {
                                    text
                                });
                            }
                        });
                }
                Err(e) => {
                    ui.label(muted(e));
                }
            }
        });
    });
}

fn strings_panel(ui: &mut Ui, strings: &[String]) {
    if strings.is_empty() {
        ui.label(muted("No user strings."));
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt("dn-strings")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for s in strings {
                let interesting = looks_interesting(s);
                let text = RichText::new(format!("  {s:?}")).monospace();
                ui.label(if interesting {
                    text.color(ui.visuals().warn_fg_color)
                } else {
                    text.weak()
                });
            }
        });
}

fn looks_interesting(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [
        "http",
        "://",
        "flag",
        ".exe",
        "cmd",
        "powershell",
        "base64",
        "token",
        "key",
        "\\",
    ]
    .iter()
    .any(|k| l.contains(k))
}
