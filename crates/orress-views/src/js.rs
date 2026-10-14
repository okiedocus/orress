//! The JavaScript view: deobfuscate, beautify and extract strings from an open `.js` file (or any
//! text), powered by the pure-Rust `orress-js` transforms. Results are computed on demand and
//! cached until the file or the selected transform changes.

use std::path::PathBuf;

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_ui::muted;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Deobfuscate,
    Beautify,
    Strings,
}

/// Persistent UI state for the JavaScript tab.
pub struct JsView {
    key: Option<(PathBuf, usize, u64)>,
    src: String,
    mode: Mode,
    /// Beautify the deobfuscated output.
    beautify_result: bool,
    out: Option<String>,
    strings: Vec<String>,
}

impl Default for JsView {
    fn default() -> Self {
        Self {
            key: None,
            src: String::new(),
            mode: Mode::Deobfuscate,
            beautify_result: true,
            out: None,
            strings: Vec::new(),
        }
    }
}

pub fn js_view(ui: &mut Ui, view: &mut JsView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Js", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("JavaScript").strong());
        ui.label(muted(
            "deobfuscate · beautify · extract strings (pure-Rust)",
        ));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a .js file (or any text) to deobfuscate it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };

    let key = (doc.path.clone(), bytes.len(), doc.generation);
    if view.key.as_ref() != Some(&key) {
        view.src = String::from_utf8_lossy(bytes).into_owned();
        view.strings = orress_js::extract_strings(&view.src);
        view.out = None;
        view.key = Some(key);
    }

    let before = (view.mode, view.beautify_result);
    ui.horizontal(|ui| {
        ui.selectable_value(&mut view.mode, Mode::Deobfuscate, "Deobfuscate");
        ui.selectable_value(&mut view.mode, Mode::Beautify, "Beautify");
        ui.selectable_value(&mut view.mode, Mode::Strings, "Strings");
        if view.mode == Mode::Deobfuscate {
            ui.separator();
            ui.checkbox(&mut view.beautify_result, "beautify result");
        }
    });
    if (view.mode, view.beautify_result) != before {
        view.out = None;
    }
    ui.add_space(4.0);

    if view.mode == Mode::Strings {
        strings_panel(ui, &view.strings);
        return;
    }

    // Compute (and cache) the transformed output.
    if view.out.is_none() {
        let out = match view.mode {
            Mode::Deobfuscate => {
                let d = orress_js::deobfuscate(&view.src);
                if view.beautify_result {
                    orress_js::beautify(&d)
                } else {
                    d
                }
            }
            Mode::Beautify => orress_js::beautify(&view.src),
            Mode::Strings => String::new(),
        };
        view.out = Some(out);
    }

    let out = view.out.as_deref().unwrap_or("");
    ui.label(muted(format!(
        "{} bytes in · {} bytes out",
        view.src.len(),
        out.len()
    )));
    egui::ScrollArea::both()
        .id_salt("js-output")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut buf = out;
            ui.add(
                egui::TextEdit::multiline(&mut buf)
                    .code_editor()
                    .desired_width(f32::INFINITY),
            );
        });
}

fn strings_panel(ui: &mut Ui, strings: &[String]) {
    if strings.is_empty() {
        ui.label(muted("No string literals found."));
        return;
    }
    ui.label(RichText::new(format!("{} distinct string(s)", strings.len())).strong());
    egui::ScrollArea::vertical()
        .id_salt("js-strings")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for s in strings {
                let interesting = looks_interesting(s);
                let text = RichText::new(format!("  {s:?}")).monospace();
                if interesting {
                    ui.label(text.color(ui.visuals().warn_fg_color));
                } else {
                    ui.label(text.weak());
                }
            }
        });
}

/// Highlights strings that often matter in a dropper: URLs, flags, commands, encoded blobs.
fn looks_interesting(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("http")
        || l.contains("://")
        || l.contains("flag")
        || l.contains("eval")
        || l.contains("powershell")
        || l.contains("cmd")
        || l.contains(".exe")
        || l.contains("base64")
}
