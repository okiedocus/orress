//! The Archive view: open a ZIP/JAR, list its members, read the JAR manifest, and open a `.class`
//! member straight into the Java disassembler — powered by the pure-Rust `orress-archive` reader.
//! The decoded content of the selected entry is cached so only a new selection does work.

use egui::{RichText, Ui};
use orress_archive::Archive;
use orress_dex::Dex;
use orress_java::ClassFile;
use orress_project::DocStore;
use orress_ui::muted;

/// Persistent UI state for the Archive tab.
#[derive(Default)]
pub struct ArchiveView {
    selected: Option<String>,
    method_sel: usize,
    /// The file (path and generation) the selection and cache belong to: another file resets
    /// the selection, and a patch decodes the entry again.
    doc: Option<(std::path::PathBuf, u64)>,
    /// The decoded content of `selected`, cached by entry name.
    cache_name: Option<String>,
    cached_class: Option<Result<ClassFile, String>>,
    cached_dex: Option<Result<Dex, String>>,
    /// Raw decompressed bytes of the selected .dex (needed to disassemble a method).
    cached_dex_bytes: Option<Vec<u8>>,
    dex_method_sel: usize,
    cached_text: Option<String>,
}

/// Bytes of a non-class entry shown as a text preview.
const PREVIEW_BYTES: usize = 8192;

pub fn archive_view(ui: &mut Ui, view: &mut ArchiveView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Archive", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Archive").strong());
        ui.label(muted("ZIP / JAR entries · manifest · open .class members"));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a .zip, .jar or .apk file to inspect it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };
    if !orress_archive::looks_like_zip(bytes) {
        ui.label(muted(format!(
            "{} is not a ZIP-based archive (no PK signature).",
            doc.file_name()
        )));
        return;
    }

    // The archive borrows the file bytes, so re-open each frame (a cheap central-directory scan).
    let ar = match Archive::open(bytes) {
        Ok(a) => a,
        Err(e) => {
            ui.colored_label(
                ui.visuals().error_fg_color,
                format!("Could not read archive: {e}"),
            );
            return;
        }
    };

    let is_apk = ar.by_name("AndroidManifest.xml").is_some()
        && ar.entries.iter().any(|e| e.name.ends_with(".dex"));
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} entries", ar.entries.len())).strong());
        if is_apk {
            let dex = ar
                .entries
                .iter()
                .filter(|e| e.name.ends_with(".dex"))
                .count();
            ui.label(muted(format!("· Android APK ({dex} dex)")));
        } else if let Some(mc) = manifest_main_class(&ar) {
            ui.label(muted(format!("· Main-Class: {mc}")));
        }
    });
    ui.add_space(4.0);

    let doc_key = (doc.path.clone(), doc.generation);
    if view.doc.as_ref().map(|(p, _)| p) != Some(&doc.path) {
        view.selected = None;
    }
    let doc_changed = view.doc.as_ref() != Some(&doc_key);
    view.doc = Some(doc_key);

    // Decode the selection (once) when it, or the file, changes.
    if doc_changed || view.cache_name != view.selected {
        view.cached_class = None;
        view.cached_dex = None;
        view.cached_dex_bytes = None;
        view.cached_text = None;
        view.method_sel = 0;
        view.dex_method_sel = 0;
        if let Some(name) = view.selected.clone()
            && let Some(entry) = ar.by_name(&name)
        {
            match ar.read(entry) {
                Ok(data) => {
                    if name.ends_with(".class") {
                        view.cached_class = Some(orress_java::parse(&data));
                    } else if name.ends_with(".dex") {
                        view.cached_dex = Some(orress_dex::parse(&data));
                        view.cached_dex_bytes = Some(data);
                    } else {
                        view.cached_text = Some(text_preview(&data));
                    }
                }
                Err(e) => view.cached_text = Some(format!("(could not extract: {e})")),
            }
        }
        view.cache_name = view.selected.clone();
    }

    ui.horizontal_top(|ui| {
        // Left: entry list.
        ui.vertical(|ui| {
            ui.set_width(320.0);
            egui::ScrollArea::vertical()
                .id_salt("archive-entries")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for e in &ar.entries {
                        if e.is_dir() {
                            ui.label(
                                RichText::new(format!("  {}/", e.name.trim_end_matches('/')))
                                    .monospace()
                                    .weak(),
                            );
                            continue;
                        }
                        let selected = view.selected.as_deref() == Some(e.name.as_str());
                        let label =
                            format!("{}  ({}, {})", e.name, e.uncompressed_size, e.method_name());
                        if ui
                            .selectable_label(selected, RichText::new(label).monospace())
                            .clicked()
                        {
                            view.selected = Some(e.name.clone());
                        }
                    }
                });
        });
        ui.separator();
        // Right: the selected entry.
        ui.vertical(|ui| {
            let Some(name) = view.selected.clone() else {
                ui.label(muted("Select an entry to view it."));
                return;
            };
            ui.label(RichText::new(&name).strong().monospace());
            if let Some(dex) = &view.cached_dex {
                match dex {
                    Ok(d) => dex_panel(
                        ui,
                        d,
                        view.cached_dex_bytes.as_deref().unwrap_or(&[]),
                        &mut view.dex_method_sel,
                    ),
                    Err(e) => {
                        ui.colored_label(
                            ui.visuals().error_fg_color,
                            format!("Not a valid DEX: {e}"),
                        );
                    }
                }
                return;
            }
            match (&view.cached_class, &view.cached_text) {
                (Some(Ok(cf)), _) => {
                    ui.add_space(2.0);
                    crate::java::class_file_panel(ui, cf, &mut view.method_sel, "arch");
                }
                (Some(Err(e)), _) => {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        format!("Not a valid class: {e}"),
                    );
                }
                (None, Some(text)) => {
                    egui::ScrollArea::both()
                        .id_salt("archive-preview")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let mut buf = text.as_str();
                            ui.add(
                                egui::TextEdit::multiline(&mut buf)
                                    .code_editor()
                                    .desired_width(f32::INFINITY),
                            );
                        });
                }
                (None, None) => {
                    ui.label(muted("(empty)"));
                }
            }
        });
    });
}

fn dex_panel(ui: &mut Ui, d: &Dex, data: &[u8], method_sel: &mut usize) {
    ui.label(muted(format!(
        "DEX {} · {} strings · {} types · {} methods · {} classes",
        d.version, d.string_count, d.type_count, d.method_count, d.class_def_count
    )));

    // Strings (collapsed to leave room for the code).
    egui::CollapsingHeader::new(format!(
        "Strings ({})",
        d.strings.iter().filter(|s| !s.trim().is_empty()).count()
    ))
    .id_salt("dex-strings-h")
    .show(ui, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("dex-strings")
            .max_height(160.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for s in d.strings.iter().filter(|s| !s.trim().is_empty()).take(2000) {
                    let text = RichText::new(format!("  {s:?}")).monospace();
                    ui.label(if looks_interesting(s) {
                        text.color(ui.visuals().warn_fg_color)
                    } else {
                        text.weak()
                    });
                }
            });
    });

    // Flatten (class, method) pairs that have code.
    let methods: Vec<(&str, &orress_dex::DexMethod)> = d
        .classes
        .iter()
        .flat_map(|c| {
            c.methods
                .iter()
                .filter(|m| m.code_off != 0)
                .map(move |m| (c.name.as_str(), m))
        })
        .collect();
    if methods.is_empty() {
        return;
    }
    if *method_sel >= methods.len() {
        *method_sel = 0;
    }
    ui.add_space(4.0);
    ui.separator();
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(220.0);
            ui.label(RichText::new(format!("Methods ({})", methods.len())).strong());
            egui::ScrollArea::vertical()
                .id_salt("dex-methods")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (i, (_, m)) in methods.iter().enumerate() {
                        if ui
                            .selectable_label(*method_sel == i, RichText::new(&m.name).monospace())
                            .clicked()
                        {
                            *method_sel = i;
                        }
                    }
                });
        });
        ui.separator();
        ui.vertical(|ui| {
            let Some((_, m)) = methods.get(*method_sel) else {
                return;
            };
            ui.label(
                RichText::new(format!("{} (smali)", m.name))
                    .strong()
                    .monospace(),
            );
            match d.disassemble_method(data, m.code_off) {
                Ok(il) => {
                    egui::ScrollArea::vertical()
                        .id_salt("dex-smali")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for ins in &il {
                                let mark = if ins.is_branch_target { ">>" } else { "  " };
                                let line = format!(
                                    "{mark} {:04x}: {:<22} {}",
                                    ins.offset, ins.mnemonic, ins.operand
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

/// Highlights strings that often matter in an APK: URLs, commands, secrets.
fn looks_interesting(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [
        "http", "://", "flag", ".so", "/data/", "exec", "http://", "token", "secret", "password",
    ]
    .iter()
    .any(|k| l.contains(k))
}

fn manifest_main_class(ar: &Archive) -> Option<String> {
    let entry = ar.by_name("META-INF/MANIFEST.MF")?;
    let bytes = ar.read(entry).ok()?;
    orress_archive::parse_manifest(&bytes)
        .into_iter()
        .find(|(k, _)| k == "Main-Class")
        .map(|(_, v)| v)
}

/// A printable preview of an entry's first bytes (non-printable bytes shown as `.`).
fn text_preview(data: &[u8]) -> String {
    let shown = &data[..data.len().min(PREVIEW_BYTES)];
    let mut s: String = shown
        .iter()
        .map(|&b| {
            if b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if data.len() > PREVIEW_BYTES {
        s.push_str("\n…");
    }
    s
}
