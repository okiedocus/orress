//! The Java class view: open a `.class` file and browse its header, fields (with recovered
//! constant values), and methods with a JVM bytecode disassembly — powered by the pure-Rust
//! `orress-java` loader. Parsing is cached per file.

use std::path::PathBuf;

use egui::{RichText, Ui};
use orress_java::{ClassFile, Member};
use orress_project::DocStore;
use orress_ui::muted;

/// Persistent UI state for the Java class tab.
#[derive(Default)]
pub struct JavaView {
    key: Option<(PathBuf, usize, u64)>,
    class: Option<Result<ClassFile, String>>,
    /// Index into the methods list.
    selected: usize,
}

pub fn java_view(ui: &mut Ui, view: &mut JavaView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Java", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Java class").strong());
        ui.label(muted("constant pool · fields · methods · JVM disassembly"));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a .class file to inspect it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };
    if !orress_java::is_class(bytes) {
        ui.label(muted(format!(
            "{} is not a Java class file (no 0xCAFEBABE magic).",
            doc.file_name()
        )));
        return;
    }

    let key = (doc.path.clone(), bytes.len(), doc.generation);
    if view.key.as_ref() != Some(&key) {
        view.class = Some(orress_java::parse(bytes));
        // A patch or rename re-parses; only another file resets the selection (it is
        // clamped to the new contents below).
        if view.key.as_ref().map(|k| &k.0) != Some(&key.0) {
            view.selected = 0;
        }
        view.key = Some(key);
    }

    let cf = match view.class.as_ref().unwrap() {
        Ok(c) => c,
        Err(e) => {
            ui.colored_label(ui.visuals().error_fg_color, format!("Could not parse: {e}"));
            return;
        }
    };

    class_file_panel(ui, cf, &mut view.selected, "java");
}

/// Renders a parsed class file: header, fields (with recovered constants), a method list and the
/// selected method's JVM disassembly. Shared by the Java tab and the Archive tab (for `.class`
/// members); `id` keeps scroll areas distinct between callers.
pub(crate) fn class_file_panel(ui: &mut Ui, cf: &ClassFile, selected: &mut usize, id: &str) {
    // 0x20 on a class is ACC_SUPER (a historical artifact), not "synchronized".
    let flags = orress_java::access_flag_names(cf.access & !0x0020).join(" ");
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{flags} class {}", cf.this_class))
                .strong()
                .monospace(),
        );
        ui.label(muted(cf.java_version()));
    });
    if let Some(sup) = &cf.super_class {
        let impls = if cf.interfaces.is_empty() {
            String::new()
        } else {
            format!(" · implements {}", cf.interfaces.join(", "))
        };
        ui.label(muted(format!("extends {sup}{impls}")));
    }

    // Fields (with recovered compile-time constants).
    if !cf.fields.is_empty() {
        ui.add_space(4.0);
        ui.label(RichText::new("Fields").strong());
        for f in &cf.fields {
            let fl = orress_java::access_flag_names(f.access).join(" ");
            let cv = f
                .constant_value
                .map(|i| format!("  = {}", cf.cp.resolve(i)))
                .unwrap_or_default();
            ui.label(
                RichText::new(format!("  {fl} {}: {}{cv}", f.name, f.descriptor))
                    .monospace()
                    .weak(),
            );
        }
    }

    ui.add_space(6.0);
    ui.separator();

    if cf.methods.is_empty() {
        ui.label(muted("No methods."));
        return;
    }
    if *selected >= cf.methods.len() {
        *selected = 0;
    }

    ui.horizontal_top(|ui| {
        // Left: method list.
        ui.vertical(|ui| {
            ui.set_width(260.0);
            ui.label(muted(format!("{} methods", cf.methods.len())));
            egui::ScrollArea::vertical()
                .id_salt(format!("{id}-methods"))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (idx, m) in cf.methods.iter().enumerate() {
                        let label = format!("{}{}", m.name, m.descriptor);
                        if ui
                            .selectable_label(*selected == idx, RichText::new(label).monospace())
                            .clicked()
                        {
                            *selected = idx;
                        }
                    }
                });
        });
        ui.separator();
        // Right: selected method.
        ui.vertical(|ui| {
            if let Some(m) = cf.methods.get(*selected) {
                method_detail(ui, m, cf, id);
            }
        });
    });
}

fn method_detail(ui: &mut Ui, m: &Member, cf: &ClassFile, id: &str) {
    let flags = orress_java::access_flag_names(m.access).join(" ");
    ui.label(
        RichText::new(format!("{flags} {}{}", m.name, m.descriptor))
            .strong()
            .monospace(),
    );

    let Some(code) = &m.code else {
        ui.label(muted("No Code attribute (abstract or native method)."));
        return;
    };
    ui.label(muted(format!(
        "max_stack {} · max_locals {} · {} bytes",
        code.max_stack,
        code.max_locals,
        code.bytecode.len()
    )));
    if !code.exceptions.is_empty() {
        for e in &code.exceptions {
            let ty = e.catch_type.as_deref().unwrap_or("any");
            ui.label(
                RichText::new(format!(
                    "  catch {ty}: [{}..{}) → {}",
                    e.start, e.end, e.handler
                ))
                .monospace()
                .weak(),
            );
        }
    }

    ui.add_space(4.0);
    let insns = orress_java::disassemble(code, &cf.cp);
    ui.label(RichText::new(format!("Disassembly ({} instructions)", insns.len())).strong());
    egui::ScrollArea::both()
        .id_salt(format!("{id}-disasm"))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for ins in &insns {
                let marker = if ins.is_branch_target { ">>" } else { "  " };
                let line = format!(
                    "{marker} {:>4}: {:<16} {}",
                    ins.offset, ins.mnemonic, ins.operands
                );
                let text = RichText::new(line).monospace();
                if ins.is_branch_target {
                    ui.label(text.color(ui.visuals().hyperlink_color));
                } else {
                    ui.label(text);
                }
            }
        });
}
