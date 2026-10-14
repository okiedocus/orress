//! The Python bytecode view: open a `.pyc` and browse its code-object tree (module, functions,
//! comprehensions) with each one's metadata, constants, names and a disassembly, powered by the
//! pure-Rust `orress-pyc` loader. Parsing is cached per file.

use std::path::PathBuf;

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_pyc::{CodeObject, Insn, Pyc};
use orress_ui::muted;

/// Persistent UI state for the Python bytecode tab.
#[derive(Default)]
pub struct PycView {
    key: Option<(PathBuf, usize, u64)>,
    pyc: Option<Result<Pyc, String>>,
    /// Index into the flattened code-object tree.
    selected: usize,
}

/// Flattens the code-object tree depth-first into `(depth, code)` pairs.
fn flatten<'a>(code: &'a CodeObject, depth: usize, out: &mut Vec<(usize, &'a CodeObject)>) {
    out.push((depth, code));
    for nested in code.nested() {
        flatten(nested, depth + 1, out);
    }
}

pub fn pyc_view(ui: &mut Ui, view: &mut PycView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Pyc", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Python bytecode").strong());
        ui.label(muted(
            "code-object tree · disassembly (pure-Rust .pyc loader)",
        ));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a .pyc file to inspect it."));
        return;
    };
    let Some(bytes) = doc.bytes() else {
        ui.label(muted("Reading the file…"));
        return;
    };
    if !orress_pyc::looks_like_pyc(bytes) {
        ui.label(muted(format!(
            "{} is not a .pyc file (no Python magic + \\r\\n header).",
            doc.file_name()
        )));
        return;
    }

    let key = (doc.path.clone(), bytes.len(), doc.generation);
    if view.key.as_ref() != Some(&key) {
        view.pyc = Some(orress_pyc::parse(bytes));
        // A patch or rename re-parses; only another file resets the selection (it is
        // clamped to the new contents below).
        if view.key.as_ref().map(|k| &k.0) != Some(&key.0) {
            view.selected = 0;
        }
        view.key = Some(key);
    }

    let pyc = match view.pyc.as_ref().unwrap() {
        Ok(p) => p,
        Err(e) => {
            ui.colored_label(ui.visuals().error_fg_color, format!("Could not parse: {e}"));
            return;
        }
    };

    ui.horizontal(|ui| {
        ui.label(RichText::new(pyc.version_label()).strong());
        ui.label(muted(format!(
            "magic {} · {} · {}-byte header",
            pyc.magic,
            if pyc.hash_based {
                "hash-based"
            } else {
                "timestamp"
            },
            pyc.header_len
        )));
    });
    if !pyc.can_disassemble() {
        ui.label(muted(
            "ORRESS doesn't bundle this Python version's opcode table yet — showing structure, \
             constants and raw bytecode. (Named disassembly: 3.14.)",
        ));
    }
    ui.add_space(4.0);

    let mut flat = Vec::new();
    flatten(&pyc.top, 0, &mut flat);
    if view.selected >= flat.len() {
        view.selected = 0;
    }

    ui.horizontal_top(|ui| {
        // Left: the code-object tree.
        ui.vertical(|ui| {
            ui.set_width(250.0);
            ui.label(muted(format!("{} code objects", flat.len())));
            egui::ScrollArea::vertical()
                .id_salt("pyc-tree")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (idx, (depth, c)) in flat.iter().enumerate() {
                        let label = format!("{}{}", "   ".repeat(*depth), c.name);
                        if ui
                            .selectable_label(
                                view.selected == idx,
                                RichText::new(label).monospace(),
                            )
                            .clicked()
                        {
                            view.selected = idx;
                        }
                    }
                });
        });
        ui.separator();
        // Right: the selected code object.
        ui.vertical(|ui| {
            if let Some((_, code)) = flat.get(view.selected) {
                code_detail(ui, code, pyc);
            }
        });
    });
}

fn code_detail(ui: &mut Ui, code: &CodeObject, pyc: &Pyc) {
    ui.label(RichText::new(code.signature()).strong().monospace());
    if let Some(doc) = code.docstring() {
        let one_line = doc.lines().next().unwrap_or("");
        ui.label(
            RichText::new(format!("  \"\"\"{one_line}\"\"\""))
                .monospace()
                .weak(),
        );
    }
    let flags = orress_pyc::flag_names(code.flags).join(" | ");
    ui.label(muted(format!(
        "args: {} (+{} pos-only, {} kw-only) · stack {} · flags 0x{:x} {}",
        code.argcount, code.posonlyargcount, code.kwonlyargcount, code.stacksize, code.flags, flags
    )));
    if !code.filename.is_empty() {
        ui.label(muted(format!(
            "file: {} · line {}",
            code.filename, code.firstlineno
        )));
    }

    egui::ScrollArea::both()
        .id_salt("pyc-detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Constants & names (where flags and strings usually hide).
            if !code.consts.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new("Constants").strong());
                for (i, c) in code.consts.iter().enumerate() {
                    ui.label(
                        RichText::new(format!("  [{i}] {}", c.render()))
                            .monospace()
                            .weak(),
                    );
                }
            }
            if !code.names.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new("Names").strong());
                ui.label(
                    RichText::new(format!("  {}", code.names.join(", ")))
                        .monospace()
                        .weak(),
                );
            }

            ui.add_space(6.0);
            match orress_pyc::disassemble(code, pyc.version) {
                Some(insns) => disasm_table(ui, &insns),
                None => {
                    ui.label(RichText::new("Raw bytecode").strong());
                    ui.label(RichText::new(hex_dump(&code.code)).monospace().weak());
                }
            }
        });
}

fn disasm_table(ui: &mut Ui, insns: &[Insn]) {
    ui.label(RichText::new(format!("Disassembly ({} instructions)", insns.len())).strong());
    for ins in insns {
        let marker = if ins.is_jump_target { ">>" } else { "  " };
        let arg = match (ins.arg, &ins.argval) {
            (Some(a), Some(v)) => format!("{a:<5} ({v})"),
            (Some(a), None) => format!("{a}"),
            (None, _) => String::new(),
        };
        let line = format!("{marker} {:>5}  {:<28} {}", ins.offset, ins.opname, arg);
        let text = RichText::new(line).monospace();
        if ins.is_jump_target {
            ui.label(text.color(ui.visuals().hyperlink_color));
        } else {
            ui.label(text);
        }
    }
}

fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(2048)
        .enumerate()
        .map(|(i, b)| {
            if i % 16 == 15 {
                format!("{b:02x}\n")
            } else {
                format!("{b:02x} ")
            }
        })
        .collect()
}
