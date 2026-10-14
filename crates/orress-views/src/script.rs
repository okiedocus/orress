//! The Scripting console: run a Rhai script against the open binary's analysis (functions,
//! strings, bytes, disassembly) and see its output — for automating queries without recompiling.
//! The engine (`orress-script`) is sandboxed and bounded, so a runaway script can't hang the UI.

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_ui::muted;

const EXAMPLE: &str = r#"// Rhai script — runs against the open binary.
// API: function_count(), functions(), func_name(a), func_blocks(a),
//      name(a), strings(), string_count(), read(addr, len), disasm(addr, n)
print("functions: " + function_count());
print("strings:   " + string_count());
let f = functions();
if f.len() > 0 {
    print("first function " + f[0] + " = " + func_name(f[0]));
    disasm(f[0], 5)
}
"#;

#[derive(Default)]
pub struct ScriptView {
    src: String,
    output: Option<Result<String, String>>,
    /// The example is filled in once; after that an empty editor stays empty.
    seeded: bool,
}

pub fn script_view(ui: &mut Ui, view: &mut ScriptView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Script", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Scripting").strong());
        ui.label(muted("automate analysis with Rhai · sandboxed, pure-Rust"));
    });
    ui.separator();

    if !view.seeded {
        view.seeded = true;
        if view.src.is_empty() {
            view.src = EXAMPLE.to_string();
        }
    }

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a binary to script its analysis."));
        return;
    };
    let (Some(analysis), Some(program)) = (doc.analysis(), doc.program()) else {
        ui.label(muted("Analysis is still running…"));
        return;
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.add(
            egui::TextEdit::multiline(&mut view.src)
                .font(egui::TextStyle::Monospace)
                .code_editor()
                .desired_rows(12)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            if ui.button("▶ Run").clicked() {
                let strings: Vec<&str> = analysis.strings.iter().map(|s| s.text.as_str()).collect();
                view.output = Some(orress_script::run(&view.src, program, &strings));
            }
            if ui.button("Reset example").clicked() {
                view.src = EXAMPLE.to_string();
                view.output = None;
            }
        });

        if let Some(result) = &view.output {
            ui.add_space(6.0);
            match result {
                Ok(out) => {
                    if ui.small_button("copy output").clicked() {
                        ui.ctx().copy_text(out.clone());
                    }
                    ui.label(RichText::new(out).monospace());
                }
                Err(e) => {
                    ui.colored_label(ui.visuals().error_fg_color, RichText::new(e).monospace());
                }
            }
        }
    });
}
