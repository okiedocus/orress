//! The "set prototype" editor for the decompiler: pin a function's return type and named,
//! typed parameters so the decompiler prints that signature instead of the recovered one.
//! It writes `func_prototypes` on the document; the decompiler consumes them (see
//! `orress_decompiler::decompile_with`). Types come from the same catalog the Types view edits.

use egui::{RichText, Ui};
use orress_project::Document;
use orress_project::types::{FuncProto, Prim};
use orress_ui::muted;

use crate::typepick::{Base, base_combo, from_typeref, to_typeref};

/// One parameter being edited: a name and a base type with an optional pointer.
#[derive(Clone)]
struct ParamDraft {
    name: String,
    base: Base,
    pointer: bool,
}

impl ParamDraft {
    fn blank(i: usize) -> Self {
        Self {
            name: format!("a{}", i + 1),
            base: Base::Prim(Prim::U64),
            pointer: false,
        }
    }
}

/// The in-progress prototype for one function.
#[derive(Clone)]
pub(crate) struct ProtoDraft {
    func: u64,
    ret_enabled: bool,
    ret_base: Base,
    ret_pointer: bool,
    params: Vec<ParamDraft>,
}

impl ProtoDraft {
    /// Loads the saved prototype for `func`, or a blank one-parameter draft.
    pub(crate) fn load(doc: &Document, func: u64) -> Self {
        if let Some(p) = doc.annotations.func_prototypes.get(&func) {
            let (ret_base, ret_pointer) = p
                .ret
                .as_ref()
                .map(from_typeref)
                .unwrap_or((Base::Prim(Prim::U64), false));
            let params = p
                .params
                .iter()
                .map(|(name, ty)| {
                    let (base, pointer) = from_typeref(ty);
                    ParamDraft {
                        name: name.clone(),
                        base,
                        pointer,
                    }
                })
                .collect();
            Self {
                func,
                ret_enabled: p.ret.is_some(),
                ret_base,
                ret_pointer,
                params,
            }
        } else {
            Self {
                func,
                ret_enabled: false,
                ret_base: Base::Prim(Prim::U64),
                ret_pointer: false,
                params: vec![ParamDraft::blank(0)],
            }
        }
    }

    fn to_proto(&self) -> FuncProto {
        FuncProto {
            ret: self
                .ret_enabled
                .then(|| to_typeref(&self.ret_base, self.ret_pointer)),
            params: self
                .params
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let name = if p.name.trim().is_empty() {
                        format!("a{}", i + 1)
                    } else {
                        p.name.trim().to_owned()
                    };
                    (name, to_typeref(&p.base, p.pointer))
                })
                .collect(),
        }
    }
}

/// Draws the prototype editor as a window while `draft` is set. Applies changes to `doc`
/// and clears `draft` when the user saves, clears or closes.
pub(crate) fn window(ui: &mut Ui, draft: &mut Option<ProtoDraft>, doc: &mut Document, name: &str) {
    let Some(d) = draft.as_mut() else {
        return;
    };
    let names: Vec<String> = doc.type_catalog().types.keys().cloned().collect();
    let has_saved = doc.annotations.func_prototypes.contains_key(&d.func);

    let mut open = true;
    let mut close = false;
    let mut save = false;
    let mut clear = false;

    egui::Window::new(format!("Prototype — {name}"))
        .id(egui::Id::new(("orress::proto_window", d.func)))
        .collapsible(false)
        .resizable(true)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(muted(format!("Function at 0x{:x}", d.func)));
            ui.separator();

            ui.horizontal(|ui| {
                ui.checkbox(&mut d.ret_enabled, "Returns");
                ui.add_enabled_ui(d.ret_enabled, |ui| {
                    base_combo(ui, usize::MAX, &mut d.ret_base, &names);
                    ui.checkbox(&mut d.ret_pointer, "pointer");
                });
            });
            ui.separator();

            ui.label(RichText::new("Parameters").strong());
            let mut remove = None;
            egui::Grid::new("proto_params")
                .num_columns(4)
                .spacing([8.0, 4.0])
                .show(ui, |ui| {
                    ui.label(muted("name"));
                    ui.label(muted("type"));
                    ui.label(muted("ptr"));
                    ui.label("");
                    ui.end_row();
                    for (i, p) in d.params.iter_mut().enumerate() {
                        ui.add(egui::TextEdit::singleline(&mut p.name).desired_width(120.0));
                        base_combo(ui, i, &mut p.base, &names);
                        ui.checkbox(&mut p.pointer, "");
                        if ui.small_button("✕").clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                });
            if let Some(i) = remove {
                d.params.remove(i);
            }
            if ui.button("+ Add parameter").clicked() {
                let n = d.params.len();
                d.params.push(ParamDraft::blank(n));
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    save = true;
                }
                if has_saved && ui.button("Clear prototype").clicked() {
                    clear = true;
                }
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
            ui.label(muted(
                "Names come from the Types view; pointer-to-struct params print as field accesses.",
            ));
        });

    if save {
        let proto = d.to_proto();
        doc.set_prototype(d.func, proto);
    }
    if clear {
        doc.clear_prototype(d.func);
    }
    if !open || close || save || clear {
        *draft = None;
    }
}
