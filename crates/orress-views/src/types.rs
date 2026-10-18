//! The Types panel: declare `struct`/`union`/`enum`/`typedef` with a form builder and see
//! their memory layout. Types are per-binary and persist with the rest of your work
//! (names, comments) via [`orress_project::Annotations`]; applying a type to data happens
//! in the hex/inspector views. The layout maths lives in `orress_project::types`.

use egui::{ComboBox, RichText, Ui};
use orress_project::types::{FieldDef, Prim, TypeRef, UserType};
use orress_project::{DocStore, TypeCatalog};
use orress_ui::muted;

/// A field type the dropdown can produce: a base (primitive or named type) optionally
/// wrapped in a single pointer. One pointer level is enough for the form; deeper nesting
/// is out of scope.
#[derive(Clone, PartialEq, Eq)]
enum Base {
    Prim(Prim),
    Named(String),
}

#[derive(Clone)]
struct FieldDraft {
    name: String,
    base: Base,
    pointer: bool,
    count: String,
}

impl FieldDraft {
    fn blank() -> Self {
        Self {
            name: String::new(),
            base: Base::Prim(Prim::U32),
            pointer: false,
            count: "1".into(),
        }
    }

    fn from_def(f: &FieldDef) -> Self {
        let (base, pointer) = base_of(&f.ty);
        Self {
            name: f.name.clone(),
            base,
            pointer,
            count: f.count.max(1).to_string(),
        }
    }

    fn to_def(&self) -> FieldDef {
        let base = match &self.base {
            Base::Prim(p) => TypeRef::Prim(*p),
            Base::Named(n) => TypeRef::Named(n.clone()),
        };
        let ty = if self.pointer {
            TypeRef::Pointer(Box::new(base))
        } else {
            base
        };
        FieldDef {
            name: self.name.trim().to_owned(),
            ty,
            count: self.count.trim().parse().unwrap_or(1).max(1),
        }
    }
}

/// Splits a type reference into its base and whether it is behind a pointer.
fn base_of(ty: &TypeRef) -> (Base, bool) {
    match ty {
        TypeRef::Prim(p) => (Base::Prim(*p), false),
        TypeRef::Named(n) => (Base::Named(n.clone()), false),
        TypeRef::Pointer(inner) => match inner.as_ref() {
            TypeRef::Prim(p) => (Base::Prim(*p), true),
            TypeRef::Named(n) => (Base::Named(n.clone()), true),
            // Nested pointer: collapse to its innermost base (one-level form).
            TypeRef::Pointer(_) => {
                let (b, _) = base_of(inner);
                (b, true)
            }
        },
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Struct,
    Union,
    Enum,
    Typedef,
}

/// The type currently being edited, as editable buffers.
#[derive(Clone)]
struct Draft {
    /// The name the draft was loaded from, so a rename replaces the old entry. Empty for
    /// a new type.
    orig: String,
    kind: Kind,
    name: String,
    fields: Vec<FieldDraft>,
    variants: Vec<(String, String)>,
    enum_width: Prim,
    typedef_base: Base,
    typedef_pointer: bool,
}

impl Draft {
    fn new(kind: Kind) -> Self {
        Self {
            orig: String::new(),
            kind,
            name: String::new(),
            fields: vec![FieldDraft::blank()],
            variants: vec![(String::new(), "0".into())],
            enum_width: Prim::U32,
            typedef_base: Base::Prim(Prim::U32),
            typedef_pointer: false,
        }
    }

    fn from_type(ty: &UserType) -> Self {
        let mut d = Self::new(Kind::Struct);
        d.orig = ty.name().to_owned();
        d.name = ty.name().to_owned();
        match ty {
            UserType::Struct { fields, .. } => {
                d.kind = Kind::Struct;
                d.fields = fields.iter().map(FieldDraft::from_def).collect();
            }
            UserType::Union { fields, .. } => {
                d.kind = Kind::Union;
                d.fields = fields.iter().map(FieldDraft::from_def).collect();
            }
            UserType::Enum { width, variants, .. } => {
                d.kind = Kind::Enum;
                d.enum_width = *width;
                d.variants = variants
                    .iter()
                    .map(|(n, v)| (n.clone(), v.to_string()))
                    .collect();
            }
            UserType::Typedef { target, .. } => {
                d.kind = Kind::Typedef;
                let (b, p) = base_of(target);
                d.typedef_base = b;
                d.typedef_pointer = p;
            }
        }
        d
    }

    fn to_type(&self) -> UserType {
        let name = self.name.trim().to_owned();
        match self.kind {
            Kind::Struct => UserType::Struct {
                name,
                fields: self.fields.iter().map(FieldDraft::to_def).collect(),
            },
            Kind::Union => UserType::Union {
                name,
                fields: self.fields.iter().map(FieldDraft::to_def).collect(),
            },
            Kind::Enum => UserType::Enum {
                name,
                width: self.enum_width,
                variants: self
                    .variants
                    .iter()
                    .map(|(n, v)| (n.trim().to_owned(), v.trim().parse().unwrap_or(0)))
                    .collect(),
            },
            Kind::Typedef => {
                let base = match &self.typedef_base {
                    Base::Prim(p) => TypeRef::Prim(*p),
                    Base::Named(n) => TypeRef::Named(n.clone()),
                };
                UserType::Typedef {
                    name,
                    target: if self.typedef_pointer {
                        TypeRef::Pointer(Box::new(base))
                    } else {
                        base
                    },
                }
            }
        }
    }
}

/// Persistent UI state for the Types tab.
#[derive(Default)]
pub struct TypesView {
    draft: Option<Draft>,
    error: Option<String>,
    status: Option<String>,
}

pub fn types_view(ui: &mut Ui, view: &mut TypesView, docs: &mut DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Types", ui.max_rect());

    let Some(doc) = docs.active_mut() else {
        ui.heading("Types");
        ui.label(muted(
            "Open a binary to declare structs, unions, enums and typedefs, then apply them to data.",
        ));
        return;
    };

    let catalog = doc.type_catalog();
    let names: Vec<String> = catalog.types.keys().cloned().collect();

    ui.horizontal(|ui| {
        ui.label(RichText::new("Types").strong());
        ui.label(muted(format!("{} defined · saved with this binary", names.len())));
    });
    ui.separator();

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(200.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("+ Struct").clicked() {
                    view.draft = Some(Draft::new(Kind::Struct));
                    view.error = None;
                }
                if ui.button("+ Union").clicked() {
                    view.draft = Some(Draft::new(Kind::Union));
                    view.error = None;
                }
                if ui.button("+ Enum").clicked() {
                    view.draft = Some(Draft::new(Kind::Enum));
                    view.error = None;
                }
                if ui.button("+ Typedef").clicked() {
                    view.draft = Some(Draft::new(Kind::Typedef));
                    view.error = None;
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for name in &names {
                    let ty = &catalog.types[name];
                    let selected = view.draft.as_ref().is_some_and(|d| &d.orig == name);
                    ui.horizontal(|ui| {
                        if ui.selectable_label(selected, format!("{} {name}", ty.kind_label())).clicked() {
                            view.draft = Some(Draft::from_type(ty));
                            view.error = None;
                            view.status = None;
                        }
                        if ui.small_button("🗑").on_hover_text("Delete type").clicked() {
                            doc.remove_type(name);
                            if selected {
                                view.draft = None;
                            }
                            view.status = Some(format!("Deleted {name}"));
                        }
                    });
                }
                if names.is_empty() {
                    ui.label(muted("No types yet. Start with + Struct."));
                }
            });
        });

        ui.separator();

        ui.vertical(|ui| {
            let Some(draft) = view.draft.as_mut() else {
                ui.label(muted("Select a type on the left, or create one."));
                return;
            };
            let save = editor(ui, draft, &names, view.error.as_deref(), view.status.as_deref(), &catalog);
            if save {
                match commit(doc, draft) {
                    Ok(_) => {
                        view.error = None;
                        view.status = Some(format!("Saved {}", draft.name.trim()));
                        draft.orig = draft.name.trim().to_owned();
                    }
                    Err(e) => view.error = Some(e),
                }
            }
        });
    });
}

/// Draws the editor form for one draft, returning whether Save was clicked.
fn editor(
    ui: &mut Ui,
    draft: &mut Draft,
    names: &[String],
    error: Option<&str>,
    status: Option<&str>,
    catalog: &TypeCatalog,
) -> bool {
    ui.horizontal(|ui| {
        ui.label("Name");
        ui.text_edit_singleline(&mut draft.name);
        ui.label(muted(kind_word(draft.kind)));
    });
    ui.separator();

    match draft.kind {
        Kind::Struct | Kind::Union => fields_editor(ui, draft, names),
        Kind::Enum => enum_editor(ui, draft),
        Kind::Typedef => typedef_editor(ui, draft, names),
    }

    ui.separator();
    let save = ui.button("Save").clicked();
    if let Some(e) = error {
        ui.colored_label(ui.visuals().error_fg_color, e);
    } else if let Some(s) = status {
        ui.label(muted(s));
    }

    // Live layout preview.
    ui.add_space(6.0);
    ui.label(RichText::new("Layout").strong());
    let ty = draft.to_type();
    let mut probe = catalog.clone();
    probe.types.insert(ty.name().to_owned(), ty.clone());
    match probe.layout(&ty) {
        Some(fields) if !fields.is_empty() => {
            egui::Grid::new("types_layout").num_columns(4).spacing([14.0, 2.0]).show(ui, |ui| {
                ui.label(muted("offset"));
                ui.label(muted("name"));
                ui.label(muted("type"));
                ui.label(muted("size"));
                ui.end_row();
                for f in &fields {
                    ui.label(RichText::new(format!("+0x{:X}", f.offset)).monospace());
                    ui.label(&f.path);
                    let arr = if f.count > 1 { format!("{}[{}]", f.ty.label(), f.count) } else { f.ty.label() };
                    ui.label(RichText::new(arr).monospace());
                    ui.label(RichText::new(format!("0x{:X}", f.size)).monospace());
                    ui.end_row();
                }
            });
            if let Some(total) = probe.size_of(&TypeRef::Named(ty.name().to_owned())) {
                ui.label(muted(format!("total size 0x{total:X} ({total} bytes)")));
            }
        }
        Some(_) => {
            if let Some(total) = probe.size_of(&TypeRef::Named(ty.name().to_owned())) {
                ui.label(muted(format!("size 0x{total:X} ({total} bytes)")));
            }
        }
        None => {
            ui.label(muted("layout unavailable (unknown or self-referential member)"));
        }
    }
    save
}

fn fields_editor(ui: &mut Ui, draft: &mut Draft, names: &[String]) {
    let mut remove = None;
    egui::Grid::new("types_fields").num_columns(5).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(muted("name"));
        ui.label(muted("type"));
        ui.label(muted("ptr"));
        ui.label(muted("count"));
        ui.label("");
        ui.end_row();
        for (i, f) in draft.fields.iter_mut().enumerate() {
            ui.add(egui::TextEdit::singleline(&mut f.name).desired_width(120.0));
            base_combo(ui, i, &mut f.base, names);
            ui.checkbox(&mut f.pointer, "");
            ui.add(egui::TextEdit::singleline(&mut f.count).desired_width(48.0));
            if ui.small_button("✕").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove
        && draft.fields.len() > 1
    {
        draft.fields.remove(i);
    }
    if ui.button("+ Add field").clicked() {
        draft.fields.push(FieldDraft::blank());
    }
}

fn enum_editor(ui: &mut Ui, draft: &mut Draft) {
    ui.horizontal(|ui| {
        ui.label("Underlying");
        ComboBox::from_id_salt("enum_width")
            .selected_text(draft.enum_width.label())
            .show_ui(ui, |ui| {
                for p in [Prim::U8, Prim::I8, Prim::U16, Prim::I16, Prim::U32, Prim::I32, Prim::U64, Prim::I64] {
                    ui.selectable_value(&mut draft.enum_width, p, p.label());
                }
            });
    });
    let mut remove = None;
    egui::Grid::new("types_variants").num_columns(3).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(muted("name"));
        ui.label(muted("value"));
        ui.label("");
        ui.end_row();
        for (i, (name, value)) in draft.variants.iter_mut().enumerate() {
            ui.add(egui::TextEdit::singleline(name).desired_width(140.0));
            ui.add(egui::TextEdit::singleline(value).desired_width(80.0));
            if ui.small_button("✕").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove
        && draft.variants.len() > 1
    {
        draft.variants.remove(i);
    }
    if ui.button("+ Add variant").clicked() {
        draft.variants.push((String::new(), "0".into()));
    }
}

fn typedef_editor(ui: &mut Ui, draft: &mut Draft, names: &[String]) {
    ui.horizontal(|ui| {
        ui.label("Alias for");
        base_combo(ui, usize::MAX, &mut draft.typedef_base, names);
        ui.checkbox(&mut draft.typedef_pointer, "pointer");
    });
}

/// A dropdown over every primitive and every named type. `salt` disambiguates rows.
fn base_combo(ui: &mut Ui, salt: usize, base: &mut Base, names: &[String]) {
    let text = match base {
        Base::Prim(p) => p.label().to_owned(),
        Base::Named(n) => n.clone(),
    };
    ComboBox::from_id_salt(("base_combo", salt))
        .selected_text(text)
        .width(130.0)
        .show_ui(ui, |ui| {
            for p in Prim::ALL {
                ui.selectable_value(base, Base::Prim(p), p.label());
            }
            if !names.is_empty() {
                ui.separator();
                for n in names {
                    ui.selectable_value(base, Base::Named(n.clone()), n);
                }
            }
        });
}

fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Struct => "struct",
        Kind::Union => "union",
        Kind::Enum => "enum",
        Kind::Typedef => "typedef",
    }
}

/// Validates and writes the draft to the document, handling a rename (removing the old
/// name). Returns the previous name if it changed.
fn commit(
    doc: &mut orress_project::Document,
    draft: &Draft,
) -> Result<Option<String>, String> {
    let ty = draft.to_type();
    doc.define_type(ty)?;
    let renamed = (!draft.orig.is_empty() && draft.orig != draft.name.trim())
        .then(|| draft.orig.clone());
    if let Some(old) = &renamed {
        doc.remove_type(old);
    }
    Ok(renamed)
}
