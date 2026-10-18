//! A small type-reference picker shared by the Types view and the decompiler's "set
//! prototype" editor: a base type (a primitive or a named user type) with an optional single
//! pointer. One pointer level is enough for the form; deeper nesting is out of scope.

use egui::{ComboBox, Ui};
use orress_project::types::{Prim, TypeRef};

/// A base type the dropdown can select: a primitive or another user type by name.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Base {
    Prim(Prim),
    Named(String),
}

/// Builds a [`TypeRef`] from a base and whether it is behind a pointer.
pub(crate) fn to_typeref(base: &Base, pointer: bool) -> TypeRef {
    let inner = match base {
        Base::Prim(p) => TypeRef::Prim(*p),
        Base::Named(n) => TypeRef::Named(n.clone()),
    };
    if pointer {
        TypeRef::Pointer(Box::new(inner))
    } else {
        inner
    }
}

/// Splits a type reference into its base and whether it is behind a pointer. A nested pointer
/// collapses to its innermost base (the one-level form).
pub(crate) fn from_typeref(ty: &TypeRef) -> (Base, bool) {
    match ty {
        TypeRef::Prim(p) => (Base::Prim(*p), false),
        TypeRef::Named(n) => (Base::Named(n.clone()), false),
        TypeRef::Pointer(inner) => match inner.as_ref() {
            TypeRef::Prim(p) => (Base::Prim(*p), true),
            TypeRef::Named(n) => (Base::Named(n.clone()), true),
            TypeRef::Pointer(_) => {
                let (b, _) = from_typeref(inner);
                (b, true)
            }
        },
    }
}

/// A dropdown over every primitive and every named type. `salt` disambiguates rows.
pub(crate) fn base_combo(ui: &mut Ui, salt: usize, base: &mut Base, names: &[String]) {
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
