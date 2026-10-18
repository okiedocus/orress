//! Data inspector: the bytes at the cursor read as every common type.

use egui::{RichText, Ui};
use orress_bytes::Endian;
use orress_project::types::{Prim, TypeRef};
use orress_project::{DocStore, TypeCatalog};
use orress_ui::{ExplainExt as _, muted};

pub fn inspector(ui: &mut Ui, docs: &mut DocStore) {
    let Some(doc) = docs.active_mut() else {
        ui.heading("Inspector");
        ui.label("Open a file and click a byte in the hex view. The inspector shows what those bytes mean as numbers, text, dates and more.");
        return;
    };
    let Some(data) = doc.bytes().cloned() else {
        ui.spinner();
        return;
    };
    let offset = doc.cursor;
    let analysis = doc.analysis().cloned();

    ui.label(RichText::new(doc.file_name()).strong());
    egui::Grid::new("inspector_pos").num_columns(2).spacing([12.0, 3.0]).show(ui, |ui| {
        ui.label(RichText::new("Offset").weak()).explain("Offset", "Position of the cursor in the file, in hexadecimal and decimal.");
        ui.label(RichText::new(format!("0x{offset:X} ({offset})")).monospace());
        ui.end_row();
        if let Some(a) = &analysis {
            ui.label(RichText::new("Address").weak()).explain(
                "Address",
                "Where this byte is in memory when the program runs. Empty if the byte is not loaded (headers, overlay data).",
            );
            match a.info.offset_to_address(offset) {
                Some(va) => ui.label(RichText::new(format!("0x{va:X}")).monospace()),
                None => ui.label(muted("not loaded in memory")),
            };
            ui.end_row();
            ui.label(RichText::new("Section").weak());
            ui.label(a.info.section_at_offset(offset).map_or("—", |s| s.name.as_str()));
            ui.end_row();
        }
        if let Some((s, e)) = doc.selection {
            ui.label(RichText::new("Selection").weak());
            ui.label(format!("{} bytes", e.saturating_sub(s)));
            ui.end_row();
        }
    });

    // A type applied to this address: lay its fields out over the bytes.
    if let Some(addr) = analysis.as_ref().and_then(|a| a.info.offset_to_address(offset))
        && let Some(applied) = doc.annotations.data_types.get(&addr).cloned()
    {
        let catalog = doc.type_catalog();
        applied_type(ui, &catalog, &applied, &data, offset as usize, doc.endian);
    }

    ui.horizontal(|ui| {
        ui.label(RichText::new("Byte order").weak()).explain(
            "Byte order (endianness)",
            "Multi-byte numbers can be stored lowest byte first (little-endian, used by x86 and \
             most ARM) or highest byte first (big-endian, used by network protocols). The bytes \
             01 00 00 00 are 1 in little-endian but 16777216 in big-endian.",
        );
        ui.selectable_value(&mut doc.endian, Endian::Little, "little");
        ui.selectable_value(&mut doc.endian, Endian::Big, "big");
    });
    ui.separator();

    let start = offset as usize;
    let bytes = &data[start.min(data.len())..(start + 16).min(data.len())];
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("inspector_values")
                .num_columns(2)
                .striped(true)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for item in orress_bytes::inspect::interpret(bytes, doc.endian) {
                        ui.label(RichText::new(item.label).weak())
                            .explain(item.label, item.explain);
                        let value = ui.add(
                            egui::Label::new(RichText::new(&item.value).monospace())
                                .sense(egui::Sense::click()),
                        );
                        if value.on_hover_text("Click to copy").clicked() {
                            ui.ctx().copy_text(item.value.clone());
                        }
                        ui.end_row();
                    }
                });
        });
}

/// Renders the fields of a type applied at the cursor: `+off  name : type = value`.
fn applied_type(
    ui: &mut Ui,
    catalog: &TypeCatalog,
    applied: &TypeRef,
    data: &[u8],
    base: usize,
    endian: Endian,
) {
    // Resolve the applied reference to a named user type we can lay out.
    let name = match applied {
        TypeRef::Named(n) => n.clone(),
        other => {
            ui.label(RichText::new("Applied type").strong());
            ui.label(muted(format!("{} (apply a struct/union to see fields)", other.label())));
            ui.separator();
            return;
        }
    };
    let Some(ty) = catalog.types.get(&name) else {
        return;
    };
    ui.label(RichText::new(format!("Applied type: {name}")).strong());
    match catalog.layout(ty) {
        Some(fields) if !fields.is_empty() => {
            egui::Grid::new("inspector_applied")
                .num_columns(4)
                .striped(true)
                .spacing([12.0, 3.0])
                .show(ui, |ui| {
                    for f in &fields {
                        ui.label(RichText::new(format!("+0x{:X}", f.offset)).monospace().weak());
                        ui.label(&f.path);
                        let tylabel = if f.count > 1 {
                            format!("{}[{}]", f.ty.label(), f.count)
                        } else {
                            f.ty.label()
                        };
                        ui.label(RichText::new(tylabel).monospace().weak());
                        let at = base + f.offset as usize;
                        ui.label(
                            RichText::new(field_value(catalog, &f.ty, f.count, data, at, endian))
                                .monospace(),
                        );
                        ui.end_row();
                    }
                });
        }
        Some(_) => {
            ui.label(muted("(no fields — enum or typedef)"));
        }
        None => {
            ui.label(muted("layout unavailable (unknown or self-referential member)"));
        }
    }
    ui.separator();
}

/// Formats the value of one (possibly array) field read from `data` at `at`.
fn field_value(
    catalog: &TypeCatalog,
    ty: &TypeRef,
    count: u64,
    data: &[u8],
    at: usize,
    endian: Endian,
) -> String {
    let elem_size = catalog.size_of(ty).unwrap_or(0) as usize;
    // Char arrays read as text; other arrays show their element count.
    if count > 1 {
        if matches!(ty, TypeRef::Prim(Prim::Char | Prim::I8 | Prim::U8)) {
            let end = (at + count as usize).min(data.len());
            let raw = data.get(at..end).unwrap_or(&[]);
            let text: String = raw
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                .collect();
            return format!("\"{text}\"");
        }
        return format!("[{count} × {}]", ty.label());
    }
    let Some(bytes) = data.get(at..at + elem_size) else {
        return "—".into();
    };
    scalar_value(ty, bytes, endian)
}

/// Formats a single scalar value from its raw bytes.
fn scalar_value(ty: &TypeRef, bytes: &[u8], endian: Endian) -> String {
    let le = endian == Endian::Little;
    macro_rules! int {
        ($t:ty) => {{
            const N: usize = std::mem::size_of::<$t>();
            let mut buf = [0u8; N];
            if bytes.len() < N {
                return "—".into();
            }
            buf.copy_from_slice(&bytes[..N]);
            let v = if le { <$t>::from_le_bytes(buf) } else { <$t>::from_be_bytes(buf) };
            v.to_string()
        }};
    }
    match ty {
        TypeRef::Prim(Prim::U8) => int!(u8),
        TypeRef::Prim(Prim::I8) => int!(i8),
        TypeRef::Prim(Prim::U16) => int!(u16),
        TypeRef::Prim(Prim::I16) => int!(i16),
        TypeRef::Prim(Prim::U32) => int!(u32),
        TypeRef::Prim(Prim::I32) => int!(i32),
        TypeRef::Prim(Prim::U64) => int!(u64),
        TypeRef::Prim(Prim::I64) => int!(i64),
        TypeRef::Prim(Prim::F32) => {
            let mut buf = [0u8; 4];
            if bytes.len() < 4 {
                return "—".into();
            }
            buf.copy_from_slice(&bytes[..4]);
            let v = if le { f32::from_le_bytes(buf) } else { f32::from_be_bytes(buf) };
            format!("{v}")
        }
        TypeRef::Prim(Prim::F64) => {
            let mut buf = [0u8; 8];
            if bytes.len() < 8 {
                return "—".into();
            }
            buf.copy_from_slice(&bytes[..8]);
            let v = if le { f64::from_le_bytes(buf) } else { f64::from_be_bytes(buf) };
            format!("{v}")
        }
        TypeRef::Prim(Prim::Bool) => {
            if bytes.first() == Some(&0) { "false".into() } else { "true".into() }
        }
        TypeRef::Prim(Prim::Char) => {
            let b = bytes.first().copied().unwrap_or(0);
            if (0x20..0x7f).contains(&b) {
                format!("'{}'", b as char)
            } else {
                format!("0x{b:02X}")
            }
        }
        TypeRef::Prim(Prim::Void) => "void".into(),
        TypeRef::Pointer(_) => {
            // Pointer width follows the catalog; show as hex.
            let mut v: u64 = 0;
            for (i, &b) in bytes.iter().enumerate().take(8) {
                if le {
                    v |= (b as u64) << (8 * i);
                } else {
                    v = (v << 8) | b as u64;
                }
            }
            format!("0x{v:X}")
        }
        // A nested named type: show its raw bytes; apply it separately to expand.
        TypeRef::Named(n) => format!("<{n}>"),
    }
}
