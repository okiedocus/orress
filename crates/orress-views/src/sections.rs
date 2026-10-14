//! Section table.

use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use orress_project::Document;
use orress_ui::{ExplainExt as _, muted};

use crate::colors::{entropy_color, section_color};
use crate::{DocView, ViewCtx, ViewRequest, fmt_addr};

pub fn sections(ui: &mut Ui, doc: &mut Document, cx: &mut ViewCtx<'_>) {
    let Some(analysis) = doc.analysis().cloned() else {
        return;
    };
    let info = &analysis.info;
    let wide = info.bits == Some(64);
    ui.label(muted(
        "A program is divided into sections. Each has a place in the file (offset, size) and \
         a place in memory (address). Permissions: R = readable, W = writable, X = executable \
         (code). Click a row to see its bytes; hover a name to learn what it usually holds.",
    ));
    ui.add_space(4.0);
    if info.sections.is_empty() {
        ui.label(muted("This file has no section table."));
    }

    let mut clicked = None;
    TableBuilder::new(ui)
        .id_salt("sections")
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(90.0))
        .columns(Column::auto().at_least(80.0), 4)
        .column(Column::auto().at_least(50.0))
        .column(Column::auto().at_least(110.0))
        .column(Column::remainder())
        .header(20.0, |mut h| {
            for (name, explain) in [
                ("Name", "Section name, chosen by the compiler or linker."),
                ("Offset", "Where the section starts in the file."),
                ("Size", "Bytes in the file."),
                ("Address", "Where the section is loaded in memory."),
                ("Mem size", "Bytes in memory. Larger than the file size for zero-filled data like .bss."),
                ("Perms", "R readable, W writable, X executable. Code is R-X; writable code (RWX) is suspicious."),
                ("Entropy", "Randomness of the section's bytes, 0–8. Near 8 means compressed or encrypted."),
                ("Usually contains", "What this section name normally means."),
            ] {
                h.col(|ui| {
                    ui.label(RichText::new(name).strong()).explain(name, explain);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, info.sections.len(), |mut row| {
                let i = row.index();
                let s = &info.sections[i];
                row.set_selected(s.contains_offset(doc.cursor));
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(egui::vec2(4.0, 14.0), Sense::hover());
                        ui.painter().rect_filled(r, 1.0, section_color(i));
                        ui.label(RichText::new(&s.name).monospace());
                    });
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("0x{:X}", s.offset)).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("0x{:X}", s.file_size)).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(fmt_addr(s.address, wide)).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("0x{:X}", s.virtual_size)).monospace());
                });
                row.col(|ui| {
                    let label = s.perms.label();
                    let rwx = s.perms.write && s.perms.execute;
                    let text = RichText::new(label).monospace();
                    ui.label(if rwx { text.color(ui.visuals().warn_fg_color) } else { text });
                });
                row.col(|ui| match s.entropy {
                    Some(e) => {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(egui::vec2(40.0 * e / 8.0 + 1.0, 10.0), Sense::hover());
                            ui.painter().rect_filled(r, 1.0, entropy_color(e));
                            ui.label(format!("{e:.2}"));
                        });
                    }
                    None => {
                        ui.label(muted("—"));
                    }
                });
                row.col(|ui| {
                    let meaning = orress_loaders::sections::explain(&s.name);
                    ui.label(RichText::new(meaning).small())
                        .on_hover_text(meaning);
                });
                if row.response().clicked() && s.file_size > 0 {
                    clicked = Some(i);
                }
            });
        });

    if let Some(i) = clicked {
        let s = &info.sections[i];
        doc.select(s.offset, s.file_size);
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Hex));
    }

    if !info.segments.is_empty() {
        ui.add_space(8.0);
        ui.collapsing(format!("Segments ({})", info.segments.len()), |ui| {
            ui.label(muted(
                "Segments are what the operating system actually loads. Each covers one or more \
                 sections with the same permissions.",
            ));
            egui::Grid::new("segments")
                .striped(true)
                .num_columns(5)
                .show(ui, |ui| {
                    for h in ["Name", "Offset", "Size", "Address", "Perms"] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for s in &info.segments {
                        ui.label(s.name.as_deref().unwrap_or("—"));
                        ui.monospace(format!("0x{:X}", s.offset));
                        ui.monospace(format!("0x{:X}", s.file_size));
                        ui.monospace(fmt_addr(s.address, wide));
                        ui.monospace(s.perms.label());
                        ui.end_row();
                    }
                });
        });
    }
}
