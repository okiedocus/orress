//! Data inspector: the bytes at the cursor read as every common type.

use egui::{RichText, Ui};
use orress_bytes::Endian;
use orress_project::DocStore;
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
