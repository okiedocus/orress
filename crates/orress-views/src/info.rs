//! "What is this file?": the triage overview.

use egui::{Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2};
use orress_loaders::{DetectionCategory, InsightLevel, ProtectionState};
use orress_project::Document;
use orress_ui::{ExplainExt as _, muted};

use crate::colors::entropy_color;
use crate::{DocView, ViewCtx, ViewRequest, fmt_addr};

fn card(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui)) {
    egui::Frame::group(ui.style())
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).strong().size(15.0));
            ui.add_space(4.0);
            add(ui);
        });
    ui.add_space(6.0);
}

fn row(ui: &mut Ui, label: &str, value: impl Into<egui::WidgetText>, explain: &str) {
    ui.label(RichText::new(label).weak())
        .explain(label, explain);
    ui.label(value);
    ui.end_row();
}

pub fn info(ui: &mut Ui, doc: &mut Document, cx: &mut ViewCtx<'_>) {
    let Some(analysis) = doc.analysis().cloned() else {
        return;
    };
    let info = &analysis.info;
    let wide = info.bits == Some(64);
    let path = doc.path.clone();

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.heading(doc.file_name());
        ui.label(muted(doc.path.display().to_string()));
        ui.horizontal(|ui| {
            if let Some(main) = doc.program().and_then(|p| p.main)
                && ui
                    .button(RichText::new("Go to main").strong())
                    .explain(
                        "Go to main",
                        "Jump to the program's own main function. The entry point runs C                          runtime start-up code first; main is where the programmer's code begins                          and usually where you want to start reading.",
                    )
                    .clicked()
            {
                doc.navigate_to_address(main);
                cx.requests.push(ViewRequest::Open(path.clone(), DocView::Disassembly));
            }
            for view in [
                DocView::Functions,
                DocView::Disassembly,
                DocView::Strings,
                DocView::Imports,
                DocView::Sections,
                DocView::Hex,
            ] {
                if ui.button(view.name()).explain(view.name(), view.explain()).clicked() {
                    cx.requests.push(ViewRequest::Open(path.clone(), view));
                }
            }
        });
        ui.add_space(8.0);

        card(ui, "What is this file?", |ui| {
            ui.label(RichText::new(info.format.name()).size(16.0));
            ui.label(info.format.explain());
            if let Some(e) = &info.parse_error {
                ui.label(muted(format!("Parser said: {e}")));
            }
            ui.add_space(6.0);
            egui::Grid::new("facts").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                row(ui, "Size", format!("{} bytes", info.size), "File size on disk.");
                if info.format != orress_loaders::Format::Unknown {
                    row(ui, "Kind", info.kind.name(), "Whether this is a program you run, a library other programs load, or an intermediate object file.");
                    row(
                        ui,
                        "Architecture",
                        format!("{} · {}", info.arch, info.endian.name()),
                        "The processor the code is written for, and the byte order of numbers. \
                         x86-64 is the 64-bit PC; ARM64 is phones, Apple Silicon and many servers. \
                         Little-endian stores the lowest byte first: 0x12345678 is 78 56 34 12.",
                    );
                    row(
                        ui,
                        "Image base",
                        fmt_addr(info.image_base, wide),
                        "The preferred memory address the file is loaded at. Addresses in the \
                         disassembly are this base plus an offset.",
                    );
                    if let Some(entry) = info.entry {
                        ui.label(RichText::new("Entry point").weak()).explain(
                            "Entry point",
                            "The address where the program starts running. Note: for C programs \
                             this is the C runtime start-up code, which calls main() a bit later.",
                        );
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(fmt_addr(entry, wide)).monospace());
                            if let Some(offset) = info.entry_offset()
                                && ui.small_button("show bytes").clicked()
                            {
                                doc.go_to(offset);
                                cx.requests.push(ViewRequest::Open(path.clone(), DocView::Hex));
                            }
                        });
                        ui.end_row();
                    }
                    row(
                        ui,
                        "Imports / exports",
                        format!("{} / {}", info.imports.len(), info.exports.len()),
                        "Imports: library functions this file calls. Exports: functions it offers.",
                    );
                    row(
                        ui,
                        "Symbols",
                        format!("{}{}", info.symbol_count, if info.has_debug_info { " + debug info" } else { "" }),
                        "Named functions and variables stored in the file.",
                    );
                }
                row(
                    ui,
                    "Entropy",
                    format!("{:.2} / 8 · {}", info.entropy, orress_bytes::entropy::describe(info.entropy)),
                    "How random the bytes are overall. See the graph below for where.",
                );
            });
        });

        if !info.insights.is_empty() {
            card(ui, "Observations and tips", |ui| {
                for insight in &info.insights {
                    let (tag, color) = match insight.level {
                        InsightLevel::Warning => ("WARNING", ui.visuals().warn_fg_color),
                        InsightLevel::Tip => ("TIP", ui.visuals().hyperlink_color),
                        InsightLevel::Info => ("INFO", ui.visuals().weak_text_color()),
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(tag).small().strong().color(color));
                        ui.label(RichText::new(&insight.title).strong());
                    });
                    ui.label(&insight.body);
                    ui.add_space(6.0);
                }
            });
        }

        if !info.detections.is_empty() {
            card(ui, "Detected", |ui| {
                for d in &info.detections {
                    ui.horizontal_wrapped(|ui| {
                        let color = if d.category == DetectionCategory::Packer {
                            ui.visuals().warn_fg_color
                        } else {
                            ui.visuals().hyperlink_color
                        };
                        ui.label(RichText::new(d.category.name()).small().color(color));
                        ui.label(RichText::new(&d.name).strong()).explain(&d.name, d.explain);
                        ui.label(muted(format!("({})", d.evidence)));
                    });
                    ui.label(RichText::new(d.explain).small());
                    ui.add_space(4.0);
                }
            });
        }

        if !info.protections.is_empty() {
            card(ui, "Protections", |ui| {
                ui.label(muted("Security features of the file. Hover a name to learn what it means for you as a reverser."));
                egui::Grid::new("protections").num_columns(3).spacing([16.0, 4.0]).striped(true).show(ui, |ui| {
                    for p in &info.protections {
                        ui.label(p.name).explain(p.name, p.explain);
                        let (text, color) = match p.state {
                            ProtectionState::On => ("yes", ui.visuals().hyperlink_color),
                            ProtectionState::Partial => ("partial", ui.visuals().warn_fg_color),
                            ProtectionState::Off => ("no", ui.visuals().weak_text_color()),
                        };
                        ui.label(RichText::new(text).strong().color(color));
                        ui.label(muted(&p.detail));
                        ui.end_row();
                    }
                });
            });
        }

        if let Some(pe) = &info.pe {
            card(ui, "Windows details", |ui| {
                egui::Grid::new("pe").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                    row(
                        ui,
                        "Compile time",
                        format!("{} ({:#x})", orress_bytes::inspect::format_unix(i64::from(pe.timestamp)), pe.timestamp),
                        "Link time stored in the PE header. Easy to fake: malware authors often \
                         set it to a random date, and reproducible builds store a hash here.",
                    );
                    row(ui, "Subsystem", pe.subsystem.as_str(), "Console programs open a text window; GUI programs show their own windows.");
                    row(
                        ui,
                        "Linker",
                        format!("{}.{}", pe.linker_version.0, pe.linker_version.1),
                        "Version of the linker that built the file. 14.x is Visual Studio 2015 or newer.",
                    );
                    row(ui, ".NET", if pe.is_dotnet { "yes" } else { "no" }, "Whether this is a .NET (C#) program.");
                    row(ui, "TLS callbacks", if pe.has_tls { "present" } else { "none" }, "Code that runs before the entry point.");
                    row(
                        ui,
                        "Rich header",
                        format!("{} entries", pe.rich.len()),
                        "Undocumented Microsoft linker data listing the tools used to build the file.",
                    );
                });
            });
        }

        card(ui, "Hashes", |ui| {
            ui.label(muted("Fingerprints of the file. Search them on VirusTotal or MalwareBazaar to see if the file is known."));
            egui::Grid::new("hashes").num_columns(3).spacing([12.0, 4.0]).show(ui, |ui| {
                let h = &info.hashes;
                let hash = |ui: &mut Ui, name: &str, value: &str, explain: &str| {
                    ui.label(RichText::new(name).weak()).explain(name, explain);
                    ui.label(RichText::new(value).monospace());
                    if ui.small_button("copy").clicked() {
                        ui.ctx().copy_text(value.to_owned());
                    }
                    ui.end_row();
                };
                hash(ui, "MD5", &h.md5, "Old 128-bit hash. Still used to identify samples, but not secure against deliberate collisions.");
                hash(ui, "SHA-1", &h.sha1, "160-bit hash, used by many older databases.");
                hash(ui, "SHA-256", &h.sha256, "The standard identifier for malware samples today.");
                if let Some(imp) = &h.imphash {
                    hash(ui, "Imphash", imp, "Hash of the import table. Variants of the same malware often share it even when their file hashes differ.");
                }
            });
        });

        card(ui, "Entropy graph", |ui| {
            ui.label(muted(
                "Randomness of the bytes along the file, from start (left) to end (right). Flat \
                 low parts are padding, middle values are code and data, values near 8 are \
                 compressed or encrypted. Colored bars below mark the sections. Click to jump there.",
            ));
            entropy_graph(ui, doc, cx);
        });
    });
}

fn entropy_graph(ui: &mut Ui, doc: &mut Document, cx: &mut ViewCtx<'_>) {
    let Some(analysis) = doc.analysis().cloned() else {
        return;
    };
    let blocks = &analysis.entropy;
    if blocks.is_empty() {
        return;
    }
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 140.0), Sense::click());
    let painter = ui.painter_at(rect);
    let plot = Rect::from_min_max(rect.min, Pos2::new(rect.right(), rect.bottom() - 14.0));
    painter.rect_filled(rect, 3.0, ui.visuals().extreme_bg_color);
    for level in [2.0f32, 4.0, 6.0] {
        let y = plot.bottom() - level / 8.0 * plot.height();
        painter.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            Stroke::new(0.5, ui.visuals().weak_text_color().gamma_multiply(0.4)),
        );
    }
    let n = blocks.len() as f32;
    let bar_w = (plot.width() / n).max(1.0);
    for (i, &e) in blocks.iter().enumerate() {
        let x = plot.left() + i as f32 / n * plot.width();
        let h = e / 8.0 * plot.height();
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(x, plot.bottom() - h),
                Pos2::new(x + bar_w, plot.bottom()),
            ),
            0.0,
            entropy_color(e),
        );
    }
    let size = analysis.info.size.max(1) as f32;
    for (i, s) in analysis
        .info
        .sections
        .iter()
        .enumerate()
        .filter(|(_, s)| s.file_size > 0)
    {
        let x0 = plot.left() + s.offset as f32 / size * plot.width();
        let x1 = plot.left() + s.offset.saturating_add(s.file_size) as f32 / size * plot.width();
        let band = Rect::from_min_max(
            Pos2::new(x0, plot.bottom() + 3.0),
            Pos2::new(x1.max(x0 + 1.0), rect.bottom() - 2.0),
        );
        painter.rect_filled(band, 1.0, crate::colors::section_color(i));
    }

    if let Some(pos) = response.hover_pos() {
        let frac = ((pos.x - plot.left()) / plot.width()).clamp(0.0, 0.9999);
        let offset = (frac * size) as u64;
        let index = (frac * n) as usize;
        let section = analysis
            .info
            .section_at_offset(offset)
            .map_or("no section", |s| s.name.as_str());
        let tip = format!(
            "offset 0x{offset:X} · {section}\nentropy {:.2}: {}",
            blocks[index],
            orress_bytes::entropy::describe(blocks[index])
        );
        if response.clicked() {
            doc.go_to(offset);
            cx.requests
                .push(ViewRequest::Open(doc.path.clone(), DocView::Hex));
        }
        response.on_hover_text(tip);
    }
}
