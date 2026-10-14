//! Strings list with filtering and flag highlighting.

use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use orress_bytes::strings::looks_like_flag;
use orress_project::Document;
use orress_ui::{ExplainExt as _, muted};

use crate::{DocView, ViewCtx, ViewRequest};

#[derive(Default)]
pub struct StringsState {
    filter: String,
    flags_only: bool,
    /// Strings inside executable code are mostly instruction bytes that happen to be
    /// printable ("D$pH"), so they are hidden unless asked for.
    show_code_strings: bool,
    min_len: Option<usize>,
    /// Cached filter result: (filter key, matching indices).
    cache: Option<(String, Vec<usize>)>,
}

pub fn strings(ui: &mut Ui, doc: &mut Document, state: &mut StringsState, cx: &mut ViewCtx<'_>) {
    let Some(analysis) = doc.analysis().cloned() else {
        return;
    };
    let all = &analysis.strings;
    ui.label(muted(
        "Readable text found in the file. Messages like \"Wrong password\" lead you to the \
         code that checks your input. Text that looks like a CTF flag is highlighted. Click a \
         row to see it in the hex view.",
    ));
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut state.filter).hint_text("Filter (case-insensitive)…").desired_width(240.0));
        ui.checkbox(&mut state.flags_only, "Flag-like only").explain(
            "Flag-like strings",
            "Show only strings shaped like a CTF flag, e.g. flag{...}, CTF{...} or HTB{...}.",
        );
        let mut min = state.min_len.unwrap_or(orress_project::MIN_STRING_LEN);
        ui.add(egui::Slider::new(&mut min, orress_project::MIN_STRING_LEN..=32).text("min length"))
            .explain("Minimum length", "Hide strings shorter than this. Short strings are often random bytes that happen to be printable.");
        state.min_len = Some(min);
        ui.checkbox(&mut state.show_code_strings, "Include code").explain(
            "Strings inside code",
            "By default, strings found inside executable sections are hidden: they are \
             mostly machine instructions whose bytes happen to be printable, like \"D$pH\". \
             Turn this on to see everything.",
        );
    });
    let info = &analysis.info;

    // The analysis identity and generation are part of the key: a patch re-extracts the
    // strings, and indices from the old list must never index the new one.
    let key = format!(
        "{:?}",
        (
            std::sync::Arc::as_ptr(&analysis),
            doc.generation,
            &state.filter,
            state.flags_only,
            state.min_len,
            state.show_code_strings
        )
    );
    if state.cache.as_ref().is_none_or(|(k, _)| *k != key) {
        let filter = state.filter.to_lowercase();
        let min = state.min_len.unwrap_or(0);
        let indices = all
            .iter()
            .enumerate()
            .filter(|(_, s)| s.text.chars().count() >= min)
            .filter(|(_, s)| !state.flags_only || looks_like_flag(&s.text))
            .filter(|(_, s)| {
                state.show_code_strings
                    || !info
                        .section_at_offset(s.offset as u64)
                        .is_some_and(|sec| sec.perms.execute)
            })
            .filter(|(_, s)| filter.is_empty() || s.text.to_lowercase().contains(&filter))
            .map(|(i, _)| i)
            .collect();
        state.cache = Some((key, indices));
    }
    let Some((_, indices)) = &state.cache else {
        return;
    };
    let capped = if all.len() >= orress_project::MAX_STRINGS {
        " (limit reached)"
    } else {
        ""
    };
    ui.label(muted(format!(
        "{} of {} strings{capped}",
        indices.len(),
        all.len()
    )));

    let wide = info.bits == Some(64);
    let program = doc.program().cloned();
    let mut clicked = None;
    let mut follow = None;
    TableBuilder::new(ui)
        .id_salt("strings")
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(if wide { 150.0 } else { 90.0 }))
        .column(Column::auto().at_least(60.0))
        .column(Column::auto().at_least(50.0))
        .column(Column::auto().at_least(45.0))
        .column(Column::remainder())
        .header(20.0, |mut h| {
            for (name, explain) in [
                ("Offset", "Position in the file."),
                ("Address", "Where the string is in memory when the program runs. This is the number you will see in disassembly."),
                ("Section", "Which section the string is in. Constant strings are usually in .rdata or .rodata."),
                ("Type", "ASCII: one byte per character. UTF-16: two bytes per character (Windows wide strings)."),
                ("Refs", "How many instructions use this string. Click to jump to the code that uses it: the fastest way from \"Wrong password\" to the password check."),
                ("Text", "The string itself."),
            ] {
                h.col(|ui| {
                    ui.label(RichText::new(name).strong()).explain(name, explain);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, indices.len(), |mut row| {
                let Some(s) = indices.get(row.index()).and_then(|&i| all.get(i)) else {
                    return;
                };
                let offset = s.offset as u64;
                row.set_selected(doc.cursor >= offset && doc.cursor < offset + s.byte_len as u64);
                row.col(|ui| {
                    ui.label(RichText::new(format!("0x{offset:X}")).monospace());
                });
                row.col(|ui| {
                    match info.offset_to_address(offset) {
                        Some(a) => ui.label(RichText::new(crate::fmt_addr(a, wide)).monospace()),
                        None => ui.label(muted("—")),
                    };
                });
                row.col(|ui| {
                    ui.label(info.section_at_offset(offset).map_or("", |sec| sec.name.as_str()));
                });
                row.col(|ui| {
                    ui.label(RichText::new(s.encoding.label()).small().weak());
                });
                row.col(|ui| {
                    // References to any byte of the string: Rust stores literals back
                    // to back, so one row can hold several strings.
                    let refs: Vec<orress_analysis::Xref> = program
                        .as_ref()
                        .zip(info.offset_to_address(offset))
                        .map(|(p, a)| {
                            (a..a + s.byte_len as u64)
                                .flat_map(|x| p.xrefs(x).iter().copied())
                                .collect()
                        })
                        .unwrap_or_default();
                    if let Some(first) = refs.first()
                        && ui.link(format!("{} »", refs.len())).on_hover_text("Go to the code that uses this string").clicked()
                    {
                        follow = Some(first.from);
                    }
                });
                row.col(|ui| {
                    let text = RichText::new(&s.text).monospace();
                    if looks_like_flag(&s.text) {
                        ui.label(RichText::new("FLAG?").small().strong().color(ui.visuals().warn_fg_color));
                        ui.label(text.color(ui.visuals().warn_fg_color));
                    } else {
                        ui.label(text);
                    }
                });
                if row.response().clicked() {
                    clicked = Some((offset, s.byte_len as u64));
                }
            });
        });
    if let Some(from) = follow {
        doc.navigate_to_address(from);
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Disassembly));
    } else if let Some((offset, len)) = clicked {
        doc.select(offset, len);
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Hex));
    }
}
