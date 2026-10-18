//! Linear disassembly view: the whole code of the file as a listing.
//!
//! Like the hex view it scrolls virtually by line number. Keys (when focused):
//! arrows/PageUp/PageDown move, Enter follows the address on the line, Esc goes back,
//! N renames, ; comments, X shows cross-references, Space switches to the graph.
//! Ctrl+F searches the listing text, F3 / Shift+F3 find the next / previous match.

use std::sync::Arc;

use egui::{Color32, FontId, Key, Modifiers, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2};
use orress_analysis::{LineKind, Program};
use orress_project::Document;
use orress_ui::ExplainExt as _;

use crate::code::{self, Rendered, Style, Target};
use crate::edit::{self, EditPopup};
use crate::find::{self, FindInput, FindStep};
use crate::{DocView, ViewCommand, ViewCtx, ViewRequest, menu};

#[derive(Default)]
pub struct DisasmState {
    top_line: usize,
    wheel: f32,
    /// Cursor offset seen last frame; when it changes the view scrolls to it.
    last_cursor: Option<u64>,
    show_bytes: bool,
    popup: Option<EditPopup>,
    goto: Option<GotoBar>,
    find: FindBar,
    /// What was right-clicked: the line and the address under the pointer, if any.
    menu: Option<(usize, Option<u64>)>,
}

/// Search in the listing: matches the text of each line as shown (address, mnemonic,
/// operands, names, comments, string notes), ignoring case.
#[derive(Default)]
struct FindBar {
    input: FindInput,
    /// Line of the last match and the cursor it left, so "next" continues after it even when
    /// several lines share an address (a function header and its first instruction).
    last: Option<(usize, u64)>,
    /// Match count per (query, document generation, number of names and comments): counting
    /// renders every line, so it runs once per query.
    count: Option<((String, u64, usize), usize)>,
}

/// Stop counting matches after this many (the count is shown as "10000+").
const MAX_COUNT: usize = 10_000;

struct GotoBar {
    text: String,
    error: Option<String>,
    focus: bool,
}

pub fn disasm_view(ui: &mut Ui, doc: &mut Document, state: &mut DisasmState, cx: &mut ViewCtx<'_>) {
    let Some(program) = crate::program_or_message(ui, doc) else {
        return;
    };
    if program.lines.is_empty() {
        ui.label("No executable code found in this file.");
        return;
    }

    let mut find_step = None;
    for command in std::mem::take(&mut cx.commands) {
        match command {
            ViewCommand::GoTo => {
                state.goto = Some(GotoBar {
                    text: String::new(),
                    error: None,
                    focus: true,
                });
            }
            ViewCommand::FindNext if !state.find.input.query.trim().is_empty() => {
                find_step = Some(FindStep::Next);
            }
            ViewCommand::FindPrevious if !state.find.input.query.trim().is_empty() => {
                find_step = Some(FindStep::Previous);
            }
            // Find, or F3 before anything was searched: open the bar.
            ViewCommand::Find | ViewCommand::FindNext | ViewCommand::FindPrevious => {
                state.find.input.show();
            }
            _ => {}
        }
    }

    toolbar(ui, doc, &program, state);
    patch_bar(ui, doc, &program);
    if state.goto.is_some() {
        goto_bar(ui, doc, &program, state);
    }
    if state.find.input.open {
        find_step = find_bar(ui, &mut state.find).or(find_step);
    }

    let font = FontId::monospace(13.0);
    let (char_w, row_h) = ui.fonts_mut(|f| (f.glyph_width(&font, '0'), f.row_height(&font) + 3.0));
    let rect = ui.available_rect_before_wrap();
    let visible = ((rect.height() / row_h).floor() as usize).max(1);
    let total = program.lines.len();
    let max_top = total.saturating_sub(visible);

    let id = ui.id().with("disasm");
    let response = ui.interact(rect, id, Sense::click_and_drag());
    let response = response.note(
        "Disassembly",
        "The program's machine code, one instruction per line: address, mnemonic (what it \
         does) and operands (what it works on). Function names end with a colon. Click a \
         name or address to jump there; Esc goes back. Keys: N rename, ; comment, X \
         cross-references, Space graph view, Ctrl+G go to, Ctrl+F find.",
    );
    if response.clicked() {
        response.request_focus();
    }
    let focused = response.has_focus() && state.popup.is_none() && state.goto.is_none();
    if focused {
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                id,
                egui::EventFilter {
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    tab: false,
                    escape: true,
                },
            );
        });
    }

    // Current line from the shared cursor.
    let cursor_addr = program.memory.address_of(doc.cursor);
    let cursor_line = cursor_addr.and_then(|a| program.line_index(a));
    if state.last_cursor != Some(doc.cursor) {
        state.last_cursor = Some(doc.cursor);
        if let Some(line) = cursor_line
            && (line < state.top_line || line >= state.top_line + visible)
        {
            state.top_line = line.saturating_sub(visible / 3).min(max_top);
        }
    }

    // Wheel scrolling.
    if ui.rect_contains_pointer(rect) {
        let dy = ui.input(|i| i.smooth_scroll_delta.y);
        state.wheel -= dy / row_h;
        let whole = state.wheel.trunc();
        state.wheel -= whole;
        state.top_line = if whole < 0.0 {
            state.top_line.saturating_sub((-whole) as usize)
        } else {
            (state.top_line + whole as usize).min(max_top)
        };
    }

    let style = Style {
        font: font.clone(),
        colors: code::syntax(ui.ctx()),
        text: ui.visuals().text_color(),
        muted: ui.visuals().weak_text_color(),
        wide: program.isa.pointer_size() == 8,
        show_address: true,
        show_bytes: state.show_bytes,
    };

    if let Some(step) = find_step {
        let current = cursor_line.unwrap_or(state.top_line);
        if let Some(line) = find(doc, &program, &style, &mut state.find, current, step) {
            if let Some(offset) = program.memory.offset_of(program.lines[line].addr) {
                doc.go_to(offset);
            }
            state.last_cursor = Some(doc.cursor);
            state.find.last = Some((line, doc.cursor));
            if line < state.top_line || line >= state.top_line + visible {
                state.top_line = line.saturating_sub(visible / 3).min(max_top);
            }
        }
    }
    let needle = state
        .find
        .input
        .open
        .then(|| state.find.input.needle())
        .flatten();

    // Debugger overlay: the current instruction and breakpoints (file virtual addresses).
    let dbg_rip = cx.debugger.current_file_rip(&doc.path);
    let breakpoints: std::collections::BTreeSet<u64> = cx.debugger.breakpoints().clone();

    // Paint visible lines and remember their spans for clicks.
    let painter = ui.painter_at(rect);
    let mut rows: Vec<(usize, Rect, Rendered)> = Vec::new();
    for i in 0..=visible {
        let index = state.top_line + i;
        let Some(line) = program.lines.get(index) else {
            break;
        };
        let y = rect.top() + i as f32 * row_h;
        let row = Rect::from_min_size(Pos2::new(rect.left(), y), Vec2::new(rect.width(), row_h));
        if Some(index) == cursor_line {
            painter.rect_filled(
                row,
                0.0,
                ui.visuals()
                    .selection
                    .bg_fill
                    .gamma_multiply(if focused { 1.0 } else { 0.6 }),
            );
        }
        if line.kind == LineKind::Function {
            painter.line_segment(
                [Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)],
                Stroke::new(1.0, ui.visuals().weak_text_color().gamma_multiply(0.5)),
            );
        }
        if line.kind == LineKind::Insn
            && let Some(offset) = program.memory.offset_of(line.addr)
            && let Some(len) = program.insns.get(&line.addr)
            && (offset..offset + u64::from(*len)).any(|o| doc.is_patched(o))
        {
            painter.rect_filled(
                Rect::from_min_size(row.min + Vec2::new(3.0, 0.0), Vec2::new(3.0, row_h)),
                0.0,
                egui::Color32::from_rgb(255, 150, 50),
            );
        }
        if doc.annotations.bookmarks.contains(&line.addr) && line.kind != LineKind::Region {
            painter.rect_filled(
                Rect::from_min_size(row.min, Vec2::new(3.0, row_h)),
                0.0,
                ui.visuals().warn_fg_color,
            );
        }
        // The instruction the debugger is stopped on: tint the row green.
        if line.kind == LineKind::Insn && Some(line.addr) == dbg_rip {
            painter.rect_filled(
                row,
                0.0,
                Color32::from_rgb(70, 130, 60).gamma_multiply(0.45),
            );
        }
        let rendered = code::render_line(doc, &program, line, &style);
        if let Some(needle) = &needle {
            let width = needle.chars().count() as f32 * char_w;
            for column in match_columns(&rendered.job.text, needle) {
                let x = rect.left() + 6.0 + column as f32 * char_w;
                painter.rect_filled(
                    Rect::from_min_size(Pos2::new(x, y + 1.0), Vec2::new(width, row_h - 2.0)),
                    2.0,
                    Color32::from_rgb(230, 180, 40).gamma_multiply(0.45),
                );
            }
        }
        let galley = ui.fonts_mut(|f| f.layout_job(rendered.job.clone()));
        painter.galley(Pos2::new(rect.left() + 6.0, y + 1.5), galley, style.text);
        // A breakpoint dot and, on the current instruction, a play triangle, in the gutter.
        if line.kind == LineKind::Insn && breakpoints.contains(&line.addr) {
            let c = Pos2::new(rect.left() + 4.0, y + row_h / 2.0);
            painter.circle_filled(c, 4.0, Color32::from_rgb(220, 60, 60));
        }
        if line.kind == LineKind::Insn && Some(line.addr) == dbg_rip {
            let cy = y + row_h / 2.0;
            let x = rect.left() + 1.0;
            painter.add(egui::Shape::convex_polygon(
                vec![
                    Pos2::new(x, cy - 4.0),
                    Pos2::new(x, cy + 4.0),
                    Pos2::new(x + 6.0, cy),
                ],
                Color32::from_rgb(120, 230, 100),
                Stroke::NONE,
            ));
        }
        rows.push((index, row, rendered));
    }

    // Hover and clicks on tokens.
    let span_under = |pos: Pos2| {
        let (index, row, rendered) = rows.iter().find(|(_, r, _)| r.contains(pos))?;
        let column = ((pos.x - row.left() - 6.0) / char_w).floor();
        let span = (column >= 0.0)
            .then(|| code::span_at(&rendered.spans, column as usize))
            .flatten();
        Some((*index, span.cloned()))
    };
    if let Some(pos) = response.hover_pos()
        && let Some((_, Some(span))) = span_under(pos)
    {
        hover_span(ui, doc, &program, &span, &response);
    }
    // A click in the left gutter toggles a breakpoint on that instruction.
    if response.clicked()
        && let Some(pos) = response.interact_pointer_pos()
        && pos.x < rect.left() + 12.0
        && let Some((index, _, _)) = rows.iter().find(|(_, r, _)| r.contains(pos))
        && program.lines[*index].kind == LineKind::Insn
    {
        cx.debugger.toggle_breakpoint(program.lines[*index].addr);
    } else if response.clicked()
        && let Some(pos) = response.interact_pointer_pos()
        && let Some((index, span)) = span_under(pos)
    {
        match span {
            Some(code::Span {
                target: Target::Address(addr),
                ..
            }) if !matches!(
                program.lines[index].kind,
                LineKind::Function | LineKind::Label
            ) =>
            {
                if !doc.navigate_to_address(addr) {
                    cx.requests.push(ViewRequest::Message(format!(
                        "0x{addr:x} is not inside the file."
                    )));
                }
            }
            _ => {
                if let Some(offset) = program.memory.offset_of(program.lines[index].addr) {
                    doc.go_to(offset);
                }
            }
        }
    }

    if focused {
        keyboard(ui, doc, &program, state, cursor_line, visible, max_top, cx);
    }

    // Right click: move the cursor to that line, then show what can be done there.
    if response.secondary_clicked()
        && let Some(pos) = response.interact_pointer_pos()
        && let Some((index, span)) = span_under(pos)
    {
        if let Some(offset) = program.memory.offset_of(program.lines[index].addr) {
            doc.go_to(offset);
            state.last_cursor = Some(doc.cursor);
        }
        let target = match span {
            Some(code::Span {
                target: Target::Address(a),
                ..
            }) => Some(a),
            _ => operand_address(&program, index),
        };
        state.menu = Some((index, target));
    }
    response.context_menu(|ui| {
        if let Some((index, target)) = state.menu {
            context_menu(ui, doc, &program, state, &style, index, target, cx);
        }
    });

    if let Some(popup) = &mut state.popup
        && !edit::show(ui, doc, popup)
    {
        state.popup = None;
        response.request_focus();
    }
}

fn toolbar(ui: &mut Ui, doc: &Document, program: &Program, state: &mut DisasmState) {
    ui.horizontal(|ui| {
        let here = program.memory.address_of(doc.cursor).map_or_else(
            || "cursor outside code".to_owned(),
            |a| code::describe_address(doc, program, a),
        );
        ui.label(RichText::new(here).monospace().strong());
        ui.separator();
        ui.label(
            RichText::new(format!(
                "{} · {} functions",
                program.isa.name(),
                program.functions.len()
            ))
            .weak(),
        );
        ui.separator();
        ui.checkbox(&mut state.show_bytes, "Bytes").explain(
            "Show instruction bytes",
            "Show the raw bytes of each instruction next to it. Useful when patching: you see \
             exactly which bytes to change.",
        );
        ui.label(
            RichText::new("N rename · ; comment · X xrefs · Space graph · Ctrl+F find · Esc back")
                .weak()
                .small(),
        );
    });
}

/// Patch buttons for the instruction under the cursor.
fn patch_bar(ui: &mut Ui, doc: &mut Document, program: &Program) {
    let Some(addr) = program
        .memory
        .address_of(doc.cursor)
        .and_then(|a| program.insn_start(a))
    else {
        return;
    };
    let (Some(insn), Some(offset)) = (program.decode(addr), program.memory.offset_of(addr)) else {
        return;
    };
    let Some(bytes) = program
        .memory
        .read(addr, usize::from(insn.len))
        .map(<[u8]>::to_vec)
    else {
        return;
    };
    let isa = program.isa;
    let mut result = None;
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("Patch {}:", insn.mnemonic)).weak()).explain(
            "Patching",
            "Change the program's bytes. This is how crackme protections are removed: skip a \
             check, or make a jump always (or never) go to \"Correct\". Patches are kept with your \
             work and the original file is not changed; save a patched copy to run it.",
        );
        if let Some(nops) = orress_arch::patch::try_nop(isa, bytes.len())
            && ui
                .small_button("NOP")
                .explain("NOP", "Replace this instruction with NOPs (no operation): it is skipped entirely.")
                .clicked()
        {
            result = Some(doc.patch(offset, &nops));
        }
        if let Some(inverted) = orress_arch::patch::invert(isa, &bytes)
            && ui
                .small_button("Invert jump")
                .explain("Invert jump", "Flip the condition: je becomes jne, jl becomes jge, and so on. The program now goes the other way.")
                .clicked()
        {
            result = Some(doc.patch(offset, &inverted));
        }
        if let Some(forced) = orress_arch::patch::force(isa, &bytes)
            && ui
                .small_button("Always jump")
                .explain("Always jump", "Make the conditional jump unconditional: it is always taken, whatever was compared before.")
                .clicked()
        {
            result = Some(doc.patch(offset, &forced));
        }
        let patched = (offset..offset + bytes.len() as u64).any(|o| doc.is_patched(o));
        if patched
            && ui
                .small_button("Undo patch")
                .explain("Undo patch", "Restore this instruction's original bytes.")
                .clicked()
        {
            let original: Vec<u8> = (offset..offset + bytes.len() as u64)
                .filter_map(|o| doc.original_byte(o))
                .collect();
            result = Some(doc.patch(offset, &original));
        }
        let total = doc.annotations.patches.len();
        if total > 0 {
            ui.separator();
            ui.label(RichText::new(format!("{total} byte{} patched", if total == 1 { "" } else { "s" })).color(egui::Color32::from_rgb(255, 150, 50)));
            if ui.small_button("Save patched file…").clicked() {
                let message = crate::save_patched(doc);
                ui.ctx().data_mut(|d| d.insert_temp(patch_message_id(doc), message));
            }
        }
        if let Some(m) = ui.ctx().data(|d| d.get_temp::<String>(patch_message_id(doc))) {
            ui.label(RichText::new(m).weak().small());
        }
    });
    if let Some(Err(e)) = result {
        ui.colored_label(ui.visuals().warn_fg_color, e);
    }
}

/// Where the last "Save patched file" message for `doc` is kept (per file, so it does not
/// show on every other document).
fn patch_message_id(doc: &Document) -> egui::Id {
    egui::Id::new(("orress::patch_message", &doc.path))
}

/// Resolves go-to input: a name, a hex address, or an offset with `#`.
fn resolve(doc: &Document, program: &Program, text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("type an address (hex) or a name such as main".into());
    }
    if let Some((&addr, _)) = doc
        .annotations
        .names
        .iter()
        .find(|(_, n)| n.as_str() == text)
    {
        return Ok(addr);
    }
    if let Some((&addr, _)) = program.names.iter().find(|(_, n)| n.text == text) {
        return Ok(addr);
    }
    let hex = text.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16).map_err(|_| format!("no function or address called `{text}`"))
}

fn goto_bar(ui: &mut Ui, doc: &mut Document, program: &Arc<Program>, state: &mut DisasmState) {
    let Some(bar) = &mut state.goto else {
        return;
    };
    let mut close = false;
    ui.horizontal(|ui| {
        ui.label("Go to").explain(
            "Go to",
            "Type a memory address in hex (401000), or the name of a function such as main or \
             a name you gave yourself.",
        );
        let edit = ui.add(
            egui::TextEdit::singleline(&mut bar.text)
                .hint_text("address or name, e.g. main or 401000")
                .desired_width(260.0)
                .font(egui::TextStyle::Monospace),
        );
        if bar.focus {
            edit.request_focus();
            bar.focus = false;
        }
        let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if ui.button("Go").clicked() || enter {
            match resolve(doc, program, &bar.text) {
                Ok(addr) if doc.navigate_to_address(addr) => close = true,
                Ok(addr) => {
                    bar.error = Some(format!("0x{addr:x} is not inside the file"));
                    bar.focus = true;
                }
                Err(e) => {
                    bar.error = Some(e);
                    bar.focus = true;
                }
            }
        }
        if ui.button("×").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
            close = true;
        }
        if let Some(e) = &bar.error {
            ui.colored_label(ui.visuals().warn_fg_color, e);
        }
    });
    if close {
        state.goto = None;
    }
}

/// The right-click menu of a line. `target` is the address under the pointer (or the
/// line's address operand).
#[allow(clippy::too_many_arguments)]
fn context_menu(
    ui: &mut Ui,
    doc: &mut Document,
    program: &Program,
    state: &mut DisasmState,
    style: &Style,
    index: usize,
    target: Option<u64>,
    cx: &mut ViewCtx<'_>,
) {
    let Some(line) = program.lines.get(index).cloned() else {
        return;
    };
    ui.set_min_width(220.0);
    let shortcut = |label: &str, keys: &str| egui::Button::new(label).shortcut_text(keys);
    if let Some(addr) = target {
        let name = code::describe_address(doc, program, addr);
        if ui.button(format!("Go to {name}")).clicked() {
            if !doc.navigate_to_address(addr) {
                cx.requests.push(ViewRequest::Message(format!(
                    "0x{addr:x} is not inside the file."
                )));
            }
            ui.close();
        }
    }
    if let Some(addr) = rename_target(program, index) {
        let name = code::describe_address(doc, program, addr);
        if ui.add(shortcut(&format!("Rename {name}…"), "N")).clicked() {
            state.popup = Some(EditPopup::rename(doc, addr));
            ui.close();
        }
        if ui
            .add(shortcut(&format!("Cross-references to {name}"), "X"))
            .clicked()
        {
            doc.xref_target = Some(addr);
            cx.requests.push(ViewRequest::ShowXrefs);
            ui.close();
        }
    }
    if ui.add(shortcut("Comment…", ";")).clicked() {
        state.popup = Some(EditPopup::comment(doc, line.addr));
        ui.close();
    }
    let bookmarked = doc.annotations.bookmarks.contains(&line.addr);
    if ui
        .add(shortcut(
            if bookmarked {
                "Remove bookmark"
            } else {
                "Bookmark"
            },
            "B",
        ))
        .clicked()
    {
        doc.toggle_bookmark(line.addr);
        ui.close();
    }
    if line.kind == LineKind::Insn {
        let has = cx.debugger.breakpoints().contains(&line.addr);
        if ui
            .add(shortcut(
                if has {
                    "Remove breakpoint"
                } else {
                    "Set breakpoint"
                },
                "F9",
            ))
            .clicked()
        {
            cx.debugger.toggle_breakpoint(line.addr);
            ui.close();
        }
        patch_menu(ui, doc, program, line.addr, cx);
    }
    ui.menu_button("Copy", |ui| {
        menu::copy_item(ui, "Address", format!("0x{:x}", line.addr));
        let text = code::render_line(doc, program, &line, style).job.text;
        menu::copy_item(ui, "Line", text.trim().to_owned());
        if line.kind == LineKind::Insn
            && let Some(len) = program.insns.get(&line.addr)
            && let Some(bytes) = program.memory.read(line.addr, usize::from(*len))
        {
            let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
            menu::copy_item(ui, "Instruction bytes", hex.join(" "));
        }
        if let Some(f) = program.function_containing(line.addr) {
            menu::copy_item(
                ui,
                "Function name",
                code::describe_address(doc, program, f.entry),
            );
        }
    });
    ui.separator();
    if program.function_containing(line.addr).is_some() {
        menu::command(ui, cx.requests, "view::Decompiler");
    }
    if ui.add(shortcut("Show in graph", "Space")).clicked() {
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Graph));
        ui.close();
    }
    if ui.button("Show in hex").clicked() {
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Hex));
        ui.close();
    }
    if ui.add(shortcut("Find…", "Ctrl+F")).clicked() {
        state.find.input.show();
        ui.close();
    }
    if ui
        .add(shortcut("Go to address or name…", "Ctrl+G"))
        .clicked()
    {
        state.goto = Some(GotoBar {
            text: String::new(),
            error: None,
            focus: true,
        });
        ui.close();
    }
    menu::views_and_commands(ui, cx.requests);
}

/// The Patch submenu for the instruction at `addr`: the same patches as the patch bar.
pub(crate) fn patch_menu(
    ui: &mut Ui,
    doc: &mut Document,
    program: &Program,
    addr: u64,
    cx: &mut ViewCtx<'_>,
) {
    let (Some(insn), Some(offset)) = (program.decode(addr), program.memory.offset_of(addr)) else {
        return;
    };
    let Some(bytes) = program
        .memory
        .read(addr, usize::from(insn.len))
        .map(<[u8]>::to_vec)
    else {
        return;
    };
    let isa = program.isa;
    let mut options: Vec<(&str, Vec<u8>)> = Vec::new();
    if let Some(nops) = orress_arch::patch::try_nop(isa, bytes.len()) {
        options.push(("NOP (skip this instruction)", nops));
    }
    if let Some(inverted) = orress_arch::patch::invert(isa, &bytes) {
        options.push(("Invert jump", inverted));
    }
    if let Some(forced) = orress_arch::patch::force(isa, &bytes) {
        options.push(("Always jump", forced));
    }
    if (offset..offset + bytes.len() as u64).any(|o| doc.is_patched(o)) {
        let original: Vec<u8> = (offset..offset + bytes.len() as u64)
            .filter_map(|o| doc.original_byte(o))
            .collect();
        options.push(("Undo patch", original));
    }
    if options.is_empty() {
        return;
    }
    ui.menu_button("Patch", |ui| {
        for (label, patch) in options {
            if ui.button(label).clicked() {
                if let Err(e) = doc.patch(offset, &patch) {
                    cx.requests.push(ViewRequest::Message(e));
                }
                ui.close();
            }
        }
    });
}

/// Character columns where `needle` (lowercase ASCII) starts in `text`, ignoring case.
fn match_columns(text: &str, needle: &str) -> Vec<usize> {
    find::matches(text, needle)
        .into_iter()
        .map(|at| text[..at].chars().count())
        .collect()
}

fn line_matches(
    doc: &Document,
    program: &Program,
    style: &Style,
    index: usize,
    needle: &str,
) -> bool {
    program.lines.get(index).is_some_and(|line| {
        code::render_line(doc, program, line, style)
            .job
            .text
            .to_ascii_lowercase()
            .contains(needle)
    })
}

/// Finds the next or previous line matching the query, wrapping around, and updates the
/// status. Returns the line index.
fn find(
    doc: &Document,
    program: &Program,
    style: &Style,
    bar: &mut FindBar,
    current: usize,
    step: FindStep,
) -> Option<usize> {
    let Some(needle) = bar.input.needle() else {
        bar.input.status = Some(Err("type something to search for".into()));
        return None;
    };
    let total = program.lines.len();
    // Continue from the last match if the cursor has not moved since.
    let from = match bar.last {
        Some((line, cursor)) if cursor == doc.cursor && line < total => line,
        _ => current.min(total - 1),
    };
    let found = (1..=total)
        .map(|i| match step {
            FindStep::Next => (from + i) % total,
            FindStep::Previous => (from + total - i) % total,
        })
        .find(|&i| line_matches(doc, program, style, i, &needle));
    bar.input.status = Some(match found {
        Some(line) => {
            let key = (
                needle.clone(),
                doc.generation,
                doc.annotations.names.len() + doc.annotations.comments.len(),
            );
            let count = match &bar.count {
                Some((k, n)) if *k == key => *n,
                _ => {
                    let n = (0..total)
                        .filter(|&i| line_matches(doc, program, style, i, &needle))
                        .take(MAX_COUNT)
                        .count();
                    bar.count = Some((key, n));
                    n
                }
            };
            let more = if count >= MAX_COUNT { "+" } else { "" };
            let wrapped = match step {
                FindStep::Next => line <= from,
                FindStep::Previous => line >= from,
            };
            Ok(format!(
                "0x{:x} · {count}{more} matching line{}{}",
                program.lines[line].addr,
                if count == 1 { "" } else { "s" },
                if wrapped && count > 1 {
                    " · wrapped around"
                } else {
                    ""
                }
            ))
        }
        None => Err("not found".into()),
    });
    found
}

/// The find bar. Returns the search to run this frame, if any.
fn find_bar(ui: &mut Ui, bar: &mut FindBar) -> Option<FindStep> {
    let result = find::bar(
        ui,
        &mut bar.input,
        "e.g. xor, call, 0x5a, Correct",
        "Search the listing for text, ignoring upper/lower case: a mnemonic (xor), a register \
         (rcx), a number (0x5a), a function or label name, an address, or words in comments \
         and string notes (Correct). F3 finds the next match, Shift+F3 the previous one. To \
         search the file's raw bytes, use Find in the Hex view.",
    );
    if result.changed {
        bar.last = None;
    }
    result.step
}

fn hover_span(
    ui: &Ui,
    doc: &Document,
    program: &Program,
    span: &code::Span,
    response: &egui::Response,
) {
    match &span.target {
        Target::Mnemonic(m) => {
            if let Some(text) = orress_arch::explain::mnemonic(program.isa, m) {
                response.clone().explain(m, text);
            }
        }
        Target::Register(r) => {
            if let Some(text) = orress_arch::explain::register(program.isa, r) {
                response.clone().explain(r, text);
            }
        }
        Target::Number(value) => {
            response
                .clone()
                .on_hover_text_at_pointer(code::describe_number(*value));
        }
        Target::Address(addr) => {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            let mut tip = format!("0x{addr:x}");
            if let Some(name) = doc.name_of(*addr) {
                tip = format!("{name}\n{tip}");
            }
            if let Some(s) = program.string_refs.get(addr) {
                tip += &format!("\nstring: \"{}\"", s.chars().take(80).collect::<String>());
            }
            let refs = program.xrefs(*addr).len();
            if refs > 0 {
                tip += &format!("\n{refs} reference(s)");
            }
            tip += "\nclick to go there";
            response.clone().on_hover_text_at_pointer(tip);
        }
    }
}

/// First address operand of the instruction on a line (what Enter follows).
fn operand_address(program: &Program, index: usize) -> Option<u64> {
    let line = program.lines.get(index)?;
    let insn = program.decode(line.addr)?;
    insn.operands.iter().find_map(|t| match t.kind {
        orress_analysis::TokenKind::Address(a) => Some(a),
        _ => None,
    })
}

/// The address N (rename) applies to on the current line: the line's own name, or the
/// named target on an instruction (rename a callee from its call site).
fn rename_target(program: &Program, index: usize) -> Option<u64> {
    let line = program.lines.get(index)?;
    match line.kind {
        LineKind::Function | LineKind::Label => Some(line.addr),
        LineKind::Insn => {
            let insn = program.decode(line.addr)?;
            insn.operands
                .iter()
                .find_map(|t| match t.kind {
                    orress_analysis::TokenKind::Address(a) => Some(a),
                    _ => None,
                })
                .or_else(|| program.function_containing(line.addr).map(|f| f.entry))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn keyboard(
    ui: &Ui,
    doc: &mut Document,
    program: &Program,
    state: &mut DisasmState,
    cursor_line: Option<usize>,
    visible: usize,
    max_top: usize,
    cx: &mut ViewCtx<'_>,
) {
    let total = program.lines.len();
    let current = cursor_line.unwrap_or(state.top_line);
    let press = |key| ui.input_mut(|i| i.consume_key(Modifiers::NONE, key));
    let mut target_line = None;
    if press(Key::ArrowDown) {
        target_line = Some((current + 1).min(total - 1));
    }
    if press(Key::ArrowUp) {
        target_line = Some(current.saturating_sub(1));
    }
    if press(Key::PageDown) {
        target_line = Some((current + visible).min(total - 1));
    }
    if press(Key::PageUp) {
        target_line = Some(current.saturating_sub(visible));
    }
    if let Some(t) = target_line
        && let Some(offset) = program.memory.offset_of(program.lines[t].addr)
    {
        doc.go_to(offset);
        if t < state.top_line {
            state.top_line = t;
        } else if t >= state.top_line + visible {
            state.top_line = (t + 1 - visible).min(max_top);
        }
        state.last_cursor = Some(doc.cursor);
    }
    if press(Key::Enter)
        && let Some(addr) = operand_address(program, current)
    {
        doc.navigate_to_address(addr);
    }
    if press(Key::Escape) || press(Key::Backspace) {
        doc.go_back();
    }
    if press(Key::N)
        && let Some(addr) = rename_target(program, current)
    {
        state.popup = Some(EditPopup::rename(doc, addr));
    }
    if press(Key::Semicolon)
        && let Some(line) = program.lines.get(current)
    {
        state.popup = Some(EditPopup::comment(doc, line.addr));
    }
    if press(Key::X)
        && let Some(addr) = rename_target(program, current)
    {
        doc.xref_target = Some(addr);
        cx.requests.push(ViewRequest::ShowXrefs);
    }
    if press(Key::Space) {
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Graph));
    }
    if press(Key::B)
        && let Some(line) = program.lines.get(current)
    {
        doc.toggle_bookmark(line.addr);
    }
    if press(Key::F9)
        && let Some(line) = program.lines.get(current)
        && line.kind == LineKind::Insn
    {
        cx.debugger.toggle_breakpoint(line.addr);
    }
}

#[cfg(test)]
mod tests {
    use super::match_columns;

    #[test]
    fn match_columns_ignore_case() {
        assert_eq!(match_columns("  401000  XOR eax, eax", "xor"), vec![10]);
        assert_eq!(match_columns("mov rax, rax", "rax"), vec![4, 9]);
        assert!(match_columns("call main", "jmp").is_empty());
    }
}
