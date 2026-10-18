//! The hex editor view. Edit mode overwrites bytes as patches; the file on disk is never
//! changed (save a patched copy instead).
//!
//! Scrolling is virtual: only visible rows are laid out, and the position is a row
//! number (u64), not a pixel offset, so files of any size scroll precisely. The entropy
//! minimap on the right doubles as the scrollbar.

use egui::text::LayoutJob;
use egui::{
    Color32, FontId, Key, Modifiers, Pos2, Rect, RichText, Sense, Stroke, StrokeKind, TextFormat,
    Ui, Vec2,
};
use orress_bytes::search::Pattern;
use orress_project::Document;
use orress_ui::ExplainExt as _;

use crate::colors::{entropy_color, section_color};
use crate::{ViewCommand, ViewCtx};

const BYTES_PER_ROW: u64 = 16;
/// Character columns: 8-digit offset + 2 spaces, then 16 hex bytes (3 chars each, plus
/// one extra space in the middle), 1 space, then 16 ASCII characters.
const HEX_COL: f32 = 10.0;
const ASCII_COL: f32 = HEX_COL + 16.0 * 3.0 + 1.0 + 1.0;
const MINIMAP_WIDTH: f32 = 16.0;
const MAX_COUNT: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum FindMode {
    #[default]
    Text,
    Utf16,
    Hex,
}

#[derive(Default)]
struct FindBar {
    open: bool,
    mode: FindMode,
    query: String,
    status: Option<Result<String, String>>,
    focus: bool,
    /// Matches in the whole file for (mode, query, document generation): counting scans the
    /// file, so it runs once per pattern, not on every Find / F3.
    count: Option<((FindMode, String, u64), usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum GotoMode {
    #[default]
    Offset,
    Address,
}

#[derive(Default)]
struct GotoBar {
    open: bool,
    mode: GotoMode,
    input: String,
    error: Option<String>,
    focus: bool,
}

#[derive(Default)]
pub struct HexState {
    top_row: u64,
    anchor: Option<u64>,
    wheel: f32,
    find: FindBar,
    goto: GotoBar,
    dragging_minimap: bool,
    /// Edit mode: typing hex digits overwrites bytes (as patches).
    edit: bool,
    /// First hex digit typed for the byte at the cursor.
    nibble: Option<u8>,
    message: Option<String>,
}

struct Geometry {
    char_w: f32,
    row_h: f32,
    content: Rect,
    visible_rows: u64,
}

/// Space left of the offset column for the section band.
const LEFT_PAD: f32 = 7.0;

impl Geometry {
    fn x0(&self) -> f32 {
        self.content.left() + LEFT_PAD
    }

    fn row_y(&self, row_from_top: u64) -> f32 {
        self.content.top() + row_from_top as f32 * self.row_h
    }

    fn hex_x(&self, i: u64) -> f32 {
        let extra = if i >= 8 { 1.0 } else { 0.0 };
        self.x0() + (HEX_COL + i as f32 * 3.0 + extra) * self.char_w
    }

    fn ascii_x(&self, i: u64) -> f32 {
        self.x0() + (ASCII_COL + i as f32) * self.char_w
    }

    /// Byte column (0..16) under x, and whether x is in the hex or ascii area.
    fn column_at(&self, x: f32) -> u64 {
        let col = (x - self.x0()) / self.char_w;
        if col >= ASCII_COL - 0.5 {
            ((col - ASCII_COL).floor().max(0.0) as u64).min(15)
        } else {
            let c = (col - HEX_COL).max(0.0);
            let i = if c >= 24.5 {
                8.0 + ((c - 25.0).max(0.0) / 3.0).floor()
            } else {
                (c / 3.0).floor()
            };
            (i as u64).min(15)
        }
    }
}

pub fn hex_view(ui: &mut Ui, doc: &mut Document, state: &mut HexState, cx: &mut ViewCtx<'_>) {
    let Some(data) = doc.bytes().cloned() else {
        return;
    };
    let len = data.len() as u64;

    for command in std::mem::take(&mut cx.commands) {
        match command {
            ViewCommand::GoTo => {
                state.goto.open = true;
                state.goto.focus = true;
                state.find.open = false;
            }
            ViewCommand::Find => {
                state.find.open = true;
                state.find.focus = true;
                state.goto.open = false;
            }
            ViewCommand::FindNext => find(doc, &data, &mut state.find, true),
            ViewCommand::FindPrevious => find(doc, &data, &mut state.find, false),
            ViewCommand::CopyHex | ViewCommand::CopyCArray | ViewCommand::CopyPython => {
                copy_selection(ui, doc, &data, command);
            }
        }
    }

    toolbar(ui, doc, state);
    // Patching re-analyzes in the background; use the freshest bytes.
    let Some(data) = doc.bytes().cloned() else {
        return;
    };
    if state.goto.open {
        goto_bar(ui, doc, &mut state.goto);
    }
    if state.find.open {
        find_bar(ui, doc, &data, &mut state.find);
    }
    ui.add_space(2.0);

    if len == 0 {
        ui.label(RichText::new("The file is empty.").weak());
        return;
    }

    // Layout
    let font = FontId::monospace(13.0);
    let (char_w, row_h) = ui.fonts_mut(|f| (f.glyph_width(&font, '0'), f.row_height(&font) + 2.0));
    let full = ui.available_rect_before_wrap();
    let content = Rect::from_min_max(
        full.min,
        Pos2::new(full.right() - MINIMAP_WIDTH - 4.0, full.bottom()),
    );
    let minimap = Rect::from_min_max(
        Pos2::new(full.right() - MINIMAP_WIDTH, full.top()),
        full.max,
    );
    let geo = Geometry {
        char_w,
        row_h,
        content,
        visible_rows: ((content.height() / row_h).floor() as u64).max(1),
    };
    let total_rows = len.div_ceil(BYTES_PER_ROW);
    let max_top = total_rows.saturating_sub(geo.visible_rows);

    let id = ui.id().with("hex_grid");
    let response = ui.interact(content, id, Sense::click_and_drag());
    let response = response.note(
        "Hex view",
        "Each row shows 16 bytes. Left: the offset (position in the file) of the first byte. \
         Middle: the bytes as two-digit hexadecimal numbers. Right: the same bytes as text, \
         with a dot for bytes that are not printable. Click a byte to inspect it; drag to \
         select. Arrow keys move, Shift extends the selection, Ctrl+G goes to an offset, \
         Ctrl+F searches.",
    );
    if response.clicked() || response.drag_started() {
        response.request_focus();
    }
    let focused = response.has_focus();
    if focused {
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                id,
                egui::EventFilter {
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    tab: false,
                    escape: false,
                },
            );
        });
    }

    // Mouse
    let byte_at = |pos: Pos2, top_row: u64| -> u64 {
        let row = top_row + ((pos.y - content.top()) / row_h).max(0.0) as u64;
        (row * BYTES_PER_ROW + geo.column_at(pos.x)).min(len - 1)
    };
    if let Some(pos) = response.interact_pointer_pos() {
        let byte = byte_at(pos, state.top_row);
        let shift = ui.input(|i| i.modifiers.shift);
        if response.drag_started() || (response.clicked() && !shift) {
            state.anchor = Some(byte);
            doc.cursor = byte;
            doc.selection = None;
        } else if response.dragged() || (response.clicked() && shift) {
            let anchor = *state.anchor.get_or_insert(doc.cursor);
            doc.cursor = byte;
            doc.selection = (anchor != byte).then(|| (anchor.min(byte), anchor.max(byte) + 1));
        }
        // Auto-scroll while dragging past the edges.
        if response.dragged() {
            if pos.y < content.top() {
                state.top_row = state.top_row.saturating_sub(1);
            } else if pos.y > content.bottom() {
                state.top_row = (state.top_row + 1).min(max_top);
            }
        }
    }
    if ui.rect_contains_pointer(full) {
        let dy = ui.input(|i| i.smooth_scroll_delta.y);
        state.wheel -= dy / row_h;
        let whole = state.wheel.trunc();
        state.wheel -= whole;
        state.top_row = if whole < 0.0 {
            state.top_row.saturating_sub((-whole) as u64)
        } else {
            (state.top_row + whole as u64).min(max_top)
        };
    }

    // Right click: on a byte outside the selection, move the cursor there first.
    if response.secondary_clicked()
        && let Some(pos) = response.interact_pointer_pos()
    {
        let byte = byte_at(pos, state.top_row);
        let inside = doc.selection.is_some_and(|(a, b)| (a..b).contains(&byte));
        if !inside {
            doc.cursor = byte;
            doc.selection = None;
            state.anchor = Some(byte);
        }
    }
    response.context_menu(|ui| context_menu(ui, doc, &data, state, cx));

    // Keyboard
    if focused {
        keyboard(ui, doc, state, &geo, len);
        if state.edit {
            edit_keys(ui, doc, state, len);
        }
        // Ctrl+C arrives as a Copy event rather than a key press.
        if ui.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Copy))) {
            copy_selection(ui, doc, &data, ViewCommand::CopyHex);
        }
    }

    // Keep the cursor visible after keyboard moves and reveal requests.
    if doc.reveal {
        doc.reveal = false;
        let row = doc.cursor / BYTES_PER_ROW;
        if row < state.top_row || row >= state.top_row + geo.visible_rows {
            state.top_row = row.saturating_sub(geo.visible_rows / 3).min(max_top);
        }
    }
    state.top_row = state.top_row.min(max_top);

    paint_rows(ui, doc, &data, state.top_row, &geo, &font, focused);
    minimap_ui(ui, doc, state, minimap, &geo, total_rows, max_top);
}

fn toolbar(ui: &mut Ui, doc: &mut Document, state: &mut HexState) {
    ui.horizontal(|ui| {
        if ui
            .selectable_label(state.edit, "Edit bytes")
            .explain(
                "Edit bytes",
                "Turn on, click a byte and type two hex digits to change it. Changes are \
                 patches: the file on disk stays untouched until you save a patched copy. \
                 Changed bytes are shown in orange.",
            )
            .clicked()
        {
            state.edit = !state.edit;
            state.nibble = None;
        }
        if let Some(n) = state.nibble {
            ui.label(RichText::new(format!("typing: {n:X}_")).monospace().strong());
        }
        let patched = doc.annotations.patches.len();
        if patched > 0 {
            ui.label(
                RichText::new(format!("{patched} byte{} patched", if patched == 1 { "" } else { "s" }))
                    .color(ui.visuals().warn_fg_color),
            );
            if ui.small_button("Revert all").explain("Revert all", "Remove every patch and go back to the original bytes.").clicked() {
                doc.revert_patches();
            }
            if ui
                .small_button("Save patched file…")
                .explain("Save patched file", "Write a copy of the file with your patches applied, e.g. to run the cracked program.")
                .clicked()
            {
                state.message = Some(crate::save_patched(doc));
            }
        }
        if let Some(m) = &state.message {
            ui.label(RichText::new(m).weak());
        }
        ui.separator();
        ui.label(RichText::new(doc.file_name()).strong())
            .on_hover_text(doc.path.display().to_string());
        ui.label(RichText::new(format!("{} bytes", doc.len())).weak());
        ui.separator();
        if ui
            .selectable_label(state.goto.open, "Go to…")
            .explain(
                "Go to",
                "Jump to a file offset or a memory address. Shortcut: Ctrl+G.",
            )
            .clicked()
        {
            state.goto.open = !state.goto.open;
            state.goto.focus = state.goto.open;
        }
        if ui
            .selectable_label(state.find.open, "Find…")
            .explain(
                "Find",
                "Search for text or a byte pattern. Shortcut: Ctrl+F, then F3 for the next match.",
            )
            .clicked()
        {
            state.find.open = !state.find.open;
            state.find.focus = state.find.open;
        }
        ui.separator();
        let sel = match doc.selection {
            Some((a, b)) => format!(
                "selection 0x{a:X}–0x{:X} ({} bytes)",
                b.saturating_sub(1).max(a),
                b.saturating_sub(a)
            ),
            None => format!("cursor 0x{:X}", doc.cursor),
        };
        ui.label(RichText::new(sel).monospace().weak());
    });
}

fn parse_number(text: &str) -> Result<u64, String> {
    let t = text.trim().replace('_', "");
    if let Some(dec) = t.strip_prefix('#') {
        return dec
            .parse()
            .map_err(|_| format!("`{dec}` is not a decimal number"));
    }
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(&t);
    let hex = hex.strip_suffix('h').unwrap_or(hex);
    u64::from_str_radix(hex, 16).map_err(|_| format!("`{t}` is not a hexadecimal number"))
}

/// Resolves the go-to input to a file offset.
fn resolve_goto(doc: &Document, input: &str, mode: GotoMode) -> Result<u64, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("type an offset, e.g. 1F0 or 0x1F0".into());
    }
    if let Some(rest) = input.strip_prefix('+') {
        return Ok(doc.cursor.saturating_add(parse_number(rest)?));
    }
    if let Some(rest) = input.strip_prefix('-') {
        return Ok(doc.cursor.saturating_sub(parse_number(rest)?));
    }
    let value = parse_number(input)?;
    let offset = match mode {
        GotoMode::Offset => value,
        GotoMode::Address => {
            let analysis = doc
                .analysis()
                .ok_or("still analyzing; try again in a moment")?;
            analysis
                .info
                .address_to_offset(value)
                .ok_or_else(|| format!("address 0x{value:X} is not part of the file (not mapped, or only exists in memory)"))?
        }
    };
    if offset >= doc.len() {
        return Err(format!(
            "offset 0x{offset:X} is past the end of the file (size 0x{:X})",
            doc.len()
        ));
    }
    Ok(offset)
}

fn goto_bar(ui: &mut Ui, doc: &mut Document, bar: &mut GotoBar) {
    ui.horizontal(|ui| {
        ui.radio_value(&mut bar.mode, GotoMode::Offset, "File offset")
            .explain(
                "File offset",
                "Position in the file, counted in bytes from the start (0). This is what the hex \
             view shows on the left.",
            );
        ui.radio_value(&mut bar.mode, GotoMode::Address, "Address")
            .explain(
                "Address (virtual address)",
                "Where a byte ends up in memory when the program runs, as shown by disassemblers \
             and debuggers. ORRESS converts it to a file offset using the section table.",
            );
        let edit = ui.add(
            egui::TextEdit::singleline(&mut bar.input)
                .hint_text("hex, e.g. 401000 · #1234 for decimal · +10 relative")
                .desired_width(280.0)
                .font(egui::TextStyle::Monospace),
        );
        if bar.focus {
            edit.request_focus();
            bar.focus = false;
        }
        let submit = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if ui.button("Go").clicked() || submit {
            match resolve_goto(doc, &bar.input, bar.mode) {
                Ok(offset) => {
                    doc.go_to(offset);
                    bar.error = None;
                    bar.open = false;
                }
                Err(e) => {
                    bar.error = Some(e);
                    bar.focus = true;
                }
            }
        }
        if ui.button("×").on_hover_text("Close").clicked()
            || (edit.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)))
        {
            bar.open = false;
        }
    });
    if let Some(e) = &bar.error {
        ui.colored_label(ui.visuals().warn_fg_color, e);
    }
}

fn pattern(bar: &FindBar) -> Result<Pattern, String> {
    match bar.mode {
        FindMode::Text => Pattern::text(&bar.query, false),
        FindMode::Utf16 => Pattern::text(&bar.query, true),
        FindMode::Hex => Pattern::parse_hex(&bar.query),
    }
    .map_err(|e| e.to_string())
}

fn find(doc: &mut Document, data: &[u8], bar: &mut FindBar, forward: bool) {
    let pattern = match pattern(bar) {
        Ok(p) => p,
        Err(e) => {
            bar.status = Some(Err(e));
            return;
        }
    };
    let found = if forward {
        pattern.find_next_wrapping(data, doc.cursor as usize)
    } else {
        pattern
            .find_before(data, doc.cursor as usize)
            .or_else(|| pattern.find_before(data, data.len()))
    };
    bar.status = Some(match found {
        Some(at) => {
            doc.select(at as u64, pattern.len() as u64);
            let key = (bar.mode, bar.query.clone(), doc.generation);
            let count = match &bar.count {
                Some((k, n)) if *k == key => *n,
                _ => {
                    let n = pattern.count(data, MAX_COUNT);
                    bar.count = Some((key, n));
                    n
                }
            };
            let more = if count >= MAX_COUNT { "+" } else { "" };
            Ok(format!(
                "found at 0x{at:X} · {count}{more} matches in the file"
            ))
        }
        None => Err("not found".into()),
    });
}

fn find_bar(ui: &mut Ui, doc: &mut Document, data: &[u8], bar: &mut FindBar) {
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("find_mode")
            .selected_text(match bar.mode {
                FindMode::Text => "Text",
                FindMode::Utf16 => "Wide text (UTF-16)",
                FindMode::Hex => "Hex bytes",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut bar.mode, FindMode::Text, "Text")
                    .explain(
                        "Text search",
                        "Finds ASCII/UTF-8 text, as most Linux programs store it.",
                    );
                ui.selectable_value(&mut bar.mode, FindMode::Utf16, "Wide text (UTF-16)").explain(
                    "Wide text",
                    "Finds text stored as UTF-16, the way Windows programs often store strings: \
                     every letter followed by a 0 byte.",
                );
                ui.selectable_value(&mut bar.mode, FindMode::Hex, "Hex bytes")
                    .explain(
                        "Hex pattern",
                        "Finds a sequence of bytes such as `E8 ?? ?? ?? ??` (a call instruction). \
                     `??` matches any byte.",
                    );
            });
        let hint = match bar.mode {
            FindMode::Hex => "e.g. 4D 5A ?? 00",
            _ => "e.g. flag{  or  Wrong password",
        };
        let edit = ui.add(
            egui::TextEdit::singleline(&mut bar.query)
                .hint_text(hint)
                .desired_width(260.0),
        );
        if bar.focus {
            edit.request_focus();
            bar.focus = false;
        }
        let submit = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if ui.button("Next").on_hover_text("F3").clicked() || submit {
            find(doc, data, bar, true);
            if submit {
                bar.focus = true;
            }
        }
        if ui.button("Previous").on_hover_text("Shift+F3").clicked() {
            find(doc, data, bar, false);
        }
        if ui.button("×").on_hover_text("Close").clicked()
            || (edit.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)))
        {
            bar.open = false;
        }
        match &bar.status {
            Some(Ok(s)) => {
                ui.label(RichText::new(s).weak());
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().warn_fg_color, e);
            }
            None => {}
        }
    });
}

/// Hex digits typed in edit mode overwrite the byte at the cursor.
fn edit_keys(ui: &Ui, doc: &mut Document, state: &mut HexState, len: u64) {
    let typed: Vec<char> = ui.input(|i| {
        i.events
            .iter()
            .filter_map(|e| match e {
                egui::Event::Text(t) => Some(t.chars().collect::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect()
    });
    if ui.input(|i| i.key_pressed(Key::Escape)) {
        state.nibble = None;
    }
    for c in typed {
        let Some(digit) = c.to_digit(16) else {
            continue;
        };
        let digit = digit as u8;
        match state.nibble.take() {
            None => state.nibble = Some(digit),
            Some(high) => {
                let offset = doc.cursor;
                if let Err(e) = doc.patch(offset, &[high << 4 | digit]) {
                    state.message = Some(e);
                }
                if offset + 1 < len {
                    doc.cursor = offset + 1;
                    state.anchor = Some(doc.cursor);
                }
            }
        }
    }
}

fn keyboard(ui: &Ui, doc: &mut Document, state: &mut HexState, geo: &Geometry, len: u64) {
    let page = geo.visible_rows.saturating_sub(1).max(1) * BYTES_PER_ROW;
    let (moves, shift) = ui.input_mut(|i| {
        let shift = i.modifiers.shift;
        let ctrl = i.modifiers.command;
        fn pressed(i: &mut egui::InputState, key: Key) -> bool {
            i.consume_key(Modifiers::NONE, key) || i.consume_key(Modifiers::SHIFT, key)
        }
        let mut target: Option<i128> = None;
        let cur = i128::from(doc.cursor);
        let row_start = cur - cur % 16;
        if pressed(i, Key::ArrowLeft) {
            target = Some(cur - 1);
        }
        if pressed(i, Key::ArrowRight) {
            target = Some(cur + 1);
        }
        if pressed(i, Key::ArrowUp) {
            target = Some(cur - 16);
        }
        if pressed(i, Key::ArrowDown) {
            target = Some(cur + 16);
        }
        if pressed(i, Key::PageUp) {
            target = Some(cur - i128::from(page));
        }
        if pressed(i, Key::PageDown) {
            target = Some(cur + i128::from(page));
        }
        let home = i.consume_key(Modifiers::COMMAND, Key::Home)
            || i.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::Home);
        let end = i.consume_key(Modifiers::COMMAND, Key::End)
            || i.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::End);
        if home {
            target = Some(0);
        } else if end {
            target = Some(i128::from(len) - 1);
        } else if !ctrl && pressed(i, Key::Home) {
            target = Some(row_start);
        } else if !ctrl && pressed(i, Key::End) {
            target = Some(row_start + 15);
        }
        (target, shift)
    });
    let Some(target) = moves else {
        return;
    };
    let new = target.clamp(0, i128::from(len) - 1) as u64;
    if shift {
        let anchor = *state.anchor.get_or_insert(doc.cursor);
        doc.selection = (anchor != new).then(|| (anchor.min(new), anchor.max(new) + 1));
    } else {
        state.anchor = Some(new);
        doc.selection = None;
    }
    doc.cursor = new;
    // Minimal scroll to keep the cursor on screen.
    let row = new / BYTES_PER_ROW;
    if row < state.top_row {
        state.top_row = row;
    } else if row >= state.top_row + geo.visible_rows {
        state.top_row = row + 1 - geo.visible_rows;
    }
}

struct Palette {
    offset: Color32,
    zero: Color32,
    printable: Color32,
    other: Color32,
    selection: Color32,
    cursor: Stroke,
    patched: Color32,
}

impl Palette {
    fn new(ui: &Ui, focused: bool) -> Self {
        let v = ui.visuals();
        Self {
            offset: v.weak_text_color(),
            zero: v.weak_text_color().gamma_multiply(0.7),
            printable: v.text_color(),
            other: v.hyperlink_color,
            selection: v.selection.bg_fill,
            cursor: Stroke::new(
                1.5,
                if focused {
                    v.selection.stroke.color
                } else {
                    v.weak_text_color()
                },
            ),
            patched: Color32::from_rgb(255, 150, 50),
        }
    }

    fn byte(&self, doc: &Document, offset: u64, b: u8) -> Color32 {
        if doc.is_patched(offset) {
            self.patched
        } else {
            self.of(b)
        }
    }

    fn of(&self, b: u8) -> Color32 {
        match b {
            0 => self.zero,
            0x20..=0x7e => self.printable,
            _ => self.other,
        }
    }
}

fn paint_rows(
    ui: &Ui,
    doc: &Document,
    data: &[u8],
    top_row: u64,
    geo: &Geometry,
    font: &FontId,
    focused: bool,
) {
    let painter = ui.painter_at(geo.content);
    let pal = Palette::new(ui, focused);
    let len = data.len() as u64;
    let sections = doc.analysis().map(|a| &a.info.sections);
    let selected = |off: u64| doc.selection.is_some_and(|(a, b)| off >= a && off < b);

    for r in 0..=geo.visible_rows {
        let row = top_row + r;
        let start = row * BYTES_PER_ROW;
        if start >= len {
            break;
        }
        let end = (start + BYTES_PER_ROW).min(len);
        let y = geo.row_y(r);

        // Section band: a thin colored bar showing which section the row belongs to.
        if let Some(sections) = sections
            && let Some(index) = sections.iter().position(|s| s.contains_offset(start))
        {
            let band =
                Rect::from_min_size(Pos2::new(geo.content.left(), y), Vec2::new(3.0, geo.row_h));
            painter.rect_filled(band, 0.0, section_color(index));
        }

        // Selection and cursor backgrounds.
        for off in start..end {
            let i = off - start;
            let hex_rect = Rect::from_min_size(
                Pos2::new(geo.hex_x(i) - 1.0, y),
                Vec2::new(geo.char_w * 2.0 + 2.0, geo.row_h),
            );
            let ascii_rect = Rect::from_min_size(
                Pos2::new(geo.ascii_x(i), y),
                Vec2::new(geo.char_w, geo.row_h),
            );
            if selected(off) {
                painter.rect_filled(hex_rect, 0.0, pal.selection);
                painter.rect_filled(ascii_rect, 0.0, pal.selection);
            }
            if off == doc.cursor {
                painter.rect_stroke(hex_rect, 2.0, pal.cursor, StrokeKind::Inside);
                painter.rect_stroke(ascii_rect, 1.0, pal.cursor, StrokeKind::Inside);
            }
        }

        let mut job = LayoutJob::default();
        let fmt = |color| TextFormat::simple(font.clone(), color);
        job.append(&format!("{start:08X}  "), 0.0, fmt(pal.offset));
        for i in 0..BYTES_PER_ROW {
            let gap = if i == 8 { " " } else { "" };
            match data.get((start + i) as usize) {
                Some(&b) if start + i < end => job.append(
                    &format!("{gap}{b:02X} "),
                    0.0,
                    fmt(pal.byte(doc, start + i, b)),
                ),
                _ => job.append(&format!("{gap}   "), 0.0, fmt(pal.zero)),
            }
        }
        job.append(" ", 0.0, fmt(pal.offset));
        for (i, &b) in data[start as usize..end as usize].iter().enumerate() {
            let ch = if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            };
            job.append(
                &ch.to_string(),
                0.0,
                fmt(pal.byte(doc, start + i as u64, b)),
            );
        }
        let galley = ui.fonts_mut(|f| f.layout_job(job));
        painter.galley(Pos2::new(geo.x0(), y + 1.0), galley, pal.printable);
    }
}

fn minimap_ui(
    ui: &mut Ui,
    doc: &Document,
    state: &mut HexState,
    rect: Rect,
    geo: &Geometry,
    total_rows: u64,
    max_top: u64,
) {
    let response = ui.interact(rect, ui.id().with("hex_minimap"), Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, ui.visuals().extreme_bg_color);

    let entropy = doc.analysis().map(|a| (&a.entropy, a.entropy_block));
    if let Some((blocks, _)) = entropy
        && !blocks.is_empty()
    {
        let h = rect.height().max(1.0);
        let steps = h.floor() as usize;
        for px in 0..steps {
            let frac = px as f32 / h;
            let index = ((frac * blocks.len() as f32) as usize).min(blocks.len() - 1);
            let y = rect.top() + px as f32;
            painter.line_segment(
                [
                    Pos2::new(rect.left() + 2.0, y),
                    Pos2::new(rect.right() - 2.0, y),
                ],
                Stroke::new(1.0, entropy_color(blocks[index])),
            );
        }
    }

    // Viewport indicator.
    if total_rows > 0 {
        let top = state.top_row as f32 / total_rows as f32;
        let size = (geo.visible_rows as f32 / total_rows as f32).min(1.0);
        let view = Rect::from_min_max(
            Pos2::new(rect.left(), rect.top() + top * rect.height()),
            Pos2::new(
                rect.right(),
                rect.top() + (top + size) * rect.height().max(4.0),
            ),
        );
        painter.rect_stroke(
            view,
            2.0,
            Stroke::new(1.5, ui.visuals().text_color()),
            StrokeKind::Inside,
        );
    }

    if response.drag_started() || response.clicked() {
        state.dragging_minimap = true;
    }
    if !response.dragged() && !response.clicked() {
        state.dragging_minimap = false;
    }
    if let Some(pos) = response.interact_pointer_pos()
        && state.dragging_minimap
    {
        let frac = ((pos.y - rect.top()) / rect.height()).clamp(0.0, 1.0);
        let row = (frac * total_rows as f32) as u64;
        state.top_row = row.saturating_sub(geo.visible_rows / 2).min(max_top);
    }

    let response = response.note(
        "Entropy map",
        "This strip is a map of the whole file, colored by entropy (how random the bytes \
         are). Blue: zeros or simple data. Green: normal code and data. Yellow and red: \
         compressed or encrypted. The white box shows what is on screen; click or drag to jump.",
    );
    if let Some(pos) = response.hover_pos()
        && let Some((blocks, block)) = entropy
        && !blocks.is_empty()
    {
        let frac = ((pos.y - rect.top()) / rect.height()).clamp(0.0, 0.9999);
        let index = (frac * blocks.len() as f32) as usize;
        let e = blocks[index];
        response.on_hover_text(format!(
            "offset 0x{:X}\nentropy {e:.2}: {}",
            index * block,
            orress_bytes::entropy::describe(e)
        ));
    }
}

/// The right-click menu: copy, go to, find, edit, and the matching code.
fn context_menu(
    ui: &mut Ui,
    doc: &mut Document,
    data: &[u8],
    state: &mut HexState,
    cx: &mut ViewCtx<'_>,
) {
    ui.set_min_width(220.0);
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
    let what = if doc.selection.is_some() {
        "selection"
    } else {
        "byte"
    };
    ui.menu_button(format!("Copy {what}"), |ui| {
        for (label, format) in [
            ("As hex", ViewCommand::CopyHex),
            ("As C array", ViewCommand::CopyCArray),
            ("As Python bytes", ViewCommand::CopyPython),
        ] {
            if ui.button(label).clicked() {
                copy_selection(ui, doc, data, format);
                ui.close();
            }
        }
        crate::menu::copy_item(ui, "Offset", format!("0x{:X}", doc.cursor));
    });
    let shortcut = |label: &str, keys: &str| egui::Button::new(label).shortcut_text(keys);
    if ui
        .add(shortcut("Go to offset or address…", "Ctrl+G"))
        .clicked()
    {
        state.goto.open = true;
        state.goto.focus = true;
        state.find.open = false;
        ui.close();
    }
    if ui.add(shortcut("Find…", "Ctrl+F")).clicked() {
        state.find.open = true;
        state.find.focus = true;
        state.goto.open = false;
        ui.close();
    }
    if ui
        .button(if state.edit {
            "Stop editing bytes"
        } else {
            "Edit bytes"
        })
        .clicked()
    {
        state.edit = !state.edit;
        ui.close();
    }
    let in_code = doc.program().is_some_and(|p| {
        p.memory
            .address_of(doc.cursor)
            .is_some_and(|a| p.insn_start(a).is_some())
    });
    if in_code {
        ui.separator();
        if ui.button("Show in disassembly").clicked() {
            cx.requests.push(crate::ViewRequest::Open(
                doc.path.clone(),
                crate::DocView::Disassembly,
            ));
            ui.close();
        }
        crate::menu::command(ui, cx.requests, "view::Decompiler");
    }
    // Apply a user-defined type to the data at the cursor (needs a loaded address).
    if let Some(addr) = doc.cursor_address() {
        let names: Vec<String> = doc.type_catalog().types.keys().cloned().collect();
        let applied = doc.annotations.data_types.get(&addr).cloned();
        ui.separator();
        ui.menu_button("Apply type", |ui| {
            if names.is_empty() {
                ui.label(orress_ui::muted(
                    "No types yet — define one in the Types view.",
                ));
                crate::menu::command(ui, cx.requests, "view::Types");
            }
            for name in &names {
                if ui.button(name).clicked() {
                    doc.apply_data_type(addr, orress_project::TypeRef::Named(name.clone()));
                    ui.close();
                }
            }
        });
        if let Some(ty) = applied
            && ui.button(format!("Clear type ({})", ty.label())).clicked()
        {
            doc.clear_data_type(addr);
            ui.close();
        }
    }
    ui.separator();
    crate::menu::command(ui, cx.requests, "view::Inspector");
    crate::menu::views_and_commands(ui, cx.requests);
}

fn copy_selection(ui: &Ui, doc: &Document, data: &[u8], format: ViewCommand) {
    let (a, b) = doc.selection.unwrap_or((doc.cursor, doc.cursor + 1));
    let Some(bytes) = data.get(a as usize..(b as usize).min(data.len())) else {
        return;
    };
    let text = match format {
        ViewCommand::CopyCArray => {
            let body: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
            format!(
                "unsigned char data[{}] = {{\n    {}\n}};",
                bytes.len(),
                body.chunks(12)
                    .map(|c| c.join(", "))
                    .collect::<Vec<_>>()
                    .join(",\n    ")
            )
        }
        ViewCommand::CopyPython => {
            let body: String = bytes.iter().map(|b| format!("\\x{b:02x}")).collect();
            format!("data = b\"{body}\"")
        }
        _ => bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
    };
    ui.ctx().copy_text(text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_default_to_hex() {
        assert_eq!(parse_number("1F0"), Ok(0x1f0));
        assert_eq!(parse_number("0x401000"), Ok(0x40_1000));
        assert_eq!(parse_number("401000h"), Ok(0x40_1000));
        assert_eq!(parse_number("#100"), Ok(100));
        assert_eq!(parse_number("0x_10_00"), Ok(0x1000));
        assert!(parse_number("xyz").is_err());
    }

    const TOTAL_COLS: f32 = ASCII_COL + 16.0;

    #[test]
    fn column_hit_testing() {
        let geo = Geometry {
            char_w: 10.0,
            row_h: 16.0,
            content: Rect::from_min_size(Pos2::ZERO, Vec2::new(1000.0, 500.0)),
            visible_rows: 30,
        };
        // Byte 0 starts at column 10, byte 8 at column 10 + 24 + 1.
        assert_eq!(geo.column_at(geo.hex_x(0) + 5.0), 0);
        assert_eq!(geo.column_at(geo.hex_x(7) + 5.0), 7);
        assert_eq!(geo.column_at(geo.hex_x(8) + 5.0), 8);
        assert_eq!(geo.column_at(geo.hex_x(15) + 5.0), 15);
        assert_eq!(geo.column_at(geo.ascii_x(3) + 5.0), 3);
        assert_eq!(geo.column_at(0.0), 0);
        assert_eq!(geo.column_at(LEFT_PAD + TOTAL_COLS * 10.0 + 50.0), 15);
    }
}
