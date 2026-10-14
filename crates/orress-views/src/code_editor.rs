//! A custom multi-cursor code-editor widget.
//!
//! egui's built-in `TextEdit` has a single cursor baked in, which rules out IDE-style
//! multi-cursor editing. This widget owns its carets, painting and input instead: it lays
//! out the text with the caller's syntax-highlighting `LayoutJob`, paints every selection
//! and caret itself, and applies each keystroke to *all* carets at once.
//!
//! Features: Alt+click to add a caret, Ctrl+D to add the next occurrence of the selection,
//! Ctrl+Alt+Up/Down to add a caret above/below, simultaneous typing/deletion at every caret,
//! Esc to collapse to one, word/line selection, undo/redo, and the standard clipboard events
//! (so the Edit menu and Ctrl+C/X/V keep working). Selections are dimmed when unfocused.
//!
//! The buffer stays a plain `String` (the eventual scalability upgrade is a rope behind this
//! same widget boundary); carets are character indices so the galley's cursor navigation can
//! be reused directly.

use std::sync::Arc;

use egui::text::{CCursor, Galley, LayoutJob};
use egui::{
    Color32, Event, EventFilter, Key, Modifiers, Pos2, Rect, Response, Sense, Stroke, Ui, Vec2,
};
use ropey::Rope;

/// One caret and its selection, as character indices into the buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Caret {
    /// The moving end (where new text is inserted).
    head: usize,
    /// The fixed end of the selection (`== head` when there is no selection).
    anchor: usize,
}

impl Caret {
    fn at(pos: usize) -> Self {
        Self {
            head: pos,
            anchor: pos,
        }
    }
    /// The selection as an ordered `(min, max)` character range.
    fn range(&self) -> (usize, usize) {
        (self.head.min(self.anchor), self.head.max(self.anchor))
    }
    fn is_empty(&self) -> bool {
        self.head == self.anchor
    }
}

/// How the last edit was classified, for coalescing consecutive edits into one undo step.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EditKind {
    Insert,
    Delete,
    Boundary,
}

#[derive(Clone)]
struct Snapshot {
    /// A rope clone is cheap (structural sharing), so snapshots are light.
    text: Rope,
    carets: Vec<Caret>,
}

/// The persistent multi-cursor state for one editor tab.
pub struct MultiCursor {
    carets: Vec<Caret>,
    /// Preferred x (screen-relative to the galley) for vertical movement, per caret.
    pref_x: Vec<Option<f32>>,
    undo: Vec<Snapshot>,
    redo: Vec<Snapshot>,
    last_kind: Option<EditKind>,
    dragging: bool,
    /// Set when a caret moved by keyboard, so the view scrolls to the primary caret.
    scroll_to_caret: bool,
}

impl Default for MultiCursor {
    fn default() -> Self {
        Self {
            carets: vec![Caret::at(0)],
            pref_x: vec![None],
            undo: Vec::new(),
            redo: Vec::new(),
            last_kind: None,
            dragging: false,
            scroll_to_caret: false,
        }
    }
}

impl MultiCursor {
    /// The primary caret (the most recently placed), as a character index.
    pub fn primary_char(&self) -> usize {
        self.carets.last().map(|c| c.head).unwrap_or(0)
    }

    /// Collapses to a single caret at `char_idx` (used by go-to-definition and completion).
    pub fn set_single(&mut self, char_idx: usize) {
        self.carets = vec![Caret::at(char_idx)];
        self.pref_x = vec![None];
        self.last_kind = Some(EditKind::Boundary);
        self.scroll_to_caret = true;
    }

    fn clamp(&mut self, nchars: usize) {
        for c in &mut self.carets {
            c.head = c.head.min(nchars);
            c.anchor = c.anchor.min(nchars);
        }
        self.pref_x.resize(self.carets.len(), None);
    }

    /// Sorts carets and merges any that overlap, keeping the set tidy.
    fn normalize(&mut self) {
        if self.carets.len() > 1 {
            // Sort carets and their preferred-x together.
            let mut idx: Vec<usize> = (0..self.carets.len()).collect();
            idx.sort_by_key(|&i| self.carets[i].range().0);
            let carets: Vec<Caret> = idx.iter().map(|&i| self.carets[i]).collect();
            let pref: Vec<Option<f32>> = idx.iter().map(|&i| self.pref_x[i]).collect();

            let mut out: Vec<Caret> = Vec::new();
            let mut out_pref: Vec<Option<f32>> = Vec::new();
            for (c, px) in carets.into_iter().zip(pref) {
                if let Some(last) = out.last_mut() {
                    let (ls, le) = last.range();
                    let (cs, ce) = c.range();
                    if cs <= le {
                        *last = Caret {
                            anchor: ls.min(cs),
                            head: le.max(ce),
                        };
                        *out_pref.last_mut().unwrap() = None;
                        continue;
                    }
                }
                out.push(c);
                out_pref.push(px);
            }
            self.carets = out;
            self.pref_x = out_pref;
        }
        if self.carets.is_empty() {
            self.carets.push(Caret::at(0));
            self.pref_x.push(None);
        }
    }

    fn push_undo(&mut self, text: &Rope, kind: EditKind) {
        let coalesce =
            self.last_kind == Some(kind) && kind != EditKind::Boundary && !self.undo.is_empty();
        if !coalesce {
            self.undo.push(Snapshot {
                text: text.clone(),
                carets: self.carets.clone(),
            });
            if self.undo.len() > 300 {
                self.undo.remove(0);
            }
        }
        self.redo.clear();
        self.last_kind = Some(kind);
    }

    fn undo(&mut self, text: &mut Rope) {
        if let Some(prev) = self.undo.pop() {
            self.redo.push(Snapshot {
                text: text.clone(),
                carets: self.carets.clone(),
            });
            *text = prev.text;
            self.carets = prev.carets;
            self.pref_x = vec![None; self.carets.len()];
            self.last_kind = None;
            self.scroll_to_caret = true;
        }
    }

    fn redo(&mut self, text: &mut Rope) {
        if let Some(next) = self.redo.pop() {
            self.undo.push(Snapshot {
                text: text.clone(),
                carets: self.carets.clone(),
            });
            *text = next.text;
            self.carets = next.carets;
            self.pref_x = vec![None; self.carets.len()];
            self.last_kind = None;
            self.scroll_to_caret = true;
        }
    }
}

/// A splice: replace the characters in `[start, end)` with `repl`.
struct Splice {
    start: usize,
    end: usize,
    repl: String,
}

/// Applies non-overlapping splices (one per caret) and collapses each caret to the end of
/// its inserted text, shifting later carets by the net length change. All indices are
/// character indices.
fn apply_splices(text: &mut Rope, mut splices: Vec<Splice>) -> Vec<Caret> {
    splices.sort_by_key(|s| s.start);
    // Resulting caret positions, computed with a running character shift.
    let mut new_carets = Vec::with_capacity(splices.len());
    let mut shift: isize = 0;
    for sp in &splices {
        let repl_chars = sp.repl.chars().count();
        let pos = (sp.start as isize + shift + repl_chars as isize).max(0) as usize;
        new_carets.push(Caret::at(pos));
        shift += repl_chars as isize - (sp.end - sp.start) as isize;
    }
    // Apply highest-index first so the lower (still-pending) indices stay valid.
    for sp in splices.iter().rev() {
        if sp.start < sp.end {
            text.remove(sp.start..sp.end);
        }
        if !sp.repl.is_empty() {
            text.insert(sp.start, &sp.repl);
        }
    }
    new_carets
}

/// What the editor widget returns, mirroring the parts of egui's `TextEditOutput` the
/// surrounding code uses.
pub struct CodeEditorOutput {
    pub response: Response,
    pub galley: Arc<Galley>,
    pub galley_pos: Pos2,
    /// The primary caret as a character index.
    pub primary_char: usize,
    /// Whether the text changed this frame.
    pub changed: bool,
}

/// Draws the multi-cursor code editor. `job` is the pre-built highlight/diagnostic layout for
/// the current `text`; `font` is used to size the caret.
pub fn code_editor(
    ui: &mut Ui,
    text: &mut Rope,
    mc: &mut MultiCursor,
    job: LayoutJob,
    id_salt: &str,
) -> CodeEditorOutput {
    let galley = ui.fonts_mut(|f| f.layout_job(job));

    let size = Vec2::new(
        galley.size().x.max(ui.available_width()),
        galley.size().y.max(ui.available_height()),
    );
    // A stable id (per tab) so keyboard focus and the focus-lock filter persist across frames.
    let id = ui.make_persistent_id(id_salt);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let mut response = ui.interact(rect, id, Sense::click_and_drag());
    let galley_pos = rect.min;

    let nchars = text.len_chars();
    mc.clamp(nchars);
    mc.scroll_to_caret = false;

    // --- Mouse -------------------------------------------------------------
    let modifiers = ui.input(|i| i.modifiers);
    let pointer_char = |pos: Pos2| galley.cursor_from_pos(pos - galley_pos).index.0;
    if response.double_clicked() {
        if let Some(pos) = response.interact_pointer_pos() {
            let (s, e) = word_bounds(text, pointer_char(pos));
            mc.carets = vec![Caret { anchor: s, head: e }];
            mc.pref_x = vec![None];
        }
        response.request_focus();
    } else if response.clicked() {
        if let Some(pos) = response.interact_pointer_pos() {
            let c = pointer_char(pos);
            if modifiers.alt {
                mc.carets.push(Caret::at(c));
                mc.pref_x.push(None);
            } else if modifiers.shift {
                if let Some(p) = mc.carets.last_mut() {
                    p.head = c;
                }
            } else {
                // Plain (or Ctrl, for go-to-definition) click: one caret here.
                mc.carets = vec![Caret::at(c)];
                mc.pref_x = vec![None];
            }
        }
        response.request_focus();
    }
    if response.drag_started() && !modifiers.command {
        if let Some(pos) = response.interact_pointer_pos() {
            let c = pointer_char(pos);
            if modifiers.alt {
                mc.carets.push(Caret::at(c));
                mc.pref_x.push(None);
            } else if !modifiers.shift {
                mc.carets = vec![Caret::at(c)];
                mc.pref_x = vec![None];
            }
            mc.dragging = true;
        }
        response.request_focus();
    }
    if mc.dragging
        && response.dragged()
        && let Some(pos) = response.interact_pointer_pos()
    {
        let c = pointer_char(pos);
        if let Some(p) = mc.carets.last_mut() {
            p.head = c;
        }
    }
    if response.drag_stopped() {
        mc.dragging = false;
        mc.normalize();
    }

    // --- Keyboard & text ---------------------------------------------------
    let focused = response.has_focus();
    let mut changed = false;
    if focused {
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                id,
                EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            );
        });
        let events = ui.input(|i| i.events.clone());
        let mut keep = vec![true; events.len()];
        for (i, ev) in events.iter().enumerate() {
            if handle_event(ev, text, mc, &galley, &mut changed) {
                keep[i] = false;
            }
        }
        if keep.iter().any(|k| !k) {
            ui.input_mut(|inp| {
                let mut it = keep.iter();
                inp.events.retain(|_| *it.next().unwrap_or(&true));
            });
        }
        if changed {
            response.mark_changed();
            ui.ctx().request_repaint();
        }
    }

    // --- Paint -------------------------------------------------------------
    let painter = ui.painter_at(rect.intersect(ui.clip_rect()));
    let sel_color = {
        let c = ui.visuals().selection.bg_fill;
        if focused { c } else { c.gamma_multiply(0.65) }
    };
    let nchars = text.len_chars();
    // Selection highlights sit under the text.
    for caret in &mc.carets {
        let (s, e) = caret.range();
        if s != e {
            paint_selection(
                &painter,
                &galley,
                galley_pos,
                s.min(nchars),
                e.min(nchars),
                sel_color,
            );
        }
    }
    // The text itself (colours come from the layout job).
    painter.galley(galley_pos, Arc::clone(&galley), ui.visuals().text_color());
    if focused {
        let caret_color = ui.visuals().text_cursor.stroke.color;
        for caret in &mc.carets {
            let r = galley
                .pos_from_cursor(CCursor::new(caret.head.min(nchars)))
                .translate(galley_pos.to_vec2());
            painter.vline(r.center().x, r.y_range(), Stroke::new(2.0, caret_color));
        }
    }

    // Scroll to the primary caret after keyboard movement.
    if mc.scroll_to_caret {
        let r = galley
            .pos_from_cursor(CCursor::new(mc.primary_char().min(nchars)))
            .translate(galley_pos.to_vec2());
        ui.scroll_to_rect(r.expand2(Vec2::new(24.0, 8.0)), None);
    }

    CodeEditorOutput {
        primary_char: mc.primary_char().min(nchars),
        changed,
        response,
        galley,
        galley_pos,
    }
}

/// Handles one input event, returning true if it was consumed.
fn handle_event(
    ev: &Event,
    text: &mut Rope,
    mc: &mut MultiCursor,
    galley: &Galley,
    changed: &mut bool,
) -> bool {
    match ev {
        // Control chars (Tab, Enter) arrive as dedicated key events; don't double-insert them.
        Event::Text(s) if !s.is_empty() && !s.chars().all(char::is_control) => {
            insert_at_carets(text, mc, s);
            *changed = true;
            mc.scroll_to_caret = true;
            true
        }
        Event::Paste(s) => {
            paste(text, mc, s);
            *changed = true;
            mc.scroll_to_caret = true;
            true
        }
        Event::Copy => {
            if let Some(clip) = gather_clipboard(text, mc) {
                // Copy is handled by the app via ctx; we stash it through output below.
                COPY_PENDING.with(|c| *c.borrow_mut() = Some(clip));
            }
            true
        }
        Event::Cut => {
            if let Some(clip) = gather_clipboard(text, mc) {
                COPY_PENDING.with(|c| *c.borrow_mut() = Some(clip));
                delete_selections_or_lines(text, mc);
                *changed = true;
            }
            true
        }
        Event::Key {
            key,
            pressed: true,
            modifiers,
            ..
        } => handle_key(*key, *modifiers, text, mc, galley, changed),
        _ => false,
    }
}

thread_local! {
    /// Set by a Copy/Cut event; drained by the caller to push onto the OS clipboard.
    static COPY_PENDING: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Drains any text a Copy/Cut produced this frame (to be sent to the clipboard).
pub fn take_clipboard() -> Option<String> {
    COPY_PENDING.with(|c| c.borrow_mut().take())
}

#[allow(clippy::too_many_lines)]
fn handle_key(
    key: Key,
    m: Modifiers,
    text: &mut Rope,
    mc: &mut MultiCursor,
    galley: &Galley,
    changed: &mut bool,
) -> bool {
    let word = m.command; // Ctrl+arrow = by word
    match key {
        Key::Backspace => {
            backspace(text, mc, word);
            *changed = true;
            mc.scroll_to_caret = true;
            true
        }
        Key::Delete => {
            delete_forward(text, mc, word);
            *changed = true;
            mc.scroll_to_caret = true;
            true
        }
        Key::Enter => {
            newline(text, mc);
            *changed = true;
            mc.scroll_to_caret = true;
            true
        }
        Key::Tab => {
            mc.push_undo(text, EditKind::Boundary);
            let splices = mc
                .carets
                .iter()
                .map(|c| {
                    let (s, e) = c.range();
                    Splice {
                        start: s,
                        end: e,
                        repl: "    ".to_string(),
                    }
                })
                .collect();
            mc.carets = apply_splices(text, splices);
            mc.pref_x = vec![None; mc.carets.len()];
            mc.normalize();
            *changed = true;
            mc.scroll_to_caret = true;
            true
        }
        Key::A if m.command => {
            let n = text.len_chars();
            mc.carets = vec![Caret { anchor: 0, head: n }];
            mc.pref_x = vec![None];
            mc.last_kind = Some(EditKind::Boundary);
            true
        }
        Key::Z if m.command && !m.shift => {
            mc.undo(text);
            *changed = true;
            true
        }
        Key::Z if m.command && m.shift => {
            mc.redo(text);
            *changed = true;
            true
        }
        Key::Y if m.command => {
            mc.redo(text);
            *changed = true;
            true
        }
        Key::D if m.command => {
            add_next_occurrence(text, mc);
            mc.scroll_to_caret = true;
            true
        }
        Key::Escape => {
            if mc.carets.len() > 1 || !mc.carets.last().map(Caret::is_empty).unwrap_or(true) {
                let head = mc.primary_char();
                mc.carets = vec![Caret::at(head)];
                mc.pref_x = vec![None];
                true
            } else {
                false
            }
        }
        Key::ArrowUp | Key::ArrowDown if m.command && m.alt => {
            add_caret_vertical(mc, galley, key == Key::ArrowUp);
            mc.scroll_to_caret = true;
            true
        }
        Key::ArrowLeft | Key::ArrowRight => {
            move_horizontal(text, mc, galley, key == Key::ArrowLeft, m.shift, word);
            mc.last_kind = Some(EditKind::Boundary);
            mc.scroll_to_caret = true;
            true
        }
        Key::ArrowUp | Key::ArrowDown => {
            move_vertical(mc, galley, key == Key::ArrowUp, m.shift);
            mc.last_kind = Some(EditKind::Boundary);
            mc.scroll_to_caret = true;
            true
        }
        Key::Home => {
            move_line_edge(mc, galley, true, m.shift);
            mc.scroll_to_caret = true;
            true
        }
        Key::End => {
            move_line_edge(mc, galley, false, m.shift);
            mc.scroll_to_caret = true;
            true
        }
        _ => false,
    }
}

fn insert_at_carets(text: &mut Rope, mc: &mut MultiCursor, s: &str) {
    mc.push_undo(text, EditKind::Insert);
    let splices = mc
        .carets
        .iter()
        .map(|c| {
            let (start, end) = c.range();
            Splice {
                start,
                end,
                repl: s.to_string(),
            }
        })
        .collect();
    mc.carets = apply_splices(text, splices);
    mc.pref_x = vec![None; mc.carets.len()];
    mc.normalize();
}

fn newline(text: &mut Rope, mc: &mut MultiCursor) {
    mc.push_undo(text, EditKind::Boundary);
    let splices = mc
        .carets
        .iter()
        .map(|c| {
            let (start, end) = c.range();
            let indent = line_indent(text, start);
            Splice {
                start,
                end,
                repl: format!("\n{indent}"),
            }
        })
        .collect();
    mc.carets = apply_splices(text, splices);
    mc.pref_x = vec![None; mc.carets.len()];
    mc.normalize();
}

fn backspace(text: &mut Rope, mc: &mut MultiCursor, word: bool) {
    mc.push_undo(text, EditKind::Delete);
    let splices = mc
        .carets
        .iter()
        .map(|c| {
            let (start, end) = c.range();
            if start != end {
                Splice {
                    start,
                    end,
                    repl: String::new(),
                }
            } else {
                let new_start = if word {
                    word_left(text, start)
                } else {
                    start.saturating_sub(1)
                };
                Splice {
                    start: new_start,
                    end: start,
                    repl: String::new(),
                }
            }
        })
        .collect();
    mc.carets = apply_splices(text, splices);
    mc.pref_x = vec![None; mc.carets.len()];
    mc.normalize();
}

fn delete_forward(text: &mut Rope, mc: &mut MultiCursor, word: bool) {
    mc.push_undo(text, EditKind::Delete);
    let n = text.len_chars();
    let splices = mc
        .carets
        .iter()
        .map(|c| {
            let (start, end) = c.range();
            if start != end {
                Splice {
                    start,
                    end,
                    repl: String::new(),
                }
            } else {
                let new_end = if word {
                    word_right(text, end)
                } else {
                    (end + 1).min(n)
                };
                Splice {
                    start: end,
                    end: new_end,
                    repl: String::new(),
                }
            }
        })
        .collect();
    mc.carets = apply_splices(text, splices);
    mc.pref_x = vec![None; mc.carets.len()];
    mc.normalize();
}

fn delete_selections_or_lines(text: &mut Rope, mc: &mut MultiCursor) {
    mc.push_undo(text, EditKind::Boundary);
    let splices = mc
        .carets
        .iter()
        .map(|c| {
            let (start, end) = c.range();
            if start != end {
                Splice {
                    start,
                    end,
                    repl: String::new(),
                }
            } else {
                let (ls, le) = line_span(text, start);
                Splice {
                    start: ls,
                    end: le,
                    repl: String::new(),
                }
            }
        })
        .collect();
    mc.carets = apply_splices(text, splices);
    mc.pref_x = vec![None; mc.carets.len()];
    mc.normalize();
}

fn paste(text: &mut Rope, mc: &mut MultiCursor, s: &str) {
    mc.push_undo(text, EditKind::Boundary);
    let lines: Vec<&str> = s.split('\n').collect();
    // Distribute one line per caret when the counts match (VS Code behaviour).
    let per_caret = lines.len() == mc.carets.len() && mc.carets.len() > 1;
    let mut ordered: Vec<usize> = (0..mc.carets.len()).collect();
    ordered.sort_by_key(|&i| mc.carets[i].range().0);
    let splices = mc
        .carets
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let (start, end) = c.range();
            let repl = if per_caret {
                let rank = ordered.iter().position(|&x| x == i).unwrap_or(0);
                lines[rank].to_string()
            } else {
                s.to_string()
            };
            Splice { start, end, repl }
        })
        .collect();
    mc.carets = apply_splices(text, splices);
    mc.pref_x = vec![None; mc.carets.len()];
    mc.normalize();
}

fn gather_clipboard(text: &Rope, mc: &MultiCursor) -> Option<String> {
    let mut carets: Vec<Caret> = mc.carets.clone();
    carets.sort_by_key(|c| c.range().0);
    let any_sel = carets.iter().any(|c| !c.is_empty());
    let parts: Vec<String> = carets
        .iter()
        .map(|c| {
            if any_sel {
                let (s, e) = c.range();
                slice_chars(text, s, e)
            } else {
                let (ls, le) = line_span(text, c.head);
                slice_chars(text, ls, le)
            }
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(if any_sel { "\n" } else { "" }))
    }
}

/// Ctrl+D: select the word under the caret first, then add the next occurrence of the
/// selected text as a new (primary) caret.
fn add_next_occurrence(text: &Rope, mc: &mut MultiCursor) {
    let primary = *mc.carets.last().unwrap();
    if primary.is_empty() {
        let (s, e) = word_bounds(text, primary.head);
        if s != e
            && let Some(last) = mc.carets.last_mut()
        {
            *last = Caret { anchor: s, head: e };
        }
        return;
    }
    let (s, e) = primary.range();
    let needle = slice_chars(text, s, e);
    if needle.is_empty() {
        return;
    }
    // Search from the end of the last caret, wrapping around. Ctrl+D is a user action, not
    // a per-frame path, so materializing the text for a substring search is fine.
    let haystack = text.to_string();
    let max_end = mc.carets.iter().map(|c| c.range().1).max().unwrap_or(e);
    let from_byte = char_to_byte(text, max_end);
    let found = haystack[from_byte..]
        .find(&needle)
        .map(|b| from_byte + b)
        .or_else(|| haystack.find(&needle));
    if let Some(byte) = found {
        let start = text.byte_to_char(byte);
        let end = start + needle.chars().count();
        if !mc.carets.iter().any(|c| c.range() == (start, end)) {
            mc.carets.push(Caret {
                anchor: start,
                head: end,
            });
            mc.pref_x.push(None);
        }
    }
}

fn add_caret_vertical(mc: &mut MultiCursor, galley: &Galley, up: bool) {
    let primary = *mc.carets.last().unwrap();
    let px = *mc.pref_x.last().unwrap_or(&None);
    let (new, new_px) = if up {
        galley.cursor_up_one_row(&CCursor::new(primary.head), px)
    } else {
        galley.cursor_down_one_row(&CCursor::new(primary.head), px)
    };
    let pos = new.index.0;
    if pos != primary.head {
        mc.carets.push(Caret::at(pos));
        mc.pref_x.push(new_px);
    }
}

fn move_horizontal(
    text: &Rope,
    mc: &mut MultiCursor,
    galley: &Galley,
    left: bool,
    shift: bool,
    word: bool,
) {
    let n = text.len_chars();
    for (c, px) in mc.carets.iter_mut().zip(mc.pref_x.iter_mut()) {
        *px = None;
        if !shift && !c.is_empty() {
            // Collapse to the appropriate edge instead of moving.
            let (s, e) = c.range();
            let target = if left { s } else { e };
            *c = Caret::at(target);
            continue;
        }
        let new_head = if word {
            if left {
                word_left(text, c.head)
            } else {
                word_right(text, c.head)
            }
        } else if left {
            galley
                .cursor_left_one_character(&CCursor::new(c.head))
                .index
                .0
        } else {
            galley
                .cursor_right_one_character(&CCursor::new(c.head))
                .index
                .0
        };
        c.head = new_head.min(n);
        if !shift {
            c.anchor = c.head;
        }
    }
    mc.normalize();
}

fn move_vertical(mc: &mut MultiCursor, galley: &Galley, up: bool, shift: bool) {
    for (c, px) in mc.carets.iter_mut().zip(mc.pref_x.iter_mut()) {
        let (new, new_px) = if up {
            galley.cursor_up_one_row(&CCursor::new(c.head), *px)
        } else {
            galley.cursor_down_one_row(&CCursor::new(c.head), *px)
        };
        *px = new_px;
        c.head = new.index.0;
        if !shift {
            c.anchor = c.head;
        }
    }
    mc.normalize();
}

fn move_line_edge(mc: &mut MultiCursor, galley: &Galley, begin: bool, shift: bool) {
    for (c, px) in mc.carets.iter_mut().zip(mc.pref_x.iter_mut()) {
        *px = None;
        let new = if begin {
            galley.cursor_begin_of_row(&CCursor::new(c.head))
        } else {
            galley.cursor_end_of_row(&CCursor::new(c.head))
        };
        c.head = new.index.0;
        if !shift {
            c.anchor = c.head;
        }
    }
    mc.normalize();
}

/// Paints the selection rectangles for `[s, e)` (character indices).
fn paint_selection(
    painter: &egui::Painter,
    galley: &Galley,
    origin: Pos2,
    s: usize,
    e: usize,
    color: Color32,
) {
    let r0 = galley.pos_from_cursor(CCursor::new(s));
    let r1 = galley.pos_from_cursor(CCursor::new(e));
    let lc0 = galley.layout_from_cursor(CCursor::new(s));
    let lc1 = galley.layout_from_cursor(CCursor::new(e));
    let paint_rect = |r: Rect| {
        painter.rect_filled(r.translate(origin.to_vec2()), 1.0, color);
    };
    if lc0.row == lc1.row {
        paint_rect(Rect::from_min_max(
            Pos2::new(r0.left(), r0.top()),
            Pos2::new(r1.left(), r0.bottom()),
        ));
        return;
    }
    // First row: from the start caret to the row's right edge.
    let row0 = galley.rows[lc0.row].rect();
    paint_rect(Rect::from_min_max(
        Pos2::new(r0.left(), row0.top()),
        Pos2::new(row0.right().max(r0.left() + 4.0), row0.bottom()),
    ));
    // Middle rows: full width.
    for ri in (lc0.row + 1)..lc1.row {
        let rr = galley.rows[ri].rect();
        paint_rect(Rect::from_min_max(
            Pos2::new(rr.left(), rr.top()),
            Pos2::new(rr.right().max(rr.left() + 4.0), rr.bottom()),
        ));
    }
    // Last row: from the row's left edge to the end caret.
    let rown = galley.rows[lc1.row].rect();
    paint_rect(Rect::from_min_max(
        Pos2::new(rown.left(), rown.top()),
        Pos2::new(r1.left(), rown.bottom()),
    ));
}

// --- character/byte helpers (all indices are character indices) -----------

fn char_to_byte(text: &Rope, ci: usize) -> usize {
    text.char_to_byte(ci.min(text.len_chars()))
}

fn slice_chars(text: &Rope, s: usize, e: usize) -> String {
    let n = text.len_chars();
    text.slice(s.min(n)..e.min(n)).to_string()
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn char_at(text: &Rope, i: usize) -> Option<char> {
    text.get_char(i)
}

/// The word boundaries `[start, end)` around character index `ci`.
fn word_bounds(text: &Rope, ci: usize) -> (usize, usize) {
    let n = text.len_chars();
    let is_w = |i: usize| char_at(text, i).is_some_and(is_word);
    let anchor = if ci < n && is_w(ci) {
        ci
    } else if ci > 0 && is_w(ci - 1) {
        ci - 1
    } else {
        return (ci, ci);
    };
    let mut s = anchor;
    while s > 0 && is_w(s - 1) {
        s -= 1;
    }
    let mut e = anchor + 1;
    while e < n && is_w(e) {
        e += 1;
    }
    (s, e)
}

/// The next word boundary to the left of `ci` (skips whitespace, then a run of word chars).
fn word_left(text: &Rope, ci: usize) -> usize {
    let is_ws = |i: usize| char_at(text, i).is_some_and(char::is_whitespace);
    let is_w = |i: usize| char_at(text, i).is_some_and(is_word);
    let mut i = ci.min(text.len_chars());
    while i > 0 && is_ws(i - 1) {
        i -= 1;
    }
    if i > 0 && is_w(i - 1) {
        while i > 0 && is_w(i - 1) {
            i -= 1;
        }
    } else {
        i = i.saturating_sub(1);
    }
    i
}

fn word_right(text: &Rope, ci: usize) -> usize {
    let n = text.len_chars();
    let is_ws = |i: usize| char_at(text, i).is_some_and(char::is_whitespace);
    let is_w = |i: usize| char_at(text, i).is_some_and(is_word);
    let mut i = ci.min(n);
    while i < n && is_ws(i) {
        i += 1;
    }
    if i < n && is_w(i) {
        while i < n && is_w(i) {
            i += 1;
        }
    } else if i < n {
        i += 1;
    }
    i
}

/// The leading whitespace of the line containing character index `ci`.
fn line_indent(text: &Rope, ci: usize) -> String {
    let line = text.char_to_line(ci.min(text.len_chars()));
    let start = text.line_to_char(line);
    let mut indent = String::new();
    let mut i = start;
    while let Some(c) = char_at(text, i) {
        if c == ' ' || c == '\t' {
            indent.push(c);
            i += 1;
        } else {
            break;
        }
    }
    indent
}

/// The character span of the whole line containing `ci`, including its trailing newline.
fn line_span(text: &Rope, ci: usize) -> (usize, usize) {
    let n = text.len_chars();
    let line = text.char_to_line(ci.min(n));
    let start = text.line_to_char(line);
    let end = if line + 1 < text.len_lines() {
        text.line_to_char(line + 1)
    } else {
        n
    };
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mc(carets: &[(usize, usize)]) -> MultiCursor {
        let mut m = MultiCursor::default();
        m.carets = carets
            .iter()
            .map(|&(anchor, head)| Caret { anchor, head })
            .collect();
        m.pref_x = vec![None; m.carets.len()];
        m
    }

    fn heads(m: &MultiCursor) -> Vec<usize> {
        m.carets.iter().map(|c| c.head).collect()
    }

    #[test]
    fn insert_at_multiple_carets() {
        // Two carets, both collapsed, at the start of each word.
        let mut text = Rope::from_str("foo bar");
        let mut m = mc(&[(0, 0), (4, 4)]);
        insert_at_carets(&mut text, &mut m, "X");
        assert_eq!(text.to_string(), "Xfoo Xbar");
        // Carets land right after each inserted "X".
        assert_eq!(heads(&m), vec![1, 6]);
    }

    #[test]
    fn insert_replaces_selections() {
        let mut text = Rope::from_str("foo bar");
        // Select "foo" (0..3) and "bar" (4..7).
        let mut m = mc(&[(0, 3), (4, 7)]);
        insert_at_carets(&mut text, &mut m, "baz");
        assert_eq!(text.to_string(), "baz baz");
    }

    #[test]
    fn backspace_at_multiple_carets() {
        let mut text = Rope::from_str("ab cd");
        // Carets after 'b' (2) and after 'd' (5).
        let mut m = mc(&[(2, 2), (5, 5)]);
        backspace(&mut text, &mut m, false);
        assert_eq!(text.to_string(), "a c");
    }

    #[test]
    fn apply_splices_shifts_later_carets() {
        let mut text = Rope::from_str("0123456789");
        let splices = vec![
            Splice {
                start: 2,
                end: 2,
                repl: "AA".into(),
            },
            Splice {
                start: 6,
                end: 6,
                repl: "B".into(),
            },
        ];
        let carets = apply_splices(&mut text, splices);
        assert_eq!(text.to_string(), "01AA2345B6789");
        assert_eq!(carets[0].head, 4); // after "AA"
        assert_eq!(carets[1].head, 9); // 6 + 2 (shift) + 1 (len "B")
    }

    #[test]
    fn ctrl_d_selects_word_then_next_occurrence() {
        let text = Rope::from_str("let x = x + x;");
        // Caret inside the first "x" (collapsed at index 4).
        let mut m = mc(&[(4, 4)]);
        add_next_occurrence(&text, &mut m); // first: select the word
        assert_eq!(m.carets.last().unwrap().range(), (4, 5));
        add_next_occurrence(&text, &mut m); // second: add next "x"
        assert_eq!(m.carets.len(), 2);
        assert_eq!(m.carets.last().unwrap().range(), (8, 9));
    }

    #[test]
    fn word_bounds_finds_identifier() {
        let text = Rope::from_str("foo_bar baz");
        assert_eq!(word_bounds(&text, 2), (0, 7)); // inside foo_bar
        assert_eq!(word_bounds(&text, 8), (8, 11)); // inside baz
    }

    #[test]
    fn normalize_merges_overlapping_carets() {
        let mut m = mc(&[(0, 5), (3, 8)]);
        m.normalize();
        assert_eq!(m.carets.len(), 1);
        assert_eq!(m.carets[0].range(), (0, 8));
    }

    #[test]
    fn undo_restores_text_and_carets() {
        let mut text = Rope::from_str("abc");
        let mut m = mc(&[(3, 3)]);
        insert_at_carets(&mut text, &mut m, "d");
        assert_eq!(text.to_string(), "abcd");
        m.undo(&mut text);
        assert_eq!(text.to_string(), "abc");
    }
}
