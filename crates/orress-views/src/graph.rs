//! Graph view: the function under the cursor as a flow chart of basic blocks.

use std::sync::Arc;

use egui::{
    Color32, FontId, Key, Modifiers, Pos2, Rect, RichText, Sense, Shape, Stroke, StrokeKind, Ui,
    Vec2,
};
use orress_analysis::{EdgeKind, Function, Program};
use orress_project::Document;
use orress_ui::ExplainExt as _;

use crate::code::{self, Style, Target};
use crate::edit::{self, EditPopup};
use crate::graph_layout::{self, Layout};
use crate::{DocView, ViewCtx, ViewRequest};

const MIN_ZOOM: f32 = 0.04;
const MAX_ZOOM: f32 = 2.5;

struct Cached {
    entry: u64,
    generation: u64,
    layout: Layout,
    /// Per node: block start and the addresses of its lines (first line is the label).
    blocks: Vec<(u64, Vec<u64>)>,
    edge_kinds: Vec<EdgeKind>,
}

pub struct GraphState {
    cache: Option<Cached>,
    pan: Vec2,
    zoom: f32,
    last_cursor: Option<u64>,
    popup: Option<EditPopup>,
    fit: bool,
}

impl Default for GraphState {
    fn default() -> Self {
        Self {
            cache: None,
            pan: Vec2::new(40.0, 20.0),
            zoom: 1.0,
            last_cursor: None,
            popup: None,
            fit: false,
        }
    }
}

fn style(ui: &Ui, program: &Program, size: f32) -> Style {
    Style {
        font: FontId::monospace(size),
        colors: code::syntax(ui.ctx()),
        text: ui.visuals().text_color(),
        muted: ui.visuals().weak_text_color(),
        wide: program.isa.pointer_size() == 8,
        show_address: false,
        show_bytes: false,
    }
}

fn build(ui: &Ui, doc: &Document, program: &Program, f: &Function) -> Cached {
    let st = style(ui, program, 13.0);
    let index_of = |addr: u64| f.blocks.iter().position(|b| b.start == addr);
    let mut sizes = Vec::new();
    let mut blocks = Vec::new();
    for b in &f.blocks {
        let mut width = label(doc, f, b.start).chars().count();
        for &a in &b.insns {
            if let Some(insn) = program.decode(a) {
                width = width.max(code::render_insn(doc, program, &insn, &st).chars);
            }
        }
        sizes.push(Vec2::new(width as f32 + 2.0, b.insns.len() as f32 + 1.6));
        let mut lines = vec![b.start];
        lines.extend(&b.insns);
        blocks.push((b.start, lines));
    }
    let mut edges = Vec::new();
    let mut edge_kinds = Vec::new();
    for (i, b) in f.blocks.iter().enumerate() {
        for e in &b.succs {
            if let Some(j) = index_of(e.target) {
                edges.push((i, j));
                edge_kinds.push(e.kind);
            }
        }
    }
    let root = index_of(f.entry).unwrap_or(0);
    Cached {
        entry: f.entry,
        generation: doc.generation,
        layout: graph_layout::layout(&sizes, &edges, root),
        blocks,
        edge_kinds,
    }
}

fn label(doc: &Document, f: &Function, start: u64) -> String {
    let name = doc.name_of(start).unwrap_or_else(|| {
        if start == f.entry {
            format!("sub_{start:x}")
        } else {
            format!("loc_{start:x}")
        }
    });
    format!("{name}:")
}

pub fn graph_view(ui: &mut Ui, doc: &mut Document, state: &mut GraphState, cx: &mut ViewCtx<'_>) {
    let Some(program) = crate::program_or_message(ui, doc) else {
        return;
    };
    cx.commands.clear();
    let cursor_addr = program.memory.address_of(doc.cursor);
    let Some(function) = cursor_addr.and_then(|a| program.function_containing(a)) else {
        ui.label(
            "The cursor is not inside a known function. Pick a function in the Functions list \
             or the disassembly, then come back here (Space).",
        );
        return;
    };

    let rebuild = state
        .cache
        .as_ref()
        .is_none_or(|c| c.entry != function.entry || c.generation != doc.generation);
    let new_function = state
        .cache
        .as_ref()
        .is_none_or(|c| c.entry != function.entry);
    if rebuild {
        state.cache = Some(build(ui, doc, &program, function));
    }
    // Taken out for the frame so the rest of `state` can be borrowed mutably.
    let Some(cache) = state.cache.take() else {
        return;
    };

    toolbar(ui, doc, &program, function, state);
    let font = FontId::monospace(13.0);
    let (char_w, row_h) = ui.fonts_mut(|f| (f.glyph_width(&font, '0'), f.row_height(&font) + 2.0));
    let rect = ui.available_rect_before_wrap();
    let id = ui.id().with("graph");
    let response = ui.interact(rect, id, Sense::click_and_drag());
    let response = response.note(
        "Graph view",
        "Each box is a basic block: instructions that always run together, top to bottom. \
         Arrows show where execution can go next. Green: the jump is taken (condition true). \
         Red: not taken (condition false). Blue: always. Arrows looping back up are loops. \
         Drag to move, Ctrl+scroll to zoom, Space for the linear listing.",
    );
    if response.clicked() || response.drag_started() {
        response.request_focus();
    }
    let focused = response.has_focus() && state.popup.is_none();

    // Zoom (Ctrl+scroll / pinch) around the pointer, pan with drag and scroll.
    let zoom_delta = ui.input(|i| i.zoom_delta());
    if zoom_delta != 1.0 && ui.rect_contains_pointer(rect) {
        let pointer = ui.input(|i| i.pointer.hover_pos()).unwrap_or(rect.center());
        let before = (pointer - rect.min - state.pan) / state.zoom;
        state.zoom = (state.zoom * zoom_delta).clamp(MIN_ZOOM, MAX_ZOOM);
        state.pan = pointer - rect.min - before * state.zoom;
    } else if ui.rect_contains_pointer(rect) {
        state.pan += ui.input(|i| i.smooth_scroll_delta);
    }
    if response.dragged() {
        state.pan += response.drag_delta();
    }

    if std::mem::take(&mut state.fit) {
        let b = cache.layout.bounds;
        let zx = rect.width() / (b.width().max(1.0) * char_w * 1.05);
        let zy = rect.height() / (b.height().max(1.0) * row_h * 1.05);
        state.zoom = zx.min(zy).clamp(MIN_ZOOM, MAX_ZOOM);
        let size = Vec2::new(b.width() * char_w, b.height() * row_h) * state.zoom;
        state.pan =
            (rect.size() - size) / 2.0 - Vec2::new(b.left() * char_w, b.top() * row_h) * state.zoom;
        state.last_cursor = Some(doc.cursor);
    }
    let sx = char_w * state.zoom;
    let sy = row_h * state.zoom;
    let to_screen = |p: Pos2| rect.min + state.pan + Vec2::new(p.x * sx, p.y * sy);

    // Keep the cursor's block in view when the cursor moves (or a new function opens).
    let cursor_block = cursor_addr.and_then(|a| {
        cache
            .blocks
            .iter()
            .position(|(_, lines)| lines[1..].contains(&a))
            .or_else(|| {
                function
                    .block_at(a)
                    .and_then(|b| cache.blocks.iter().position(|(s, _)| *s == b.start))
            })
    });
    if state.last_cursor != Some(doc.cursor) || new_function {
        state.last_cursor = Some(doc.cursor);
        let node = cursor_block.unwrap_or(0);
        if let Some(r) = cache.layout.nodes.get(node) {
            let screen = Rect::from_min_max(to_screen(r.min), to_screen(r.max));
            if new_function || !rect.contains_rect(screen) {
                // A new function starts at the top; a moved cursor goes a bit lower so
                // the blocks above it stay in sight.
                let y = if new_function {
                    rect.top() + 24.0
                } else {
                    rect.top() + rect.height() * 0.25
                };
                let target = Pos2::new(rect.center().x, y);
                state.pan += target - Pos2::new(screen.center().x, screen.top());
            }
        }
    }
    let to_screen = |p: Pos2| rect.min + state.pan + Vec2::new(p.x * sx, p.y * sy);

    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, ui.visuals().extreme_bg_color);
    let colors = code::syntax(ui.ctx());

    // Edges first, under the blocks.
    for (path, kind) in cache.layout.edges.iter().zip(&cache.edge_kinds) {
        let color = match kind {
            EdgeKind::Taken => Color32::from_rgb(80, 180, 90),
            EdgeKind::NotTaken => Color32::from_rgb(215, 85, 80),
            EdgeKind::Jump | EdgeKind::FallThrough => Color32::from_rgb(90, 140, 220),
        };
        let points: Vec<Pos2> = path.points.iter().map(|&p| to_screen(p)).collect();
        // Arrows into and out of the current block stand out.
        let touching = cursor_block.is_some_and(|c| path.from == c || path.to == c);
        let width = if touching {
            2.6
        } else if path.back {
            1.2
        } else {
            1.6
        };
        let stroke = Stroke::new(width, color);
        painter.add(Shape::line(points.clone(), stroke));
        if let [.., before, end] = points.as_slice() {
            let dir = (*end - *before).normalized();
            let side = Vec2::new(-dir.y, dir.x) * 4.0;
            let tip = *end;
            let base = tip - dir * 8.0;
            painter.add(Shape::convex_polygon(
                vec![tip, base + side, base - side],
                color,
                Stroke::NONE,
            ));
        }
    }

    // Blocks.
    let draw_text = state.zoom >= 0.35;
    let st = style(ui, &program, 13.0 * state.zoom);
    let mut hits: Vec<(Rect, u64, Vec<code::Span>)> = Vec::new();
    for (i, node) in cache.layout.nodes.iter().enumerate() {
        let screen = Rect::from_min_max(to_screen(node.min), to_screen(node.max));
        if !screen.intersects(rect) {
            continue;
        }
        let current = Some(i) == cursor_block;
        let entry = cache.blocks[i].0 == function.entry;
        painter.rect_filled(screen, 4.0 * state.zoom, ui.visuals().window_fill);
        let border = if current {
            Stroke::new(2.0, ui.visuals().selection.stroke.color)
        } else if entry {
            Stroke::new(1.5, colors.function.0)
        } else {
            Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color)
        };
        painter.rect_stroke(screen, 4.0 * state.zoom, border, StrokeKind::Inside);
        if !draw_text {
            continue;
        }
        let (start, lines) = &cache.blocks[i];
        for (row, &addr) in lines.iter().enumerate() {
            let y = screen.top() + (0.3 + row as f32) * sy;
            let x = screen.left() + sx;
            let line_rect =
                Rect::from_min_size(Pos2::new(screen.left(), y), Vec2::new(screen.width(), sy));
            if row == 0 {
                let text = label(doc, function, *start);
                let color = if entry {
                    colors.function.0
                } else {
                    colors.label.0
                };
                painter.text(
                    Pos2::new(x, y),
                    egui::Align2::LEFT_TOP,
                    text,
                    st.font.clone(),
                    color,
                );
                continue;
            }
            if Some(addr) == cursor_addr {
                painter.rect_filled(line_rect, 0.0, ui.visuals().selection.bg_fill);
            }
            if let Some(insn) = program.decode(addr) {
                let rendered = code::render_insn(doc, &program, &insn, &st);
                let galley = ui.fonts_mut(|f| f.layout_job(rendered.job));
                painter.galley(Pos2::new(x, y), galley, st.text);
                hits.push((line_rect, addr, rendered.spans));
            }
        }
    }

    // Clicks: on an address token navigate, on a line move the cursor.
    let hit_at = |pos: Pos2| {
        let (r, addr, spans) = hits.iter().find(|(r, _, _)| r.contains(pos))?;
        let column = ((pos.x - r.left() - sx) / sx).floor();
        let span = (column >= 0.0)
            .then(|| code::span_at(spans, column as usize))
            .flatten()
            .cloned();
        Some((*addr, span))
    };
    if let Some(pos) = response.hover_pos()
        && let Some((_, Some(span))) = hit_at(pos)
    {
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
            Target::Address(a) => {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                let name = doc.name_of(*a).unwrap_or_else(|| format!("0x{a:x}"));
                response
                    .clone()
                    .on_hover_text_at_pointer(format!("{name}\nclick to go there"));
            }
        }
    }
    if response.clicked()
        && let Some(pos) = response.interact_pointer_pos()
        && let Some((addr, span)) = hit_at(pos)
    {
        match span.map(|s| s.target) {
            Some(Target::Address(a)) => {
                doc.navigate_to_address(a);
            }
            _ => {
                if let Some(offset) = program.memory.offset_of(addr) {
                    doc.go_to(offset);
                    state.last_cursor = Some(doc.cursor);
                }
            }
        }
    }

    if focused {
        keyboard(ui, doc, &program, function, state, cx);
    }
    if let Some(popup) = &mut state.popup
        && !edit::show(ui, doc, popup)
    {
        state.popup = None;
        response.request_focus();
    }
    state.cache = Some(cache);
}

fn toolbar(
    ui: &mut Ui,
    doc: &Document,
    program: &Arc<Program>,
    f: &Function,
    state: &mut GraphState,
) {
    ui.horizontal(|ui| {
        let name = doc
            .name_of(f.entry)
            .unwrap_or_else(|| format!("sub_{:x}", f.entry));
        ui.label(RichText::new(name).monospace().strong());
        ui.label(
            RichText::new(format!(
                "{} blocks · {} instructions · {} bytes · {} callers",
                f.blocks.len(),
                f.insn_count(),
                f.size(),
                program.xrefs(f.entry).len()
            ))
            .weak(),
        );
        ui.separator();
        if ui.small_button("−").clicked() {
            state.zoom = (state.zoom / 1.25).max(MIN_ZOOM);
        }
        ui.label(format!("{:.0}%", state.zoom * 100.0));
        if ui.small_button("+").clicked() {
            state.zoom = (state.zoom * 1.25).min(MAX_ZOOM);
        }
        if ui.small_button("100%").clicked() {
            state.zoom = 1.0;
            state.last_cursor = None;
        }
        if ui
            .small_button("Fit")
            .on_hover_text("Zoom to show the whole function")
            .clicked()
        {
            state.fit = true;
        }
        ui.separator();
        ui.label(
            RichText::new("green = taken · red = not taken · blue = always")
                .weak()
                .small(),
        );
    });
}

fn keyboard(
    ui: &Ui,
    doc: &mut Document,
    program: &Program,
    f: &Function,
    state: &mut GraphState,
    cx: &mut ViewCtx<'_>,
) {
    let press = |key| ui.input_mut(|i| i.consume_key(Modifiers::NONE, key));
    let cursor = program.memory.address_of(doc.cursor);
    if press(Key::Space) {
        cx.requests
            .push(ViewRequest::Open(doc.path.clone(), DocView::Disassembly));
    }
    if press(Key::Escape) || press(Key::Backspace) {
        doc.go_back();
    }
    if press(Key::N) {
        state.popup = Some(EditPopup::rename(doc, f.entry));
    }
    if press(Key::Semicolon)
        && let Some(addr) = cursor
    {
        state.popup = Some(EditPopup::comment(doc, addr));
    }
    if press(Key::X) {
        doc.xref_target = Some(f.entry);
        cx.requests.push(ViewRequest::ShowXrefs);
    }
}
