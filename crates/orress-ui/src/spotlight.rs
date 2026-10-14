//! Spotlight: lessons can point at a part of the interface ("open the command
//! palette here"). Widgets register their screen area under a name with [`mark`];
//! [`paint`] dims everything else and outlines the target.
//!
//! Marks from the previous frame are used for painting, because the overlay is drawn
//! before or after the target depending on panel order.

use std::collections::HashMap;

use egui::{Color32, Context, Id, LayerId, Order, Rect, Stroke, StrokeKind};

#[derive(Clone, Default)]
struct Marks {
    current: HashMap<String, Rect>,
    previous: HashMap<String, Rect>,
}

fn id() -> Id {
    Id::new("orress::spotlight")
}

/// Call once at the start of every frame.
pub fn begin_frame(ctx: &Context) {
    ctx.data_mut(|d| {
        let marks = d.get_temp_mut_or_default::<Marks>(id());
        marks.previous = std::mem::take(&mut marks.current);
    });
}

/// Registers the screen area of a named part of the UI.
pub fn mark(ctx: &Context, name: &str, rect: Rect) {
    ctx.data_mut(|d| {
        d.get_temp_mut_or_default::<Marks>(id())
            .current
            .insert(name.to_owned(), rect);
    });
}

/// Where a named part was drawn (this frame if already, else last frame).
pub fn rect(ctx: &Context, name: &str) -> Option<Rect> {
    ctx.data(|d| {
        d.get_temp::<Marks>(id()).and_then(|m| {
            m.current
                .get(name)
                .or_else(|| m.previous.get(name))
                .copied()
        })
    })
}

/// Dims the screen around `name` (and keeps the `keep_clear` areas, such as the lesson
/// panel, undimmed) and outlines the target with a pulsing border. Returns `false` if
/// that part is not visible (e.g. its dock is closed).
pub fn paint(ctx: &Context, name: &str, label: &str, keep_clear: &[Rect]) -> bool {
    let Some(target) = rect(ctx, name) else {
        return false;
    };
    let screen = ctx.content_rect();
    let target = target.expand(4.0).intersect(screen);
    let painter = ctx.layer_painter(LayerId::new(
        Order::Foreground,
        Id::new("orress::spotlight_layer"),
    ));
    let dim = Color32::from_black_alpha(130);
    // Cut the screen into a grid along the edges of all clear areas and dim the cells
    // outside them. Painting only (no input is captured), so clicks reach everything.
    let holes: Vec<Rect> = std::iter::once(target)
        .chain(keep_clear.iter().map(|r| r.intersect(screen)))
        .filter(|r| r.is_positive())
        .collect();
    let mut xs = vec![screen.min.x, screen.max.x];
    let mut ys = vec![screen.min.y, screen.max.y];
    for h in &holes {
        xs.extend([h.min.x, h.max.x]);
        ys.extend([h.min.y, h.max.y]);
    }
    xs.sort_by(f32::total_cmp);
    xs.dedup();
    ys.sort_by(f32::total_cmp);
    ys.dedup();
    for x in xs.windows(2) {
        for y in ys.windows(2) {
            let cell = Rect::from_min_max(egui::pos2(x[0], y[0]), egui::pos2(x[1], y[1]));
            if !holes.iter().any(|h| h.contains(cell.center())) {
                painter.rect_filled(cell, 0.0, dim);
            }
        }
    }
    let t = ctx.input(|i| i.time);
    let pulse = (0.5 + 0.5 * (t * 3.0).sin()) as f32;
    let color = Color32::from_rgb(255, 200, 60);
    painter.rect_stroke(
        target,
        6.0,
        Stroke::new(2.0 + 2.0 * pulse, color),
        StrokeKind::Outside,
    );
    if !label.is_empty() {
        let below = target.max.y + 8.0 < screen.max.y - 40.0;
        let pos = if below {
            egui::pos2(target.min.x, target.max.y + 8.0)
        } else {
            egui::pos2(target.min.x, target.min.y - 30.0)
        };
        let galley = painter.layout(
            label.to_owned(),
            egui::FontId::proportional(14.0),
            Color32::BLACK,
            320.0,
        );
        let bubble = Rect::from_min_size(pos, galley.size()).expand(6.0);
        painter.rect_filled(bubble, 6.0, color);
        painter.galley(pos, galley, Color32::BLACK);
    }
    ctx.request_repaint();
    true
}
