//! The startup splash screen: the ORRESS logo, name, tagline, version and an animated progress bar
//! with staged status messages. Drawn as a full-window foreground overlay for the first couple of
//! seconds (click or press Esc/Enter/Space to skip).

use std::time::Instant;

use egui::{Align2, Color32, Context, CornerRadius, FontId, Id, LayerId, Order, Pos2, Rect, Vec2};

/// The logo, embedded from the repo's assets.
const LOGO_PNG: &[u8] = include_bytes!("../../../assets/logo.png");

const DURATION: f32 = 2.4;
const BG: Color32 = Color32::from_rgb(0x0b, 0x0e, 0x14);
const ACCENT: Color32 = Color32::from_rgb(0x3a, 0xa0, 0xff);
const TEXT: Color32 = Color32::from_rgb(0xe6, 0xed, 0xf3);
const MUTED: Color32 = Color32::from_rgb(0x8b, 0x94, 0x9e);
const TRACK: Color32 = Color32::from_rgb(0x20, 0x27, 0x30);

pub struct Splash {
    start: Instant,
    logo: Option<egui::TextureHandle>,
}

impl Splash {
    /// Creates the splash and decodes the logo into a texture (the egui context is available at app
    /// construction).
    pub fn new(ctx: &Context) -> Self {
        Self {
            start: Instant::now(),
            logo: load_logo(ctx),
        }
    }

    /// Draws the splash. Returns `true` while it should keep showing, `false` once it has finished
    /// (time elapsed or the user skipped).
    pub fn show(&mut self, ctx: &Context) -> bool {
        let t = (self.start.elapsed().as_secs_f32() / DURATION).min(1.0);
        let skip = ctx.input(|i| {
            i.pointer.any_click()
                || i.key_pressed(egui::Key::Escape)
                || i.key_pressed(egui::Key::Enter)
                || i.key_pressed(egui::Key::Space)
        });

        let screen = ctx.content_rect();
        let painter = ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("orress-splash")));
        painter.rect_filled(screen, CornerRadius::ZERO, BG);

        let cx = screen.center().x;
        // Lay the block out from a little above centre so it reads as centred overall.
        let mut y = screen.center().y - 200.0;

        // Logo.
        if let Some(logo) = &self.logo {
            let size = 220.0_f32.min(screen.width() * 0.5);
            let rect = Rect::from_center_size(Pos2::new(cx, y + size / 2.0), Vec2::splat(size));
            let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
            painter.image(logo.id(), rect, uv, Color32::WHITE);
            y = rect.bottom() + 20.0;
        }

        // Wordmark + tagline + version.
        painter.text(
            Pos2::new(cx, y),
            Align2::CENTER_TOP,
            "ORRESS",
            FontId::proportional(46.0),
            TEXT,
        );
        y += 58.0;
        painter.text(
            Pos2::new(cx, y),
            Align2::CENTER_TOP,
            "Okiedocus Rusty Reverse Engineering Software Suite",
            FontId::proportional(15.0),
            MUTED,
        );
        y += 26.0;
        painter.text(
            Pos2::new(cx, y),
            Align2::CENTER_TOP,
            concat!("v", env!("CARGO_PKG_VERSION")),
            FontId::proportional(13.0),
            ACCENT,
        );
        y += 42.0;

        // Progress bar.
        let bar_w = (screen.width() * 0.4).clamp(240.0, 480.0);
        let track = Rect::from_center_size(Pos2::new(cx, y + 5.0), Vec2::new(bar_w, 8.0));
        painter.rect_filled(track, CornerRadius::same(4), TRACK);
        let fill = Rect::from_min_size(track.min, Vec2::new(track.width() * t, track.height()));
        painter.rect_filled(fill, CornerRadius::same(4), ACCENT);
        y = track.bottom() + 14.0;

        // Status line + percentage.
        painter.text(
            Pos2::new(cx, y),
            Align2::CENTER_TOP,
            format!("{}   {:.0}%", status_for(t), t * 100.0),
            FontId::proportional(12.0),
            MUTED,
        );

        ctx.request_repaint(); // keep animating
        t < 1.0 && !skip
    }
}

fn status_for(t: f32) -> &'static str {
    match (t * 100.0) as u32 {
        0..=24 => "Loading analysis engines…",
        25..=54 => "Initializing decompiler & emulator…",
        55..=79 => "Starting language servers & extensions…",
        _ => "Preparing workspace…",
    }
}

/// Decodes the logo PNG (via eframe's decoder) into a texture.
fn load_logo(ctx: &Context) -> Option<egui::TextureHandle> {
    let icon = eframe::icon_data::from_png_bytes(LOGO_PNG).ok()?;
    let image = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    Some(ctx.load_texture("orress-splash-logo", image, egui::TextureOptions::LINEAR))
}
