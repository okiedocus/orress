//! Shared egui widgets for ORRESS.

pub mod explain;
pub mod palette;
pub mod spotlight;

pub use explain::{ExplainExt, Explanation};
pub use palette::{CommandPalette, PaletteItem};

use egui::{RichText, Ui};

/// Draws a keyboard shortcut as a small "key cap" chip, e.g. `Ctrl+Shift+P`.
pub fn kbd(ui: &mut Ui, label: &str) -> egui::Response {
    let visuals = ui.visuals().clone();
    egui::Frame::new()
        .fill(visuals.extreme_bg_color)
        .stroke(visuals.widgets.noninteractive.bg_stroke)
        .corner_radius(3.0)
        .inner_margin(egui::Margin::symmetric(4, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(label).monospace().small().weak());
        })
        .response
}

/// Secondary text in the theme's muted color.
pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text).weak()
}
