//! Explain Mode: every widget can carry a plain-language explanation.
//!
//! ```ignore
//! ui.button("Entropy").explain(
//!     "Entropy",
//!     "How random the bytes look. Close to 8 means compressed or encrypted data.",
//! );
//! ```
//!
//! When Explain Mode is on, hovering shows the explanation as a tooltip. Whether it is
//! on or off, the last hovered explanation is remembered so the Explain panel can show it
//! in full.

use egui::{Context, Id, Response, RichText};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    pub title: String,
    pub body: String,
}

fn mode_id() -> Id {
    Id::new("orress::explain_mode")
}

fn last_id() -> Id {
    Id::new("orress::last_explanation")
}

pub fn set_explain_mode(ctx: &Context, on: bool) {
    ctx.data_mut(|d| d.insert_temp(mode_id(), on));
}

pub fn explain_mode(ctx: &Context) -> bool {
    ctx.data(|d| d.get_temp(mode_id())).unwrap_or(true)
}

/// The explanation of the most recently hovered widget, if any.
pub fn last_explanation(ctx: &Context) -> Option<Explanation> {
    ctx.data(|d| d.get_temp(last_id()))
}

pub trait ExplainExt {
    /// Explanation shown in the Explain panel and, in Explain Mode, as a tooltip.
    fn explain(self, title: &str, body: &str) -> Self;
    /// Explanation shown only in the Explain panel: for large areas such as the hex grid,
    /// where a tooltip would cover what you are looking at.
    fn note(self, title: &str, body: &str) -> Self;
}

fn record(ctx: &Context, title: &str, body: &str) {
    let explanation = Explanation {
        title: title.to_owned(),
        body: body.to_owned(),
    };
    if last_explanation(ctx).as_ref() != Some(&explanation) {
        ctx.data_mut(|d| d.insert_temp(last_id(), explanation));
    }
}

impl ExplainExt for Response {
    fn note(self, title: &str, body: &str) -> Self {
        if self.hovered() {
            record(&self.ctx, title, body);
        }
        self
    }

    fn explain(self, title: &str, body: &str) -> Self {
        if !self.hovered() {
            return self;
        }
        let ctx = self.ctx.clone();
        record(&ctx, title, body);
        if explain_mode(&ctx) {
            self.on_hover_ui(|ui| {
                ui.set_max_width(320.0);
                ui.label(RichText::new(title).strong());
                ui.label(body);
            })
        } else {
            self
        }
    }
}
