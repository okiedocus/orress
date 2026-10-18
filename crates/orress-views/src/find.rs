//! The find bar shared by the code views (disassembly, decompiler): a text field with
//! Next / Previous, Enter / F3 / Shift+F3 and Esc to close.

use egui::{Key, RichText, Ui};
use orress_ui::ExplainExt as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FindStep {
    Next,
    Previous,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FindInput {
    pub open: bool,
    pub query: String,
    pub focus: bool,
    /// Result of the last search: where it was found, or why not.
    pub status: Option<Result<String, String>>,
}

impl FindInput {
    pub fn show(&mut self) {
        self.open = true;
        self.focus = true;
    }

    /// The query, lowercased, or `None` while it is empty.
    pub fn needle(&self) -> Option<String> {
        let q = self.query.trim();
        (!q.is_empty()).then(|| q.to_ascii_lowercase())
    }
}

/// What the bar asks for this frame.
#[derive(Default)]
pub(crate) struct BarResult {
    pub step: Option<FindStep>,
    /// The query text changed (so a remembered match position is stale).
    pub changed: bool,
}

/// Draws the bar. `explain` is shown in Explain Mode on its label.
pub(crate) fn bar(ui: &mut Ui, input: &mut FindInput, hint: &str, explain: &str) -> BarResult {
    let mut result = BarResult::default();
    ui.horizontal_wrapped(|ui| {
        ui.label("Find").explain("Find", explain);
        let edit = ui.add(
            egui::TextEdit::singleline(&mut input.query)
                .hint_text(hint)
                .desired_width(260.0)
                .font(egui::TextStyle::Monospace),
        );
        if input.focus {
            edit.request_focus();
            input.focus = false;
        }
        if edit.changed() {
            input.status = None;
            result.changed = true;
        }
        let submit = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if ui.button("Next").on_hover_text("F3").clicked() || submit {
            result.step = Some(FindStep::Next);
            if submit {
                input.focus = true;
            }
        }
        if ui.button("Previous").on_hover_text("Shift+F3").clicked() {
            result.step = Some(FindStep::Previous);
        }
        if ui.button("×").on_hover_text("Close (Esc)").clicked()
            || (edit.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)))
        {
            input.open = false;
        }
        match &input.status {
            Some(Ok(s)) => {
                ui.label(RichText::new(s).weak());
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().warn_fg_color, e);
            }
            None => {}
        }
    });
    result
}

/// Byte offsets where `needle` (lowercase ASCII) starts in `text`, ignoring ASCII case.
pub(crate) fn matches(text: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    text.to_ascii_lowercase()
        .match_indices(needle)
        .map(|(at, _)| at)
        .collect()
}

/// The next (or previous) entry of a sorted list of match positions after (before)
/// `from`, wrapping around.
pub(crate) fn step_index(len: usize, current: Option<usize>, step: FindStep) -> Option<usize> {
    if len == 0 {
        return None;
    }
    Some(match (current, step) {
        (None, FindStep::Next) => 0,
        (None, FindStep::Previous) => len - 1,
        (Some(i), FindStep::Next) => (i + 1) % len,
        (Some(i), FindStep::Previous) => (i + len - 1) % len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ignoring_case() {
        assert_eq!(matches("if a1 == 7 { XOR }", "xor"), vec![13]);
        assert!(matches("abc", "").is_empty());
    }

    #[test]
    fn steps_wrap_around() {
        assert_eq!(step_index(3, None, FindStep::Next), Some(0));
        assert_eq!(step_index(3, Some(2), FindStep::Next), Some(0));
        assert_eq!(step_index(3, Some(0), FindStep::Previous), Some(2));
        assert_eq!(step_index(0, None, FindStep::Next), None);
    }
}
