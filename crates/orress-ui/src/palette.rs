//! The command palette (Ctrl+Shift+P): fuzzy search over every action.

use egui::{Align, Context, Id, Key, Modifiers, RichText, Sense};
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use orress_actions::ActionId;

#[derive(Clone, Debug)]
pub struct PaletteItem {
    pub action: ActionId,
    pub title: String,
    pub category: String,
    pub shortcut: Option<String>,
    pub explain: String,
}

impl PaletteItem {
    fn haystack(&self) -> String {
        format!("{}: {}", self.category, self.title)
    }
}

const MAX_RECENT: usize = 8;

pub struct CommandPalette {
    open: bool,
    query: String,
    selected: usize,
    /// Set when the selection moved by keyboard, so the list scrolls to it.
    scroll_to_selected: bool,
    recent: Vec<ActionId>,
    matcher: Matcher,
}

impl Default for CommandPalette {
    fn default() -> Self {
        Self {
            open: false,
            query: String::new(),
            selected: 0,
            scroll_to_selected: false,
            recent: Vec::new(),
            matcher: Matcher::new(Config::DEFAULT),
        }
    }
}

impl CommandPalette {
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn toggle(&mut self) {
        if self.open {
            self.close();
        } else {
            self.open = true;
            self.query.clear();
            self.selected = 0;
        }
    }

    pub fn close(&mut self) {
        self.open = false;
    }

    /// Indices into `items`, best match first. With an empty query, recently used
    /// actions come first and the rest are alphabetical.
    pub fn filter(&mut self, items: &[PaletteItem]) -> Vec<usize> {
        if self.query.trim().is_empty() {
            let mut order: Vec<usize> = (0..items.len()).collect();
            order.sort_by_key(|&i| {
                let recent_rank = self
                    .recent
                    .iter()
                    .position(|a| a == &items[i].action)
                    .unwrap_or(usize::MAX);
                (recent_rank, items[i].haystack().to_lowercase())
            });
            return order;
        }

        let pattern = Pattern::parse(&self.query, CaseMatching::Ignore, Normalization::Smart);
        let mut buf = Vec::new();
        let mut scored: Vec<(usize, u32)> = items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| {
                let haystack = item.haystack();
                pattern
                    .score(Utf32Str::new(&haystack, &mut buf), &mut self.matcher)
                    .map(|score| (i, score))
            })
            .collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.into_iter().map(|(i, _)| i).collect()
    }

    fn remember(&mut self, action: &ActionId) {
        self.recent.retain(|a| a != action);
        self.recent.insert(0, action.clone());
        self.recent.truncate(MAX_RECENT);
    }

    /// Shows the palette if open. Returns the action the user picked.
    pub fn show(&mut self, ctx: &Context, items: &[PaletteItem]) -> Option<ActionId> {
        if !self.open {
            return None;
        }

        let matches = self.filter(items);
        if self.selected >= matches.len() {
            self.selected = matches.len().saturating_sub(1);
        }

        // Navigation keys are consumed before the text field sees them.
        let (up, down, enter, escape) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::NONE, Key::ArrowUp),
                i.consume_key(Modifiers::NONE, Key::ArrowDown),
                i.consume_key(Modifiers::NONE, Key::Enter),
                i.consume_key(Modifiers::NONE, Key::Escape),
            )
        });
        if up && self.selected > 0 {
            self.selected -= 1;
            self.scroll_to_selected = true;
        }
        if down && self.selected + 1 < matches.len() {
            self.selected += 1;
            self.scroll_to_selected = true;
        }

        let mut picked = None;
        if enter {
            picked = matches.get(self.selected).map(|&i| items[i].action.clone());
        }

        let area = egui::Area::new(Id::new("orress::palette_area"))
            .anchor(egui::Align2::CENTER_TOP, [0.0, 80.0])
            .order(egui::Order::Foreground);
        let modal = egui::Modal::new(Id::new("orress::palette"))
            .area(area)
            .show(ctx, |ui| {
                ui.set_width(560.0);
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text("Type a command… (try \"dock\", \"theme\" or \"open\")")
                        .desired_width(f32::INFINITY),
                );
                edit.request_focus();
                if edit.changed() {
                    self.selected = 0;
                }
                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(360.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        if matches.is_empty() {
                            ui.label(RichText::new("No matching command.").weak());
                        }
                        for (row, &index) in matches.iter().enumerate() {
                            let item = &items[index];
                            let selected = row == self.selected;
                            let response = palette_row(ui, item, selected);
                            if selected && self.scroll_to_selected {
                                response.scroll_to_me(Some(Align::Center));
                            }
                            if response.hovered()
                                && ui.input(|i| i.pointer.delta() != egui::Vec2::ZERO)
                            {
                                self.selected = row;
                            }
                            if response.clicked() {
                                picked = Some(item.action.clone());
                            }
                        }
                    });
                self.scroll_to_selected = false;

                // Beginner help: what does the highlighted command do?
                if let Some(item) = matches.get(self.selected).map(|&i| &items[i]) {
                    ui.separator();
                    ui.label(RichText::new(&item.explain).small().weak());
                }
            });

        if escape || modal.should_close() {
            self.close();
        }
        if let Some(action) = &picked {
            self.remember(action);
            self.close();
        }
        picked
    }
}

fn palette_row(ui: &mut egui::Ui, item: &PaletteItem, selected: bool) -> egui::Response {
    let fill = if selected {
        ui.visuals().selection.bg_fill
    } else {
        egui::Color32::TRANSPARENT
    };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(6, 3))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{}:", item.category)).weak());
                ui.label(&item.title);
                if let Some(shortcut) = &item.shortcut {
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        crate::kbd(ui, shortcut);
                    });
                }
            });
        })
        .response
        .interact(Sense::click())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, category: &str, title: &str) -> PaletteItem {
        PaletteItem {
            action: id.into(),
            title: title.into(),
            category: category.into(),
            shortcut: None,
            explain: String::new(),
        }
    }

    fn items() -> Vec<PaletteItem> {
        vec![
            item("workspace::ToggleLeftDock", "workspace", "Toggle Left Dock"),
            item("workspace::Open", "workspace", "Open File…"),
            item("theme::Dark", "theme", "ORRESS Dark"),
        ]
    }

    #[test]
    fn fuzzy_match_ranks_relevant_first() {
        let mut p = CommandPalette::default();
        let items = items();
        p.query = "tgl dock".into();
        let m = p.filter(&items);
        assert_eq!(items[m[0]].action.as_str(), "workspace::ToggleLeftDock");

        p.query = "zzzz".into();
        assert!(p.filter(&items).is_empty());
    }

    #[test]
    fn empty_query_puts_recent_first() {
        let mut p = CommandPalette::default();
        let items = items();
        p.remember(&"theme::Dark".into());
        let m = p.filter(&items);
        assert_eq!(items[m[0]].action.as_str(), "theme::Dark");
        assert_eq!(m.len(), 3);
    }
}
