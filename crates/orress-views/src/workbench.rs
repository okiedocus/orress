//! The Workbench: decode, decrypt and decompress data with a chain of operations
//! (a recipe), with "Magic" to find the chain automatically.

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_transforms::{ParamKind, Recipe, Step, Suggestion};
use orress_ui::{ExplainExt as _, muted};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    Text,
    Hex,
}

/// Output (or error) of every step of a recipe.
type StepOutputs = Vec<Result<Vec<u8>, String>>;

pub struct Workbench {
    input: Vec<u8>,
    input_text: String,
    input_mode: Mode,
    output_mode: Mode,
    /// Where the input came from, e.g. "crackme01.exe 0x1200..0x1240".
    source: Option<(std::path::PathBuf, u64, u64)>,
    pub recipe: Recipe,
    recipe_text: String,
    recipe_error: Option<String>,
    filter: String,
    magic: Option<Vec<Suggestion>>,
    cache: Option<(String, StepOutputs)>,
    message: Option<String>,
}

impl Default for Workbench {
    fn default() -> Self {
        let mut wb = Self {
            input: Vec::new(),
            input_text: "ZmxhZ3t3ZWxjb21lX3RvX3RoZV93b3JrYmVuY2h9".into(),
            input_mode: Mode::Text,
            output_mode: Mode::Text,
            source: None,
            recipe: Recipe(vec![Step::new("from_base64")]),
            recipe_text: String::new(),
            recipe_error: None,
            filter: String::new(),
            magic: None,
            cache: None,
            message: None,
        };
        wb.input = wb.input_text.clone().into_bytes();
        wb.recipe_text = wb.recipe.to_string();
        wb
    }
}

impl Workbench {
    /// Loads bytes from a file region (from the hex view's selection).
    pub fn set_input(&mut self, bytes: Vec<u8>, source: Option<(std::path::PathBuf, u64, u64)>) {
        self.input_mode = if bytes
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            Mode::Text
        } else {
            Mode::Hex
        };
        self.input_text = render(&bytes, self.input_mode);
        self.input = bytes;
        self.source = source;
        self.magic = None;
    }

    fn outputs(&mut self) -> &[Result<Vec<u8>, String>] {
        let key = format!("{}\u{0}{}", self.recipe_with_flags(), fnv(&self.input));
        if self.cache.as_ref().is_none_or(|(k, _)| *k != key) {
            let outputs = self.recipe.run(&self.input);
            self.cache = Some((key, outputs));
        }
        &self.cache.as_ref().expect("just set").1
    }

    fn recipe_with_flags(&self) -> String {
        let flags: String = self
            .recipe
            .0
            .iter()
            .map(|s| if s.enabled { '1' } else { '0' })
            .collect();
        format!("{}#{flags}", self.recipe)
    }

    fn final_output(&mut self) -> Result<Vec<u8>, String> {
        let input = self.input.clone();
        match self.outputs().last() {
            Some(r) => r.clone(),
            None => Ok(input),
        }
    }

    fn sync_text(&mut self) {
        self.recipe_text = self.recipe.to_string();
        self.recipe_error = None;
    }
}

fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

fn render(bytes: &[u8], mode: Mode) -> String {
    match mode {
        Mode::Text => String::from_utf8_lossy(bytes).into_owned(),
        Mode::Hex => bytes
            .chunks(16)
            .map(|row| {
                row.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn parse_input(text: &str, mode: Mode) -> Result<Vec<u8>, String> {
    match mode {
        Mode::Text => Ok(text.as_bytes().to_vec()),
        Mode::Hex => orress_transforms::parse_key(&format!("hex:{text}")),
    }
}

pub fn workbench(ui: &mut Ui, wb: &mut Workbench, docs: &mut DocStore) {
    ui.horizontal(|ui| {
        ui.heading("Workbench");
        ui.label(muted(
            "Chain operations to decode, decrypt or decompress data. Each step works on the \
             previous step's output. Not sure where to start? Press Magic.",
        ));
    });
    ui.separator();
    ui.columns(3, |cols| {
        operations(&mut cols[0], wb);
        recipe(&mut cols[1], wb);
        data(&mut cols[2], wb, docs);
    });
}

fn operations(ui: &mut Ui, wb: &mut Workbench) {
    ui.label(RichText::new("Operations").strong()).explain(
        "Operations",
        "Click an operation to add it to the end of the recipe. Hover one to see what it does.",
    );
    ui.add(
        egui::TextEdit::singleline(&mut wb.filter)
            .hint_text("Search, e.g. base64, xor, aes")
            .desired_width(f32::INFINITY),
    );
    let filter = wb.filter.to_lowercase();
    egui::ScrollArea::vertical()
        .id_salt("wb_ops")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut category = None;
            for op in orress_transforms::ops() {
                if !filter.is_empty()
                    && !op.name.to_lowercase().contains(&filter)
                    && !op.id.contains(&filter)
                {
                    continue;
                }
                if category != Some(op.category) {
                    category = Some(op.category);
                    ui.add_space(4.0);
                    ui.label(RichText::new(op.category.name()).small().weak());
                }
                if ui
                    .selectable_label(false, op.name)
                    .explain(op.name, op.explain)
                    .clicked()
                {
                    wb.recipe.0.push(Step::new(op.id));
                    wb.sync_text();
                }
            }
        });
}

fn recipe(ui: &mut Ui, wb: &mut Workbench) {
    ui.label(RichText::new("Recipe").strong()).explain(
        "Recipe",
        "The steps, top to bottom. Untick a step to skip it, use the arrows to reorder. The \
         text field below holds the same recipe as text: copy it, share it, or use it with \
         orress-cli.",
    );
    let outputs: Vec<Result<usize, String>> = wb
        .outputs()
        .iter()
        .map(|r| r.as_ref().map(Vec::len).map_err(Clone::clone))
        .collect();
    let mut action: Option<(usize, i32)> = None; // (index, -1 up / +1 down / 0 remove)
    let mut changed = false;
    egui::ScrollArea::vertical()
        .id_salt("wb_recipe")
        .max_height(ui.available_height() - 90.0)
        .show(ui, |ui| {
            let mut enabled_index = 0;
            for (i, step) in wb.recipe.0.iter_mut().enumerate() {
                let Some(op) = orress_transforms::find(&step.op) else {
                    continue;
                };
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        changed |= ui
                            .checkbox(&mut step.enabled, "")
                            .on_hover_text("Run this step")
                            .changed();
                        ui.label(RichText::new(op.name).strong())
                            .explain(op.name, op.explain);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("x").on_hover_text("Remove").clicked() {
                                action = Some((i, 0));
                            }
                            if ui.small_button("v").on_hover_text("Move down").clicked() {
                                action = Some((i, 1));
                            }
                            if ui.small_button("^").on_hover_text("Move up").clicked() {
                                action = Some((i, -1));
                            }
                        });
                    });
                    for p in op.params {
                        let value = step
                            .params
                            .entry(p.name.to_owned())
                            .or_insert_with(|| p.default.to_owned());
                        ui.horizontal(|ui| {
                            ui.label(muted(p.name)).explain(p.name, p.explain);
                            match p.kind {
                                ParamKind::Choice(options) => {
                                    egui::ComboBox::from_id_salt((i, p.name))
                                        .selected_text(value.as_str())
                                        .show_ui(ui, |ui| {
                                            for o in options {
                                                changed |= ui
                                                    .selectable_value(value, (*o).to_owned(), *o)
                                                    .changed();
                                            }
                                        });
                                }
                                _ => {
                                    changed |= ui
                                        .add(
                                            egui::TextEdit::singleline(value)
                                                .id_salt((i, p.name))
                                                .desired_width(f32::INFINITY),
                                        )
                                        .changed();
                                }
                            }
                        });
                    }
                    if step.enabled {
                        match outputs.get(enabled_index) {
                            Some(Ok(n)) => {
                                ui.label(muted(format!("{n} bytes out")));
                            }
                            Some(Err(e)) => {
                                ui.colored_label(ui.visuals().warn_fg_color, e);
                            }
                            None => {
                                ui.label(muted("not run (an earlier step failed)"));
                            }
                        }
                        enabled_index += 1;
                    }
                });
            }
            if wb.recipe.0.is_empty() {
                ui.label(muted("Empty. Click operations on the left to add them."));
            }
        });
    if let Some((i, dir)) = action {
        match dir {
            0 => {
                wb.recipe.0.remove(i);
            }
            -1 if i > 0 => wb.recipe.0.swap(i, i - 1),
            1 if i + 1 < wb.recipe.0.len() => wb.recipe.0.swap(i, i + 1),
            _ => {}
        }
        changed = true;
    }
    if changed {
        wb.sync_text();
    }
    ui.separator();
    ui.label(muted("As text (edit or paste a recipe):"));
    let edit = ui.add(
        egui::TextEdit::singleline(&mut wb.recipe_text)
            .id_salt("wb_recipe_text")
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    if edit.changed() {
        match Recipe::parse(&wb.recipe_text) {
            Ok(r) => {
                wb.recipe = r;
                wb.recipe_error = None;
            }
            Err(e) => wb.recipe_error = Some(e),
        }
    }
    if let Some(e) = &wb.recipe_error {
        ui.colored_label(ui.visuals().warn_fg_color, e);
    }
    ui.horizontal(|ui| {
        if ui.small_button("Copy as command").explain(
            "Copy as command",
            "Copies a orress-cli command that runs this recipe on a file, for scripts and terminals.",
        ).clicked() {
            ui.ctx().copy_text(format!("orress-cli recipe \"{}\" INPUT_FILE", wb.recipe));
        }
        if ui.small_button("Clear").clicked() {
            wb.recipe.0.clear();
            wb.sync_text();
        }
    });
}

fn data(ui: &mut Ui, wb: &mut Workbench, docs: &mut DocStore) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Input").strong());
        let old = wb.input_mode;
        ui.selectable_value(&mut wb.input_mode, Mode::Text, "text");
        ui.selectable_value(&mut wb.input_mode, Mode::Hex, "hex").explain(
            "Hex input",
            "Type or paste bytes as hex (41 42 43). Use this for binary data.",
        );
        if wb.input_mode != old {
            wb.input_text = render(&wb.input, wb.input_mode);
        }
        if ui.small_button("From selection").explain(
            "From selection",
            "Use the bytes selected in the hex view of the current file. You can also select bytes there and use the palette command \"Hex: Send to Workbench\".",
        ).clicked() {
            match docs.active().and_then(|d| Some((d, d.selection?))) {
                Some((doc, (a, b))) => {
                    let bytes = doc.bytes().and_then(|x| x.get(a as usize..b as usize)).map(<[u8]>::to_vec).unwrap_or_default();
                    let path = doc.path.clone();
                    wb.set_input(bytes, Some((path, a, b)));
                }
                None => wb.message = Some("Select some bytes in the hex view first.".into()),
            }
        }
    });
    let edit = ui.add(
        egui::TextEdit::multiline(&mut wb.input_text)
            .id_salt("wb_input")
            .desired_rows(6)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    if edit.changed() {
        match parse_input(&wb.input_text, wb.input_mode) {
            Ok(bytes) => {
                wb.input = bytes;
                wb.source = None;
                wb.message = None;
                wb.magic = None;
            }
            Err(e) => wb.message = Some(format!("Input: {e}")),
        }
    }
    ui.label(muted(format!("{} bytes", wb.input.len())));
    if let Some(m) = &wb.message {
        ui.colored_label(ui.visuals().warn_fg_color, m);
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Output").strong());
        ui.selectable_value(&mut wb.output_mode, Mode::Text, "text");
        ui.selectable_value(&mut wb.output_mode, Mode::Hex, "hex");
    });
    let output = wb.final_output();
    match &output {
        Ok(bytes) => {
            let flag = orress_bytes::strings::looks_like_flag(&String::from_utf8_lossy(bytes));
            if flag {
                ui.label(
                    RichText::new("This looks like a flag!")
                        .strong()
                        .color(ui.visuals().warn_fg_color),
                );
            }
            let shown = &bytes[..bytes.len().min(64 * 1024)];
            let mut text = render(shown, wb.output_mode);
            if shown.len() < bytes.len() {
                text += "\n… (first 64 KiB shown)";
            }
            egui::ScrollArea::vertical()
                .id_salt("wb_output")
                .max_height(180.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace)
                            .interactive(true),
                    );
                });
            ui.horizontal(|ui| {
                ui.label(muted(format!("{} bytes · entropy {:.2}", bytes.len(), orress_bytes::entropy::shannon(bytes))));
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(String::from_utf8_lossy(bytes).into_owned());
                }
                if ui.small_button("Save…").clicked()
                    && let Some(path) = rfd_save()
                    && let Err(e) = std::fs::write(&path, bytes)
                {
                    wb.message = Some(format!("Could not save: {e}"));
                }
                if let Some((path, start, end)) = wb.source.clone()
                    && bytes.len() as u64 == end - start
                    && ui
                        .small_button("Write back to file")
                        .explain(
                            "Write back",
                            "Replace the selected bytes in the file with this output (as a patch, the file on disk is not changed). Useful to decrypt data in place and then read it in the disassembly or hex view.",
                        )
                        .clicked()
                    && let Some(doc) = docs.get_mut(&path)
                {
                    if let Err(e) = doc.patch(start, bytes) {
                        wb.message = Some(e);
                    } else {
                        wb.message = Some(format!("Patched {} bytes at 0x{start:x}.", bytes.len()));
                    }
                }
            });
        }
        Err(e) => {
            ui.colored_label(ui.visuals().warn_fg_color, e);
        }
    }

    ui.add_space(6.0);
    if ui
        .button(RichText::new("Magic").strong())
        .explain(
            "Magic",
            "Tries common decodings (hex, base64, base32, URL, zlib, gzip, XOR, ROT13, UTF-16 ...) \
             in chains of up to 3 steps, and lists the most readable results. Click Use to \
             load a result's recipe.",
        )
        .clicked()
    {
        wb.magic = Some(orress_transforms::magic(&wb.input, 3));
    }
    if let Some(suggestions) = wb.magic.clone() {
        if suggestions.is_empty() {
            ui.label(muted("Magic found nothing more readable than the input."));
        }
        let mut chosen = None;
        egui::ScrollArea::vertical()
            .id_salt("wb_magic")
            .max_height(200.0)
            .show(ui, |ui| {
                for (i, s) in suggestions.iter().enumerate() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            if ui.small_button("Use").clicked() {
                                chosen = Some(i);
                            }
                            ui.label(RichText::new(s.recipe.to_string()).monospace().strong());
                        });
                        let preview: String = String::from_utf8_lossy(&s.output)
                            .chars()
                            .take(120)
                            .collect();
                        ui.label(RichText::new(preview).monospace().small());
                        ui.label(muted(&s.why));
                    });
                }
            });
        if let Some(i) = chosen {
            wb.recipe = suggestions[i].recipe.clone();
            wb.sync_text();
        }
    }
}

fn rfd_save() -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_title("Save output").save_file()
}
