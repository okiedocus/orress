//! The Challenge Workbench panel: author a CTF challenge from a template, build and test it with
//! the run console, and submit it to the site's Forge for review. The scaffolding, template and
//! HTTP submit live in `orress-challenge`; this is the egui front end.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use egui::Ui;
use orress_challenge::{KitSource, Meta};
use orress_ui::muted;

use crate::RunConsole;

/// What to do once `main.rs` has been saved from the open editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterSave {
    Build,
    Submit,
}

/// State for the Challenge Workbench (owned by the app; not persisted, so the password never is).
pub struct ChallengeWorkbenchView {
    /// A Build or Submit waiting for the workspace to save `main.rs`'s editor buffer (unsaved
    /// edits must not be built or submitted stale), and the outcome of that save.
    after_save: Option<AfterSave>,
    save_result: Option<Result<(), String>>,
    meta: Meta,
    /// Hints, edited as one newline-separated field.
    hints_text: String,
    project_dir: Option<PathBuf>,
    main_rs: Option<PathBuf>,
    /// Use the bundled, offline `challenge-kit` (true) or a custom dependency (false).
    use_builtin_kit: bool,
    /// The custom `challenge-kit` dependency spec, used when `use_builtin_kit` is false.
    kit_source: String,
    site_url: String,
    username: String,
    password: String,
    status: Arc<Mutex<String>>,
    busy: Arc<AtomicBool>,
}

impl Default for ChallengeWorkbenchView {
    fn default() -> Self {
        Self {
            after_save: None,
            save_result: None,
            meta: Meta::default(),
            hints_text: String::new(),
            project_dir: None,
            main_rs: None,
            use_builtin_kit: true,
            kit_source: String::new(),
            site_url: "https://ctf.okiedocus.nl".to_string(),
            username: String::new(),
            password: String::new(),
            status: Arc::new(Mutex::new(String::new())),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ChallengeWorkbenchView {
    fn sync_hints(&mut self) {
        self.meta.hints = self
            .hints_text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
    }

    fn set_status(&self, s: impl Into<String>) {
        if let Ok(mut g) = self.status.lock() {
            *g = s.into();
        }
    }

    /// The source file the workspace should save from its editor tab before a pending Build or
    /// Submit runs (`None` when nothing waits for a save). Answer with [`Self::report_save`].
    pub fn save_request(&self) -> Option<std::path::PathBuf> {
        if self.after_save.is_some() && self.save_result.is_none() {
            self.main_rs.clone()
        } else {
            None
        }
    }

    /// The outcome of saving `main.rs` (Ok also when no editor had it open, or it was clean).
    pub fn report_save(&mut self, result: Result<(), String>) {
        self.save_result = Some(result);
    }

    /// Runs a Build or Submit once its save went through.
    fn take_ready_action(&mut self) -> Option<AfterSave> {
        self.after_save?;
        match self.save_result.take()? {
            Ok(()) => self.after_save.take(),
            Err(e) => {
                self.after_save = None;
                self.set_status(format!("Could not save main.rs, so nothing was run: {e}"));
                None
            }
        }
    }
}

/// Draws the workbench. Scaffolding pushes the generated `main.rs` to `open_requests` (the app
/// opens it in the editor); Build & test drives `run_console`; Submit runs on a background thread.
pub fn challenge_workbench(
    ui: &mut Ui,
    view: &mut ChallengeWorkbenchView,
    open_requests: &mut Vec<PathBuf>,
    run_console: &mut RunConsole,
) {
    // Build / Submit first save main.rs from the editor (via the workspace); act once it has.
    let ready = view.take_ready_action();
    if view.after_save.is_some() {
        ui.ctx().request_repaint();
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.heading("Challenge Workbench");
            ui.label(muted(
                "Build your own crackme or keygen, test it, and submit it for review. You write the \
                 check() logic; the platform owns the flag, the build and the challenge id.",
            ));
            ui.add_space(6.0);

            // 1. Metadata.
            ui.heading("1 · Describe it");
            egui::Grid::new("cw_meta")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Title");
                    ui.text_edit_singleline(&mut view.meta.title);
                    ui.end_row();
                    ui.label("Category");
                    ui.text_edit_singleline(&mut view.meta.category);
                    ui.end_row();
                    ui.label("Technique");
                    ui.text_edit_singleline(&mut view.meta.technique);
                    ui.end_row();
                    ui.label("Difficulty");
                    egui::ComboBox::from_id_salt("cw_level")
                        .selected_text(format!("Level {}", view.meta.level))
                        .show_ui(ui, |ui| {
                            for l in 1..=5u8 {
                                ui.selectable_value(&mut view.meta.level, l, format!("Level {l}"));
                            }
                        });
                    ui.end_row();
                    ui.label("Input label");
                    ui.text_edit_singleline(&mut view.meta.input_label);
                    ui.end_row();
                });
            ui.label("Brief");
            ui.text_edit_multiline(&mut view.meta.brief);
            ui.label("Hints (one per line)");
            ui.text_edit_multiline(&mut view.hints_text);
            ui.label("Writeup (shown after solving)");
            ui.text_edit_multiline(&mut view.meta.writeup);

            ui.add_space(6.0);
            ui.separator();

            // 2. Source.
            ui.heading("2 · Write the logic");
            ui.horizontal(|ui| {
                ui.label("challenge-kit:");
                ui.radio_value(&mut view.use_builtin_kit, true, "Built-in")
                    .on_hover_text(
                        "Use the challenge-kit bundled with ORRESS. It is vendored into the project, \
                         so it builds offline with no external repository.",
                    );
                ui.radio_value(&mut view.use_builtin_kit, false, "External")
                    .on_hover_text("Depend on your own challenge-kit checkout instead.");
            });
            if !view.use_builtin_kit {
                ui.horizontal(|ui| {
                    ui.label("    dependency:");
                    ui.add(
                        egui::TextEdit::singleline(&mut view.kit_source)
                            .desired_width(360.0)
                            .hint_text(r#"git = "https://…"  or  path = "../checkout""#),
                    )
                    .on_hover_text(
                        "A Cargo dependency spec body for challenge-kit, e.g. \
                         git = \"https://github.com/you/challenge-kit\" or path = \"../checkout\".",
                    );
                });
            }
            ui.horizontal(|ui| {
                if ui
                    .button("Scaffold & open in editor")
                    .on_hover_text("Create a challenge-kit project and open its main.rs in the editor")
                    .clicked()
                    && let Some(dir) = rfd::FileDialog::new()
                        .set_title("Choose an (empty) folder for the challenge project")
                        .pick_folder()
                {
                    view.sync_hints();
                    let kit = if view.use_builtin_kit {
                        KitSource::BuiltIn
                    } else {
                        KitSource::External(view.kit_source.clone())
                    };
                    match orress_challenge::scaffold(&dir, &view.meta, &kit) {
                        Ok(main) => {
                            view.project_dir = Some(dir);
                            open_requests.push(main.clone());
                            view.main_rs = Some(main);
                            view.set_status(
                                "Scaffolded. Edit main.rs in the editor, then Build & test or Submit.",
                            );
                        }
                        Err(e) => view.set_status(format!("Scaffold failed: {e}")),
                    }
                }
                if let Some(main) = view.main_rs.clone()
                    && ui.button("Re-open main.rs").clicked()
                {
                    open_requests.push(main);
                }
            });
            if let Some(dir) = &view.project_dir {
                ui.label(muted(format!("Project: {}", dir.display())));
            }
            let can_build =
                view.project_dir.is_some() && !run_console.is_running() && view.after_save.is_none();
            if ui
                .add_enabled(can_build, egui::Button::new("Build & test (cargo run)"))
                .on_hover_text(
                    "Save main.rs, then compile and run your challenge to try it in \
                     challenge-kit's window",
                )
                .clicked()
            {
                view.after_save = Some(AfterSave::Build);
                view.save_result = None;
            }
            if ready == Some(AfterSave::Build)
                && let Some(dir) = view.project_dir.clone()
            {
                let task = orress_editor::Task {
                    label: "cargo run".into(),
                    steps: vec![orress_editor::Command {
                        program: "cargo".into(),
                        args: vec!["run".into()],
                        cwd: dir,
                    }],
                };
                let ctx = ui.ctx().clone();
                run_console.run(task, Arc::new(move || ctx.request_repaint()));
                view.set_status("Building — see the Output panel.");
            }

            ui.add_space(6.0);
            ui.separator();

            // 3. Submit.
            ui.heading("3 · Submit for review");
            egui::Grid::new("cw_submit")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Site URL");
                    ui.text_edit_singleline(&mut view.site_url);
                    ui.end_row();
                    ui.label("Username");
                    ui.text_edit_singleline(&mut view.username);
                    ui.end_row();
                    ui.label("Password");
                    ui.add(egui::TextEdit::singleline(&mut view.password).password(true));
                    ui.end_row();
                });
            let busy = view.busy.load(Ordering::Relaxed);
            let can_submit = !busy
                && view.main_rs.is_some()
                && !view.username.is_empty()
                && view.after_save.is_none();
            if ui
                .add_enabled(can_submit, egui::Button::new("Submit to CTF site"))
                .on_hover_text("Save main.rs, log in and send the source + metadata for review")
                .clicked()
            {
                view.after_save = Some(AfterSave::Submit);
                view.save_result = None;
            }
            if ready == Some(AfterSave::Submit) {
                view.sync_hints();
                match view.main_rs.as_ref().map(std::fs::read_to_string) {
                    Some(Ok(source)) => {
                        let base = view.site_url.clone();
                        let user = view.username.clone();
                        let pass = view.password.clone();
                        let meta = view.meta.clone();
                        let status = Arc::clone(&view.status);
                        let busy_flag = Arc::clone(&view.busy);
                        busy_flag.store(true, Ordering::Relaxed);
                        view.set_status("Submitting…");
                        let ctx = ui.ctx().clone();
                        std::thread::spawn(move || {
                            let result = orress_challenge::submit(&base, &user, &pass, &meta, &source);
                            if let Ok(mut g) = status.lock() {
                                *g = match result {
                                    Ok(m) => m,
                                    Err(e) => format!("Error: {e}"),
                                };
                            }
                            busy_flag.store(false, Ordering::Relaxed);
                            ctx.request_repaint();
                        });
                    }
                    Some(Err(e)) => view.set_status(format!("Could not read main.rs (save it first?): {e}")),
                    None => view.set_status("Scaffold the challenge first."),
                }
            }
            if busy {
                ui.ctx().request_repaint();
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("working…");
                });
            }

            let status = view.status.lock().map(|g| g.clone()).unwrap_or_default();
            if !status.is_empty() {
                ui.add_space(4.0);
                ui.separator();
                ui.label(&status);
            }
        });
}
