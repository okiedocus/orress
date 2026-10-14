use std::path::PathBuf;

use egui::{Context, RichText, Ui};
use orress_actions::{ActionId, ActionRegistry, KeyContext, Keymap};
use orress_project::DocStore;
use orress_settings::{Paths, Settings};
use orress_theme::Theme;
use orress_ui::{CommandPalette, ExplainExt as _, PaletteItem, explain, kbd};
use orress_views::{DocView, ViewCommand, ViewRequest};
use orress_workspace::{Slot, TabEnv, TabKind, Workspace};

use crate::actions;

const WORKSPACE_KEY: &str = "orress.workspace";
const TOAST_SECONDS: f64 = 6.0;

struct Toast {
    text: String,
    error: bool,
    created: f64,
}

pub struct OrressApp {
    paths: Option<Paths>,
    settings: Settings,
    themes: Vec<Theme>,
    registry: ActionRegistry,
    keymap: Keymap,
    palette: CommandPalette,
    workspace: Workspace,
    docs: DocStore,
    academy: orress_academy::Academy,
    workbench: orress_views::Workbench,
    debugger: orress_views::DebugSession,
    run_console: orress_views::RunConsole,
    lsp: orress_lsp::LspManager,
    terminal: orress_views::TerminalSession,
    source_dbg: orress_views::SourceDebug,
    emulator: orress_views::EmulatorView,
    shellcode: orress_views::ShellcodeView,
    triage: orress_views::TriageView,
    yara: orress_views::YaraView,
    wasm: orress_views::WasmView,
    pyc: orress_views::PycView,
    java: orress_views::JavaView,
    archive: orress_views::ArchiveView,
    js: orress_views::JsView,
    dotnet: orress_views::DotNetView,
    assistant: orress_views::AssistantView,
    sandbox: orress_views::SandboxView,
    collab: orress_views::CollabView,
    diff: orress_views::DiffView,
    script: orress_views::ScriptView,
    challenge: orress_views::ChallengeWorkbenchView,
    /// The startup splash, shown for a moment then dropped.
    splash: Option<crate::splash::Splash>,
    toasts: Vec<Toast>,
    last_text_focus: Option<egui::Id>,
    /// The focused text field's selection, saved each frame so a menu click (which
    /// drops focus and clears the selection) can restore it before an edit event fires.
    last_text_cursor: Option<egui::text_selection::CCursorRange>,
    pending_edit: Option<egui::Event>,
    /// A save requested from the File menu, handed to the focused editor on the next frame.
    editor_save_request: Option<orress_views::SaveRequest>,
    /// Problems found during startup, shown as toasts on the first frame.
    startup_messages: Vec<(String, bool)>,
    show_about: bool,
    /// "Quit with unsaved changes?" is showing.
    quit_prompt: bool,
    /// The user confirmed quitting, so a window close request is let through.
    allow_close: bool,
    /// Last applied theme and zoom, so they are only pushed to egui when they change.
    applied: Option<(String, f32)>,
}

impl OrressApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut startup_messages = Vec::new();
        let paths = Paths::from_platform();

        let settings = match &paths {
            Some(paths) => {
                let (settings, err) = Settings::load(&paths.settings_file());
                if let Some(err) = err {
                    startup_messages.push((
                        format!("Settings not loaded, using defaults: {err:#}"),
                        true,
                    ));
                }
                settings
            }
            None => Settings::default(),
        };

        let mut themes = Theme::built_in();
        // Adapters contributed by installed extensions, registered into the LSP manager below.
        let mut ext_adapters: Vec<orress_lsp::LspAdapter> = Vec::new();
        // Grammar highlight queries extensions ship, handed to the editor below.
        let mut grammar_queries: Vec<orress_ext::GrammarQuery> = Vec::new();
        if let Some(paths) = &paths {
            load_user_themes(&paths.themes_dir(), &mut themes, &mut startup_messages);
            load_extensions(
                &paths.extensions_dir(),
                &mut themes,
                &mut ext_adapters,
                &mut grammar_queries,
                &mut startup_messages,
            );
        }
        orress_views::set_grammar_queries(&cc.egui_ctx, &grammar_queries);

        let mut keymap = actions::default_keymap();
        if let Some(paths) = &paths
            && let Ok(json) = std::fs::read_to_string(paths.keymap_file())
        {
            match Keymap::from_json(&json) {
                Ok(user) => keymap.merge(&user),
                Err(e) => startup_messages.push((format!("keymap.json ignored: {e}"), true)),
            }
        }

        let mut workspace = cc
            .storage
            .and_then(|s| eframe::get_value::<Workspace>(s, WORKSPACE_KEY))
            .unwrap_or_default();
        // The bottom panel (Output / Terminal / Problems) is up by default.
        workspace.bottom_open = true;
        // Open files are deliberately not persisted: every launch starts clean (the Welcome
        // screen, no documents), so a restored layout never reloads the previous session's
        // binaries. Files passed on the command line are opened below, after this.
        workspace.forget_open_files();

        // `orress file1 file2` opens those files.
        let cli_files: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();

        // Our own zoom actions replace egui's built-in ones, so they show in the palette.
        cc.egui_ctx.options_mut(|o| o.zoom_with_keyboard = false);

        let repaint = cc.egui_ctx.clone();
        let academy = orress_academy::Academy::new(paths.as_ref().map(|p| p.config_dir.as_path()));
        // The LSP manager ships built-in adapters (rust-analyzer, pyright, clangd); imported
        // adapter manifests in the `lsp/` config directory add or override servers per language.
        let mut lsp = orress_lsp::LspManager::new({
            let ctx = cc.egui_ctx.clone();
            std::sync::Arc::new(move || ctx.request_repaint())
        });
        if let Some(paths) = &paths {
            let (adapters, errors) = orress_lsp::load_adapters(&paths.lsp_dir());
            lsp.add_adapters(adapters);
            startup_messages.extend(errors.into_iter().map(|e| (e, true)));
        }
        // Language-server adapters contributed by extensions (collected above).
        lsp.add_adapters(ext_adapters);
        let mut app = Self {
            academy,
            workbench: orress_views::Workbench::default(),
            debugger: orress_views::DebugSession::default(),
            run_console: orress_views::RunConsole::default(),
            lsp,
            terminal: orress_views::TerminalSession::default(),
            source_dbg: orress_views::SourceDebug::default(),
            emulator: orress_views::EmulatorView::default(),
            shellcode: orress_views::ShellcodeView::default(),
            triage: orress_views::TriageView::default(),
            yara: orress_views::YaraView::default(),
            wasm: orress_views::WasmView::default(),
            pyc: orress_views::PycView::default(),
            java: orress_views::JavaView::default(),
            archive: orress_views::ArchiveView::default(),
            js: orress_views::JsView::default(),
            dotnet: orress_views::DotNetView::default(),
            assistant: orress_views::AssistantView::default(),
            sandbox: orress_views::SandboxView::default(),
            collab: orress_views::CollabView::default(),
            diff: orress_views::DiffView::default(),
            script: orress_views::ScriptView::default(),
            challenge: orress_views::ChallengeWorkbenchView::default(),
            splash: Some(crate::splash::Splash::new(&cc.egui_ctx)),
            docs: DocStore::new(
                move || repaint.request_repaint(),
                paths.as_ref().map(Paths::projects_dir),
            ),
            registry: actions::registry(&themes),
            paths,
            settings,
            themes,
            keymap,
            palette: CommandPalette::default(),
            workspace,
            toasts: Vec::new(),
            last_text_focus: None,
            last_text_cursor: None,
            pending_edit: None,
            editor_save_request: None,
            startup_messages,
            show_about: false,
            quit_prompt: false,
            allow_close: false,
            applied: None,
        };
        if let Some(paths) = &app.paths {
            orress_views::set_extensions_dir(&cc.egui_ctx, paths.extensions_dir());
        }
        // Expose the user's LSP settings to Zed language extensions (honoured when one resolves a
        // server command). Zed-shaped, so an extension's `get-settings` reads them directly.
        orress_views::set_lsp_settings(&cc.egui_ctx, app.settings.zed_extension_settings());
        // The same `lsp.<server>` settings configure ORRESS's own client for every server
        // (built-in adapters included): binary override, env, init options, configuration.
        match serde_json::to_value(&app.settings.lsp) {
            Ok(lsp) => app.lsp.set_server_settings(&lsp),
            Err(e) => app.notify(&cc.egui_ctx, format!("LSP settings ignored: {e}"), true),
        }
        // Decode the logo once and stash the texture in egui memory, so the Welcome and About
        // screens can show it (the way Visual Studio and Zed show their logo). Use the full-res
        // master so the wordmark and tagline stay crisp and readable when shown large.
        if let Ok(icon) =
            eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/logo-full.png"))
        {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            let tex = cc
                .egui_ctx
                .load_texture("orress-logo", image, egui::TextureOptions::LINEAR);
            cc.egui_ctx
                .data_mut(|d| d.insert_temp(egui::Id::new("orress::logo"), tex));
        }
        for file in cli_files {
            app.open_file(file);
        }
        app
    }

    /// Installs an extension from a git URL or a local directory path, then re-registers themes
    /// and language servers so the change takes effect without a restart.
    fn install_extension(&mut self, ctx: &Context, source: &str) {
        let Some(dir) = self.paths.as_ref().map(|p| p.extensions_dir()) else {
            self.notify(ctx, "No config directory for extensions", true);
            return;
        };
        let is_git = source.contains("://") || source.starts_with("git@");
        let result = if is_git {
            orress_ext::install_git(source, &dir)
        } else {
            orress_ext::install_local(std::path::Path::new(source), &dir)
        };
        match result {
            Ok(id) => {
                self.reload_extensions(ctx);
                self.notify(ctx, format!("Installed extension `{id}`"), false);
            }
            Err(e) => self.notify(ctx, format!("Install failed: {e}"), true),
        }
    }

    fn uninstall_extension(&mut self, ctx: &Context, id: &str) {
        let Some(dir) = self.paths.as_ref().map(|p| p.extensions_dir()) else {
            return;
        };
        match orress_ext::uninstall(&dir, id) {
            Ok(()) => {
                self.reload_extensions(ctx);
                self.notify(ctx, format!("Uninstalled `{id}`"), false);
            }
            Err(e) => self.notify(ctx, format!("Uninstall failed: {e}"), true),
        }
    }

    /// Rebuilds the theme list and language-server adapters from the built-ins, the user config
    /// directories and the installed extensions — so an install/uninstall applies live.
    fn reload_extensions(&mut self, ctx: &Context) {
        let Some(paths) = self.paths.clone() else {
            return;
        };
        let mut themes = Theme::built_in();
        let mut messages = Vec::new();
        load_user_themes(&paths.themes_dir(), &mut themes, &mut messages);
        let mut ext_adapters = Vec::new();
        let mut grammar_queries = Vec::new();
        load_extensions(
            &paths.extensions_dir(),
            &mut themes,
            &mut ext_adapters,
            &mut grammar_queries,
            &mut messages,
        );
        orress_views::set_grammar_queries(ctx, &grammar_queries);
        self.themes = themes;
        let (user_adapters, errors) = orress_lsp::load_adapters(&paths.lsp_dir());
        let mut adapters = user_adapters;
        adapters.extend(ext_adapters);
        self.lsp.reset_adapters(adapters);
        // The Extensions panel re-reads the installed list.
        orress_views::refresh_extensions(ctx);
        // A theme may have changed or disappeared; force the theme to re-apply next frame.
        self.applied = None;
        for e in errors {
            messages.push((e, true));
        }
        for (m, err) in messages {
            self.notify(ctx, m, err);
        }
    }

    fn notify(&mut self, ctx: &Context, text: impl Into<String>, error: bool) {
        let text = text.into();
        if error {
            tracing::warn!("{text}");
        }
        self.toasts.push(Toast {
            text,
            error,
            created: ctx.input(|i| i.time),
        });
    }

    fn current_theme(&self) -> &Theme {
        self.themes
            .iter()
            .find(|t| t.name == self.settings.theme)
            .unwrap_or(&self.themes[0])
    }

    fn apply_look(&mut self, ctx: &Context) {
        let wanted = (self.settings.theme.clone(), self.settings.ui_scale);
        if self.applied.as_ref() != Some(&wanted) {
            self.current_theme().apply(ctx);
            orress_views::set_syntax(ctx, self.current_theme().syntax.clone());
            ctx.set_zoom_factor(self.settings.ui_scale);
            self.applied = Some(wanted);
        }
        explain::set_explain_mode(ctx, self.settings.explain_mode);
    }

    fn open_file(&mut self, path: PathBuf) {
        self.settings.push_recent(path.clone());
        if opens_in_editor(&path) {
            self.workspace.open(TabKind::Editor {
                path: Some(path),
                state: Box::default(),
            });
            return;
        }
        self.docs.open(&path);
        self.docs.active = Some(path.clone());
        // Hex first, then the overview, so "What is this file?" is what you see.
        self.workspace.open_doc(&path, DocView::Hex);
        self.workspace.open_doc(&path, DocView::Info);
        self.academy
            .handle(&orress_academy::Event::FileOpened(path));
    }

    /// Facts the Academy's lesson checks look at.
    fn academy_poll(&mut self) -> orress_academy::PollState {
        let focused_view = self
            .workspace
            .focused_doc()
            .or_else(|| self.workspace.center_doc())
            .map(|(_, view)| view.name().to_owned());
        let mut state = orress_academy::PollState {
            focused_view,
            ..Default::default()
        };
        if let Some(doc) = self.docs.active() {
            state.renamed = !doc.annotations.names.is_empty();
            state.commented = !doc.annotations.comments.is_empty();
            if let Some(p) = doc.program()
                && let Some(main) = p.main
                && let Some(va) = doc.cursor_address()
            {
                state.cursor_in_main = p.function_containing(va).is_some_and(|f| f.entry == main);
            }
        }
        state
    }

    fn academy_requests(&mut self, ctx: &Context) {
        for request in self.academy.take_requests() {
            match request {
                orress_academy::Request::OpenFile(path) => self.open_file(path),
                orress_academy::Request::OpenSimulator => self.workspace.open(TabKind::Simulator),
                orress_academy::Request::OpenLesson => self.workspace.open(TabKind::Lesson),
                orress_academy::Request::Message(text) => self.notify(ctx, text, true),
            }
        }
    }

    /// Sends a command to the focused view if it handles it, otherwise to the hex view of
    /// the current file (opening it if needed).
    fn hex_command(&mut self, ctx: &Context, command: ViewCommand) {
        let focused = self.workspace.focused_doc().map(|(_, view)| view);
        let handles = match focused {
            Some(DocView::Hex) => true,
            Some(DocView::Disassembly) => command == ViewCommand::GoTo,
            _ => false,
        };
        if handles {
            self.workspace.send(command);
        } else if let Some(path) = self.docs.active.clone() {
            self.workspace.open_doc(&path, DocView::Hex);
            self.workspace.send(command);
        } else {
            self.notify(ctx, "Open a file first (Ctrl+O).", false);
        }
    }

    /// Opens another view of the current file.
    fn doc_view(&mut self, ctx: &Context, view: DocView) {
        match self.docs.active.clone() {
            Some(path) => self.workspace.open_doc(&path, view),
            None => self.notify(ctx, "Open a file first (Ctrl+O).", false),
        }
    }

    /// Quits, unless editors have unsaved changes: then asks first.
    fn request_quit(&mut self, ctx: &Context) {
        if self.workspace.dirty_editors().is_empty() {
            self.allow_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else {
            self.quit_prompt = true;
        }
    }

    /// F5 / F10 / F11 / Shift+F5: drive whichever debugger is running — the source debugger
    /// first (when a session is live), else the machine-code one.
    fn debug_command(&mut self, ctx: &Context, action: orress_views::DebugAction) {
        if !self.source_dbg.command(action) && !self.debugger.command(action) {
            self.notify(
                ctx,
                "Nothing to do: no program is stopped (or running) under a debugger.",
                false,
            );
        }
    }

    /// The "save changes?" dialogs: closing an editor tab with unsaved changes, and quitting
    /// with any. Returns whether one is showing (so shortcuts are not dispatched under it).
    fn unsaved_dialogs(&mut self, ctx: &Context) -> bool {
        if let Some((id, title)) = self.workspace.close_prompt() {
            let mut choice = None;
            let modal = egui::Modal::new(egui::Id::new("orress::close_prompt")).show(ctx, |ui| {
                ui.set_max_width(380.0);
                ui.heading("Save changes?");
                ui.label(format!(
                    "{} has changes that are not saved. They are lost if you close it without \
                     saving.",
                    title.trim_end_matches(" *")
                ));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        choice = Some(orress_workspace::CloseChoice::Save);
                    }
                    if ui.button("Don't Save").clicked() {
                        choice = Some(orress_workspace::CloseChoice::Discard);
                    }
                    if ui.button("Cancel").clicked() {
                        choice = Some(orress_workspace::CloseChoice::Cancel);
                    }
                });
            });
            if modal.should_close() && choice.is_none() {
                choice = Some(orress_workspace::CloseChoice::Cancel);
            }
            if let Some(choice) = choice
                && let Some(err) = self.workspace.resolve_close(id, choice)
            {
                self.notify(ctx, format!("Not closed: {err}"), true);
            }
            return true;
        }
        if !self.quit_prompt {
            return false;
        }
        let dirty = self.workspace.dirty_editors();
        if dirty.is_empty() {
            // Saved elsewhere meanwhile (or closed): nothing to ask any more.
            self.quit_prompt = false;
            return false;
        }
        let mut save_all = false;
        let mut quit = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::new("orress::quit_prompt")).show(ctx, |ui| {
            ui.set_max_width(400.0);
            ui.heading("Quit with unsaved changes?");
            ui.label("These files have changes that are not saved:");
            for title in &dirty {
                ui.label(RichText::new(format!("  • {}", title.trim_end_matches(" *"))).strong());
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                save_all = ui.button("Save All and Quit").clicked();
                quit = ui.button("Quit Without Saving").clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if cancel || (modal.should_close() && !save_all && !quit) {
            self.quit_prompt = false;
        } else if quit {
            self.quit_prompt = false;
            self.allow_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if save_all {
            self.quit_prompt = false;
            match self.workspace.save_all_editors() {
                Ok(true) => {
                    self.allow_close = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Ok(false) => {} // a Save dialog was cancelled: stay
                Err(e) => self.notify(ctx, format!("Not quitting: {e}"), true),
            }
        }
        true
    }

    fn zoom(&mut self, delta: f32) {
        self.settings.ui_scale = ((self.settings.ui_scale + delta) * 10.0).round() / 10.0;
        self.settings.ui_scale = self
            .settings
            .ui_scale
            .clamp(Settings::MIN_SCALE, Settings::MAX_SCALE);
    }

    fn run(&mut self, ctx: &Context, action: &ActionId) {
        tracing::debug!("action {action}");
        self.academy
            .handle(&orress_academy::Event::Action(action.as_str().to_owned()));
        match action.as_str() {
            "command_palette::Toggle" => self.palette.toggle(),
            "workspace::Open" => {
                if let Some(files) = rfd::FileDialog::new()
                    .set_title("Open a file to analyze")
                    .pick_files()
                {
                    for file in files {
                        self.open_file(file);
                    }
                }
            }
            "file::NewFile" => self.workspace.open(TabKind::Editor {
                path: None,
                state: Box::default(),
            }),
            "file::OpenSource" => {
                if let Some(file) = rfd::FileDialog::new()
                    .set_title("Open a text/source file")
                    .pick_file()
                {
                    self.workspace.open(TabKind::Editor {
                        path: Some(file),
                        state: Box::default(),
                    });
                }
            }
            "file::Save" => self.editor_save_request = Some(orress_views::SaveRequest::Save),
            "file::SaveAs" => self.editor_save_request = Some(orress_views::SaveRequest::SaveAs),
            "workspace::NewNotes" => self.workspace.open(TabKind::Notes {
                text: String::new(),
            }),
            "workspace::CloseActiveTab" => self.workspace.close_active_tab(),
            "workspace::SplitRight" => self.workspace.split_right(),
            "workspace::ToggleLeftDock" => self.workspace.toggle(Slot::Left),
            "workspace::ToggleRightDock" => self.workspace.toggle(Slot::Right),
            "workspace::ToggleBottomDock" => self.workspace.toggle(Slot::Bottom),
            "workspace::ResetLayout" => self.workspace.reset_layout(),
            "view::ToggleExplainMode" => {
                self.settings.explain_mode = !self.settings.explain_mode;
                let state = if self.settings.explain_mode {
                    "on"
                } else {
                    "off"
                };
                self.notify(ctx, format!("Explain Mode is {state}."), false);
            }
            "view::ZoomIn" => self.zoom(0.1),
            "view::ZoomOut" => self.zoom(-0.1),
            "view::ZoomReset" => self.settings.ui_scale = 1.0,
            "file::Info" => self.doc_view(ctx, DocView::Info),
            "file::Hex" => self.doc_view(ctx, DocView::Hex),
            "file::Sections" => self.doc_view(ctx, DocView::Sections),
            "file::Imports" => self.doc_view(ctx, DocView::Imports),
            "file::Strings" => self.doc_view(ctx, DocView::Strings),
            "file::Functions" => self.doc_view(ctx, DocView::Functions),
            "view::Xrefs" => self.workspace.open(TabKind::Xrefs),
            "nav::Back" => {
                if let Some(doc) = self.docs.active_mut() {
                    doc.go_back();
                }
            }
            "nav::Forward" => {
                if let Some(doc) = self.docs.active_mut() {
                    doc.go_forward();
                }
            }
            "nav::GoToMain" => {
                let main = self
                    .docs
                    .active()
                    .and_then(|d| d.program())
                    .and_then(|p| p.main);
                match (main, self.docs.active.clone()) {
                    (Some(main), Some(path)) => {
                        if let Some(doc) = self.docs.active_mut() {
                            doc.navigate_to_address(main);
                        }
                        self.workspace.open_doc(&path, DocView::Disassembly);
                    }
                    _ => self.notify(
                        ctx,
                        "No main function found (yet) in the current file.",
                        false,
                    ),
                }
            }
            "hex::GoTo" => self.hex_command(ctx, ViewCommand::GoTo),
            "hex::Find" => self.hex_command(ctx, ViewCommand::Find),
            "hex::FindNext" => self.hex_command(ctx, ViewCommand::FindNext),
            "hex::FindPrevious" => self.hex_command(ctx, ViewCommand::FindPrevious),
            "hex::CopyHex" => self.hex_command(ctx, ViewCommand::CopyHex),
            "hex::CopyCArray" => self.hex_command(ctx, ViewCommand::CopyCArray),
            "hex::CopyPython" => self.hex_command(ctx, ViewCommand::CopyPython),
            "view::Disassembly" => self.doc_view(ctx, DocView::Disassembly),
            "view::Graph" => self.doc_view(ctx, DocView::Graph),
            "view::Decompiler" => self.workspace.open(TabKind::Decompiler),
            "view::Debugger" => self.workspace.open(TabKind::Debugger),
            "view::Emulator" => self.workspace.open(TabKind::Emulator),
            "view::Shellcode" => self.workspace.open(TabKind::Shellcode),
            "view::Triage" => self.workspace.open(TabKind::Triage),
            "view::Yara" => self.workspace.open(TabKind::Yara),
            "view::Wasm" => self.workspace.open(TabKind::Wasm),
            "view::Pyc" => self.workspace.open(TabKind::Pyc),
            "view::Java" => self.workspace.open(TabKind::Java),
            "view::Archive" => self.workspace.open(TabKind::Archive),
            "view::Js" => self.workspace.open(TabKind::Js),
            "view::DotNet" => self.workspace.open(TabKind::DotNet),
            "view::Assistant" => self.workspace.open(TabKind::Assistant),
            "view::Sandbox" => self.workspace.open(TabKind::Sandbox),
            "view::Project" => self.workspace.open(TabKind::ProjectTree),
            "view::Explain" => self.workspace.open(TabKind::Explain),
            "view::Inspector" => self.workspace.open(TabKind::Inspector),
            "view::Extensions" => self.workspace.open(TabKind::Extensions),
            "view::Collaboration" => self.workspace.open(TabKind::Collaboration),
            "view::Diff" => self.workspace.open(TabKind::Diff),
            "view::Script" => self.workspace.open(TabKind::Script),
            "view::Terminal" => self.workspace.open(TabKind::Terminal),
            "theme::Next" => {
                let index = self
                    .themes
                    .iter()
                    .position(|t| t.name == self.settings.theme)
                    .map_or(0, |i| (i + 1) % self.themes.len());
                self.settings.theme = self.themes[index].name.clone();
            }
            "academy::Open" => self.workspace.open(TabKind::Academy),
            "workbench::Open" => self.workspace.open(TabKind::Workbench),
            "challenge::OpenWorkbench" => self.workspace.open(TabKind::ChallengeWorkbench),
            "hex::SendToWorkbench" => {
                let selected = self.docs.active().and_then(|doc| {
                    let (a, b) = doc.selection.unwrap_or((doc.cursor, doc.cursor + 1));
                    let bytes = doc.bytes()?.get(a as usize..b as usize)?.to_vec();
                    Some((bytes, doc.path.clone(), a, b))
                });
                match selected {
                    Some((bytes, path, a, b)) => {
                        self.workbench.set_input(bytes, Some((path, a, b)));
                        self.workspace.open(TabKind::Workbench);
                    }
                    None => self.notify(ctx, "Select some bytes in the hex view first.", false),
                }
            }
            "patch::Export" => match self.docs.active() {
                Some(doc) if !doc.annotations.patches.is_empty() => {
                    let message = orress_views::save_patched(doc);
                    self.notify(ctx, message, false);
                }
                Some(_) => self.notify(ctx, "This file has no patches yet.", false),
                None => self.notify(ctx, "Open a file first (Ctrl+O).", false),
            },
            "patch::RevertAll" => {
                if let Some(doc) = self.docs.active_mut() {
                    doc.revert_patches();
                }
            }
            "academy::OpenSimulator" => self.workspace.open(TabKind::Simulator),
            "academy::Lesson" => {
                if self.academy.active.is_none()
                    && let Some(next) = self.academy.next_lesson()
                {
                    self.academy.start(next);
                }
                self.workspace.open(TabKind::Lesson);
            }
            "help::Welcome" => self.workspace.open(TabKind::Welcome),
            "help::Keybindings" => self.workspace.open(TabKind::Keybindings),
            "help::OpenConfigFolder" => self.open_config_folder(ctx),
            "help::About" => self.show_about = true,
            "app::Quit" => self.request_quit(ctx),
            "debug::Continue" => self.debug_command(ctx, orress_views::DebugAction::Continue),
            "debug::StepOver" => self.debug_command(ctx, orress_views::DebugAction::StepOver),
            "debug::StepInto" => self.debug_command(ctx, orress_views::DebugAction::StepInto),
            "debug::StepOut" => self.debug_command(ctx, orress_views::DebugAction::StepOut),
            "debug::Pause" => self.debug_command(ctx, orress_views::DebugAction::Pause),
            "debug::Stop" => self.debug_command(ctx, orress_views::DebugAction::Stop),
            other => {
                if let Some(name) = actions::theme_from_action(other) {
                    self.settings.theme = name.to_owned();
                } else {
                    self.notify(ctx, format!("Unknown action `{other}`"), true);
                }
            }
        }
    }

    fn open_config_folder(&mut self, ctx: &Context) {
        let Some(paths) = &self.paths else {
            self.notify(ctx, "No config folder on this system.", true);
            return;
        };
        let dir = paths.config_dir.clone();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.notify(
                ctx,
                format!("Could not create {}: {e}", dir.display()),
                true,
            );
            return;
        }
        let program = if cfg!(windows) {
            "explorer"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        if let Err(e) = std::process::Command::new(program).arg(&dir).spawn() {
            self.notify(ctx, format!("Could not open {}: {e}", dir.display()), true);
        }
    }

    fn palette_items(&self, ctx: &Context, context: KeyContext) -> Vec<PaletteItem> {
        self.registry
            .iter()
            .filter(|a| a.id.as_str() != "command_palette::Toggle")
            .map(|a| PaletteItem {
                action: a.id.clone(),
                title: a.title.clone(),
                category: a.id.namespace().replace('_', " "),
                shortcut: self
                    .keymap
                    .keystroke_for(&a.id, context)
                    .map(|k| k.label(ctx)),
                explain: a.explain.clone(),
            })
            .collect()
    }

    /// A menu entry for an action, with its shortcut and explanation. A shortcut that only works
    /// in one place (e.g. the hex view) is shown with that place.
    fn menu_entry(&self, ui: &mut Ui, id: &str, clicked: &mut Vec<ActionId>) {
        let id = ActionId::from(id);
        let Some(action) = self.registry.get(&id) else {
            return;
        };
        let shortcut = self
            .keymap
            .keystroke_anywhere(&id, KeyContext::Workspace)
            .map(|(k, ctx)| match ctx {
                KeyContext::Global | KeyContext::Workspace => k.label(ui.ctx()),
                other => format!("{} ({other:?})", k.label(ui.ctx())),
            })
            .unwrap_or_default();
        if ui
            .add(egui::Button::new(action.title.as_str()).shortcut_text(shortcut))
            .explain(&action.title, &action.explain)
            .clicked()
        {
            clicked.push(id);
            ui.close();
        }
    }

    fn menu_bar(&mut self, ui: &mut Ui) -> Vec<ActionId> {
        let mut clicked = Vec::new();
        let mut open_recent = None;
        let mut edit_event: Option<egui::Event> = None;
        // Save / Save As act on the focused code editor, so enable them only for an editor tab.
        let editor_active = self.workspace.active_is_editor();
        // The widget focused before the menu was opened — editing commands re-focus it so
        // the injected events reach it (clicking a menu moves keyboard focus away).
        let prev_focus = self.last_text_focus;
        egui::Panel::top("orress::menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    self.menu_entry(ui, "workspace::Open", &mut clicked);
                    ui.menu_button("Open Recent", |ui| {
                        if self.settings.recent_files.is_empty() {
                            ui.label(RichText::new("No recent files").weak());
                        }
                        for path in &self.settings.recent_files {
                            if ui.button(path.display().to_string()).clicked() {
                                open_recent = Some(path.clone());
                                ui.close();
                            }
                        }
                    });
                    self.menu_entry(ui, "file::NewFile", &mut clicked);
                    self.menu_entry(ui, "file::OpenSource", &mut clicked);
                    self.menu_entry(ui, "workspace::NewNotes", &mut clicked);
                    ui.separator();
                    ui.add_enabled_ui(editor_active, |ui| {
                        self.menu_entry(ui, "file::Save", &mut clicked);
                        self.menu_entry(ui, "file::SaveAs", &mut clicked);
                    });
                    ui.separator();
                    self.menu_entry(ui, "patch::Export", &mut clicked);
                    self.menu_entry(ui, "patch::RevertAll", &mut clicked);
                    ui.separator();
                    self.menu_entry(ui, "workspace::CloseActiveTab", &mut clicked);
                    self.menu_entry(ui, "app::Quit", &mut clicked);
                });
                ui.menu_button("Edit", |ui| {
                    // Clicking a menu clears the text field's focus/selection, so we can't
                    // act this frame. Instead refocus the field now and queue the event to
                    // inject next frame, once it is focused again.
                    if edit_item(ui, "Undo", "Ctrl+Z") {
                        edit_event = Some(key_event(egui::Key::Z, egui::Modifiers::COMMAND));
                        ui.close();
                    }
                    if edit_item(ui, "Redo", "Ctrl+Shift+Z") {
                        edit_event = Some(key_event(
                            egui::Key::Z,
                            egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
                        ));
                        ui.close();
                    }
                    ui.separator();
                    if edit_item(ui, "Cut", "Ctrl+X") {
                        edit_event = Some(egui::Event::Cut);
                        ui.close();
                    }
                    if edit_item(ui, "Copy", "Ctrl+C") {
                        edit_event = Some(egui::Event::Copy);
                        ui.close();
                    }
                    if edit_item(ui, "Paste", "Ctrl+V") {
                        edit_event = read_clipboard().map(egui::Event::Paste);
                        ui.close();
                    }
                    ui.separator();
                    if edit_item(ui, "Select All", "Ctrl+A") {
                        edit_event = Some(key_event(egui::Key::A, egui::Modifiers::COMMAND));
                        ui.close();
                    }
                });
                ui.menu_button("View", |ui| {
                    self.menu_entry(ui, "command_palette::Toggle", &mut clicked);
                    ui.separator();
                    self.menu_entry(ui, "workspace::ToggleLeftDock", &mut clicked);
                    self.menu_entry(ui, "workspace::ToggleRightDock", &mut clicked);
                    self.menu_entry(ui, "workspace::ToggleBottomDock", &mut clicked);
                    self.menu_entry(ui, "workspace::SplitRight", &mut clicked);
                    self.menu_entry(ui, "workspace::ResetLayout", &mut clicked);
                    ui.separator();
                    ui.menu_button("This File", |ui| {
                        for id in [
                            "file::Info",
                            "file::Hex",
                            "file::Sections",
                            "file::Imports",
                            "file::Strings",
                            "file::Functions",
                            "view::Xrefs",
                        ] {
                            self.menu_entry(ui, id, &mut clicked);
                        }
                    });
                    ui.menu_button("Open View", |ui| {
                        for id in [
                            "view::Disassembly",
                            "view::Graph",
                            "view::Decompiler",
                            "view::Debugger",
                            "view::Emulator",
                            "view::Shellcode",
                            "view::Triage",
                            "view::Yara",
                            "view::Wasm",
                            "view::Pyc",
                            "view::Java",
                            "view::Archive",
                            "view::Js",
                            "view::DotNet",
                            "view::Assistant",
                            "view::Sandbox",
                            "view::Project",
                            "view::Explain",
                            "view::Inspector",
                            "view::Extensions",
                            "view::Collaboration",
                            "view::Diff",
                            "view::Script",
                            "view::Terminal",
                        ] {
                            self.menu_entry(ui, id, &mut clicked);
                        }
                    });
                    ui.menu_button("Theme", |ui| {
                        for theme in &self.themes {
                            let selected = theme.name == self.settings.theme;
                            if ui.radio(selected, theme.name.as_str()).clicked() {
                                clicked.push(ActionId::new(actions::theme_action(&theme.name)));
                                ui.close();
                            }
                        }
                    });
                    self.menu_entry(ui, "view::ToggleExplainMode", &mut clicked);
                    self.menu_entry(ui, "view::ZoomIn", &mut clicked);
                    self.menu_entry(ui, "view::ZoomOut", &mut clicked);
                    self.menu_entry(ui, "view::ZoomReset", &mut clicked);
                });
                ui.menu_button("Go", |ui| {
                    self.menu_entry(ui, "nav::Back", &mut clicked);
                    self.menu_entry(ui, "nav::Forward", &mut clicked);
                    self.menu_entry(ui, "nav::GoToMain", &mut clicked);
                    ui.separator();
                    self.menu_entry(ui, "hex::GoTo", &mut clicked);
                    self.menu_entry(ui, "hex::Find", &mut clicked);
                    self.menu_entry(ui, "hex::FindNext", &mut clicked);
                    self.menu_entry(ui, "hex::FindPrevious", &mut clicked);
                });
                ui.menu_button("Debug", |ui| {
                    for id in [
                        "debug::Continue",
                        "debug::StepOver",
                        "debug::StepInto",
                        "debug::StepOut",
                        "debug::Pause",
                        "debug::Stop",
                    ] {
                        self.menu_entry(ui, id, &mut clicked);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    self.menu_entry(ui, "workbench::Open", &mut clicked);
                    self.menu_entry(ui, "hex::SendToWorkbench", &mut clicked);
                    ui.separator();
                    self.menu_entry(ui, "challenge::OpenWorkbench", &mut clicked);
                });
                ui.menu_button("Learn", |ui| {
                    self.menu_entry(ui, "academy::Open", &mut clicked);
                    self.menu_entry(ui, "academy::Lesson", &mut clicked);
                    self.menu_entry(ui, "academy::OpenSimulator", &mut clicked);
                    ui.separator();
                    self.menu_entry(ui, "help::Keybindings", &mut clicked);
                });
                ui.menu_button("Help", |ui| {
                    self.menu_entry(ui, "help::Welcome", &mut clicked);
                    self.menu_entry(ui, "help::OpenConfigFolder", &mut clicked);
                    self.menu_entry(ui, "help::About", &mut clicked);
                });
            });
        });
        if let Some(path) = open_recent {
            self.open_file(path);
        }
        if let Some(event) = edit_event {
            // Refocus the text field now; the queued event is injected next frame.
            if let Some(id) = prev_focus {
                ui.ctx().memory_mut(|m| m.request_focus(id));
            }
            self.pending_edit = Some(event);
            ui.ctx().request_repaint();
        }
        clicked
    }

    fn status_bar(&mut self, ui: &mut Ui, context: KeyContext) -> Vec<ActionId> {
        let mut clicked = Vec::new();
        let title = self.workspace.active_title();
        egui::Panel::bottom("orress::status").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(title.unwrap_or_else(|| "No tab focused".into()))
                    .explain("Focused tab", "The tab that receives keyboard shortcuts.");
                ui.separator();
                if let Some(doc) = self.docs.active() {
                    ui.separator();
                    let mut text = format!("offset 0x{:X}", doc.cursor);
                    if let Some(a) = doc.analysis() {
                        if let Some(va) = a.info.offset_to_address(doc.cursor) {
                            text += &format!(" · address 0x{va:X}");
                        }
                        if let Some(sec) = a.info.section_at_offset(doc.cursor) {
                            text += &format!(" · {}", sec.name);
                        }
                    }
                    if let Some(p) = doc.program()
                        && let Some(va) = doc.cursor_address()
                        && let Some(f) = p.function_containing(va)
                    {
                        let name = doc
                            .name_of(f.entry)
                            .unwrap_or_else(|| format!("sub_{:x}", f.entry));
                        text += &format!(" · {name}+0x{:x}", va - f.entry);
                    }
                    ui.label(RichText::new(text).monospace()).explain(
                        "Cursor position",
                        "Where the cursor is in the current file: the file offset, the memory \
                         address it maps to when the program runs, and the section it is in.",
                    );
                }
                ui.separator();
                ui.label(RichText::new(format!("{context:?}")).weak())
                    .explain(
                        "Key context",
                        "Which set of keyboard shortcuts is active. The same key can do \
                     different things in the hex view and in the notes editor.",
                    );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(concat!("ORRESS ", env!("CARGO_PKG_VERSION"))).weak());
                    ui.separator();
                    ui.label(format!("{:.0}%", self.settings.ui_scale * 100.0))
                        .explain(
                            "Zoom",
                            "Size of text and controls. Ctrl+= and Ctrl+- change it.",
                        );
                    ui.separator();
                    let label = if self.settings.explain_mode {
                        "Explain: on"
                    } else {
                        "Explain: off"
                    };
                    let toggle = ui
                        .selectable_label(self.settings.explain_mode, label)
                        .explain(
                            "Explain Mode",
                            "Click to turn plain-language tooltips on or off. Hover over \
                             anything to learn what it is.",
                        );
                    orress_ui::spotlight::mark(ui.ctx(), "explain_toggle", toggle.rect);
                    if toggle.clicked() {
                        clicked.push(ActionId::from("view::ToggleExplainMode"));
                    }
                    ui.separator();
                    if let Some(k) = self
                        .keymap
                        .keystroke_for(&"command_palette::Toggle".into(), context)
                    {
                        let response = kbd(ui, &k.label(ui.ctx())).explain(
                            "Command palette",
                            "Press this to search every command. You never need to remember \
                             where a button is.",
                        );
                        orress_ui::spotlight::mark(ui.ctx(), "palette", response.rect);
                        if response.interact(egui::Sense::click()).clicked() {
                            clicked.push(ActionId::from("command_palette::Toggle"));
                        }
                    }
                });
            });
        });
        clicked
    }

    fn about_window(&mut self, ctx: &Context) {
        egui::Window::new("About ORRESS")
            .open(&mut self.show_about)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_min_width(440.0);
                ui.vertical_centered(|ui| {
                    // The logo, large enough that its lettering reads clearly.
                    if let Some(tex) = ui
                        .ctx()
                        .data(|d| d.get_temp::<egui::TextureHandle>(egui::Id::new("orress::logo")))
                    {
                        ui.add_space(6.0);
                        ui.image((tex.id(), egui::vec2(320.0, 320.0)));
                        ui.add_space(6.0);
                    }
                    ui.heading(concat!("ORRESS ", env!("CARGO_PKG_VERSION")));
                    ui.label(
                        RichText::new("Okiedocus Rusty Reverse Engineering Software Suite").weak(),
                    );
                });
                ui.add_space(8.0);
                ui.label("A reverse-engineering IDE for CTF challenges and malware analysis.");
                ui.label("Built with Rust and egui. Workspace design inspired by Zed.");
                ui.label("License: MIT OR Apache-2.0");
                if let Some(paths) = &self.paths {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("Config: {}", paths.config_dir.display())).weak(),
                    );
                }
            });
    }

    fn toasts_ui(&mut self, ctx: &Context) {
        let now = ctx.input(|i| i.time);
        self.toasts.retain(|t| now - t.created < TOAST_SECONDS);
        if self.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        egui::Area::new(egui::Id::new("orress::toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -36.0])
            .order(egui::Order::Tooltip)
            .show(ctx, |ui| {
                for toast in &self.toasts {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.set_max_width(360.0);
                        if toast.error {
                            ui.colored_label(ui.visuals().warn_fg_color, &toast.text);
                        } else {
                            ui.label(&toast.text);
                        }
                    });
                }
            });
    }

    fn drop_overlay(ctx: &Context) {
        if ctx.input(|i| i.raw.hovered_files.is_empty()) {
            return;
        }
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("orress::drop"),
        ));
        let rect = ctx.content_rect();
        painter.rect_filled(rect, 0.0, egui::Color32::from_black_alpha(160));
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Drop to open",
            egui::FontId::proportional(28.0),
            egui::Color32::WHITE,
        );
    }
}

impl eframe::App for OrressApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Startup splash: a full-window overlay for the first moments, then it drops away.
        if let Some(splash) = &mut self.splash {
            if splash.show(&ctx) {
                return;
            }
            self.splash = None;
        }
        // Closing the window with unsaved editor changes asks first (Quit does the same).
        if ctx.input(|i| i.viewport().close_requested())
            && !self.allow_close
            && !self.workspace.dirty_editors().is_empty()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.quit_prompt = true;
        }
        // Drive the live collaboration session each frame; while connected, keep repainting so CRDT
        // sync and presence stay live even without local input.
        if self.collab.tick() {
            ctx.request_repaint();
        }
        // Reconcile the active document with the shared CRDT (annotations flow both ways), broadcast
        // where this user is looking, and jump to a teammate when following them — only for the
        // room's binary (another open file is neither merged nor followed into).
        if self.collab.is_connected()
            && let Some(doc) = self.docs.active_mut()
        {
            if self.collab.bridge(doc) {
                ctx.request_repaint();
            }
            if self.collab.shares(doc) {
                if let Some(addr) = doc.cursor_address() {
                    self.collab.set_local_addr_if_changed(addr);
                }
                if let Some(addr) = self.collab.take_follow_jump() {
                    doc.navigate_to_address(addr);
                    ctx.request_repaint();
                }
            }
        }
        if self.collab.is_connected() || self.collab.is_connecting() {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
        // Adopt a source-debug session that finished starting in the background.
        self.source_dbg.poll();
        // Remember the last focused widget, so the Edit menu can restore it (clicking a
        // menu clears focus from the text field). Keep the old value when focus is None.
        if let Some(id) = ctx.memory(|m| m.focused()) {
            self.last_text_focus = Some(id);
            // Also remember its selection, which a menu click would otherwise clear.
            if let Some(state) = egui::text_edit::TextEditState::load(&ctx, id)
                && let Some(range) = state.cursor.char_range()
            {
                self.last_text_cursor = Some(range);
            }
        }
        // A queued Edit-menu command: the field is focused again now, so inject it.
        if let Some(event) = self.pending_edit.take() {
            if let Some(id) = self.last_text_focus {
                ctx.memory_mut(|m| m.request_focus(id));
                // Restore the selection the menu click cleared, so Copy/Cut have a target.
                if let Some(range) = self.last_text_cursor
                    && let Some(mut state) = egui::text_edit::TextEditState::load(&ctx, id)
                {
                    state.cursor.set_char_range(Some(range));
                    state.store(&ctx, id);
                }
            }
            ctx.input_mut(|i| i.events.push(event));
            ctx.request_repaint();
        }
        orress_ui::spotlight::begin_frame(&ctx);
        for (text, error) in std::mem::take(&mut self.startup_messages) {
            self.notify(&ctx, text, error);
        }
        self.apply_look(&ctx);

        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        for path in dropped {
            self.open_file(path);
        }

        if self.docs.active.is_none()
            && let Some((path, _)) = self.workspace.center_doc()
        {
            self.docs.active = Some(path);
        }
        let context = if self.palette.is_open() {
            KeyContext::CommandPalette
        } else {
            self.workspace.key_context()
        };
        let mut pending: Vec<ActionId> = Vec::new();

        pending.extend(self.menu_bar(ui));
        pending.extend(self.status_bar(ui, context));

        // A shell started now opens in the current file's folder.
        self.terminal.set_cwd(
            self.docs
                .active
                .as_ref()
                .and_then(|p| p.parent())
                .filter(|d| d.is_dir())
                .map(std::path::Path::to_path_buf),
        );
        // A File-menu save queued last frame goes to the focused editor this frame.
        let editor_save = self.editor_save_request.take();
        let mut env = TabEnv::new(
            &self.registry,
            &self.keymap,
            &self.settings.recent_files,
            &mut self.docs,
            &mut self.academy,
            &mut self.workbench,
            &mut self.debugger,
            &mut self.run_console,
            &mut self.lsp,
            &mut self.terminal,
            &mut self.source_dbg,
            &mut self.emulator,
            &mut self.shellcode,
            &mut self.triage,
            &mut self.yara,
            &mut self.wasm,
            &mut self.pyc,
            &mut self.java,
            &mut self.archive,
            &mut self.js,
            &mut self.dotnet,
            &mut self.assistant,
            &mut self.sandbox,
            &mut self.collab,
            &mut self.diff,
            &mut self.script,
            &mut self.challenge,
        );
        env.editor_save = editor_save;
        self.workspace.show(ui, &mut env);
        let TabEnv {
            emitted,
            open_requests,
            view_requests,
            editor_nav,
            ..
        } = env;
        // A "save changes?" dialog takes the keyboard while it is up.
        let dialog = self.unsaved_dialogs(&ctx);
        // Dispatch global shortcuts on the keys the focused view did not consume, so a
        // focused editor's own bindings (e.g. Ctrl+D for multi-cursor) win over global ones,
        // and a focused terminal (which consumes its keys) keeps Ctrl+W / Ctrl+Q / Ctrl+D.
        if !dialog {
            pending.extend(self.keymap.dispatch(&ctx, context));
        }
        pending.extend(emitted);
        for path in open_requests {
            self.open_file(path);
        }
        for request in view_requests {
            match request {
                ViewRequest::Open(path, view) => self.workspace.open_doc(&path, view),
                ViewRequest::ShowXrefs => self.workspace.open(TabKind::Xrefs),
                ViewRequest::Message(text) => self.notify(&ctx, text, false),
                ViewRequest::OpenInEditor { name, contents } => {
                    self.workspace.open(TabKind::Editor {
                        path: None,
                        state: Box::new(orress_views::EditorState::scratch(&name, &contents)),
                    });
                }
                ViewRequest::InstallExtension(source) => self.install_extension(&ctx, &source),
                ViewRequest::UninstallExtension(id) => self.uninstall_extension(&ctx, &id),
            }
        }
        // Cross-file go-to-definition: stash the target line for the editor to consume,
        // then open the file in the editor.
        for goto in editor_nav {
            let key = egui::Id::new(("orress-goto", &goto.path));
            ctx.data_mut(|d| d.insert_temp(key, goto.line));
            self.open_file(goto.path);
        }
        // Free files no tab shows any more.
        let in_use = self.workspace.doc_paths();
        self.docs.retain(|p| in_use.iter().any(|u| u == p));
        // Language servers stop tracking files whose editor tab was closed.
        let editing = self.workspace.editor_paths();
        self.lsp.close_documents(|p| editing.iter().any(|e| e == p));

        let items = self.palette_items(&ctx, context);
        if let Some(action) = self.palette.show(&ctx, &items) {
            pending.push(action);
        }

        self.about_window(&ctx);
        self.toasts_ui(&ctx);
        Self::drop_overlay(&ctx);

        for action in pending {
            self.run(&ctx, &action);
        }
        let poll = self.academy_poll();
        self.academy.poll(&poll);
        self.academy_requests(&ctx);
        orress_academy::spotlight_overlay(&ctx, &self.academy);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, WORKSPACE_KEY, &self.workspace);
        if let Some(paths) = &self.paths
            && let Err(e) = self.settings.save(&paths.settings_file())
        {
            tracing::error!("saving settings: {e:#}");
        }
    }
}

fn load_user_themes(
    dir: &std::path::Path,
    themes: &mut Vec<Theme>,
    messages: &mut Vec<(String, bool)>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let parsed = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|json| {
                // A Zed theme-family file carries a `themes` array (and yields several themes); a
                // native ORRESS theme does not, so fall back to the single-theme format.
                match Theme::from_zed_json(&json) {
                    Ok(v) if !v.is_empty() => Ok(v),
                    _ => Theme::from_json(&json)
                        .map(|t| vec![t])
                        .map_err(|e| e.to_string()),
                }
            });
        match parsed {
            Ok(loaded) => {
                for theme in loaded {
                    themes.retain(|t| t.name != theme.name);
                    themes.push(theme);
                }
            }
            Err(e) => messages.push((format!("Theme {} ignored: {e}", path.display()), true)),
        }
    }
}

/// Loads installed extensions (one directory each under `extensions/`): registers their themes
/// and language-server adapters, collects the grammar highlight queries they ship (the editor
/// applies those over its bundled grammars — Rust, Python, C, C++ — with the compiled query cached
/// per (language, query) in `orress-editor`), and surfaces any warnings.
fn load_extensions(
    dir: &std::path::Path,
    themes: &mut Vec<Theme>,
    adapters: &mut Vec<orress_lsp::LspAdapter>,
    grammar_queries: &mut Vec<orress_ext::GrammarQuery>,
    messages: &mut Vec<(String, bool)>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.join("extension.toml").is_file() {
            continue;
        }
        match orress_ext::load_extension(&path) {
            Ok(loaded) => {
                for theme in loaded.themes {
                    themes.retain(|t| t.name != theme.name);
                    themes.push(theme);
                }
                adapters.extend(loaded.lsp_adapters);
                grammar_queries.extend(loaded.grammar_queries);
                let who = if loaded.manifest.name.is_empty() {
                    path.display().to_string()
                } else {
                    loaded.manifest.name.clone()
                };
                for w in loaded.warnings {
                    messages.push((format!("Extension {who}: {w}"), true));
                }
            }
            Err(e) => messages.push((format!("Extension {} ignored: {e}", path.display()), true)),
        }
    }
}

/// Files opened as editable text (source, config, notes) rather than analyzed as binaries.
fn opens_in_editor(path: &std::path::Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some(
            "rs" | "py"
                | "pyw"
                | "asm"
                | "s"
                | "nasm"
                | "inc"
                | "toml"
                | "json"
                | "md"
                | "markdown"
                | "txt"
                | "c"
                | "cc"
                | "cpp"
                | "cxx"
                | "h"
                | "hpp"
                | "hh"
                | "hxx"
                | "sh"
                | "rhai"
                | "yar"
                | "yara"
                | "cfg"
                | "ini"
                | "csv"
                | "log"
                | "yml"
                | "yaml"
        )
    )
}

/// A menu item for an editing command, with its keyboard shortcut shown on the right.
fn edit_item(ui: &mut Ui, label: &str, shortcut: &str) -> bool {
    ui.add(egui::Button::new(label).shortcut_text(shortcut))
        .clicked()
}

fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
    egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    }
}

/// Reads the system clipboard as text (for the Edit > Paste menu item).
fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok()
}
