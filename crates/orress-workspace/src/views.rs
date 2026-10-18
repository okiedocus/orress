//! What each tab draws.

use egui::{RichText, Ui, WidgetText};
use egui_dock::TabViewer;
use egui_dock::tab_viewer::OnCloseResponse;
use orress_actions::{ActionId, KeyContext};
use orress_ui::{ExplainExt as _, explain, kbd, muted};

use crate::{Tab, TabEnv, TabKind};

pub(crate) struct Viewer<'e, 'a> {
    pub env: &'e mut TabEnv<'a>,
    /// The focused tab, which receives `commands`.
    pub focused_tab: Option<u64>,
    pub commands: Vec<orress_views::ViewCommand>,
    /// Editor tabs with unsaved changes whose close button was clicked (kept open; the
    /// workspace asks Save / Don't Save / Cancel).
    pub close_requests: Vec<u64>,
}

impl TabViewer for Viewer<'_, '_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> egui::Id {
        egui::Id::new(("orress::tab", tab.id))
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        tab.kind.title().into()
    }

    fn on_close(&mut self, tab: &mut Tab) -> OnCloseResponse {
        if tab.is_dirty() {
            self.close_requests.push(tab.id);
            OnCloseResponse::Focus
        } else {
            OnCloseResponse::Close
        }
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Tab) {
        match &mut tab.kind {
            TabKind::Welcome => welcome(ui, self.env),
            TabKind::Academy => orress_academy::overview(ui, self.env.academy),
            TabKind::Lesson => orress_academy::lesson_panel(ui, self.env.academy),
            TabKind::Simulator => orress_academy::simulator(ui, self.env.academy),
            TabKind::Workbench => orress_views::workbench(ui, self.env.workbench, self.env.docs),
            TabKind::Keybindings => keybindings(ui, self.env),
            TabKind::Notes { text } => notes(ui, text),
            TabKind::Doc { path, view, state } => {
                orress_ui::spotlight::mark(
                    ui.ctx(),
                    &format!("view.{}", view.name()),
                    ui.max_rect(),
                );
                let commands = if self.focused_tab == Some(tab.id) {
                    std::mem::take(&mut self.commands)
                } else {
                    Vec::new()
                };
                let mut cx = orress_views::ViewCtx {
                    commands,
                    requests: &mut self.env.view_requests,
                    debugger: self.env.debugger,
                };
                orress_views::show(ui, self.env.docs, path, *view, state, &mut cx);
            }
            TabKind::ProjectTree => {
                // The project folder tree (if a folder is open) sits on top; the open-files list
                // with each file's analysis views stays below it.
                if let Some(root) = self.env.project_root.clone() {
                    orress_views::folder_tree(
                        ui,
                        &root,
                        self.env.docs,
                        &mut self.env.view_requests,
                    );
                    ui.separator();
                }
                orress_views::project_tree(ui, self.env.docs, &mut self.env.view_requests);
            }
            TabKind::Inspector => orress_views::inspector(ui, self.env.docs),
            TabKind::Types => orress_views::types_view(ui, self.env.types, self.env.docs),
            TabKind::Collaboration => orress_views::collab_panel(ui, self.env.collab),
            TabKind::Diff => orress_views::diff_panel(ui, self.env.diff, self.env.docs),
            TabKind::Script => orress_views::script_view(ui, self.env.script, self.env.docs),
            TabKind::Extensions => {
                orress_views::extensions_panel(ui, &mut self.env.view_requests);
            }
            TabKind::Editor { path, state } => {
                orress_ui::spotlight::mark(ui.ctx(), "view.Editor", ui.max_rect());
                // Only the focused editor acts on a File-menu save request.
                let save_cmd = if self.focused_tab == Some(tab.id) {
                    self.env.editor_save.take()
                } else {
                    None
                };
                let active_binary = self.env.docs.active_mut();
                orress_views::editor_view(
                    ui,
                    path,
                    state,
                    self.env.run_console,
                    self.env.lsp,
                    &mut self.env.editor_nav,
                    self.env.source_dbg,
                    save_cmd,
                    active_binary,
                );
            }
            TabKind::Xrefs => {
                orress_views::xrefs_panel(ui, self.env.docs, &mut self.env.view_requests);
            }
            TabKind::Explain => explain_panel(ui),
            TabKind::Decompiler => {
                orress_ui::spotlight::mark(ui.ctx(), "view.Decompiler", ui.max_rect());
                let commands = if self.focused_tab == Some(tab.id) {
                    std::mem::take(&mut self.commands)
                } else {
                    Vec::new()
                };
                orress_views::decompiler_panel(
                    ui,
                    self.env.docs,
                    &mut self.env.view_requests,
                    commands,
                );
            }
            TabKind::Debugger => {
                orress_ui::spotlight::mark(ui.ctx(), "view.Debugger", ui.max_rect());
                let doc = self.env.docs.active_mut();
                orress_views::debugger_panel(ui, self.env.debugger, doc);
            }
            TabKind::Emulator => {
                orress_views::emulator_view(ui, self.env.emulator, self.env.docs);
            }
            TabKind::Shellcode => {
                orress_views::shellcode_view(ui, self.env.shellcode);
            }
            TabKind::Triage => {
                orress_views::triage_view(ui, self.env.triage, self.env.docs);
            }
            TabKind::Yara => {
                orress_views::yara_view(ui, self.env.yara, self.env.docs);
            }
            TabKind::Wasm => {
                orress_views::wasm_view(ui, self.env.wasm, self.env.docs);
            }
            TabKind::Pyc => {
                orress_views::pyc_view(ui, self.env.pyc, self.env.docs);
            }
            TabKind::Java => {
                orress_views::java_view(ui, self.env.java, self.env.docs);
            }
            TabKind::Archive => {
                orress_views::archive_view(ui, self.env.archive, self.env.docs);
            }
            TabKind::Resources => {
                let root = self.env.project_root.clone();
                orress_views::resources_view(
                    ui,
                    self.env.resources,
                    self.env.docs,
                    root.as_deref(),
                    &mut self.env.view_requests,
                );
            }
            TabKind::Exploit => {
                orress_views::exploit_view(ui, self.env.exploit, self.env.docs);
            }
            TabKind::Heap => {
                orress_views::heap_view(ui, self.env.heap, self.env.debugger);
            }
            TabKind::Gadgets => {
                orress_views::gadgets_view(ui, self.env.gadgets, self.env.docs);
            }
            TabKind::Js => {
                orress_views::js_view(ui, self.env.js, self.env.docs);
            }
            TabKind::DotNet => {
                orress_views::dotnet_view(ui, self.env.dotnet, self.env.docs);
            }
            TabKind::Assistant => {
                orress_views::assistant_view(ui, self.env.assistant, self.env.docs);
            }
            TabKind::Sandbox => {
                orress_views::sandbox_view(ui, self.env.sandbox, self.env.docs);
            }
            TabKind::ChallengeWorkbench => {
                orress_views::challenge_workbench(
                    ui,
                    self.env.challenge,
                    &mut self.env.open_requests,
                    self.env.run_console,
                );
            }
            TabKind::Terminal => {
                orress_ui::spotlight::mark(ui.ctx(), "view.Terminal", ui.max_rect());
                let notify = {
                    let ctx = ui.ctx().clone();
                    std::sync::Arc::new(move || ctx.request_repaint())
                };
                orress_views::terminal_panel(ui, self.env.terminal, notify);
            }
            TabKind::Output => {
                orress_ui::spotlight::mark(ui.ctx(), "view.Output", ui.max_rect());
                orress_views::run_panel(ui, self.env.run_console);
            }
            TabKind::DebugSource => {
                orress_ui::spotlight::mark(ui.ctx(), "view.DebugSource", ui.max_rect());
                orress_views::source_debug_panel(ui, self.env.source_dbg);
            }
            TabKind::Problems => {
                orress_ui::spotlight::mark(ui.ctx(), "view.Problems", ui.max_rect());
                orress_views::problems_panel(ui, self.env.lsp);
            }
            // Retired; dropped from restored layouts at startup, so normally never drawn.
            TabKind::Jobs => {
                ui.label(muted("This tab is no longer used. Close it."));
            }
        }
    }

    fn scroll_bars(&self, tab: &Tab) -> [bool; 2] {
        // The hex view virtualizes its own scrolling.
        match tab.kind {
            TabKind::Doc { .. }
            | TabKind::Inspector
            | TabKind::Xrefs
            | TabKind::Decompiler
            | TabKind::Editor { .. }
            | TabKind::Academy
            | TabKind::Lesson
            | TabKind::Emulator
            | TabKind::Shellcode
            | TabKind::Triage
            | TabKind::Yara
            | TabKind::Wasm
            | TabKind::Pyc
            | TabKind::Java
            | TabKind::Archive
            | TabKind::Js
            | TabKind::DotNet
            | TabKind::Assistant
            | TabKind::Script
            | TabKind::Workbench => [false, false],
            _ => [true, true],
        }
    }
}

fn shortcut_label(ui: &Ui, env: &TabEnv<'_>, action: &str) -> Option<String> {
    env.keymap
        .keystroke_anywhere(&ActionId::from(action), KeyContext::Workspace)
        .map(|(k, ctx)| with_context(k.label(ui.ctx()), ctx))
}

/// A shortcut label, with the context it works in when that is not everywhere (e.g.
/// "Ctrl+Shift+C (Hex)").
fn with_context(label: String, ctx: KeyContext) -> String {
    match ctx {
        KeyContext::Global | KeyContext::Workspace => label,
        other => format!("{label} ({other:?})"),
    }
}

/// A button that emits an action, with its shortcut and explanation.
fn action_button(ui: &mut Ui, env: &mut TabEnv<'_>, action: &str, label: &str) {
    let id = ActionId::from(action);
    let explanation = env
        .registry
        .get(&id)
        .map(|a| a.explain.clone())
        .unwrap_or_default();
    let shortcut = shortcut_label(ui, env, action);
    ui.horizontal(|ui| {
        if ui.button(label).explain(label, &explanation).clicked() {
            env.emitted.push(id);
        }
        if let Some(s) = shortcut {
            kbd(ui, &s);
        }
    });
}

fn welcome(ui: &mut Ui, env: &mut TabEnv<'_>) {
    // Inset the whole home screen so copy doesn't run flush to the panel edges.
    egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(36, 12))
        .show(ui, |ui| {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                // The logo as the centrepiece of the home screen (like Visual Studio's start page / Zed's
                // empty-pane logo). The texture is loaded at startup; fall back to a text wordmark.
                let logo = ui
                    .ctx()
                    .data(|d| d.get_temp::<egui::TextureHandle>(egui::Id::new("orress::logo")));
                if let Some(tex) = logo {
                    // Large enough that the wordmark and tagline in the logo read clearly; scales with the
                    // tab width on smaller windows.
                    let size = (ui.available_width() * 0.55).clamp(300.0, 460.0);
                    ui.image((tex.id(), egui::vec2(size, size)));
                    ui.add_space(6.0);
                } else {
                    ui.heading(RichText::new("ORRESS").size(34.0).strong());
                    ui.label(muted("Okiedocus Rusty Reverse Engineering Software Suite"));
                }
                ui.add_space(2.0);
                ui.label(muted(
                    "Reverse engineering for CTFs and malware analysis — and a place to learn it.",
                ));
            });
            ui.add_space(24.0);

            ui.columns(2, |cols| {
                let ui = &mut cols[0];
                ui.label(RichText::new("Start").strong().size(16.0));
                action_button(ui, env, "workspace::Open", "Open a file…");
                action_button(ui, env, "academy::Open", "Start the Academy");
                action_button(ui, env, "command_palette::Toggle", "Command palette");
                action_button(ui, env, "help::Keybindings", "All keyboard shortcuts");
                action_button(ui, env, "workspace::NewNotes", "New notes tab");

                ui.add_space(12.0);
                ui.label(RichText::new("Recent files").strong().size(16.0));
                if env.recent_files.is_empty() {
                    ui.label(muted("Nothing yet. Files you open show up here."));
                }
                for path in env.recent_files {
                    let name = path.file_name().map_or_else(
                        || path.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    );
                    if ui
                        .link(name)
                        .on_hover_text(path.display().to_string())
                        .clicked()
                    {
                        env.open_requests.push(path.clone());
                    }
                }

                let ui = &mut cols[1];
                ui.label(
                    RichText::new("New to reverse engineering?")
                        .strong()
                        .size(16.0),
                );
                ui.label(
                    "Reverse engineering means figuring out how a program works when you only have \
             the program, not its source code. You read its machine code, run it under a \
             debugger, and rebuild its logic step by step.",
                );
                ui.add_space(6.0);
                ui.label(
            "In CTF competitions, \"reversing\" challenges hide a flag inside a program. In \
             malware analysis, you find out what a malicious program does so you can detect \
             and stop it.",
        );
                ui.add_space(6.0);
                ui.label(
                    "The Academy teaches all of it, from binary numbers to unpacking malware. \
             Explain Mode is on: hover over anything and the Explain panel on the right \
             tells you what it is.",
                );
            });
        });
}

fn keybindings(ui: &mut Ui, env: &mut TabEnv<'_>) {
    ui.heading("Keyboard shortcuts");
    ui.label(muted(
        "Every command in ORRESS. Change shortcuts in keymap.json (Help > Open Config Folder); \
         the format is the same as Zed's keymap.",
    ));
    ui.add_space(8.0);
    egui::Grid::new("orress::keybindings")
        .striped(true)
        .num_columns(3)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Command").strong());
            ui.label(RichText::new("Shortcut").strong());
            ui.label(RichText::new("What it does").strong());
            ui.end_row();
            let mut actions: Vec<_> = env.registry.iter().collect();
            actions.sort_by(|a, b| a.id.cmp(&b.id));
            for action in actions {
                ui.label(&action.title)
                    .on_hover_text(RichText::new(action.id.as_str()).monospace());
                match env
                    .keymap
                    .keystroke_anywhere(&action.id, KeyContext::Workspace)
                {
                    Some((k, ctx)) => {
                        ui.horizontal(|ui| {
                            kbd(ui, &k.label(ui.ctx()));
                            if !matches!(ctx, KeyContext::Global | KeyContext::Workspace) {
                                ui.label(muted(format!("in {ctx:?}")));
                            }
                        });
                    }
                    None => {
                        ui.label(muted("—"));
                    }
                }
                ui.label(&action.explain);
                ui.end_row();
            }
        });
}

fn notes(ui: &mut Ui, text: &mut String) {
    ui.label(muted(
        "Write down what you find: addresses, ideas, the flag. In later versions notes link \
         to addresses and turn into your writeup.",
    ));
    ui.add(
        egui::TextEdit::multiline(text)
            .code_editor()
            .desired_width(f32::INFINITY)
            .desired_rows(24)
            .hint_text("# Notes\n\n- main is at 0x401000\n- input is compared with ..."),
    );
}

fn explain_panel(ui: &mut Ui) {
    // Prose wraps to the panel width; the scroll area keeps a long explanation readable in the
    // narrow dock (and gives a horizontal scrollbar for anything that can't wrap).
    let content_width = ui.available_width();
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_max_width(content_width);
            match explain::last_explanation(ui.ctx()) {
                Some(e) => {
                    ui.heading(&e.title);
                    ui.add_space(4.0);
                    ui.label(&e.body);
                }
                None => {
                    ui.heading("Explain");
                    ui.label(
                        "Hover over a button, label or value and its explanation appears here. \
                     It stays until you hover over something else, so you can read it at \
                     your own pace.",
                    );
                }
            }
        });
}
