//! The workspace, modeled on Zed: a center area of split panes with tabs, plus a left,
//! right and bottom dock. Each of the four areas is its own `egui_dock` tree, so any of
//! them can hold several tabs and be split further. The whole layout is serializable
//! and restored on the next start.

mod views;

use std::path::{Path, PathBuf};

use egui::{Id, Ui};
use egui_dock::{DockArea, DockState, NodeIndex, NodePath, SurfaceIndex};
use orress_actions::{ActionId, ActionRegistry, KeyContext, Keymap};
use orress_project::DocStore;
use orress_views::{DocView, ViewCommand, ViewRequest, ViewState};
use serde::{Deserialize, Serialize};

/// What a tab shows.
#[derive(Serialize, Deserialize)]
pub enum TabKind {
    Welcome,
    Academy,
    /// The running lesson (right dock).
    Lesson,
    /// The Academy's CPU simulator.
    Simulator,
    /// Data transforms (decode, decrypt, decompress).
    Workbench,
    Keybindings,
    Notes {
        text: String,
    },
    /// A view of an open file.
    Doc {
        path: PathBuf,
        view: DocView,
        #[serde(skip)]
        state: Box<ViewState>,
    },
    /// A code editor buffer (center). `path` is None for a new untitled file.
    Editor {
        #[serde(default)]
        path: Option<PathBuf>,
        #[serde(skip)]
        state: Box<orress_views::EditorState>,
    },
    /// Cross-references of the current file (follows the focused document).
    Xrefs,
    /// The decompiler (right dock): the function under the cursor as Rust-style code.
    Decompiler,
    /// The machine-code debugger (bottom dock).
    Debugger,
    /// The emulator: run a function, side-channel solve.
    Emulator,
    /// The shellcode workbench: decode, disassemble, emulate a code blob.
    Shellcode,
    /// Static malware triage report.
    Triage,
    /// YARA workbench.
    Yara,
    /// WebAssembly module overview + WAT disassembly.
    Wasm,
    /// Python bytecode (.pyc) code-object tree + disassembly.
    Pyc,
    /// Java class file: constant pool, fields, methods + JVM disassembly.
    Java,
    /// ZIP/JAR archive: entries, manifest, open .class members.
    Archive,
    /// Resource extractor: native resources, embedded files, sections and overlay.
    Resources,
    /// JavaScript deobfuscation / beautify / string extraction.
    Js,
    /// .NET assembly metadata: types, methods, user strings.
    DotNet,
    /// AI assistant (Claude CLI / offline).
    Assistant,
    /// Dynamic-analysis sandbox (safety gate + launcher).
    Sandbox,
    /// Challenge Workbench: author, test and submit a user-made CTF challenge to the site.
    ChallengeWorkbench,
    ProjectTree,
    Explain,
    Inspector,
    /// Extension manager: installed extensions, install/uninstall.
    Extensions,
    /// Team collaboration: shared project over a relay, presence/follow, claims, chat, CTF.
    Collaboration,
    /// Binary diff: BinDiff-style function matching between the open binary and another.
    Diff,
    /// Scripting console: run a Rhai script against the open binary's analysis.
    Script,
    /// The integrated terminal (a real shell).
    Terminal,
    /// Build/run task output.
    Output,
    /// Source-level debugger (DAP).
    DebugSource,
    Problems,
    /// Retired (it was a placeholder). Kept only so layouts saved by older versions still load;
    /// [`Workspace::forget_open_files`] drops it at startup and nothing opens it.
    Jobs,
}

/// What to do with unsaved changes when closing an editor tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseChoice {
    Save,
    Discard,
    Cancel,
}

/// A tab title for an editor before its buffer is created.
fn editor_title(path: Option<&Path>) -> String {
    path.and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "untitled".into())
}

impl TabKind {
    pub fn title(&self) -> String {
        match self {
            Self::Welcome => "Welcome".into(),
            Self::Academy => "Academy".into(),
            Self::Lesson => "Lesson".into(),
            Self::Simulator => "CPU Simulator".into(),
            Self::Workbench => "Workbench".into(),
            Self::Keybindings => "Keybindings".into(),
            Self::Notes { .. } => "Notes".into(),
            Self::Doc { path, view, .. } => {
                format!("{} · {}", orress_project::file_name(path), view.name())
            }
            Self::Editor { path, state } => state
                .title()
                .unwrap_or_else(|| editor_title(path.as_deref())),
            Self::Xrefs => "Cross-references".into(),
            Self::Decompiler => "Decompiler".into(),
            Self::Debugger => "Debugger".into(),
            Self::Emulator => "Emulator".into(),
            Self::Shellcode => "Shellcode".into(),
            Self::Triage => "Triage".into(),
            Self::Yara => "YARA".into(),
            Self::Wasm => "WASM".into(),
            Self::Pyc => "Python".into(),
            Self::Java => "Java".into(),
            Self::Archive => "Archive".into(),
            Self::Resources => "Resources".into(),
            Self::Js => "JavaScript".into(),
            Self::DotNet => ".NET".into(),
            Self::Assistant => "Assistant".into(),
            Self::Sandbox => "Sandbox".into(),
            Self::ChallengeWorkbench => "Challenge Workbench".into(),
            Self::ProjectTree => "Project".into(),
            Self::Explain => "Explain".into(),
            Self::Inspector => "Inspector".into(),
            Self::Extensions => "Extensions".into(),
            Self::Collaboration => "Collaboration".into(),
            Self::Diff => "Binary diff".into(),
            Self::Script => "Scripting".into(),
            Self::Terminal => "Terminal".into(),
            Self::Output => "Output".into(),
            Self::DebugSource => "Debug".into(),
            Self::Problems => "Problems".into(),
            Self::Jobs => "Jobs".into(),
        }
    }

    pub fn key_context(&self) -> KeyContext {
        match self {
            Self::Doc {
                view: DocView::Hex, ..
            } => KeyContext::Hex,
            Self::Doc {
                view: DocView::Disassembly,
                ..
            } => KeyContext::Disassembly,
            Self::Doc {
                view: DocView::Graph,
                ..
            } => KeyContext::Graph,
            Self::Editor { .. } => KeyContext::Editor,
            Self::Decompiler => KeyContext::Decompiler,
            // Both debuggers take F5 / F10 / F11 while focused.
            Self::Debugger | Self::DebugSource => KeyContext::Debugger,
            Self::Notes { .. } => KeyContext::Notes,
            Self::Terminal => KeyContext::Terminal,
            _ => KeyContext::Workspace,
        }
    }

    /// The area a tab of this kind opens in by default.
    pub fn home(&self) -> Slot {
        match self {
            Self::ProjectTree => Slot::Left,
            Self::Explain | Self::Inspector | Self::Lesson | Self::Decompiler | Self::Assistant => {
                Slot::Right
            }
            Self::Xrefs
            | Self::Terminal
            | Self::Problems
            | Self::Jobs
            | Self::Debugger
            | Self::Output
            | Self::DebugSource => Slot::Bottom,
            _ => Slot::Center,
        }
    }

    /// Whether opening this kind again should focus the existing tab instead.
    fn same_view(&self, other: &TabKind) -> bool {
        match (self, other) {
            (Self::Notes { .. }, _) | (_, Self::Notes { .. }) => false,
            // New (untitled) editors are always separate; a path focuses its tab.
            (Self::Editor { path: a, .. }, Self::Editor { path: b, .. }) => a.is_some() && a == b,
            (Self::Editor { .. }, _) | (_, Self::Editor { .. }) => false,
            (
                Self::Doc {
                    path: a, view: va, ..
                },
                Self::Doc {
                    path: b, view: vb, ..
                },
            ) => a == b && va == vb,
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tab {
    id: u64,
    pub kind: TabKind,
}

impl Tab {
    /// Whether this is an editor with unsaved changes.
    fn is_dirty(&self) -> bool {
        matches!(&self.kind, TabKind::Editor { state, .. } if state.is_dirty())
    }

    /// Saves an editor's unsaved changes (see [`orress_views::EditorState::save_interactive`]).
    /// `Ok(true)` for anything else.
    fn save(&mut self) -> Result<bool, String> {
        match &mut self.kind {
            TabKind::Editor { path, state } => state.save_interactive(path),
            _ => Ok(true),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    Center,
    Left,
    Right,
    Bottom,
}

/// Things tab views need from the app, and requests they send back to it.
pub struct TabEnv<'a> {
    pub registry: &'a ActionRegistry,
    pub keymap: &'a Keymap,
    pub recent_files: &'a [PathBuf],
    /// The open project folder (Zed-style), shown as a tree at the top of the left dock. Set by
    /// the app after construction; `None` when no folder is open.
    pub project_root: Option<PathBuf>,
    /// Actions triggered from inside a view (e.g. a button on the welcome page).
    pub emitted: Vec<ActionId>,
    /// Files the user asked to open from inside a view.
    pub open_requests: Vec<PathBuf>,
    pub docs: &'a mut DocStore,
    /// Views of documents the user asked for from inside a view.
    pub view_requests: Vec<ViewRequest>,
    /// Cross-file go-to-definition targets from the editor.
    pub editor_nav: Vec<orress_views::GotoFile>,
    /// A save requested from the File menu, delivered to the focused editor tab.
    pub editor_save: Option<orress_views::SaveRequest>,
    pub academy: &'a mut orress_academy::Academy,
    pub workbench: &'a mut orress_views::Workbench,
    pub debugger: &'a mut orress_views::DebugSession,
    pub run_console: &'a mut orress_views::RunConsole,
    pub lsp: &'a mut orress_lsp::LspManager,
    pub terminal: &'a mut orress_views::TerminalSession,
    pub source_dbg: &'a mut orress_views::SourceDebug,
    pub emulator: &'a mut orress_views::EmulatorView,
    pub shellcode: &'a mut orress_views::ShellcodeView,
    pub triage: &'a mut orress_views::TriageView,
    pub yara: &'a mut orress_views::YaraView,
    pub wasm: &'a mut orress_views::WasmView,
    pub pyc: &'a mut orress_views::PycView,
    pub java: &'a mut orress_views::JavaView,
    pub archive: &'a mut orress_views::ArchiveView,
    pub resources: &'a mut orress_views::ResourcesView,
    pub js: &'a mut orress_views::JsView,
    pub dotnet: &'a mut orress_views::DotNetView,
    pub assistant: &'a mut orress_views::AssistantView,
    pub sandbox: &'a mut orress_views::SandboxView,
    pub collab: &'a mut orress_views::CollabView,
    pub diff: &'a mut orress_views::DiffView,
    pub script: &'a mut orress_views::ScriptView,
    pub challenge: &'a mut orress_views::ChallengeWorkbenchView,
}

impl<'a> TabEnv<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: &'a ActionRegistry,
        keymap: &'a Keymap,
        recent_files: &'a [PathBuf],
        docs: &'a mut DocStore,
        academy: &'a mut orress_academy::Academy,
        workbench: &'a mut orress_views::Workbench,
        debugger: &'a mut orress_views::DebugSession,
        run_console: &'a mut orress_views::RunConsole,
        lsp: &'a mut orress_lsp::LspManager,
        terminal: &'a mut orress_views::TerminalSession,
        source_dbg: &'a mut orress_views::SourceDebug,
        emulator: &'a mut orress_views::EmulatorView,
        shellcode: &'a mut orress_views::ShellcodeView,
        triage: &'a mut orress_views::TriageView,
        yara: &'a mut orress_views::YaraView,
        wasm: &'a mut orress_views::WasmView,
        pyc: &'a mut orress_views::PycView,
        java: &'a mut orress_views::JavaView,
        archive: &'a mut orress_views::ArchiveView,
        resources: &'a mut orress_views::ResourcesView,
        js: &'a mut orress_views::JsView,
        dotnet: &'a mut orress_views::DotNetView,
        assistant: &'a mut orress_views::AssistantView,
        sandbox: &'a mut orress_views::SandboxView,
        collab: &'a mut orress_views::CollabView,
        diff: &'a mut orress_views::DiffView,
        script: &'a mut orress_views::ScriptView,
        challenge: &'a mut orress_views::ChallengeWorkbenchView,
    ) -> Self {
        Self {
            registry,
            keymap,
            recent_files,
            project_root: None,
            emitted: Vec::new(),
            open_requests: Vec::new(),
            docs,
            view_requests: Vec::new(),
            editor_nav: Vec::new(),
            editor_save: None,
            academy,
            workbench,
            debugger,
            run_console,
            lsp,
            terminal,
            source_dbg,
            emulator,
            shellcode,
            triage,
            yara,
            wasm,
            pyc,
            java,
            archive,
            resources,
            js,
            dotnet,
            assistant,
            sandbox,
            collab,
            diff,
            script,
            challenge,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Workspace {
    center: DockState<Tab>,
    left: DockState<Tab>,
    right: DockState<Tab>,
    bottom: DockState<Tab>,
    pub left_open: bool,
    pub right_open: bool,
    pub bottom_open: bool,
    focused: Slot,
    next_id: u64,
    /// Commands waiting for the focused document view.
    #[serde(skip)]
    commands: Vec<ViewCommand>,
    /// An editor tab with unsaved changes the user asked to close: the app asks Save / Don't
    /// Save / Cancel, then calls [`Workspace::resolve_close`].
    #[serde(skip)]
    pending_close: Option<u64>,
}

impl Default for Workspace {
    fn default() -> Self {
        let mut next_id = 0;
        let mut tab = |kind| {
            next_id += 1;
            Tab { id: next_id, kind }
        };
        let new_dock = |tabs| {
            let mut dock = DockState::new(tabs);
            dock.set_focused_node_and_surface(NodePath {
                surface: SurfaceIndex::main(),
                node: NodeIndex::root(),
            });
            dock
        };
        let center = new_dock(vec![tab(TabKind::Welcome)]);
        let left = new_dock(vec![tab(TabKind::ProjectTree)]);
        let right = new_dock(vec![tab(TabKind::Explain), tab(TabKind::Inspector)]);
        let bottom = new_dock(vec![
            tab(TabKind::Xrefs),
            tab(TabKind::Terminal),
            tab(TabKind::Output),
            tab(TabKind::DebugSource),
            tab(TabKind::Problems),
        ]);
        Self {
            center,
            left,
            right,
            bottom,
            left_open: true,
            right_open: true,
            bottom_open: true,
            focused: Slot::Center,
            next_id,
            commands: Vec::new(),
            pending_close: None,
        }
    }
}

impl Workspace {
    fn dock(&mut self, slot: Slot) -> &mut DockState<Tab> {
        match slot {
            Slot::Center => &mut self.center,
            Slot::Left => &mut self.left,
            Slot::Right => &mut self.right,
            Slot::Bottom => &mut self.bottom,
        }
    }

    fn set_open(&mut self, slot: Slot, open: bool) {
        match slot {
            Slot::Center => {}
            Slot::Left => self.left_open = open,
            Slot::Right => self.right_open = open,
            Slot::Bottom => self.bottom_open = open,
        }
    }

    pub fn toggle(&mut self, slot: Slot) {
        let open = match slot {
            Slot::Center => return,
            Slot::Left => !self.left_open,
            Slot::Right => !self.right_open,
            Slot::Bottom => !self.bottom_open,
        };
        self.set_open(slot, open);
        if !open && self.focused == slot {
            self.focused = Slot::Center;
        }
    }

    /// Opens a tab, or focuses the existing one if this view is already open.
    pub fn open(&mut self, kind: TabKind) {
        for slot in [Slot::Center, Slot::Left, Slot::Right, Slot::Bottom] {
            let dock = self.dock(slot);
            if let Some(path) = dock.find_tab_from(|t| t.kind.same_view(&kind)) {
                let _ = dock.set_active_tab(path);
                dock.set_focused_node_and_surface(path.node_path());
                self.set_open(slot, true);
                self.focused = slot;
                return;
            }
        }
        let slot = kind.home();
        self.next_id += 1;
        let tab = Tab {
            id: self.next_id,
            kind,
        };
        let dock = self.dock(slot);
        dock.push_to_focused_leaf(tab);
        if let Some(path) = focused_leaf(dock) {
            dock.set_focused_node_and_surface(path);
        }
        self.set_open(slot, true);
        self.focused = slot;
    }

    /// Drop every file-backed tab (open documents and editor buffers) from all docks, so a
    /// restored session starts with no files loaded. The dock layout and non-file views are
    /// kept; if pruning empties the center, a fresh Welcome tab replaces them. Called once at
    /// startup, since open files are deliberately not persisted across launches.
    pub fn forget_open_files(&mut self) {
        // Retired tab kinds from older layouts go too.
        let is_file = |t: &mut Tab| {
            matches!(
                t.kind,
                TabKind::Doc { .. } | TabKind::Editor { .. } | TabKind::Jobs
            )
        };
        for dock in [
            &mut self.center,
            &mut self.left,
            &mut self.right,
            &mut self.bottom,
        ] {
            dock.retain_tabs(|t| !is_file(t));
        }
        if self.center.iter_all_tabs().next().is_none() {
            self.next_id += 1;
            let mut center = DockState::new(vec![Tab {
                id: self.next_id,
                kind: TabKind::Welcome,
            }]);
            center.set_focused_node_and_surface(NodePath {
                surface: SurfaceIndex::main(),
                node: NodeIndex::root(),
            });
            self.center = center;
        }
        self.focused = Slot::Center;
    }

    /// Closes the focused tab — unless it is an editor with unsaved changes, which is left open
    /// with a close prompt pending (see [`Workspace::close_prompt`]).
    pub fn close_active_tab(&mut self) {
        let dock = self.dock(self.focused);
        if let Some(leaf_path) = focused_leaf(dock)
            && let Ok(leaf) = dock.leaf(leaf_path)
            && let Some(tab) = leaf.tabs.get(leaf.active.0)
        {
            if tab.is_dirty() {
                self.pending_close = Some(tab.id);
                return;
            }
            let active = leaf.active;
            dock.remove_tab((leaf_path, active).into());
        }
    }

    /// The editor tab waiting for a Save / Don't Save / Cancel answer, with its title.
    pub fn close_prompt(&self) -> Option<(u64, String)> {
        let id = self.pending_close?;
        self.all_tabs()
            .find(|t| t.id == id)
            .map(|t| (id, t.kind.title()))
    }

    /// Applies the answer to a close prompt. Saving may show a file dialog (untitled buffers);
    /// cancelling that, or a failed save, keeps the tab open. Returns a save error to show.
    pub fn resolve_close(&mut self, id: u64, choice: CloseChoice) -> Option<String> {
        self.pending_close = None;
        let close = match choice {
            CloseChoice::Cancel => false,
            CloseChoice::Discard => true,
            CloseChoice::Save => match self.tab_mut(id).map(Tab::save) {
                Some(Ok(saved)) => saved,
                Some(Err(e)) => return Some(e),
                None => false,
            },
        };
        if close {
            self.remove_tab(id);
        }
        None
    }

    fn all_tabs(&self) -> impl Iterator<Item = &Tab> {
        [&self.center, &self.left, &self.right, &self.bottom]
            .into_iter()
            .flat_map(|dock| dock.iter_all_tabs().map(|(_, t)| t))
    }

    fn all_tabs_mut(&mut self) -> impl Iterator<Item = &mut Tab> {
        [
            &mut self.center,
            &mut self.left,
            &mut self.right,
            &mut self.bottom,
        ]
        .into_iter()
        .flat_map(|dock| dock.iter_all_tabs_mut().map(|(_, t)| t))
    }

    fn tab_mut(&mut self, id: u64) -> Option<&mut Tab> {
        self.all_tabs_mut().find(|t| t.id == id)
    }

    fn remove_tab(&mut self, id: u64) {
        for slot in [Slot::Center, Slot::Left, Slot::Right, Slot::Bottom] {
            let dock = self.dock(slot);
            if let Some(path) = dock.find_tab_from(|t| t.id == id) {
                dock.remove_tab(path);
                return;
            }
        }
    }

    /// Titles of the editor tabs with unsaved changes.
    pub fn dirty_editors(&self) -> Vec<String> {
        self.all_tabs()
            .filter(|t| t.is_dirty())
            .map(|t| t.kind.title())
            .collect()
    }

    /// Saves every editor with unsaved changes (asking for a file name for untitled ones).
    /// `Ok(false)` when the user cancelled a file dialog; `Err` on the first failed save.
    pub fn save_all_editors(&mut self) -> Result<bool, String> {
        for tab in self.all_tabs_mut() {
            if tab.is_dirty() && !tab.save()? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Saves the open editor of `path`, if any, when it has unsaved changes (no dialog: it has a
    /// file). `Ok` also when no editor has the file open.
    pub fn save_editor(&mut self, path: &Path) -> Result<(), String> {
        for tab in self.all_tabs_mut() {
            if let TabKind::Editor {
                path: Some(p),
                state,
            } = &mut tab.kind
                && p == path
                && state.is_dirty()
            {
                let mut p = Some(p.clone());
                return match state.save_interactive(&mut p) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("the save was cancelled".into()),
                    Err(e) => Err(e),
                };
            }
        }
        Ok(())
    }

    /// The files open in editor tabs.
    pub fn editor_paths(&self) -> Vec<PathBuf> {
        self.all_tabs()
            .filter_map(|t| match &t.kind {
                TabKind::Editor { path: Some(p), .. } => Some(p.clone()),
                _ => None,
            })
            .collect()
    }

    /// Puts every dock back to its first-start layout. Work in progress survives: notes, code
    /// editors (with their unsaved buffers) and open file views move to the center area.
    pub fn reset_layout(&mut self) {
        let mut fresh = Workspace::default();
        let keep = |t: &mut Tab| {
            matches!(
                t.kind,
                TabKind::Notes { .. } | TabKind::Editor { .. } | TabKind::Doc { .. }
            )
        };
        let mut kept: Vec<Tab> = Vec::new();
        for dock in [
            &mut self.center,
            &mut self.left,
            &mut self.right,
            &mut self.bottom,
        ] {
            let paths: Vec<_> = dock
                .iter_all_tabs_mut()
                .filter_map(|(path, t)| keep(t).then_some(path))
                .collect();
            // Remove back to front, so earlier paths in the same leaf stay valid.
            for path in paths.into_iter().rev() {
                if let Some(tab) = dock.remove_tab(path) {
                    kept.push(tab);
                }
            }
        }
        // Tab ids must stay unique: renumber the kept tabs after both layouts' ids.
        fresh.next_id = fresh.next_id.max(self.next_id);
        for mut tab in kept.into_iter().rev() {
            fresh.next_id += 1;
            tab.id = fresh.next_id;
            fresh.center.push_to_focused_leaf(tab);
        }
        *self = fresh;
    }

    /// Splits the focused center pane and opens a fresh notes tab beside it.
    pub fn split_right(&mut self) {
        self.next_id += 1;
        let tab = Tab {
            id: self.next_id,
            kind: TabKind::Notes {
                text: String::new(),
            },
        };
        let node = focused_leaf(&self.center).map_or(NodeIndex::root(), |p| p.node);
        let surface = self.center.main_surface_mut();
        if surface.is_empty() {
            surface.push_to_first_leaf(tab);
        } else {
            surface.split_right(node, 0.5, vec![tab]);
        }
        self.focused = Slot::Center;
    }

    /// Key context of whatever has focus, used to pick key bindings.
    pub fn key_context(&mut self) -> KeyContext {
        self.active_tab()
            .map_or(KeyContext::Workspace, |tab| tab.kind.key_context())
    }

    /// Title of the focused tab, for the status bar.
    pub fn active_title(&mut self) -> Option<String> {
        self.active_tab().map(|tab| tab.kind.title())
    }

    /// Opens (or focuses) a view of a file.
    pub fn open_doc(&mut self, path: &Path, view: DocView) {
        self.open(TabKind::Doc {
            path: path.to_path_buf(),
            view,
            state: Box::default(),
        });
    }

    /// The file and view of the focused tab, if it is a document view.
    pub fn focused_doc(&mut self) -> Option<(PathBuf, DocView)> {
        match &self.active_tab()?.kind {
            TabKind::Doc { path, view, .. } => Some((path.clone(), *view)),
            _ => None,
        }
    }

    /// Whether the decompiler panel has focus (it takes Find commands).
    pub fn decompiler_focused(&mut self) -> bool {
        self.active_tab()
            .is_some_and(|tab| matches!(tab.kind, TabKind::Decompiler))
    }

    /// The file view shown in the main (center) area, even when keyboard focus is in a
    /// dock such as the lesson panel.
    pub fn center_doc(&self) -> Option<(PathBuf, DocView)> {
        let leaf = self.center.leaf(focused_leaf(&self.center)?).ok()?;
        match &leaf.tabs.get(leaf.active.0)?.kind {
            TabKind::Doc { path, view, .. } => Some((path.clone(), *view)),
            _ => None,
        }
    }

    /// Queues a command for the focused document view (delivered next frame).
    pub fn send(&mut self, command: ViewCommand) {
        self.commands.push(command);
    }

    /// Every file shown by some tab.
    pub fn doc_paths(&self) -> Vec<PathBuf> {
        [&self.center, &self.left, &self.right, &self.bottom]
            .into_iter()
            .flat_map(|dock| dock.iter_all_tabs())
            .filter_map(|(_, tab)| match &tab.kind {
                TabKind::Doc { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect()
    }

    /// Whether the focused tab is a code-editor buffer (so Save / Save As apply).
    pub fn active_is_editor(&mut self) -> bool {
        matches!(
            self.active_tab().map(|t| &t.kind),
            Some(TabKind::Editor { .. })
        )
    }

    fn active_tab(&mut self) -> Option<&Tab> {
        let slot = self.focused;
        let dock = self.dock(slot);
        let leaf = dock.leaf(focused_leaf(dock)?).ok()?;
        leaf.tabs.get(leaf.active.0)
    }

    pub fn show(&mut self, ui: &mut Ui, env: &mut TabEnv<'_>) {
        // The Challenge Workbench builds/submits main.rs from disk: save its editor buffer first.
        if let Some(path) = env.challenge.save_request() {
            let result = self.save_editor(&path);
            env.challenge.report_save(result);
        }
        let style = egui_dock::Style::from_egui(ui.style());
        let focused_tab = self.active_tab().map(|t| t.id);
        let mut viewer = views::Viewer {
            env,
            focused_tab,
            commands: std::mem::take(&mut self.commands),
            close_requests: Vec::new(),
        };
        let pressed_at = ui.input(|i| {
            i.pointer
                .any_pressed()
                .then(|| i.pointer.interact_pos())
                .flatten()
        });
        let mut clicked_slot = None;

        let mut dock_area = |ui: &mut Ui, slot: Slot, dock: &mut DockState<Tab>| {
            DockArea::new(dock)
                .id(Id::new(("orress::dock", slot as u8)))
                .style(style.clone())
                .show_leaf_collapse_buttons(false)
                .show_leaf_close_all_buttons(false)
                .show_inside(ui, &mut viewer);
            if pressed_at.is_some_and(|p| ui.min_rect().contains(p)) {
                clicked_slot = Some(slot);
            }
            let name = match slot {
                Slot::Center => "dock.center",
                Slot::Left => "dock.left",
                Slot::Right => "dock.right",
                Slot::Bottom => "dock.bottom",
            };
            orress_ui::spotlight::mark(ui.ctx(), name, ui.min_rect());
        };

        egui::Panel::left("orress::left_dock")
            .resizable(true)
            .default_size(240.0)
            .min_size(140.0)
            .show_collapsible(ui, &mut self.left_open, |ui| {
                dock_area(ui, Slot::Left, &mut self.left);
            });
        egui::Panel::right("orress::right_dock")
            .resizable(true)
            .default_size(440.0)
            .min_size(160.0)
            .show_collapsible(ui, &mut self.right_open, |ui| {
                dock_area(ui, Slot::Right, &mut self.right);
            });
        egui::Panel::bottom("orress::bottom_dock")
            .resizable(true)
            .default_size(200.0)
            .min_size(80.0)
            .show_collapsible(ui, &mut self.bottom_open, |ui| {
                dock_area(ui, Slot::Bottom, &mut self.bottom);
            });
        egui::CentralPanel::no_frame().show(ui, |ui| {
            dock_area(ui, Slot::Center, &mut self.center);
        });

        if let Some(slot) = clicked_slot {
            self.focused = slot;
        }
        // An editor with unsaved changes whose close button was clicked: ask first.
        if let Some(&id) = viewer.close_requests.first() {
            self.pending_close = Some(id);
        }
        // The inspector follows the last focused file.
        if let Some((path, _)) = self.focused_doc() {
            viewer.env.docs.active = Some(path);
        }
    }
}

/// The focused leaf, falling back to the main surface's last focused node: a fresh
/// `DockState` has no focused surface until the user clicks into it.
fn focused_leaf(dock: &DockState<Tab>) -> Option<NodePath> {
    dock.focused_leaf().or_else(|| {
        dock.main_surface().focused_leaf().map(|node| NodePath {
            surface: SurfaceIndex::main(),
            node,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(ws: &mut Workspace, slot: Slot) -> usize {
        ws.dock(slot).iter_all_tabs().count()
    }

    #[test]
    fn opening_singleton_twice_focuses_existing() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Keybindings);
        ws.open(TabKind::Keybindings);
        assert_eq!(count(&mut ws, Slot::Center), 2); // Welcome + Keybindings
    }

    #[test]
    fn notes_can_open_many_times() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Notes {
            text: String::new(),
        });
        ws.open(TabKind::Notes {
            text: String::new(),
        });
        assert_eq!(count(&mut ws, Slot::Center), 3);
    }

    #[test]
    fn opening_dock_view_opens_its_dock() {
        // Start with the bottom dock closed, so we can verify opening a bottom view reopens it.
        let mut ws = Workspace {
            bottom_open: false,
            ..Default::default()
        };
        assert!(!ws.bottom_open);
        ws.open(TabKind::Terminal);
        assert!(ws.bottom_open);
        assert_eq!(ws.key_context(), KeyContext::Terminal);
    }

    #[test]
    fn fresh_workspace_reports_welcome_as_active() {
        let mut ws = Workspace::default();
        assert_eq!(ws.active_title().as_deref(), Some("Welcome"));
    }

    #[test]
    fn forget_open_files_drops_documents_and_restores_welcome() {
        let mut ws = Workspace::default();
        // Simulate a restored session with files open (and the Welcome tab closed).
        ws.close_active_tab(); // close the default Welcome
        ws.open_doc(Path::new("crackme02.exe"), DocView::Disassembly);
        ws.open_doc(Path::new("crackme02.exe"), DocView::Info);
        assert!(count(&mut ws, Slot::Center) >= 2);

        ws.forget_open_files();

        // No document tabs survive, and the center falls back to a single Welcome tab.
        assert!(
            ws.dock(Slot::Center)
                .iter_all_tabs()
                .all(|(_, t)| !matches!(t.kind, TabKind::Doc { .. }))
        );
        assert_eq!(count(&mut ws, Slot::Center), 1);
        assert_eq!(ws.active_title().as_deref(), Some("Welcome"));
    }

    #[test]
    fn forget_open_files_keeps_non_file_layout() {
        let mut ws = Workspace::default();
        ws.open_doc(Path::new("a.bin"), DocView::Info);
        ws.forget_open_files();
        // The side/bottom docks (ProjectTree, Explain/Inspector, Terminal, …) are untouched.
        assert_eq!(count(&mut ws, Slot::Left), 1);
        assert_eq!(count(&mut ws, Slot::Right), 2);
        assert!(count(&mut ws, Slot::Bottom) >= 1);
    }

    #[test]
    fn close_active_tab_removes_it() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Keybindings);
        ws.close_active_tab();
        assert_eq!(count(&mut ws, Slot::Center), 1);
    }

    #[test]
    fn reset_layout_keeps_notes_and_restores_docks() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Notes {
            text: "flag{keep me}".into(),
        });
        ws.toggle(Slot::Left);
        ws.open(TabKind::Keybindings);
        ws.reset_layout();
        assert!(ws.left_open);
        let notes: Vec<_> = ws
            .all_tabs()
            .filter_map(|t| match &t.kind {
                TabKind::Notes { text } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(notes, vec!["flag{keep me}".to_string()]);
        // Keybindings is not work in progress, so it is not kept.
        assert!(
            !ws.all_tabs()
                .any(|t| matches!(t.kind, TabKind::Keybindings))
        );
        // Ids stay unique.
        let mut ids: Vec<u64> = ws.all_tabs().map(|t| t.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn retired_jobs_tab_is_dropped_from_old_layouts() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Jobs);
        assert!(ws.all_tabs().any(|t| matches!(t.kind, TabKind::Jobs)));
        ws.forget_open_files();
        assert!(!ws.all_tabs().any(|t| matches!(t.kind, TabKind::Jobs)));
    }

    #[test]
    fn closing_a_clean_tab_needs_no_prompt() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Editor {
            path: None,
            state: Box::default(),
        });
        // A buffer that was never shown has no unsaved changes.
        ws.close_active_tab();
        assert!(ws.close_prompt().is_none());
        assert!(ws.dirty_editors().is_empty());
    }

    #[test]
    fn closing_a_dirty_editor_asks_first() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Editor {
            path: None,
            state: Box::new(orress_views::EditorState::scratch(
                "solve.rs",
                "fn main() {}",
            )),
        });
        ws.close_active_tab();
        let (id, title) = ws.close_prompt().expect("a prompt for the unsaved buffer");
        assert!(title.contains("solve.rs"));
        assert_eq!(ws.dirty_editors().len(), 1);
        // Cancel keeps it; Discard closes it.
        assert!(ws.resolve_close(id, CloseChoice::Cancel).is_none());
        assert_eq!(ws.dirty_editors().len(), 1);
        assert!(ws.resolve_close(id, CloseChoice::Discard).is_none());
        assert!(ws.dirty_editors().is_empty());
    }

    #[test]
    fn layout_serializes() {
        let mut ws = Workspace::default();
        ws.open(TabKind::Notes {
            text: "flag{?}".into(),
        });
        // eframe persists app state as RON, which (unlike JSON) keeps the infinite
        // rects egui_dock stores for tabs that were never drawn.
        let text = ron::to_string(&ws).unwrap();
        let back: Workspace = ron::from_str(&text).unwrap();
        assert_eq!(back.next_id, ws.next_id);
    }
}
