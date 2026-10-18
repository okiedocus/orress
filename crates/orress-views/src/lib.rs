//! Reverse-engineering views of an open document: disassembly, graph, functions, hex
//! editor, file information ("What is this file?"), sections, imports and exports,
//! strings, cross-references, the data inspector and the project overview.

mod apihash;
mod archive;
mod assistant;
mod challenge;
mod code;
mod code_editor;
mod collab;
mod colors;
mod debugger;
mod decompiler;
mod diff;
mod disasm;
mod dotnet;
mod edit;
mod editor;
mod emulator;
mod exploit;
mod extensions;
mod find;
mod folder;
mod functions;
mod gadgets;
mod heap;
mod resources;
mod graph;
mod graph_layout;
pub mod hex;
mod imports;
mod info;
mod inspector;
mod java;
mod js;
mod menu;
mod project;
mod pyc;
mod sandbox;
mod script;
mod sections;
mod shellcode;
mod source_debug;
mod strings;
mod terminal;
mod triage;
mod wasm;
mod workbench;
mod xrefs;
mod yara;

use std::path::PathBuf;
use std::sync::Arc;

use egui::{RichText, Ui};
use orress_project::{DocStore, Document, Program};

pub use archive::{ArchiveView, archive_view};
pub use assistant::{AssistantView, assistant_view};
pub use challenge::{ChallengeWorkbenchView, challenge_workbench};
pub use code::set_syntax;
pub use collab::{CollabView, collab_panel};
pub use colors::entropy_color;
pub use debugger::{DebugSession, debugger_panel};
pub use decompiler::decompiler_panel;
pub use diff::{DiffView, diff_panel};
pub use dotnet::{DotNetView, dotnet_view};
pub use editor::{
    EditorState, GotoFile, RunConsole, SaveRequest, editor_view, problems_panel, run_panel,
    set_grammar_queries, set_lsp_settings,
};
pub use emulator::{EmulatorView, emulator_view};
pub use exploit::{ExploitView, exploit_view};
pub use extensions::{extensions_panel, refresh_extensions, set_extensions_dir};
pub use inspector::inspector;
pub use java::{JavaView, java_view};
pub use js::{JsView, js_view};
pub use menu::{CommandEntry, set_commands};
pub use folder::folder_tree;
pub use gadgets::{GadgetsView, gadgets_view};
pub use heap::{HeapView, heap_view};
pub use project::project_tree;
pub use resources::{ResourcesView, resources_view};
pub use pyc::{PycView, pyc_view};
pub use sandbox::{SandboxView, sandbox_view};
pub use script::{ScriptView, script_view};
pub use shellcode::{ShellcodeView, shellcode_view};
pub use source_debug::{DebugAction, SourceDebug, source_debug_panel};
pub use terminal::{TerminalSession, terminal_panel};
pub use triage::{TriageView, triage_view};
pub use wasm::{WasmView, wasm_view};
pub use workbench::{Workbench, workbench};
pub use xrefs::xrefs_panel;
pub use yara::{YaraView, yara_view};

/// Asks where to save a patched copy of the file and writes it. Returns a status message.
pub fn save_patched(doc: &Document) -> String {
    let stem = doc
        .path
        .file_stem()
        .map_or_else(|| "file".into(), |s| s.to_string_lossy().into_owned());
    let ext = doc
        .path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let dialog = rfd::FileDialog::new()
        .set_title("Save patched copy")
        .set_file_name(format!("{stem}.patched{ext}"));
    let dialog = match doc.path.parent() {
        Some(dir) => dialog.set_directory(dir),
        None => dialog,
    };
    match dialog.save_file() {
        Some(path) => match doc.export(&path) {
            Ok(()) => format!("Saved {}", path.display()),
            Err(e) => e,
        },
        None => "Not saved.".into(),
    }
}

/// The kinds of views a document can be shown in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DocView {
    Info,
    Hex,
    Sections,
    Imports,
    Strings,
    Disassembly,
    Graph,
    Functions,
}

impl DocView {
    pub const ALL: [Self; 8] = [
        Self::Info,
        Self::Functions,
        Self::Disassembly,
        Self::Graph,
        Self::Strings,
        Self::Imports,
        Self::Sections,
        Self::Hex,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Disassembly => "Disassembly",
            Self::Graph => "Graph",
            Self::Functions => "Functions",
            Self::Info => "Info",
            Self::Hex => "Hex",
            Self::Sections => "Sections",
            Self::Imports => "Imports",
            Self::Strings => "Strings",
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            Self::Disassembly => {
                "The program's machine code as assembly instructions, one per line, with names and cross-references."
            }
            Self::Graph => {
                "The current function as a flow chart: boxes of instructions joined by arrows for every jump."
            }
            Self::Functions => {
                "Every function found in the program, with size and number of callers."
            }
            Self::Info => {
                "What is this file? Format, protections, detected compiler or packer, hashes and tips on where to start."
            }
            Self::Hex => "The raw bytes of the file, as hexadecimal numbers and as text.",
            Self::Sections => {
                "The parts the file is divided into: code, data, resources. Each has a size, an address and permissions."
            }
            Self::Imports => {
                "Library functions the program uses, and functions it offers to others. A quick look at what it can do."
            }
            Self::Strings => {
                "Readable text found in the file: messages, file names, URLs, sometimes the password or flag itself."
            }
        }
    }
}

/// Commands from the app (keyboard shortcuts, palette) for the focused document view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewCommand {
    GoTo,
    Find,
    FindNext,
    FindPrevious,
    CopyHex,
    CopyCArray,
    CopyPython,
}

/// Requests a view makes to the workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewRequest {
    /// Open (or focus) a view of a document.
    Open(PathBuf, DocView),
    /// Show the cross-references panel (for the document's `xref_target`).
    ShowXrefs,
    /// Show a short message to the user.
    Message(String),
    /// Open generated text as a new, named scratch buffer in the code editor. The language (and
    /// so the highlighting) is inferred from `name`'s extension.
    OpenInEditor { name: String, contents: String },
    /// Install an extension from a source — a local directory path or a git URL.
    InstallExtension(String),
    /// Uninstall the extension with this id.
    UninstallExtension(String),
    /// Run an app command (action id), e.g. from a right-click menu.
    RunAction(String),
    /// Open an arbitrary file path (from the folder tree), routed the usual way: source/text to
    /// the editor, binaries to analysis.
    OpenPath(PathBuf),
    /// Reveal a path in the operating system's file manager.
    RevealInOs(PathBuf),
    /// Create a new notes file in this directory (prompting for a name), then open it.
    NewNotesFile(PathBuf),
    /// Extract the resources of this executable into the project folder.
    ExtractResources(PathBuf),
    /// Adopt this folder as the open project root (and persist it).
    SetProjectRoot(PathBuf),
}

/// Per-tab state of a document view. Not saved between sessions.
#[derive(Default)]
pub struct ViewState {
    pub hex: hex::HexState,
    strings: strings::StringsState,
    imports: imports::ImportsState,
    disasm: disasm::DisasmState,
    graph: graph::GraphState,
    functions: functions::FunctionsState,
}

/// The code analysis, or a message explaining why there is none yet.
fn program_or_message(ui: &mut Ui, doc: &Document) -> Option<Arc<Program>> {
    match doc.program_state() {
        None => {
            loading(
                ui,
                "Disassembling… finding functions and cross-references in the background.",
            );
            None
        }
        Some(None) => {
            let arch = doc
                .analysis()
                .map_or_else(String::new, |a| a.info.arch.clone());
            ui.label(format!(
                "ORRESS cannot disassemble this file yet (architecture: {arch}). Supported: x86, \
                 x86-64 and ARM64. The hex view, strings and imports still work."
            ));
            None
        }
        Some(Some(p)) => Some(Arc::clone(p)),
    }
}

/// Context passed to a view each frame.
pub struct ViewCtx<'a> {
    /// Commands for this view (only filled for the focused tab).
    pub commands: Vec<ViewCommand>,
    pub requests: &'a mut Vec<ViewRequest>,
    /// The debug session, so the disassembly can show the current instruction and
    /// breakpoints and toggle them.
    pub debugger: &'a mut DebugSession,
}

/// Draws `view` of the document at `path`, opening the document if needed.
pub fn show(
    ui: &mut Ui,
    docs: &mut DocStore,
    path: &std::path::Path,
    view: DocView,
    state: &mut ViewState,
    cx: &mut ViewCtx<'_>,
) {
    let doc = docs.open(path);
    match doc.data() {
        None => {
            loading(ui, &format!("Reading {}…", doc.file_name()));
            return;
        }
        Some(Err(e)) => {
            ui.colored_label(ui.visuals().error_fg_color, "Could not open this file");
            ui.label(e.as_str());
            return;
        }
        Some(Ok(_)) => {}
    }
    match view {
        DocView::Hex => hex::hex_view(ui, doc, &mut state.hex, cx),
        DocView::Info => with_analysis(ui, doc, |ui, doc| info::info(ui, doc, cx)),
        DocView::Sections => with_analysis(ui, doc, |ui, doc| sections::sections(ui, doc, cx)),
        DocView::Imports => with_analysis(ui, doc, |ui, doc| {
            imports::imports(ui, doc, &mut state.imports, cx)
        }),
        DocView::Disassembly => disasm::disasm_view(ui, doc, &mut state.disasm, cx),
        DocView::Graph => graph::graph_view(ui, doc, &mut state.graph, cx),
        DocView::Functions => functions::functions(ui, doc, &mut state.functions, cx),
        DocView::Strings => with_analysis(ui, doc, |ui, doc| {
            strings::strings(ui, doc, &mut state.strings, cx)
        }),
    }
}

fn with_analysis(ui: &mut Ui, doc: &mut Document, f: impl FnOnce(&mut Ui, &mut Document)) {
    if doc.analysis().is_none() {
        loading(
            ui,
            "Analyzing… (this runs in the background; the hex view already works)",
        );
        return;
    }
    f(ui, doc);
}

fn loading(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(RichText::new(text).weak());
    });
}

/// `0x1A2B` style address formatting, padded for the file's pointer size.
pub fn fmt_addr(value: u64, wide: bool) -> String {
    if wide {
        format!("0x{value:016X}")
    } else {
        format!("0x{value:08X}")
    }
}
