//! Every action the app knows, with a beginner-friendly explanation.

use orress_actions::{ActionRegistry, Keymap};
use orress_theme::Theme;

pub const DEFAULT_KEYMAP: &str = include_str!("../assets/default-keymap.json");

/// Prefix of the per-theme actions, e.g. `theme::Use(High Contrast)`.
pub const THEME_PREFIX: &str = "theme::Use(";

pub fn theme_action(name: &str) -> String {
    format!("{THEME_PREFIX}{name})")
}

pub fn theme_from_action(id: &str) -> Option<&str> {
    id.strip_prefix(THEME_PREFIX)?.strip_suffix(')')
}

pub fn default_keymap() -> Keymap {
    Keymap::from_json(DEFAULT_KEYMAP).expect("built-in keymap is valid")
}

pub fn registry(themes: &[Theme]) -> ActionRegistry {
    let mut r = ActionRegistry::new();
    r.register(
        "command_palette::Toggle",
        "Command Palette",
        "Search and run any command by typing part of its name. The fastest way to do \
         anything in ORRESS.",
    )
    .register(
        "workspace::Open",
        "Open File…",
        "Open a file to analyze: a program (.exe, .dll, ELF), a firmware image or any other \
         binary. You can also drag a file onto the window.",
    )
    .register(
        "workspace::OpenFolder",
        "Open Folder…",
        "Open a project folder: its files and subfolders show as a tree in the left panel, so one \
         folder can hold a target's binary, source, notes, patches and extracted resources.",
    )
    .register(
        "workspace::NewNotes",
        "New Notes Tab",
        "Open an empty notes tab. Writing down what you learn is half of reverse engineering.",
    )
    .register(
        "workspace::CloseActiveTab",
        "Close Tab",
        "Close the tab that has focus.",
    )
    .register(
        "workspace::SplitRight",
        "Split Pane Right",
        "Split the center area so you can look at two views side by side, for example \
         disassembly next to the decompiler.",
    )
    .register(
        "workspace::ToggleLeftDock",
        "Toggle Left Dock",
        "Show or hide the left dock, which holds the project overview.",
    )
    .register(
        "workspace::ToggleRightDock",
        "Toggle Right Dock",
        "Show or hide the right dock, which holds the Explain and Inspector panels.",
    )
    .register(
        "workspace::ToggleBottomDock",
        "Toggle Bottom Dock",
        "Show or hide the bottom dock, which holds the terminal, problems and background jobs.",
    )
    .register(
        "workspace::ResetLayout",
        "Reset Layout",
        "Put all panels and tabs back where they were on first start.",
    )
    .register(
        "view::ToggleExplainMode",
        "Toggle Explain Mode",
        "Explain Mode shows a plain-language tooltip for everything you hover over. Turn it \
         off once you know your way around; the Explain panel keeps working either way.",
    )
    .register(
        "view::ZoomIn",
        "Zoom In",
        "Make all text and controls larger.",
    )
    .register(
        "view::ZoomOut",
        "Zoom Out",
        "Make all text and controls smaller.",
    )
    .register("view::ZoomReset", "Reset Zoom", "Go back to 100% size.")
    .register(
        "file::Info",
        "File: What Is This File?",
        "Overview of the current file: format, protections, detected compiler or packer, \
         hashes, entropy and tips on where to start.",
    )
    .register(
        "file::Hex",
        "File: Hex View",
        "The raw bytes of the current file.",
    )
    .register(
        "file::Sections",
        "File: Sections",
        "The sections of the current file: code, data, resources, with their permissions.",
    )
    .register(
        "file::Imports",
        "File: Imports and Exports",
        "Library functions the current file uses or offers.",
    )
    .register(
        "file::Strings",
        "File: Strings",
        "Readable text in the current file. Look for messages, URLs and flags.",
    )
    .register(
        "file::Functions",
        "File: Functions",
        "Every function found in the current file, with size and number of callers.",
    )
    .register(
        "nav::Back",
        "Go Back",
        "Return to where you were before the last jump, like the back button in a browser.",
    )
    .register("nav::Forward", "Go Forward", "Undo a Go Back.")
    .register(
        "nav::GoToMain",
        "Go to main",
        "Jump to the program's own main function, past the C runtime start-up code.",
    )
    .register(
        "view::Xrefs",
        "Cross-references",
        "Show every place that uses the function or address under the cursor. In the \
         disassembly, press X on a line.",
    )
    .register(
        "workbench::Open",
        "Workbench",
        "Decode, decrypt and decompress data with a chain of operations (base64, XOR, AES, \
         zlib ...), or let Magic find the chain for you.",
    )
    .register(
        "challenge::OpenWorkbench",
        "Challenge Workbench",
        "Author your own crackme or keygen from a template, test it, and submit it to the CTF \
         site for review and rewards.",
    )
    .register(
        "hex::SendToWorkbench",
        "Hex: Send Selection to Workbench",
        "Copy the selected bytes into the Workbench to decode or decrypt them.",
    )
    .register(
        "patch::Export",
        "Patch: Save Patched File",
        "Write a copy of the current file with your patches applied.",
    )
    .register(
        "patch::RevertAll",
        "Patch: Revert All Patches",
        "Remove every patch from the current file.",
    )
    .register(
        "hex::GoTo",
        "Hex: Go to Offset or Address",
        "Jump to a position in the file (offset) or a memory address.",
    )
    .register(
        "hex::Find",
        "Find",
        "In the Disassembly view: search the listing (mnemonics, operands, names, comments). \
         Elsewhere: search the file's bytes in the Hex view for text, wide (UTF-16) text or a \
         byte pattern with ?? wildcards.",
    )
    .register(
        "hex::FindNext",
        "Find Next",
        "Jump to the next match of the last search (Disassembly or Hex view).",
    )
    .register(
        "hex::FindPrevious",
        "Find Previous",
        "Jump to the previous match of the last search (Disassembly or Hex view).",
    )
    .register(
        "hex::CopyHex",
        "Hex: Copy as Hex",
        "Copy the selected bytes as hex text, e.g. \"4D 5A 90 00\".",
    )
    .register(
        "hex::CopyCArray",
        "Hex: Copy as C Array",
        "Copy the selected bytes as a C array, ready to paste into a solver or keygen.",
    )
    .register(
        "hex::CopyPython",
        "Hex: Copy as Python Bytes",
        "Copy the selected bytes as a Python bytes literal, handy for pwntools and solver scripts.",
    )
    .register(
        "view::Disassembly",
        "File: Disassembly",
        "The program's machine code as assembly instructions. Shortcut: Ctrl+D.",
    )
    .register(
        "view::Graph",
        "File: Graph View",
        "The current function drawn as a flow chart of instruction blocks and jumps. In the disassembly, press Space.",
    )
    .register(
        "view::Decompiler",
        "Open Decompiler",
        "The function under the cursor as Rust-style code, reconstructed from the assembly. Shortcut: F5.",
    )
    .register(
        "file::NewFile",
        "New File",
        "Open a new, empty code editor to write a script or solver. Shortcut: Ctrl+Shift+N.",
    )
    .register(
        "file::OpenSource",
        "Open Text/Source File…",
        "Open a source or text file in the code editor (binaries open in the analysis views).",
    )
    .register(
        "file::Save",
        "Save",
        "Save the active code-editor tab to its file (asks for a name if it is untitled). Shortcut: Ctrl+S.",
    )
    .register(
        "file::SaveAs",
        "Save As…",
        "Save the active code-editor tab to a new file you pick, and continue editing that file.",
    )
    .register(
        "view::Debugger",
        "Open Debugger",
        "Run the program under ORRESS's control: breakpoints, stepping, registers, stack and memory. Shortcut: F6.",
    )
    .register(
        "view::Emulator",
        "Open Emulator",
        "Run a function from the binary with arguments (string decryptors, check functions) and recover an input with the instruction-counting side-channel solver. Shortcut: F7.",
    )
    .register(
        "view::Sandbox",
        "Open Sandbox",
        "Dynamic-analysis safety gate: VM detection and a guarded launcher that refuses to run a sample outside a VM.",
    )
    .register(
        "view::Yara",
        "Open YARA Workbench",
        "Write a YARA rule and test it live against the open file (pure-Rust YARA-X engine). Shortcut: Ctrl+Shift+Y.",
    )
    .register(
        "view::Triage",
        "Open Triage Report",
        "Static malware triage of the open file: risk flags, capabilities grouped by behavior with MITRE ATT&CK, extracted IOCs (defanged), and hashes. Shortcut: Ctrl+Shift+T.",
    )
    .register(
        "view::Wasm",
        "Open WebAssembly View",
        "Inspect an open .wasm module: imports, exports, functions with signatures, memories and globals, plus a WAT disassembly (pure-Rust wasm-tools).",
    )
    .register(
        "view::Pyc",
        "Open Python Bytecode View",
        "Inspect an open .pyc file: the code-object tree (module, functions, comprehensions) with constants, names and a CPython bytecode disassembly (pure-Rust marshal loader).",
    )
    .register(
        "view::Java",
        "Open Java Class View",
        "Inspect an open .class file: the constant pool, fields (with recovered constant values) and methods, plus a JVM bytecode disassembly (pure-Rust class-file loader).",
    )
    .register(
        "view::Archive",
        "Open Archive View",
        "Browse an open ZIP/JAR/APK: its entries and JAR manifest, and open a .class member straight into the JVM disassembler (pure-Rust ZIP reader).",
    )
    .register(
        "view::Resources",
        "Open Resources View",
        "Extract an open executable's contents: native resources (icons, manifest, version, strings, RCDATA), embedded files found by signature, each PE section, and overlay data — saved into the project folder.",
    )
    .register(
        "view::Js",
        "Open JavaScript View",
        "Deobfuscate the open JavaScript (decode \\xNN/fromCharCode/concatenation), extract its strings, and beautify minified code (pure-Rust, string-level transforms).",
    )
    .register(
        "view::DotNet",
        "Open .NET View",
        "Inspect an open .NET assembly: CLI metadata — types and methods, the module/assembly names, the table overview and the user-string heap (pure-Rust metadata loader).",
    )
    .register(
        "view::Assistant",
        "Open AI Assistant",
        "Ask questions about the open binary. Uses your Claude plan via the Claude Code CLI (no API key), or an offline static-only mode. Sending context is opt-in.",
    )
    .register(
        "view::Shellcode",
        "Open Shellcode Workbench",
        "Paste a captured code blob (hex, C array, \\x escapes or base64) to decode, disassemble and emulate it in the sandbox. Shortcut: F8.",
    )
    .register(
        "view::Project",
        "Open Project Panel",
        "Overview of the open file: sections, functions, strings and imports.",
    )
    .register(
        "view::Explain",
        "Open Explain Panel",
        "Shows the explanation of the last thing you hovered over.",
    )
    .register(
        "view::Inspector",
        "Open Inspector",
        "Shows the bytes under the cursor as numbers, text, floats and timestamps.",
    )
    .register(
        "view::Extensions",
        "Manage Extensions",
        "Install, view and uninstall ORRESS and Zed-compatible extensions (themes, grammars, \
         language servers).",
    )
    .register(
        "view::Collaboration",
        "Collaboration",
        "Join a team room over a relay: shared project (CRDT), presence and follow mode, challenge \
         claims, chat, and CTFd/rCTF challenge import and flag submission.",
    )
    .register(
        "view::Diff",
        "Binary diff",
        "BinDiff-style comparison of the open binary against another: identical, changed, added and \
         removed functions (patch diffing, malware-variant comparison).",
    )
    .register(
        "view::Script",
        "Scripting console",
        "Run a Rhai script against the open binary's analysis (functions, strings, bytes, \
         disassembly) to automate queries — sandboxed and pure-Rust.",
    )
    .register(
        "view::Terminal",
        "Open Terminal",
        "A command line inside ORRESS.",
    )
    .register(
        "theme::Next",
        "Next Theme",
        "Switch to the next color theme.",
    )
    .register(
        "academy::Open",
        "Open Academy",
        "Step-by-step lessons that teach reverse engineering from zero, with practice \
         programs (crackmes) built in.",
    )
    .register(
        "academy::Lesson",
        "Academy: Current Lesson",
        "Show the lesson you are working on, or start the next one.",
    )
    .register(
        "academy::OpenSimulator",
        "Academy: CPU Simulator",
        "A tiny pretend CPU: type assembly instructions and watch registers, flags and the \
         stack change, one step at a time.",
    )
    .register(
        "help::Welcome",
        "Welcome Page",
        "Open the welcome page with shortcuts to get started.",
    )
    .register(
        "help::Keybindings",
        "Keyboard Shortcuts",
        "List every command with its keyboard shortcut and what it does.",
    )
    .register(
        "help::OpenConfigFolder",
        "Open Config Folder",
        "Open the folder with settings.json, keymap.json and custom themes.",
    )
    .register(
        "help::About",
        "About ORRESS",
        "Version and license information.",
    )
    .register(
        "debug::Continue",
        "Debug: Continue",
        "Let the stopped program run on until it hits the next breakpoint or ends. Shortcut: F5          in the Debugger or Debug panel.",
    )
    .register(
        "debug::StepOver",
        "Debug: Step Over",
        "Run one step: one machine instruction in the Debugger, or one source line (without          entering calls) in the source Debug panel. Shortcut: F10.",
    )
    .register(
        "debug::StepInto",
        "Debug: Step Into",
        "Run one step, entering a function call if the line makes one. In the machine-code          Debugger this runs one instruction. Shortcut: F11.",
    )
    .register(
        "debug::StepOut",
        "Debug: Step Out",
        "Run until the current function returns to its caller (source Debug panel). Shortcut:          Shift+F11.",
    )
    .register(
        "debug::Pause",
        "Debug: Pause",
        "Stop the running program where it is, so you can look at its state.",
    )
    .register(
        "debug::Stop",
        "Debug: Stop",
        "End the debugged program. Shortcut: Shift+F5.",
    )
    .register("app::Quit", "Quit", "Close ORRESS. Your layout is saved.");

    for theme in themes {
        r.register(
            &theme_action(&theme.name),
            &format!("Use Theme: {}", theme.name),
            "Change the colors of the whole app.",
        );
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_keymap_only_uses_registered_actions() {
        let registry = registry(&Theme::built_in());
        // `null` bindings unbind a key in a context, so only real actions are checked.
        for binding in default_keymap().bindings() {
            if let Some(action) = binding.action.as_ref() {
                assert!(registry.contains(action), "unregistered action {action}");
            }
        }
    }

    #[test]
    fn theme_action_round_trip() {
        let id = theme_action("High Contrast");
        assert_eq!(theme_from_action(&id), Some("High Contrast"));
        assert_eq!(theme_from_action("theme::Next"), None);
    }
}
