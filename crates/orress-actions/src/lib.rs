//! Actions, keystrokes and keymaps, modeled on Zed.
//!
//! Every user-facing operation in ORRESS is an [`Action`]: a stable string id such as
//! `"workspace::ToggleLeftDock"`, a human title, and a beginner-friendly explanation.
//! Keys never call code directly: a [`Keymap`] maps a [`Keystroke`] in a [`KeyContext`]
//! to an action id, and the app dispatches the action. This keeps the command palette,
//! menus, keyboard shortcuts and (later) scripts all going through one path.

mod keymap;
mod keystroke;
mod registry;

pub use keymap::{Binding, Keymap, KeymapError};
pub use keystroke::{Keystroke, KeystrokeParseError};
pub use registry::{Action, ActionRegistry};

use serde::{Deserialize, Serialize};

/// Stable identifier of an action, written `namespace::Name` like in Zed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part before `::`, used as the category in the command palette.
    pub fn namespace(&self) -> &str {
        self.0.split_once("::").map_or("", |(ns, _)| ns)
    }
}

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ActionId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Where keyboard focus is. Bindings for a specific context win over `Global` ones,
/// so the same key can mean different things in the hex view and in the code editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum KeyContext {
    #[default]
    Global,
    Workspace,
    Hex,
    Disassembly,
    Graph,
    Decompiler,
    Editor,
    Notes,
    Terminal,
    Debugger,
    CommandPalette,
}

impl KeyContext {
    pub const ALL: [Self; 11] = [
        Self::Global,
        Self::Workspace,
        Self::Hex,
        Self::Disassembly,
        Self::Graph,
        Self::Decompiler,
        Self::Editor,
        Self::Notes,
        Self::Terminal,
        Self::Debugger,
        Self::CommandPalette,
    ];
}
