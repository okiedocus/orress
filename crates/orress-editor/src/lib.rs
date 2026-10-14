//! The ORRESS code editor model: an in-memory text buffer, language detection, syntax
//! highlighting and build/run tasks. UI-agnostic, so it is testable on its own; the egui
//! editor view in `orress-views` renders it.
//!
//! The buffer is a `ropey` rope (O(log n) edits and index math, cheap snapshot clones for
//! undo) with a dependency-free tokenizer fallback plus incremental `tree-sitter` for
//! highlighting, rendered by a custom multi-cursor editor widget in `orress-views` and driven
//! by an LSP client. This mirrors Zed's layering so each piece upgrades locally.

mod highlight;
mod task;
mod ts;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use ropey::Rope;

pub use highlight::{Tok, Token};
pub use task::{Command, Task, tasks_for};

/// Highlights `text` of the given language into sparse, ordered, non-overlapping tokens.
/// Uses tree-sitter for Rust, Python, C and C++, falling back to the built-in tokenizer for other
/// languages and if a grammar is unavailable.
pub fn highlight(text: &str, lang: Language) -> Vec<Token> {
    if ts::supported(lang)
        && let Some(tokens) = ts::highlight(text, lang)
    {
        return tokens;
    }
    highlight::tokenizer(text, lang)
}

/// Highlights `text` using an *imported* tree-sitter highlight query (e.g. a Zed grammar
/// extension's `highlights.scm`) over the bundled grammar for `lang`, falling back to the built-in
/// query — then the tokenizer — if the imported query does not compile or parsing fails. This is
/// the query half of Zed grammar/query compatibility.
pub fn highlight_with_query(text: &str, lang: Language, query: &str) -> Vec<Token> {
    if ts::supported(lang)
        && let Some(tokens) = ts::highlight_with_query(text, lang, query)
    {
        return tokens;
    }
    highlight(text, lang)
}

/// Whether ORRESS bundles a tree-sitter grammar for `lang` (so an imported query can be applied).
pub fn has_grammar(lang: Language) -> bool {
    ts::supported(lang)
}

/// A language ORRESS can highlight and (for some) run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    Python,
    C,
    Cpp,
    Asm,
    Toml,
    Json,
    Markdown,
    PlainText,
}

impl Language {
    /// Every language, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Rust,
        Self::Python,
        Self::C,
        Self::Cpp,
        Self::Asm,
        Self::Toml,
        Self::Json,
        Self::Markdown,
        Self::PlainText,
    ];

    /// The language whose [`name`](Self::name) is `name` (case-insensitive), e.g. the language an
    /// extension's grammar declares.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|l| l.name().eq_ignore_ascii_case(name))
    }

    /// Guesses the language from a file name's extension.
    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("rs") => Self::Rust,
            Some("py" | "pyw") => Self::Python,
            // `.h` is ambiguous C/C++; default to C (the C grammar also parses most headers).
            Some("c" | "h") => Self::C,
            Some("cpp" | "cc" | "cxx" | "c++" | "hpp" | "hh" | "hxx") => Self::Cpp,
            Some("asm" | "s" | "nasm" | "inc") => Self::Asm,
            Some("toml") => Self::Toml,
            Some("json") => Self::Json,
            Some("md" | "markdown") => Self::Markdown,
            _ => Self::PlainText,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rust => "Rust",
            Self::Python => "Python",
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Asm => "Assembly",
            Self::Toml => "TOML",
            Self::Json => "JSON",
            Self::Markdown => "Markdown",
            Self::PlainText => "Plain text",
        }
    }
}

/// An editable text document.
///
/// The text is a `ropey::Rope`: the editor widget edits it in place (O(log n) splices, cheap
/// snapshot clones for undo), and index math (char/byte/line) is O(log n). Consumers that
/// need a contiguous `&str` — tree-sitter, the LSP client, egui's galley — materialize one
/// per frame via `as_string()`.
pub struct Buffer {
    pub path: Option<PathBuf>,
    pub language: Language,
    /// A display name for an untitled buffer (e.g. a generated scratch), shown as the tab title
    /// until it is saved and gains a path. `None` for a plain untitled buffer.
    name: Option<String>,
    /// The text, edited in place by the editor widget.
    pub text: Rope,
    /// The text as last loaded or saved, to tell whether there are unsaved changes.
    saved_text: Rope,
}

impl Buffer {
    /// A new, empty, untitled buffer.
    pub fn untitled() -> Self {
        Self {
            path: None,
            language: Language::PlainText,
            name: None,
            text: Rope::new(),
            saved_text: Rope::new(),
        }
    }

    /// A named, pre-filled buffer with no file on disk yet (e.g. a decompiler port opened for
    /// editing). The language is inferred from `name`'s extension, and it starts out dirty so the
    /// title shows it is unsaved.
    pub fn scratch(name: &str, text: &str) -> Self {
        Self {
            path: None,
            language: Language::from_path(Path::new(name)),
            name: Some(name.to_string()),
            text: Rope::from_str(text),
            saved_text: Rope::new(),
        }
    }

    /// Loads a file into a buffer.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let rope = Rope::from_str(&text);
        Ok(Self {
            path: Some(path.to_path_buf()),
            language: Language::from_path(path),
            name: None,
            saved_text: rope.clone(),
            text: rope,
        })
    }

    /// The whole buffer as a `String` (O(n); callers cache it per frame).
    pub fn as_string(&self) -> String {
        self.text.to_string()
    }

    /// Whether the text differs from what is on disk.
    pub fn is_dirty(&self) -> bool {
        self.text != self.saved_text
    }

    /// Saves to the buffer's path. Returns an error if the buffer is untitled.
    pub fn save(&mut self) -> std::io::Result<()> {
        let path = self.path.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "this buffer has no file name yet",
            )
        })?;
        self.save_as(&path)
    }

    /// Saves to a specific path and adopts it.
    pub fn save_as(&mut self, path: &Path) -> std::io::Result<()> {
        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
        self.text.write_to(&mut file)?;
        std::io::Write::flush(&mut file)?;
        self.saved_text = self.text.clone();
        self.path = Some(path.to_path_buf());
        self.language = Language::from_path(path);
        Ok(())
    }

    /// A file name to seed a Save-As dialog: the current file's name, else a scratch's name,
    /// else a plain default.
    pub fn suggested_name(&self) -> String {
        self.path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .or_else(|| self.name.clone())
            .unwrap_or_else(|| "untitled.txt".into())
    }

    /// A short title for the tab: the file name (or "untitled"), with `*` when dirty.
    pub fn title(&self) -> String {
        let name = self
            .path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .or_else(|| self.name.clone())
            .unwrap_or_else(|| "untitled".into());
        if self.is_dirty() {
            format!("{name} *")
        } else {
            name
        }
    }

    /// Highlight tokens for the current text.
    pub fn tokens(&self) -> Vec<Token> {
        highlight(&self.as_string(), self.language)
    }
}
