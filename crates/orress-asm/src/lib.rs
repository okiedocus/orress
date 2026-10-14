//! ORRESS assembler: turn assembly **text** into machine-code **bytes**, so a reverse engineer
//! can write a few instructions in the editor and patch them into a binary.
//!
//! The public surface is deliberately small: [`assemble`] takes source text, a target [`Arch`]
//! and the address the code will live at, and returns the bytes plus a per-line [`LineOutput`]
//! listing (for an `addr: bytes  source` view) — or a list of [`Diagnostic`]s, each tied to the
//! offending source line so the editor can underline it.
//!
//! Each architecture lives behind its own module (`x64`, `arm64`) with the same `assemble`
//! shape, so a new back end (another ISA, or a different encoder crate) slots in by adding an
//! [`Arch`] variant and a module — callers never change. x86-64 is encoded with the pure-Rust `iced-x86` `code_asm`
//! back end, which also resolves relative branches to labels for us.

mod arm64;
mod parse;
mod x64;

/// Target instruction set. More variants (32-bit x86, …) slot in behind the same `assemble`
/// boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Arch {
    /// 64-bit x86 (Intel syntax).
    X64,
    /// 64-bit Arm (AArch64 / A64).
    Arm64,
}

impl Arch {
    /// A short, stable name for menus and settings.
    pub fn label(self) -> &'static str {
        match self {
            Arch::X64 => "x86-64",
            Arch::Arm64 => "ARM64",
        }
    }
}

/// One source line's contribution to the output: its address, the bytes it encoded to (empty for
/// a blank line, a comment, or a bare label), and the original text. This is the listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineOutput {
    /// 1-based source line number.
    pub line: usize,
    /// Address of this line's first byte (`base_addr` + offset so far).
    pub address: u64,
    /// The machine-code bytes this line encoded to.
    pub bytes: Vec<u8>,
    /// The original source text, trimmed.
    pub source: String,
}

/// A problem found while assembling, anchored to a source line so the editor can mark it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// 1-based source line the problem is on (0 if it is not line-specific).
    pub line: usize,
    /// Human-readable explanation.
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn new(line: usize, message: impl Into<String>) -> Self {
        Diagnostic {
            line,
            message: message.into(),
        }
    }
}

/// A successful assembly: the full byte output and the per-line listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assembled {
    /// The complete machine-code output, in order.
    pub bytes: Vec<u8>,
    /// Per-source-line breakdown, in source order.
    pub lines: Vec<LineOutput>,
}

/// Assemble `source` for `arch`, laying the code out as if it starts at `base_addr` (which affects
/// RIP-relative and branch encoding, so patches land correctly). On any error, returns every
/// [`Diagnostic`] found rather than just the first.
pub fn assemble(source: &str, arch: Arch, base_addr: u64) -> Result<Assembled, Vec<Diagnostic>> {
    match arch {
        Arch::X64 => x64::assemble(source, base_addr),
        Arch::Arm64 => arm64::assemble(source, base_addr),
    }
}
