//! Byte-level tools that work on any data, whatever its file format:
//! entropy, string extraction, pattern search and value decoding (the data inspector).

pub mod entropy;
pub mod inspect;
pub mod search;
pub mod strings;

/// Byte order of multi-byte values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Endian {
    /// Least significant byte first. x86, x64 and most ARM systems.
    #[default]
    Little,
    /// Most significant byte first. Network protocols, older MIPS/PowerPC, Java class files.
    Big,
}

impl Endian {
    pub fn name(self) -> &'static str {
        match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        }
    }
}
