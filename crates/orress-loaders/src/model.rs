use std::ops::Range;

pub use orress_bytes::Endian;

use crate::Hashes;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Format {
    Pe,
    Elf,
    MachO,
    Coff,
    Wasm,
    Xcoff,
    /// Not an executable format ORRESS can parse (yet). See the detections for a guess.
    #[default]
    Unknown,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pe => "PE (Windows executable)",
            Self::Elf => "ELF (Linux/Unix executable)",
            Self::MachO => "Mach-O (macOS/iOS executable)",
            Self::Coff => "COFF object file",
            Self::Wasm => "WebAssembly module",
            Self::Xcoff => "XCOFF (AIX executable)",
            Self::Unknown => "Unknown format",
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            Self::Pe => {
                "Portable Executable: the format of Windows programs (.exe), libraries (.dll) \
                 and drivers (.sys). It starts with \"MZ\" (an old DOS header), followed by \
                 a \"PE\" header that describes sections, imports and the entry point."
            }
            Self::Elf => {
                "Executable and Linkable Format: used by Linux, BSD, Android native code and \
                 most embedded systems. It starts with the bytes 7F 45 4C 46 (\".ELF\"). \
                 Most CTF reversing challenges are ELF files."
            }
            Self::MachO => {
                "Mach-O: the format of macOS and iOS programs. It contains load commands \
                 that describe segments, libraries and the entry point."
            }
            Self::Coff => {
                "COFF: an object file produced by a compiler before linking (.obj on \
                 Windows). It contains code but is not a runnable program yet."
            }
            Self::Wasm => {
                "WebAssembly: portable bytecode that runs in browsers and in runtimes like \
                 wasmtime. It starts with \"\\0asm\"."
            }
            Self::Xcoff => "XCOFF: the executable format of IBM AIX.",
            Self::Unknown => {
                "ORRESS could not parse this as an executable. It may be data, an archive, \
                 a document or something packed or encrypted. The hex view and the strings \
                 list still work."
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    Executable,
    Library,
    Object,
    Core,
    #[default]
    Unknown,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Executable => "Executable program",
            Self::Library => "Shared library (DLL / .so / .dylib)",
            Self::Object => "Object file (not linked)",
            Self::Core => "Core dump",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Perms {
    pub fn label(self) -> String {
        format!(
            "{}{}{}",
            if self.read { 'R' } else { '-' },
            if self.write { 'W' } else { '-' },
            if self.execute { 'X' } else { '-' }
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Section {
    pub name: String,
    /// File offset and size of the section's bytes in the file (0 size for `.bss`-like
    /// sections that only exist in memory).
    pub offset: u64,
    pub file_size: u64,
    /// Address when loaded in memory (virtual address).
    pub address: u64,
    pub virtual_size: u64,
    pub perms: Perms,
    pub entropy: Option<f32>,
}

impl Section {
    pub fn file_range(&self) -> Option<Range<usize>> {
        if self.file_size == 0 {
            return None;
        }
        let start = usize::try_from(self.offset).ok()?;
        let end = start.checked_add(usize::try_from(self.file_size).ok()?)?;
        Some(start..end)
    }

    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.offset && offset - self.offset < self.file_size
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Segment {
    pub name: Option<String>,
    pub offset: u64,
    pub file_size: u64,
    pub address: u64,
    pub virtual_size: u64,
    pub perms: Perms,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// DLL or shared library name. Empty for ELF, where the library is not recorded
    /// per symbol.
    pub library: String,
    /// Function name, or `#123` for imports by ordinal number.
    pub name: String,
}

/// A name for an address (symbol, import slot ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedAddress {
    pub address: u64,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub address: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeDetails {
    /// Link time from the PE header (seconds since 1970). Often faked by malware, and
    /// replaced by a hash in reproducible builds.
    pub timestamp: u32,
    pub subsystem: String,
    pub linker_version: (u8, u8),
    pub is_dotnet: bool,
    pub has_signature: bool,
    pub has_tls: bool,
    /// Rich header entries (product id, build, count): tools that built the file.
    pub rich: Vec<(u16, u16, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionState {
    On,
    Partial,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protection {
    pub name: &'static str,
    pub state: ProtectionState,
    pub detail: String,
    /// What it is and what it means for a reverse engineer.
    pub explain: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionCategory {
    Packer,
    Language,
    Compiler,
    Installer,
    FileType,
}

impl DetectionCategory {
    pub fn name(self) -> &'static str {
        match self {
            Self::Packer => "Packer / protector",
            Self::Language => "Language",
            Self::Compiler => "Compiler",
            Self::Installer => "Installer / bundler",
            Self::FileType => "File type",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub category: DetectionCategory,
    pub name: String,
    /// What was found, e.g. `section "UPX0"`.
    pub evidence: String,
    pub explain: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InsightLevel {
    Warning,
    Tip,
    Info,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insight {
    pub level: InsightLevel,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Default)]
pub struct BinaryInfo {
    pub format: Format,
    pub kind: Kind,
    /// Human-readable architecture, e.g. "x86-64".
    pub arch: String,
    pub bits: Option<u8>,
    pub endian: Endian,
    /// Entry point address (where execution starts), if any.
    pub entry: Option<u64>,
    /// Preferred load address (PE image base, lowest ELF segment address).
    pub image_base: u64,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    /// Memory slots holding imported function addresses (PE IAT, ELF GOT).
    pub import_slots: Vec<NamedAddress>,
    /// Named functions from symbol tables, sorted by address.
    pub function_symbols: Vec<NamedAddress>,
    /// Function start addresses from exception tables (x64 PE .pdata).
    pub function_starts: Vec<u64>,
    pub symbol_count: usize,
    pub has_debug_info: bool,
    pub pe: Option<PeDetails>,
    pub protections: Vec<Protection>,
    pub detections: Vec<Detection>,
    pub insights: Vec<Insight>,
    pub hashes: Hashes,
    /// Entropy of the whole file.
    pub entropy: f32,
    pub size: u64,
    pub parse_error: Option<String>,
}

impl BinaryInfo {
    /// File ranges that map to memory: sections first, then segments (ELF files
    /// without section headers only have segments).
    fn mappings(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.sections
            .iter()
            .filter(|s| s.address != 0)
            .map(|s| (s.offset, s.file_size, s.address))
            .chain(
                self.segments
                    .iter()
                    .map(|s| (s.offset, s.file_size, s.address)),
            )
            .filter(|&(_, size, _)| size > 0)
    }

    /// Virtual address where the byte at file `offset` is loaded, if it is loaded.
    pub fn offset_to_address(&self, offset: u64) -> Option<u64> {
        self.mappings()
            .find(|&(off, size, _)| offset >= off && offset - off < size)
            .and_then(|(off, _, addr)| addr.checked_add(offset - off))
    }

    /// File offset of virtual address `address`, if that address is backed by the file.
    pub fn address_to_offset(&self, address: u64) -> Option<u64> {
        self.mappings()
            .find(|&(_, size, addr)| address >= addr && address - addr < size)
            .and_then(|(off, _, addr)| off.checked_add(address - addr))
    }

    pub fn section_at_offset(&self, offset: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_offset(offset))
    }

    pub fn entry_offset(&self) -> Option<u64> {
        self.entry.and_then(|e| self.address_to_offset(e))
    }

    pub fn imports_api(&self, names: &[&str]) -> bool {
        self.imports
            .iter()
            .any(|i| names.iter().any(|n| i.name.eq_ignore_ascii_case(n)))
    }
}
