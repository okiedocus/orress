//! Executable format loading and file triage.
//!
//! [`triage`] turns raw bytes into a [`BinaryInfo`]: format, architecture, sections,
//! imports and exports, security protections, compiler and packer detections, hashes,
//! and beginner-friendly insights ("this program compares strings: set a breakpoint on
//! strcmp"). It never executes anything and works on hostile input.

pub mod apis;
mod code_hints;
mod detect;
mod hashes;
mod insights;
mod model;
mod parse;
mod protections;
pub mod sections;

pub use apis::{ApiCategory, ApiInfo};
pub use hashes::Hashes;
pub use model::*;

/// Analyzes `data`. Parse errors are recorded in [`BinaryInfo::parse_error`], so this
/// always returns something useful (at least hashes, entropy and a format guess).
pub fn triage(data: &[u8]) -> BinaryInfo {
    let mut info = parse::parse(data);
    info.size = data.len() as u64;
    info.hashes = Hashes::compute(data, &info.imports, info.format == Format::Pe);
    info.entropy = orress_bytes::entropy::shannon(data);
    for section in &mut info.sections {
        section.entropy = section
            .file_range()
            .and_then(|r| data.get(r))
            .map(orress_bytes::entropy::shannon);
    }
    info.detections = detect::detect(data, &info);
    info.insights = insights::insights(&info);
    info
}

#[cfg(test)]
mod tests;
