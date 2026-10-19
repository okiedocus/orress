//! Import and export of names and comments, so work can move between ORRESS, IDA, Ghidra,
//! radare2 and friends. Export is a small, portable JSON keyed by hex address; import reads
//! that JSON *or* a line-/CSV-based list (`addr name`, `name,addr`, …) by finding the
//! address and the name on each line, which covers most tools' plain exports. Pure Rust.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Annotations;

/// Names and comments keyed by address, parsed from an imported file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Imported {
    pub names: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
}

impl Imported {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.comments.is_empty()
    }
}

/// The JSON export shape: addresses as `0x…` strings so the file is readable and portable.
#[derive(Serialize, Deserialize, Default)]
struct Json {
    #[serde(default)]
    names: BTreeMap<String, String>,
    #[serde(default)]
    comments: BTreeMap<String, String>,
}

/// Exports the names and comments as portable JSON keyed by hex address.
pub fn export(a: &Annotations) -> String {
    let json = Json {
        names: a
            .names
            .iter()
            .map(|(k, v)| (format!("0x{k:x}"), v.clone()))
            .collect(),
        comments: a
            .comments
            .iter()
            .map(|(k, v)| (format!("0x{k:x}"), v.clone()))
            .collect(),
    };
    serde_json::to_string_pretty(&json).expect("interop export serialises")
}

/// Parses an imported annotations file: the JSON [`export`] format, or a line-based list where
/// each line holds a hex address and a name in either order (whitespace- or comma-separated,
/// quotes stripped — Ghidra/radare2/objdump plain exports).
pub fn parse(text: &str) -> Result<Imported, String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return parse_json(text);
    }
    Ok(parse_lines(text))
}

fn parse_json(text: &str) -> Result<Imported, String> {
    let json: Json = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let convert = |m: BTreeMap<String, String>| -> BTreeMap<u64, String> {
        m.into_iter()
            .filter_map(|(k, v)| parse_addr(&k).map(|a| (a, v)))
            .collect()
    };
    Ok(Imported {
        names: convert(json.names),
        comments: convert(json.comments),
    })
}

/// Line-based import: on each non-empty, non-`#` line, the first hex-address token is the
/// address and the first other non-empty token is the name. Header rows (no address) are
/// skipped, so a CSV with a `Name,Address` header just works.
fn parse_lines(text: &str) -> Imported {
    let mut names = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let fields: Vec<&str> = line
            .split([',', '\t', ' ', ';'])
            .map(|f| f.trim().trim_matches('"'))
            .filter(|f| !f.is_empty())
            .collect();
        let Some(addr) = fields.iter().find_map(|f| parse_addr(f)) else {
            continue; // header or junk line
        };
        // The name is the first field that is not the address token itself.
        if let Some(name) = fields
            .iter()
            .find(|f| parse_addr(f) != Some(addr) && !f.is_empty())
        {
            names.insert(addr, (*name).to_owned());
        }
    }
    Imported {
        names,
        comments: BTreeMap::new(),
    }
}

/// Parses a hex address: `0x401000`, `401000`, `00401000`. Returns `None` for non-hex.
fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_import_round_trip() {
        let mut a = Annotations::default();
        a.names.insert(0x401000, "main".into());
        a.names.insert(0x401100, "check_password".into());
        a.comments.insert(0x401005, "compares with s3cret".into());
        let imported = parse(&export(&a)).unwrap();
        assert_eq!(
            imported.names.get(&0x401000).map(String::as_str),
            Some("main")
        );
        assert_eq!(
            imported.comments.get(&0x401005).map(String::as_str),
            Some("compares with s3cret")
        );
        assert_eq!(imported.names.len(), 2);
    }

    #[test]
    fn line_based_addr_then_name() {
        let imported = parse("0x401000 main\n00401100 check\n# a comment\n").unwrap();
        assert_eq!(
            imported.names.get(&0x401000).map(String::as_str),
            Some("main")
        );
        assert_eq!(
            imported.names.get(&0x401100).map(String::as_str),
            Some("check")
        );
    }

    #[test]
    fn csv_name_then_addr_with_header() {
        // A Ghidra-style symbol CSV: name first, address second, with a header row.
        let csv = "\"Name\",\"Location\"\n\"main\",\"00401000\"\n\"decrypt\",\"0x401200\"\n";
        let imported = parse(csv).unwrap();
        assert_eq!(
            imported.names.get(&0x401000).map(String::as_str),
            Some("main")
        );
        assert_eq!(
            imported.names.get(&0x401200).map(String::as_str),
            Some("decrypt")
        );
        assert_eq!(imported.names.len(), 2, "header row skipped");
    }

    #[test]
    fn flat_json_and_bad_lines() {
        let imported = parse("{\"names\":{\"0x10\":\"a\"},\"comments\":{}}").unwrap();
        assert_eq!(imported.names.get(&0x10).map(String::as_str), Some("a"));
        // A line with no address contributes nothing.
        assert!(parse("just some prose\n").unwrap().is_empty());
    }
}
