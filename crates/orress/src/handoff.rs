//! Handing the open binary to an external guided tool.
//!
//! Some analysis is a procedure a person follows rather than a pass a machine runs, and a tool
//! built for that is a separate program with its own window. ORRESS can start one and tell it what
//! it already knows: the format, a packer it recognised, anti-debugging imports, the entry point.
//! Re-answering questions the tool on screen just answered is the fastest way to make a guided
//! procedure feel like paperwork.
//!
//! # Nothing here names a particular tool
//!
//! Deliberately. The tool is whatever `ORRESS_HANDOFF_TOOL` points at, the menu entry is titled
//! after that executable's own file name, and if the variable is unset or the path does not exist
//! **the action is never registered at all** -- so it appears in no menu, no command palette and no
//! keymap listing. The menu builder already skips an unregistered id, so one gate
//! covers every surface.
//!
//! That is a stronger guarantee than hiding a disabled button, and it is also why this module has
//! no default path to go looking for: a name compiled in here would be a name in ORRESS's public
//! source, visible whether or not the tool is installed.
//!
//! # What is sent
//!
//! Observations, not conclusions. The format and a named packer are things a loader read out of
//! the file with evidence; whether the code is "obfuscated", or which string is the failure
//! message, is a judgement the receiving tool should put to a person rather than inherit from a
//! detector. The file is JSON beside the target, so it is inspectable and removable, and the
//! receiving end is expected to treat every field as optional.

use std::path::{Path, PathBuf};

use orress_loaders::{BinaryInfo, DetectionCategory};

/// The environment variable naming the executable to hand off to.
pub const TOOL_ENV: &str = "ORRESS_HANDOFF_TOOL";

/// The action id. Neutral on purpose: the keymap and any saved layout persist it, so it must not
/// change, and it must not disclose what it points at.
pub const ACTION: &str = "tool::HandOff";

/// The external tool, if one is configured and present.
///
/// Returns `None` for an unset variable, an empty one, or a path that is not a file -- each of
/// which means the same thing to the caller: offer nothing.
pub fn tool() -> Option<PathBuf> {
    decide(std::env::var_os(TOOL_ENV).as_deref(), |p| p.is_file())
}

/// The decision behind [`tool`], with the environment and the filesystem passed in.
///
/// Separated so it can be tested at all: ORRESS forbids `unsafe`, `std::env::set_var` is unsafe in
/// this edition, and a test that mutates process-wide state to check a getter is a test that can
/// fail when another test runs beside it.
fn decide(raw: Option<&std::ffi::OsStr>, exists: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let raw = raw?;
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(raw);
    exists(&path).then_some(path)
}

/// What to call the menu entry: the executable's own file stem, title-cased on the first letter.
///
/// Taken from the path rather than written here, so the name a user sees is the name of the thing
/// they installed and ORRESS's source does not carry it.
pub fn title(tool: &Path) -> String {
    let stem = tool
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "External Tool".to_string());
    let mut cs = stem.chars();
    match cs.next() {
        Some(c) => format!("Open in {}{}", c.to_uppercase(), cs.as_str()),
        None => "Open in External Tool".to_string(),
    }
}

/// The hand-off JSON for `info`.
///
/// Field names are the receiving tool's vocabulary, and every one is omitted when unknown rather
/// than sent empty: a reader cannot distinguish "not packed" from "we did not look" if an absent
/// packer arrives as `""`, and guessing on its behalf is how a hand-off starts answering questions
/// it has no business answering.
pub fn payload(target: &Path, info: &BinaryInfo) -> String {
    let mut f = Vec::new();
    f.push(format!(
        "\"target\":{}",
        json_str(&target.file_name().unwrap_or_default().to_string_lossy())
    ));
    if !info.hashes.sha256.is_empty() {
        f.push(format!("\"sha256\":{}", json_str(&info.hashes.sha256)));
    }
    f.push(format!(
        "\"format\":{}",
        json_str(&format!("{:?}", info.format).to_lowercase())
    ));

    let named = |cat: DetectionCategory| {
        info.detections
            .iter()
            .find(|d| d.category == cat)
            .map(|d| d.name.clone())
    };
    if let Some(p) = named(DetectionCategory::Packer) {
        f.push(format!("\"packer\":{}", json_str(&p)));
    }
    if let Some(l) = named(DetectionCategory::Language) {
        f.push(format!("\"language\":{}", json_str(&l)));
    }

    // Imports whose names are the usual anti-debugging calls. A list, not a verdict: the receiving
    // tool decides what it means, and a person decides whether it matters.
    const ANTI_DEBUG: [&str; 6] = [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "QueryPerformanceCounter",
        "GetTickCount",
    ];
    let found: Vec<String> = info
        .imports
        .iter()
        .filter(|i| ANTI_DEBUG.iter().any(|a| i.name.starts_with(a)))
        .map(|i| i.name.clone())
        .collect();
    if !found.is_empty() {
        let list: Vec<String> = found.iter().map(|n| json_str(n)).collect();
        f.push(format!("\"anti_debug_imports\":[{}]", list.join(",")));
    }

    if let Some(e) = info.entry {
        f.push(format!("\"check_addr\":{e}"));
    }

    format!("{{{}}}", f.join(","))
}

/// Write the hand-off beside the target and start the tool on it.
///
/// The child is spawned and not waited for: this is a separate application with its own window,
/// and blocking ORRESS's UI thread on it would freeze the editor for as long as the person used
/// the other program.
pub fn launch(tool: &Path, target: &Path, info: &BinaryInfo) -> Result<PathBuf, String> {
    let beside = target.with_extension("orress.json");
    std::fs::write(&beside, payload(target, info))
        .map_err(|e| format!("could not write {}: {e}", beside.display()))?;
    std::process::Command::new(tool)
        .arg(target)
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", tool.display()))?;
    Ok(beside)
}

/// Minimal JSON string escaping. Enough for paths and detector names, which is all that goes in.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use orress_loaders::{Detection, Import};

    fn info() -> BinaryInfo {
        let mut i = BinaryInfo::default();
        i.hashes.sha256 = "deadbeef".into();
        i.entry = Some(0x401c30);
        i.detections.push(Detection {
            category: DetectionCategory::Packer,
            name: "UPX".into(),
            evidence: "section \"UPX0\"".into(),
            explain: "",
        });
        i.imports.push(Import {
            library: "kernel32.dll".into(),
            name: "IsDebuggerPresent".into(),
        });
        i.imports.push(Import {
            library: "msvcrt.dll".into(),
            name: "printf".into(),
        });
        i
    }

    #[test]
    fn the_payload_carries_observations() {
        let p = payload(Path::new("/tmp/crackme.exe"), &info());
        assert!(p.contains("\"target\":\"crackme.exe\""), "{p}");
        assert!(p.contains("\"sha256\":\"deadbeef\""), "{p}");
        assert!(p.contains("\"packer\":\"UPX\""), "{p}");
        assert!(p.contains("\"check_addr\":4201520"), "{p}");
        assert!(p.contains("\"IsDebuggerPresent\""), "{p}");
        assert!(!p.contains("printf"), "only the anti-debug imports: {p}");
    }

    /// An unknown field must be absent, not empty. A reader cannot tell "not packed" from "nobody
    /// looked" if it arrives as `""`, and that distinction is the whole value of the hand-off.
    #[test]
    fn an_unknown_field_is_omitted_rather_than_sent_empty() {
        let p = payload(Path::new("x.bin"), &BinaryInfo::default());
        assert!(!p.contains("packer"), "{p}");
        assert!(!p.contains("language"), "{p}");
        assert!(!p.contains("anti_debug_imports"), "{p}");
        assert!(!p.contains("sha256"), "{p}");
        assert!(p.contains("\"format\""), "the format is always known: {p}");
    }

    #[test]
    fn the_title_comes_from_the_executable_not_from_here() {
        assert_eq!(
            title(Path::new("/opt/someguide/someguide.exe")),
            "Open in Someguide"
        );
        assert_eq!(title(Path::new("tool")), "Open in Tool");
    }

    /// The whole privacy property in one test: without a tool there is no action, and therefore
    /// no entry in any menu, command palette or keymap listing, because every one of those
    /// resolves ids through the registry and the registry never gets it.
    #[test]
    fn nothing_is_offered_unless_a_tool_is_configured_and_present() {
        let yes = |_: &Path| true;
        let no = |_: &Path| false;
        assert!(decide(None, yes).is_none(), "unset must offer nothing");
        assert!(
            decide(Some(std::ffi::OsStr::new("")), yes).is_none(),
            "empty must offer nothing"
        );
        assert!(
            decide(Some(std::ffi::OsStr::new("/opt/tool")), no).is_none(),
            "a configured path that is not there must offer nothing"
        );
        assert_eq!(
            decide(Some(std::ffi::OsStr::new("/opt/tool")), yes),
            Some(PathBuf::from("/opt/tool")),
            "and only a path that exists is offered"
        );
    }

    #[test]
    fn json_escaping_survives_an_awkward_name() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("line\nbreak"), "\"line\\nbreak\"");
    }
}
