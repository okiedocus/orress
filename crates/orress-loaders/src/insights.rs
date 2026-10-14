//! Beginner-friendly observations and next steps, derived from the triage results.

use std::collections::BTreeMap;

use crate::apis::{self, ApiCategory};
use crate::model::*;

pub fn insights(info: &BinaryInfo) -> Vec<Insight> {
    let mut out = Vec::new();
    let mut push = |level, title: &str, body: String| {
        out.push(Insight {
            level,
            title: title.to_owned(),
            body,
        });
    };

    let mut by_category: BTreeMap<ApiCategory, Vec<&str>> = BTreeMap::new();
    for import in &info.imports {
        if let Some(api) = apis::lookup(&import.name) {
            let list = by_category.entry(api.category).or_default();
            if !list.contains(&api.name) {
                list.push(api.name);
            }
        }
    }
    let names = |c: ApiCategory| by_category.get(&c).map(|v| v.join(", "));

    let packed = info
        .detections
        .iter()
        .find(|d| d.category == DetectionCategory::Packer);
    if let Some(p) = packed {
        push(
            InsightLevel::Warning,
            "The program is packed",
            format!(
                "{} detected ({}). What you see in the file is mostly the unpacker; the real \
                 code is created in memory at run time. Unpack it first, then analyze the result.",
                p.name, p.evidence
            ),
        );
    }

    if let Some(list) = names(ApiCategory::AntiDebug) {
        // The Microsoft C runtime start-up code imports these two in nearly every Windows
        // program (also Rust ones), so on their own they are not a red flag.
        let runtime_only = info.format == Format::Pe
            && by_category.get(&ApiCategory::AntiDebug).is_some_and(|l| {
                l.iter()
                    .all(|n| matches!(*n, "IsDebuggerPresent" | "QueryPerformanceCounter"))
            });
        if runtime_only {
            push(
                InsightLevel::Info,
                "Debugger checks (probably harmless)",
                format!(
                    "Imports {list}. Microsoft's C runtime imports these in almost every Windows \
                     program for its own start-up and crash handling. They only matter if the \
                     program's own code calls them: check their cross-references."
                ),
            );
        } else {
            push(
                InsightLevel::Warning,
                "Anti-debugging",
                format!(
                    "Imports {list}. The program may act differently when it notices a debugger. \
                     Find where these are called and patch the check, or hide the debugger."
                ),
            );
        }
    }

    if let Some(list) = names(ApiCategory::Compare) {
        push(
            InsightLevel::Tip,
            "It compares strings",
            format!(
                "Imports {list}. In a crackme, your input is often compared with the expected \
                 password here. Find the calls (cross-references), or break on them in a \
                 debugger and read both arguments."
            ),
        );
    }

    if let Some(list) = names(ApiCategory::Input) {
        push(
            InsightLevel::Info,
            "Where input comes from",
            format!("Reads input with {list}. Follow the buffer it fills to find the check."),
        );
    }

    if let Some(list) = names(ApiCategory::Crypto) {
        push(
            InsightLevel::Info,
            "Cryptography",
            format!(
                "Imports {list}. Encrypted strings, configuration or network traffic are likely. \
                 The key is usually nearby: look at the arguments."
            ),
        );
    }

    if let Some(list) = names(ApiCategory::Injection) {
        push(
            InsightLevel::Warning,
            "Code injection capability",
            format!(
                "Imports {list}. Together these can write code into another process and run \
                 it, a common malware technique. Analyze only in an isolated VM."
            ),
        );
    }

    if let Some(list) = names(ApiCategory::Network) {
        push(
            InsightLevel::Info,
            "Network activity",
            format!("Imports {list}. Look for IP addresses, domains and URLs in the strings."),
        );
    }

    let few_imports = info.format == Format::Pe && info.imports.len() < 10;
    if few_imports && info.imports_api(&["GetProcAddress", "LoadLibraryA", "LoadLibraryW"]) {
        push(
            InsightLevel::Warning,
            "Imports resolved at run time",
            format!(
                "Only {} imports, including LoadLibrary/GetProcAddress. The program looks up \
                 the functions it really uses while running, which hides them from this list. \
                 Typical for packers and malware.",
                info.imports.len()
            ),
        );
    }

    if let Some(pe) = &info.pe
        && pe.has_tls
    {
        push(
            InsightLevel::Tip,
            "TLS callbacks",
            "This file has a TLS directory. TLS callbacks run before the entry point, so code \
             there runs before a debugger that breaks on the entry point stops. Check them for \
             hidden checks."
                .to_owned(),
        );
    }

    let stripped = info
        .protections
        .iter()
        .any(|p| p.name == "Stripped" && p.state == ProtectionState::On);
    if stripped && info.format != Format::Unknown {
        push(
            InsightLevel::Info,
            "No function names",
            "The binary is stripped. Functions will show up as sub_401000 and similar. Start \
             from the entry point or from interesting strings and imports, and name functions \
             as you understand them."
                .to_owned(),
        );
    }

    if info.format == Format::Unknown {
        push(
            InsightLevel::Info,
            "Not an executable",
            "ORRESS could not parse this as a program. Check the detected file type, the \
             strings and the entropy graph to work out what it is."
                .to_owned(),
        );
    } else {
        push(
            InsightLevel::Tip,
            "Suggested first steps",
            "1. Open Strings and look for messages like \"Correct!\", \"Wrong\" or flag-like \
             text.\n2. Check Imports for what the program can do.\n3. Press Ctrl+Shift+M to jump \
             to main and read the disassembly."
                .to_owned(),
        );
    }

    out.sort_by_key(|i| i.level);
    out
}
