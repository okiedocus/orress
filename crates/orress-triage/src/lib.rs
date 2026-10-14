//! Static malware triage: assemble a report from a file's already-computed [`BinaryInfo`]
//! (hashes, sections, imports, detections) plus IOC extraction from its strings, grouped by the
//! behaviour each import enables and mapped to MITRE ATT&CK. Pure analysis — nothing runs.

use std::collections::BTreeMap;

use orress_loaders::apis::{self, ApiCategory};
use orress_loaders::{BinaryInfo, DetectionCategory};

pub mod capa;
pub mod config;
pub mod fuzzy;
pub mod hints;
pub mod ioc;
pub mod yara;

pub use capa::Capability;
pub use config::{Config, ConfigField};
pub use fuzzy::FuzzyHashes;
pub use ioc::{Ioc, IocKind};
pub use yara::{LibHit, MemHit, MemScan, YaraHit, YaraMatch, YaraOutcome};

/// Imports that enable one behaviour.
#[derive(Debug, Clone)]
pub struct BehaviorGroup {
    pub category: ApiCategory,
    pub attack: &'static str,
    pub apis: Vec<String>,
    pub suspicious: bool,
}

/// A static triage report.
#[derive(Debug, Clone)]
pub struct Report {
    /// Headline risk notes, most important first.
    pub flags: Vec<String>,
    /// Named capabilities inferred from imports + strings (capa-style).
    pub capabilities: Vec<Capability>,
    pub behaviors: Vec<BehaviorGroup>,
    pub iocs: Vec<Ioc>,
    /// Configurations recovered by the family/heuristic extractors.
    pub configs: Vec<Config>,
    /// Fuzzy/similarity hashes (TLSH, ssdeep).
    pub fuzzy: FuzzyHashes,
    /// A full Markdown rendering, for export.
    pub markdown: String,
}

/// A representative MITRE ATT&CK technique for a behaviour category.
fn attack(c: ApiCategory) -> &'static str {
    use ApiCategory::*;
    match c {
        Injection | Memory => "T1055 Process Injection",
        Network => "T1071 Application Layer Protocol",
        AntiDebug => "T1497 Sandbox Evasion / T1622 Debugger Evasion",
        Crypto => "T1573 Encrypted Channel / T1486 Data Encrypted",
        Process => "T1106 Native API",
        File => "T1005 Data from Local System",
        Registry => "T1112 Modify Registry / T1547 Autostart",
        DynamicLoading => "T1027 Obfuscation / T1620 Reflective Loading",
        Input => "T1056.001 Keylogging",
        Compare => "",
    }
}

/// Builds a triage report from `info`, the sample's extracted `strings`, and its raw bytes
/// (`data`, used for the fuzzy hashes).
pub fn build(info: &BinaryInfo, strings: &[&str], data: &[u8]) -> Report {
    // Group imports by behaviour category.
    let mut grouped: BTreeMap<ApiCategory, Vec<String>> = BTreeMap::new();
    for imp in &info.imports {
        if let Some(api) = apis::lookup(&imp.name) {
            let v = grouped.entry(api.category).or_default();
            if !v.iter().any(|n| n == &imp.name) {
                v.push(imp.name.clone());
            }
        }
    }
    let mut behaviors: Vec<BehaviorGroup> = grouped
        .into_iter()
        .map(|(category, apis)| BehaviorGroup {
            category,
            attack: attack(category),
            apis,
            suspicious: category.suspicious(),
        })
        .collect();
    // Suspicious behaviours first, then by name.
    behaviors.sort_by(|a, b| {
        b.suspicious
            .cmp(&a.suspicious)
            .then(a.category.name().cmp(b.category.name()))
    });

    let import_names: Vec<&str> = info.imports.iter().map(|i| i.name.as_str()).collect();
    let capabilities = capa::detect(&import_names, strings);
    let iocs = ioc::extract(strings);
    let configs = config::run_all(info, data, strings);
    let fuzzy = fuzzy::compute(data);
    let flags = risk_flags(info, &behaviors, &iocs);
    let markdown = render_markdown(
        info,
        &flags,
        &capabilities,
        &configs,
        &behaviors,
        &iocs,
        &fuzzy,
    );

    Report {
        flags,
        capabilities,
        behaviors,
        iocs,
        configs,
        fuzzy,
        markdown,
    }
}

fn risk_flags(info: &BinaryInfo, behaviors: &[BehaviorGroup], iocs: &[Ioc]) -> Vec<String> {
    let mut flags = Vec::new();
    for d in &info.detections {
        if d.category == DetectionCategory::Packer {
            flags.push(format!("Packed/obfuscated: {} ({})", d.name, d.evidence));
        }
    }
    if info.entropy > 7.2 {
        flags.push(format!(
            "High file entropy ({:.2}/8) — likely packed or encrypted",
            info.entropy
        ));
    }
    let suspicious: Vec<&str> = behaviors
        .iter()
        .filter(|b| b.suspicious)
        .map(|b| b.category.name())
        .collect();
    if !suspicious.is_empty() {
        flags.push(format!(
            "Suspicious capabilities: {}",
            suspicious.join(", ")
        ));
    }
    let net = iocs
        .iter()
        .filter(|i| matches!(i.kind, IocKind::Url | IocKind::Domain | IocKind::Ipv4))
        .count();
    if net > 0 {
        flags.push(format!("{net} network indicator(s) in strings"));
    }
    if let Some(pe) = &info.pe
        && !pe.has_signature
    {
        flags.push("No Authenticode signature".into());
    }
    flags
}

fn render_markdown(
    info: &BinaryInfo,
    flags: &[String],
    capabilities: &[Capability],
    configs: &[Config],
    behaviors: &[BehaviorGroup],
    iocs: &[Ioc],
    fuzzy: &FuzzyHashes,
) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "# Triage report\n");

    let _ = writeln!(s, "## Overview");
    let _ = writeln!(s, "- Format: {} ({})", info.format.name(), info.arch);
    let _ = writeln!(s, "- Size: {} bytes", info.size);
    let _ = writeln!(s, "- Entropy: {:.2}/8", info.entropy);
    let _ = writeln!(s, "- MD5: `{}`", info.hashes.md5);
    let _ = writeln!(s, "- SHA-256: `{}`", info.hashes.sha256);
    if let Some(h) = &info.hashes.imphash {
        let _ = writeln!(s, "- Imphash: `{h}`");
    }
    if let Some(t) = &fuzzy.tlsh {
        let _ = writeln!(s, "- TLSH: `{t}`");
    }
    let _ = writeln!(s, "- ssdeep: `{}`", fuzzy.ssdeep);
    let _ = writeln!(s);

    if !flags.is_empty() {
        let _ = writeln!(s, "## Risk flags");
        for f in flags {
            let _ = writeln!(s, "- {f}");
        }
        let _ = writeln!(s);
    }

    if !configs.is_empty() {
        let _ = writeln!(s, "## Extracted configuration");
        for c in configs {
            let _ = writeln!(s, "### {} _({})_", c.family, c.note);
            for f in &c.fields {
                let _ = writeln!(s, "- {}: `{}`", f.key, f.value);
            }
        }
        let _ = writeln!(s);
    }

    if !capabilities.is_empty() {
        let _ = writeln!(s, "## Capabilities");
        for c in capabilities {
            let att = if c.attack.is_empty() {
                String::new()
            } else {
                format!("  _[{}]_", c.attack)
            };
            let _ = writeln!(s, "- **{}** ({}){att}", c.name, c.namespace);
            let _ = writeln!(s, "  - evidence: {}", c.evidence.join(", "));
        }
        let _ = writeln!(s);
    }

    if !behaviors.is_empty() {
        let _ = writeln!(s, "## Imports by behaviour");
        for b in behaviors {
            let mark = if b.suspicious { " ⚠" } else { "" };
            let att = if b.attack.is_empty() {
                String::new()
            } else {
                format!("  _[{}]_", b.attack)
            };
            let _ = writeln!(
                s,
                "- **{}**{mark}{att}: {}",
                b.category.name(),
                b.apis.join(", ")
            );
        }
        let _ = writeln!(s);
    }

    if !iocs.is_empty() {
        let _ = writeln!(s, "## Indicators (defanged)");
        let mut kind = None;
        for i in iocs {
            if kind != Some(i.kind) {
                let _ = writeln!(s, "\n### {}", i.kind.label());
                kind = Some(i.kind);
            }
            let _ = writeln!(s, "- `{}`", ioc::defang(&i.value));
        }
        let _ = writeln!(s);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use orress_loaders::Import;

    fn imp(name: &str) -> Import {
        Import {
            library: "kernel32.dll".into(),
            name: name.into(),
        }
    }

    #[test]
    fn builds_report_with_behaviors_and_iocs() {
        let info = BinaryInfo {
            imports: vec![
                imp("WriteProcessMemory"),
                imp("CreateRemoteThread"),
                imp("InternetOpenA"),
                imp("printf"),
            ],
            ..Default::default()
        };
        let strings = ["beacon to http://c2.evil.example/gate.php"];
        let report = build(&info, &strings, b"sample bytes for hashing");

        // Injection + Network grouped; both suspicious.
        assert!(
            report
                .behaviors
                .iter()
                .any(|b| b.category == ApiCategory::Injection && b.apis.len() == 2)
        );
        assert!(
            report
                .behaviors
                .iter()
                .any(|b| b.category == ApiCategory::Network)
        );
        assert!(
            report
                .flags
                .iter()
                .any(|f| f.contains("Suspicious capabilities"))
        );
        assert!(report.iocs.iter().any(|i| i.kind == IocKind::Url));
        // Markdown is defanged.
        assert!(report.markdown.contains("hxxp[://]c2[.]evil"));
        assert!(report.markdown.contains("T1055"));
    }
}
