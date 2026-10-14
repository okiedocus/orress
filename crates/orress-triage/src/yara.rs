//! A thin wrapper over YARA-X (VirusTotal's pure-Rust YARA engine): compile a rule and scan the
//! open file, returning structured matches for the UI. The YARA workbench uses this to let an
//! analyst write a rule and test it live against the sample and their library, generate a
//! starter rule from the sample's strings, and scan against a folder of rules.

use std::ops::Range;
use std::path::Path;
use std::time::{Duration, Instant};

/// Per-scan time limit for a file: a pathological rule (catastrophic regex, huge loops) must not
/// hang the workbench.
const FILE_SCAN_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-region time limit for process memory (regions can be large).
const REGION_SCAN_TIMEOUT: Duration = Duration::from_secs(30);
/// Overall budget for scanning all of a process's regions.
const MEMORY_SCAN_BUDGET: Duration = Duration::from_secs(120);

/// A readable message for a scan error, spelling out timeouts.
fn scan_error_message(e: &yara_x::ScanError, limit: Duration) -> String {
    match e {
        yara_x::ScanError::Timeout => format!(
            "scan timed out after {}s — a rule is too slow for this data (simplify regexes/loops)",
            limit.as_secs()
        ),
        other => other.to_string(),
    }
}

/// One matched location of a pattern.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub pattern: String,
    pub range: Range<usize>,
    /// A short preview of the matched bytes.
    pub preview: String,
}

/// A rule that matched, with its pattern matches.
#[derive(Debug, Clone)]
pub struct YaraHit {
    pub rule: String,
    pub matches: Vec<YaraMatch>,
}

/// The outcome of compiling and running a rule.
#[derive(Debug, Clone)]
pub enum YaraOutcome {
    Hits(Vec<YaraHit>),
    CompileError(String),
    ScanError(String),
}

/// The most matches recorded per pattern (keeps the UI bounded on noisy rules).
const MAX_MATCHES: usize = 200;

/// Compiles `rule_src` and scans `data`, returning the matches (or a compile/scan error).
pub fn scan(rule_src: &str, data: &[u8]) -> YaraOutcome {
    let rules = match yara_x::compile(rule_src) {
        Ok(r) => r,
        Err(e) => return YaraOutcome::CompileError(e.to_string()),
    };
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(FILE_SCAN_TIMEOUT);
    let results = match scanner.scan(data) {
        Ok(r) => r,
        Err(e) => return YaraOutcome::ScanError(scan_error_message(&e, FILE_SCAN_TIMEOUT)),
    };
    let mut hits = Vec::new();
    for rule in results.matching_rules() {
        let mut matches = Vec::new();
        for pattern in rule.patterns() {
            let pid = pattern.identifier().to_string();
            for m in pattern.matches().take(MAX_MATCHES) {
                matches.push(YaraMatch {
                    pattern: pid.clone(),
                    range: m.range(),
                    preview: preview(m.data()),
                });
            }
        }
        hits.push(YaraHit {
            rule: rule.identifier().to_string(),
            matches,
        });
    }
    YaraOutcome::Hits(hits)
}

/// One rule from a scanned library that matched the file.
#[derive(Debug, Clone)]
pub struct LibHit {
    /// The rule file (name only).
    pub file: String,
    pub rule: String,
    pub matches: usize,
}

/// Compiles every `.yar`/`.yara` file in `dir` and scans `data` with it, aggregating the rules
/// that matched. Returns `(hits, errors)` — files that failed to compile are listed in `errors`.
pub fn scan_dir(dir: &Path, data: &[u8]) -> (Vec<LibHit>, Vec<String>) {
    let mut hits = Vec::new();
    let mut errors = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return (hits, vec![format!("{}: {e}", dir.display())]),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("yar") && !ext.eq_ignore_ascii_case("yara") {
            continue;
        }
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("{file}: {e}"));
                continue;
            }
        };
        match scan(&src, data) {
            YaraOutcome::Hits(rule_hits) => {
                for h in rule_hits {
                    hits.push(LibHit {
                        file: file.clone(),
                        rule: h.rule,
                        matches: h.matches.len(),
                    });
                }
            }
            YaraOutcome::CompileError(e) | YaraOutcome::ScanError(e) => {
                errors.push(format!("{file}: {}", e.lines().next().unwrap_or("error")));
            }
        }
    }
    (hits, errors)
}

/// Generates a starter YARA rule from a sample's distinctive strings.
pub fn generate_rule(name: &str, strings: &[&str]) -> String {
    let mut chosen: Vec<&str> = strings
        .iter()
        .copied()
        .filter(|s| {
            let n = s.chars().count();
            (8..=60).contains(&n)
                && s.is_ascii()
                && s.bytes().all(|b| (0x20..0x7f).contains(&b))
                && !s.to_ascii_lowercase().ends_with(".dll")
                && s.chars().any(|c| c.is_ascii_alphabetic())
        })
        .collect();
    chosen.sort_by_key(|s| std::cmp::Reverse(s.len()));
    chosen.dedup();
    chosen.truncate(10);

    let ident = sanitize_ident(name);
    let mut out = format!(
        "rule {ident} {{\n    meta:\n        author = \"ORRESS\"\n        description = \"auto-generated from distinctive strings\"\n    strings:\n"
    );
    if chosen.is_empty() {
        out.push_str("        $a = \"CHANGE_ME\"\n    condition:\n        $a\n}\n");
        return out;
    }
    for (i, s) in chosen.iter().enumerate() {
        out.push_str(&format!("        $s{i} = \"{}\"\n", escape_yara(s)));
    }
    let need = chosen.len().min(3);
    out.push_str(&format!("    condition:\n        {need} of them\n}}\n"));
    out
}

fn sanitize_ident(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if s.is_empty() || s.as_bytes()[0].is_ascii_digit() {
        s.insert(0, 'r');
    }
    s
}

fn escape_yara(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A YARA match located in a running process's memory.
#[derive(Debug, Clone)]
pub struct MemHit {
    pub rule: String,
    pub pattern: String,
    pub address: u64,
    pub preview: String,
}

/// The outcome of an in-memory scan.
#[derive(Debug, Clone)]
pub enum MemScan {
    Hits(Vec<MemHit>),
    CompileError(String),
}

/// Compiles `rule_src` and scans each memory region (base address + bytes), reporting matches at
/// their absolute addresses. Matches that span a region boundary are not detected. Regions that
/// fail to scan (e.g. time out) are skipped; use [`scan_regions_report`] to see those errors.
pub fn scan_regions<'a>(
    rule_src: &str,
    regions: impl IntoIterator<Item = (u64, &'a [u8])>,
) -> MemScan {
    scan_regions_report(rule_src, regions).0
}

/// Like [`scan_regions`], but also returns the per-region scan errors (timeouts included, and a
/// note if the overall memory-scan budget ran out before every region was scanned).
pub fn scan_regions_report<'a>(
    rule_src: &str,
    regions: impl IntoIterator<Item = (u64, &'a [u8])>,
) -> (MemScan, Vec<String>) {
    let rules = match yara_x::compile(rule_src) {
        Ok(r) => r,
        Err(e) => return (MemScan::CompileError(e.to_string()), Vec::new()),
    };
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(REGION_SCAN_TIMEOUT);
    let started = Instant::now();
    let mut hits = Vec::new();
    let mut errors = Vec::new();
    for (base, data) in regions {
        if started.elapsed() > MEMORY_SCAN_BUDGET {
            errors.push(format!(
                "memory scan stopped after {}s; remaining regions were not scanned",
                MEMORY_SCAN_BUDGET.as_secs()
            ));
            break;
        }
        let results = match scanner.scan(data) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!(
                    "region {base:#x}: {}",
                    scan_error_message(&e, REGION_SCAN_TIMEOUT)
                ));
                continue;
            }
        };
        for rule in results.matching_rules() {
            let rname = rule.identifier().to_string();
            for pattern in rule.patterns() {
                let pid = pattern.identifier().to_string();
                for m in pattern.matches().take(MAX_MATCHES) {
                    hits.push(MemHit {
                        rule: rname.clone(),
                        pattern: pid.clone(),
                        address: base + m.range().start as u64,
                        preview: preview(m.data()),
                    });
                }
            }
        }
        if hits.len() > 2000 {
            break;
        }
    }
    (MemScan::Hits(hits), errors)
}

/// A short printable preview of matched bytes (ASCII where printable, else `.`).
fn preview(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(32)];
    let s: String = shown
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if bytes.len() > 32 {
        format!("{s}…")
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_a_string_rule() {
        let rule = r#"rule finds_malware { strings: $a = "malware" condition: $a }"#;
        let data = b"this sample contains malware right here";
        match scan(rule, data) {
            YaraOutcome::Hits(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].rule, "finds_malware");
                assert_eq!(hits[0].matches.len(), 1);
                assert_eq!(hits[0].matches[0].range.start, 21);
                assert_eq!(hits[0].matches[0].preview, "malware");
            }
            other => panic!("expected hits, got {other:?}"),
        }
    }

    #[test]
    fn reports_compile_errors() {
        let out = scan("rule broken { condition: $nope }", b"x");
        assert!(matches!(out, YaraOutcome::CompileError(_)));
    }

    #[test]
    fn no_match_is_empty() {
        let rule = r#"rule no_hit { strings: $a = "zzzz" condition: $a }"#;
        match scan(rule, b"abcd") {
            YaraOutcome::Hits(hits) => assert!(hits.is_empty()),
            other => panic!("expected empty hits, got {other:?}"),
        }
    }

    #[test]
    fn generated_rule_compiles_and_matches() {
        let strings = [
            "this is a distinctive marker string",
            "AnotherUniqueToken_12345",
            "short",
        ];
        let rule = generate_rule("my sample.exe", &strings);
        assert!(rule.contains("rule my_sample_exe"));
        // Short strings are filtered out.
        assert!(!rule.contains("short"));
        let data = b"this is a distinctive marker string and AnotherUniqueToken_12345 too";
        assert!(matches!(scan(&rule, data), YaraOutcome::Hits(h) if !h.is_empty()));
    }

    #[test]
    fn generated_rule_escapes_quotes() {
        let rule = generate_rule("t", &["string with \"quotes\" and a marker"]);
        assert!(rule.contains("\\\"quotes\\\""));
        assert!(!matches!(scan(&rule, b""), YaraOutcome::CompileError(_)));
    }

    #[test]
    fn scan_regions_maps_absolute_addresses() {
        let rule = r#"rule mem { strings: $a = "INJECTED" condition: $a }"#;
        let r1: &[u8] = b"...nothing here...";
        let r2: &[u8] = b"junk INJECTED junk"; // "INJECTED" at offset 5
        let regions = [(0x10000u64, r1), (0x7fff_0000u64, r2)];
        match scan_regions(rule, regions) {
            MemScan::Hits(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].rule, "mem");
                assert_eq!(hits[0].address, 0x7fff_0000 + 5);
                assert_eq!(hits[0].preview, "INJECTED");
            }
            MemScan::CompileError(e) => panic!("compile error: {e}"),
        }
        let (out, errors) = scan_regions_report(rule, [(0x1000u64, r2)]);
        assert!(matches!(out, MemScan::Hits(h) if h.len() == 1));
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn timeouts_are_reported_clearly() {
        let msg = scan_error_message(&yara_x::ScanError::Timeout, FILE_SCAN_TIMEOUT);
        assert!(msg.contains("timed out after 10s"), "{msg}");
    }

    #[test]
    fn scan_dir_aggregates_library_hits() {
        let dir = std::env::temp_dir().join(format!("orress_yara_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("r.yar"),
            r#"rule lib_rule { strings: $a = "needle" condition: $a }"#,
        )
        .unwrap();
        let (hits, errors) = scan_dir(&dir, b"a haystack with a needle inside");
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "lib_rule");
        assert_eq!(hits[0].file, "r.yar");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
