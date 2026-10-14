//! A graded-hint engine for CTF/crackme challenges. From a sample's triage [`Report`] it infers
//! what *kind* of challenge it is and produces **graded hints** — a nudge, then a direction, then
//! a near-solution — so a learner is pointed forward without the answer being spoiled. Rule-based
//! (no model), so it is deterministic and testable.

use orress_loaders::apis::ApiCategory;
use orress_loaders::{BinaryInfo, DetectionCategory};

use crate::Report;

/// How much a hint gives away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintLevel {
    /// A gentle push in the right direction.
    Nudge,
    /// What to look for and roughly how.
    Direction,
    /// Almost the answer.
    Solution,
}

impl HintLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Nudge => "Nudge",
            Self::Direction => "Direction",
            Self::Solution => "Near solution",
        }
    }
}

/// One graded hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    pub level: HintLevel,
    pub text: String,
}

/// The inferred challenge category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Packed,
    Crypto,
    AntiDebug,
    Network,
    StringCompare,
    Generic,
}

impl ChallengeKind {
    fn describe(self) -> &'static str {
        match self {
            Self::Packed => {
                "a packed or encrypted binary — the real code is hidden until it's unpacked"
            }
            Self::Crypto => "a crypto challenge built around a known algorithm",
            Self::AntiDebug => "a challenge that resists debugging",
            Self::Network => "a sample that talks to the network (often for a C2 or the flag)",
            Self::StringCompare => "a password/flag check that compares your input against a value",
            Self::Generic => "a reverse-engineering challenge",
        }
    }
}

/// The classification and graded hints for a sample.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub kind: ChallengeKind,
    /// A one-line "this looks like …" summary.
    pub summary: String,
    /// Graded hints, easiest first.
    pub hints: Vec<Hint>,
    /// Suggested techniques/tools to try.
    pub techniques: Vec<&'static str>,
}

fn looks_like_flag(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("flag{") || l.contains("ctf{") || l.contains("key{") || l.contains("flag_")
}

/// Classifies a sample from its triage report and produces graded hints.
pub fn analyze(report: &Report, info: &BinaryInfo, strings: &[&str]) -> Challenge {
    let has = |c: ApiCategory| report.behaviors.iter().any(|b| b.category == c);
    let packed = info.entropy > 7.2
        || info
            .detections
            .iter()
            .any(|d| d.category == DetectionCategory::Packer);

    let flag = strings
        .iter()
        .find(|s| looks_like_flag(s))
        .map(|s| s.to_string());

    // Most salient classification first.
    let kind = if packed {
        ChallengeKind::Packed
    } else if has(ApiCategory::Crypto) {
        ChallengeKind::Crypto
    } else if has(ApiCategory::AntiDebug) {
        ChallengeKind::AntiDebug
    } else if has(ApiCategory::Network) {
        ChallengeKind::Network
    } else if has(ApiCategory::Compare) {
        ChallengeKind::StringCompare
    } else {
        ChallengeKind::Generic
    };

    let mut hints = Vec::new();
    // A plaintext flag already present is a near-solution regardless of kind.
    if let Some(f) = &flag {
        hints.push(Hint {
            level: HintLevel::Solution,
            text: format!(
                "A flag-format string is already in the binary: `{f}` — check the Strings view."
            ),
        });
    }
    hints.extend(kind_hints(kind));

    let flag_note = if flag.is_some() {
        " There's also a flag-looking string in it."
    } else {
        ""
    };
    Challenge {
        kind,
        summary: format!("This looks like {}.{flag_note}", kind.describe()),
        hints,
        techniques: techniques(kind),
    }
}

fn hint(level: HintLevel, text: &str) -> Hint {
    Hint {
        level,
        text: text.to_string(),
    }
}

fn kind_hints(kind: ChallengeKind) -> Vec<Hint> {
    use ChallengeKind::*;
    use HintLevel::*;
    match kind {
        Packed => vec![
            hint(
                Nudge,
                "The file looks packed or encrypted (high entropy or a known packer). You won't see the real logic until it's unpacked.",
            ),
            hint(
                Direction,
                "Find the original entry point: run it under the debugger and break after the unpacking stub (often a tail jump into another section), or step it in the Emulator.",
            ),
            hint(
                Solution,
                "Dump the unpacked image from memory once execution reaches the OEP, then re-analyze the dump. For UPX, `upx -d` restores it directly.",
            ),
        ],
        Crypto => vec![
            hint(
                Nudge,
                "Cryptographic constants were found — a known algorithm is involved.",
            ),
            hint(
                Direction,
                "Identify the algorithm from its constants (AES S-box, SHA/MD5 IVs, TEA delta, RC4 KSA, ChaCha \"expand 32-byte k\"), then find where the key and your input meet.",
            ),
            hint(
                Solution,
                "Recover the key/IV from the code or data and run the matching transform in the Workbench to decrypt.",
            ),
        ],
        AntiDebug => vec![
            hint(Nudge, "The program checks whether it's being debugged."),
            hint(
                Direction,
                "Locate the anti-debug check (IsDebuggerPresent, a PEB flag, ptrace, or a timing check) and see what branch it controls.",
            ),
            hint(
                Solution,
                "Patch the check to always take the \"not debugged\" path — invert the jump or NOP it — then continue.",
            ),
        ],
        Network => vec![
            hint(Nudge, "This sample talks to the network."),
            hint(
                Direction,
                "Follow the network APIs to the host/port and protocol; the C2 or the flag source is often in the strings or an embedded config.",
            ),
            hint(
                Solution,
                "Point it at the Sandbox fake network to capture its requests, or extract the endpoint from the config/strings directly.",
            ),
        ],
        StringCompare => vec![
            hint(
                Nudge,
                "Your input is compared against something — likely a password or flag check.",
            ),
            hint(
                Direction,
                "Break on the comparison (strcmp/strncmp/memcmp) and read the expected value, or look for a suspicious constant string.",
            ),
            hint(
                Solution,
                "The compared value is the answer — read it from the strings/data or the register at the compare. If it's computed (e.g. XOR with a key), recover it with the Emulator's side-channel solver or the symbolic solver.",
            ),
        ],
        Generic => vec![
            hint(
                Nudge,
                "Start from the strings and imports to form a hypothesis about what the program does.",
            ),
            hint(
                Direction,
                "Find `main`, follow how it reads your input, and locate the success/failure branch.",
            ),
            hint(
                Solution,
                "Work backward from the \"correct!\" message to the condition that guards it, and satisfy that condition.",
            ),
        ],
    }
}

fn techniques(kind: ChallengeKind) -> Vec<&'static str> {
    use ChallengeKind::*;
    match kind {
        Packed => vec!["unpacking", "debugger", "entropy map", "memory dump"],
        Crypto => vec![
            "crypto-constant detection",
            "Workbench transforms",
            "trace key setup",
        ],
        AntiDebug => vec!["anti-analysis detection", "patch & go", "debugger"],
        Network => vec![
            "IOC extraction",
            "fake network (Sandbox)",
            "config extractor",
        ],
        StringCompare => vec![
            "strings",
            "breakpoint on strcmp",
            "side-channel solver",
            "symbolic solver",
        ],
        Generic => vec!["strings", "functions", "disassembly", "decompiler"],
    }
}

#[cfg(test)]
mod hint_tests {
    use super::*;
    use orress_loaders::Import;

    fn imp(name: &str) -> Import {
        Import {
            library: "k.dll".into(),
            name: name.into(),
        }
    }

    fn challenge(info: BinaryInfo, strings: &[&str]) -> Challenge {
        let report = crate::build(&info, strings, b"data");
        analyze(&report, &info, strings)
    }

    #[test]
    fn classifies_packed_by_entropy() {
        let info = BinaryInfo {
            entropy: 7.9,
            ..Default::default()
        };
        let c = challenge(info, &[]);
        assert_eq!(c.kind, ChallengeKind::Packed);
        // Three graded hints, in order.
        let levels: Vec<HintLevel> = c.hints.iter().map(|h| h.level).collect();
        assert_eq!(
            levels,
            [HintLevel::Nudge, HintLevel::Direction, HintLevel::Solution]
        );
    }

    #[test]
    fn classifies_network() {
        let info = BinaryInfo {
            imports: vec![imp("InternetOpenA"), imp("send")],
            ..Default::default()
        };
        let c = challenge(info, &["GET http://c2.example/gate"]);
        assert_eq!(c.kind, ChallengeKind::Network);
    }

    #[test]
    fn classifies_string_compare_and_finds_flag() {
        let info = BinaryInfo {
            imports: vec![imp("strcmp")],
            ..Default::default()
        };
        let c = challenge(info, &["enter password:", "flag{h1nt_eng1ne}"]);
        assert_eq!(c.kind, ChallengeKind::StringCompare);
        // The plaintext flag surfaces as the first, near-solution hint.
        assert_eq!(c.hints[0].level, HintLevel::Solution);
        assert!(c.hints[0].text.contains("flag{h1nt_eng1ne}"));
    }

    #[test]
    fn generic_when_nothing_stands_out() {
        let info = BinaryInfo {
            imports: vec![imp("printf")],
            ..Default::default()
        };
        let c = challenge(info, &["hello"]);
        assert_eq!(c.kind, ChallengeKind::Generic);
        assert_eq!(c.hints.len(), 3);
        assert!(!c.techniques.is_empty());
    }
}
