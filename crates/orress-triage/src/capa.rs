//! Capability detection, capa-style: named, human-readable capabilities inferred from the
//! combination of imported APIs and strings a sample contains, each with the evidence that
//! triggered it and a MITRE ATT&CK technique. This is a defensive triage aid — it labels what a
//! sample *can* do so an analyst can confirm; nothing is executed.

use std::collections::BTreeSet;

/// A detected capability with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub name: &'static str,
    pub namespace: &'static str,
    pub attack: &'static str,
    pub evidence: Vec<String>,
}

/// A matching condition over a sample's imports and strings.
enum Cond {
    /// At least one of these API names is imported.
    ApiAny(&'static [&'static str]),
    /// All of these API names are imported.
    ApiAll(&'static [&'static str]),
    /// At least one of these substrings appears in a string (case-insensitive).
    StrAny(&'static [&'static str]),
    /// Any sub-condition matches.
    Any(&'static [Cond]),
}

struct Rule {
    name: &'static str,
    namespace: &'static str,
    attack: &'static str,
    cond: Cond,
}

/// Normalises an API name for matching: drop a leading `_`, a stdcall `@N` suffix and a trailing
/// A/W wideness suffix, lower-cased.
fn norm_api(name: &str) -> String {
    let n = name.trim_start_matches('_');
    let n = n.split('@').next().unwrap_or(n);
    let n = n
        .strip_suffix('A')
        .or_else(|| n.strip_suffix('W'))
        .unwrap_or(n);
    n.to_ascii_lowercase()
}

/// Evaluates a condition, returning the matched evidence if it holds.
fn eval(
    cond: &Cond,
    imports: &[(String, String)],
    strings_lc: &[(String, &str)],
) -> Option<Vec<String>> {
    match cond {
        Cond::ApiAny(names) => {
            let want: BTreeSet<String> = names.iter().map(|n| norm_api(n)).collect();
            let matched: Vec<String> = imports
                .iter()
                .filter(|(n, _)| want.contains(n))
                .map(|(_, orig)| orig.clone())
                .collect();
            (!matched.is_empty()).then_some(matched)
        }
        Cond::ApiAll(names) => {
            let mut evidence = Vec::new();
            for name in *names {
                let target = norm_api(name);
                let found = imports.iter().find(|(n, _)| *n == target);
                match found {
                    Some((_, orig)) => evidence.push(orig.clone()),
                    None => return None,
                }
            }
            Some(evidence)
        }
        Cond::StrAny(subs) => {
            let mut evidence = Vec::new();
            for sub in *subs {
                let needle = sub.to_ascii_lowercase();
                if let Some((_, orig)) = strings_lc.iter().find(|(lc, _)| lc.contains(&needle)) {
                    evidence.push(format!("\"{}\"", truncate(orig)));
                }
            }
            (!evidence.is_empty()).then_some(evidence)
        }
        Cond::Any(conds) => {
            let mut evidence = Vec::new();
            for c in *conds {
                if let Some(e) = eval(c, imports, strings_lc) {
                    evidence.extend(e);
                }
            }
            (!evidence.is_empty()).then_some(evidence)
        }
    }
}

fn truncate(s: &str) -> String {
    if s.chars().count() > 48 {
        format!("{}…", s.chars().take(48).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Detects capabilities from the sample's imported API names and strings.
pub fn detect(imports: &[&str], strings: &[&str]) -> Vec<Capability> {
    let imp: Vec<(String, String)> = imports
        .iter()
        .map(|&n| (norm_api(n), n.to_string()))
        .collect();
    let strings_lc: Vec<(String, &str)> = strings
        .iter()
        .map(|&s| (s.to_ascii_lowercase(), s))
        .collect();

    let mut out = Vec::new();
    for rule in RULES {
        if let Some(mut evidence) = eval(&rule.cond, &imp, &strings_lc) {
            evidence.sort();
            evidence.dedup();
            out.push(Capability {
                name: rule.name,
                namespace: rule.namespace,
                attack: rule.attack,
                evidence,
            });
        }
    }
    out
}

use Cond::{Any, ApiAll, ApiAny, StrAny};

/// The built-in capability rule set.
static RULES: &[Rule] = &[
    Rule {
        name: "Resolve functions dynamically",
        namespace: "load-code",
        attack: "T1027 Obfuscated Files",
        cond: ApiAll(&["GetProcAddress", "LoadLibrary"]),
    },
    Rule {
        name: "Inject code into another process",
        namespace: "injection",
        attack: "T1055 Process Injection",
        cond: Any(&[
            ApiAll(&["WriteProcessMemory", "CreateRemoteThread"]),
            ApiAll(&["VirtualAllocEx", "WriteProcessMemory"]),
            ApiAll(&["NtUnmapViewOfSection", "WriteProcessMemory"]),
        ]),
    },
    Rule {
        name: "Set a Windows hook (possible keylogger)",
        namespace: "collection",
        attack: "T1056.001 Keylogging",
        cond: Any(&[
            ApiAny(&["SetWindowsHookEx"]),
            ApiAny(&["GetAsyncKeyState", "GetKeyState", "GetKeyboardState"]),
        ]),
    },
    Rule {
        name: "Create or execute a process",
        namespace: "execution",
        attack: "T1106 Native API",
        cond: ApiAny(&[
            "CreateProcess",
            "WinExec",
            "ShellExecute",
            "ShellExecuteEx",
            "system",
        ]),
    },
    Rule {
        name: "Communicate over HTTP",
        namespace: "c2",
        attack: "T1071.001 Web Protocols",
        cond: Any(&[
            ApiAny(&[
                "InternetOpen",
                "InternetOpenUrl",
                "HttpOpenRequest",
                "HttpSendRequest",
                "WinHttpOpen",
                "WinHttpConnect",
                "WinHttpSendRequest",
            ]),
            StrAny(&["http://", "https://", "User-Agent:"]),
        ]),
    },
    Rule {
        name: "Communicate over raw sockets",
        namespace: "c2",
        attack: "T1095 Non-Application Layer Protocol",
        cond: ApiAny(&[
            "socket",
            "connect",
            "send",
            "recv",
            "WSASocket",
            "WSAStartup",
        ]),
    },
    Rule {
        name: "Download a file",
        namespace: "c2",
        attack: "T1105 Ingress Tool Transfer",
        cond: ApiAny(&["URLDownloadToFile", "InternetReadFile"]),
    },
    Rule {
        name: "Persist via registry Run key",
        namespace: "persistence",
        attack: "T1547.001 Registry Run Keys",
        cond: Any(&[
            StrAny(&["CurrentVersion\\Run", "\\Run"]),
            ApiAll(&["RegSetValueEx", "RegCreateKey"]),
        ]),
    },
    Rule {
        name: "Install or control a service",
        namespace: "persistence",
        attack: "T1543.003 Windows Service",
        cond: ApiAny(&[
            "CreateService",
            "OpenSCManager",
            "StartService",
            "ControlService",
        ]),
    },
    Rule {
        name: "Encrypt or decrypt data (CryptoAPI)",
        namespace: "crypto",
        attack: "T1573 Encrypted Channel",
        cond: ApiAny(&[
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptAcquireContext",
            "CryptGenKey",
            "BCryptEncrypt",
            "BCryptDecrypt",
        ]),
    },
    Rule {
        name: "Check for a debugger",
        namespace: "anti-analysis",
        attack: "T1622 Debugger Evasion",
        cond: Any(&[
            ApiAny(&[
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "OutputDebugString",
            ]),
            StrAny(&["\\\\.\\SICE", "\\\\.\\NTICE"]),
        ]),
    },
    Rule {
        name: "Timing-based anti-analysis",
        namespace: "anti-analysis",
        attack: "T1497.003 Time Based Evasion",
        cond: ApiAny(&["QueryPerformanceCounter", "GetTickCount", "GetTickCount64"]),
    },
    Rule {
        name: "Detect a virtual machine / sandbox",
        namespace: "anti-analysis",
        attack: "T1497.001 System Checks",
        cond: StrAny(&[
            "vmware",
            "virtualbox",
            "vbox",
            "qemu",
            "xen",
            "sandboxie",
            "wine_get_unix_file_name",
            "SbieDll.dll",
        ]),
    },
    Rule {
        name: "Enumerate running processes",
        namespace: "discovery",
        attack: "T1057 Process Discovery",
        cond: ApiAny(&[
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next",
            "EnumProcesses",
        ]),
    },
    Rule {
        name: "Gather host/user information",
        namespace: "discovery",
        attack: "T1082 System Information Discovery",
        cond: ApiAny(&[
            "GetComputerName",
            "GetUserName",
            "GetSystemInfo",
            "GetVersionEx",
            "GetNativeSystemInfo",
        ]),
    },
    Rule {
        name: "Capture the screen",
        namespace: "collection",
        attack: "T1113 Screen Capture",
        cond: ApiAll(&["BitBlt", "CreateCompatibleBitmap"]),
    },
    Rule {
        name: "Access the clipboard",
        namespace: "collection",
        attack: "T1115 Clipboard Data",
        cond: ApiAny(&["OpenClipboard", "GetClipboardData", "SetClipboardData"]),
    },
    Rule {
        name: "Write files to disk",
        namespace: "impact",
        attack: "T1105 Ingress Tool Transfer",
        cond: ApiAll(&["CreateFile", "WriteFile"]),
    },
    Rule {
        name: "Modify the registry",
        namespace: "persistence",
        attack: "T1112 Modify Registry",
        cond: ApiAny(&[
            "RegSetValueEx",
            "RegCreateKey",
            "RegDeleteValue",
            "RegDeleteKey",
        ]),
    },
    Rule {
        name: "Reference cryptocurrency / wallet",
        namespace: "impact",
        attack: "T1496 Resource Hijacking",
        cond: StrAny(&["bitcoin", "monero", "ethereum", "wallet.dat", "stratum+tcp"]),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn names(caps: &[Capability]) -> Vec<&str> {
        caps.iter().map(|c| c.name).collect()
    }

    #[test]
    fn detects_injection_and_dynamic_resolution() {
        let imports = [
            "GetProcAddress",
            "LoadLibraryA",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ];
        let caps = detect(&imports, &[]);
        let n = names(&caps);
        assert!(n.contains(&"Resolve functions dynamically"));
        assert!(n.contains(&"Inject code into another process"));
    }

    #[test]
    fn detects_http_from_strings_only() {
        let caps = detect(&[], &["connecting to http://c2.example/gate"]);
        assert!(names(&caps).contains(&"Communicate over HTTP"));
        let http = caps
            .iter()
            .find(|c| c.name == "Communicate over HTTP")
            .unwrap();
        assert!(!http.evidence.is_empty());
    }

    #[test]
    fn detects_vm_detection_and_persistence() {
        let caps = detect(
            &["RegSetValueExA", "RegCreateKeyExA"],
            &[
                "checking for VMware tools",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
        );
        let n = names(&caps);
        assert!(n.contains(&"Detect a virtual machine / sandbox"));
        assert!(n.contains(&"Persist via registry Run key"));
    }

    #[test]
    fn benign_imports_detect_little() {
        let caps = detect(&["printf", "malloc", "free"], &["hello world"]);
        assert!(caps.is_empty());
    }
}
