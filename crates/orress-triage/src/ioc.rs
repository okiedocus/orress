//! Indicator-of-compromise extraction from a sample's strings: URLs, domains, IPv4 addresses,
//! emails, registry keys, file paths, named-object namespaces (mutexes/events) and crypto wallet
//! addresses. Values can be defanged for safe sharing (`http` → `hxxp`, `.` → `[.]`).

use std::collections::BTreeSet;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IocKind {
    Url,
    Domain,
    Ipv4,
    Email,
    RegistryKey,
    FilePath,
    Namespace,
    CryptoWallet,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Url => "URLs",
            Self::Domain => "Domains",
            Self::Ipv4 => "IPv4 addresses",
            Self::Email => "Emails",
            Self::RegistryKey => "Registry keys",
            Self::FilePath => "File paths",
            Self::Namespace => "Named objects (mutex/event)",
            Self::CryptoWallet => "Crypto wallets",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
}

struct Patterns {
    url: Regex,
    email: Regex,
    ipv4: Regex,
    domain: Regex,
    registry: Regex,
    win_path: Regex,
    env_path: Regex,
    unc_path: Regex,
    namespace: Regex,
    btc: Regex,
    eth: Regex,
}

fn patterns() -> &'static Patterns {
    use std::sync::OnceLock;
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        url: Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s"'<>\)\]]+"#).unwrap(),
        email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
        ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        domain: Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
            .unwrap(),
        registry: Regex::new(r#"(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s"'<>]+"#).unwrap(),
        win_path: Regex::new(r#"\b[A-Za-z]:\\[^\s"'<>|*?]+"#).unwrap(),
        env_path: Regex::new(r#"%[A-Za-z0-9_]+%[\\/][^\s"'<>|*?]*"#).unwrap(),
        unc_path: Regex::new(r#"\\\\[A-Za-z0-9._\-]+\\[^\s"'<>|*?]+"#).unwrap(),
        namespace: Regex::new(r#"(?i)\b(?:Global|Local|Session)\\[^\s"'<>]+"#).unwrap(),
        btc: Regex::new(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b")
            .unwrap(),
        eth: Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap(),
    })
}

/// File-looking "domains" that are almost always module names, not network hosts.
fn is_module_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const EXTS: &[&str] = &[
        // Binary / data / config files that look like `name.tld`.
        ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".bin", ".dat", ".tmp", ".log",
        ".txt", ".ini", ".cfg", ".obj", ".lib", ".pdb", ".so",
        // Source-file extensions that collide with TLDs (common in compiler/debug strings,
        // e.g. a Rust binary is full of `fmt.rs`, `mod.rs`). Kept out of network IOCs.
        ".rs", ".go", ".py", ".pyc", ".rb", ".c", ".h", ".cpp", ".hpp", ".cs", ".java", ".pl",
        ".rc", ".s", ".asm", ".inc", ".md", ".toml", ".json", ".xml", ".html", ".css",
    ];
    EXTS.iter().any(|e| lower.ends_with(e))
}

fn octets_valid(ip: &str) -> bool {
    ip.split('.')
        .all(|o| o.parse::<u16>().is_ok_and(|n| n <= 255))
}

/// Extracts and de-duplicates IOCs from `strings`.
pub fn extract(strings: &[&str]) -> Vec<Ioc> {
    let p = patterns();
    let mut set: BTreeSet<Ioc> = BTreeSet::new();
    let mut add = |kind: IocKind, value: &str| {
        set.insert(Ioc {
            kind,
            value: value.to_string(),
        });
    };
    for s in strings {
        // Spans already reported as a URL or email, so their hosts aren't repeated as domains.
        let mut covered: Vec<std::ops::Range<usize>> = Vec::new();
        for m in p.url.find_iter(s) {
            add(IocKind::Url, m.as_str().trim_end_matches(['.', ',', ';']));
            covered.push(m.range());
        }
        for m in p.email.find_iter(s) {
            add(IocKind::Email, m.as_str());
            covered.push(m.range());
        }
        for m in p.ipv4.find_iter(s) {
            if octets_valid(m.as_str()) {
                add(IocKind::Ipv4, m.as_str());
            }
        }
        for m in p.registry.find_iter(s) {
            add(IocKind::RegistryKey, m.as_str());
        }
        for m in p.win_path.find_iter(s) {
            add(IocKind::FilePath, m.as_str());
        }
        for m in p.env_path.find_iter(s) {
            add(IocKind::FilePath, m.as_str());
        }
        for m in p.unc_path.find_iter(s) {
            add(IocKind::FilePath, m.as_str());
        }
        for m in p.namespace.find_iter(s) {
            add(IocKind::Namespace, m.as_str());
        }
        for m in p.btc.find_iter(s) {
            add(IocKind::CryptoWallet, m.as_str());
        }
        for m in p.eth.find_iter(s) {
            add(IocKind::CryptoWallet, m.as_str());
        }
        // Domains last, skipping ones already captured as a URL/email host or module name.
        for m in p.domain.find_iter(s) {
            let d = m.as_str();
            let in_url_or_email = covered
                .iter()
                .any(|r| m.start() < r.end && r.start < m.end());
            if in_url_or_email || is_module_name(d) || octets_valid(d) {
                continue;
            }
            add(IocKind::Domain, d);
        }
    }
    set.into_iter().collect()
}

/// Defangs an IOC value for safe display/sharing.
pub fn defang(value: &str) -> String {
    value
        .replace("http", "hxxp")
        .replace("HTTP", "HXXP")
        .replace("://", "[://]")
        .replace('.', "[.]")
        .replace('@', "[@]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(iocs: &[Ioc], kind: IocKind) -> Vec<&str> {
        iocs.iter()
            .filter(|i| i.kind == kind)
            .map(|i| i.value.as_str())
            .collect()
    }

    #[test]
    fn extracts_mixed_iocs() {
        let strings = [
            "GET http://evil.example.com/payload.bin HTTP/1.1",
            "connect to 192.168.13.37",
            "C:\\Users\\victim\\AppData\\Roaming\\svch0st.exe",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Global\\MyEvilMutex",
            "contact: badguy@evil.example.com",
            "send BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "loaded kernel32.dll ok",
        ];
        let iocs = extract(&strings);
        assert!(
            kinds(&iocs, IocKind::Url)
                .iter()
                .any(|u| u.contains("evil.example.com/payload.bin"))
        );
        assert_eq!(kinds(&iocs, IocKind::Ipv4), vec!["192.168.13.37"]);
        assert!(
            kinds(&iocs, IocKind::RegistryKey)
                .iter()
                .any(|r| r.contains("CurrentVersion"))
        );
        assert!(
            kinds(&iocs, IocKind::FilePath)
                .iter()
                .any(|f| f.contains("svch0st.exe"))
        );
        assert!(
            kinds(&iocs, IocKind::Namespace)
                .iter()
                .any(|n| n.contains("MyEvilMutex"))
        );
        assert!(kinds(&iocs, IocKind::Email).contains(&"badguy@evil.example.com"));
        assert!(
            kinds(&iocs, IocKind::CryptoWallet)
                .iter()
                .any(|w| w.starts_with("1BvBM"))
        );
        // kernel32.dll must NOT be reported as a domain.
        assert!(!kinds(&iocs, IocKind::Domain).contains(&"kernel32.dll"));
    }

    #[test]
    fn source_filenames_are_not_domains() {
        // Rust/compiler debug strings are full of these — they must not pollute domain IOCs.
        let iocs = extract(&["at library/core/src/fmt.rs and mod.rs line 10"]);
        let domains = kinds(&iocs, IocKind::Domain);
        assert!(
            !domains.iter().any(|d| d.ends_with(".rs")),
            "got {domains:?}"
        );
    }

    #[test]
    fn url_and_email_hosts_are_not_repeated_as_domains() {
        let iocs = extract(&[
            "GET http://c2.example.net/x and mail ops@drop.example.org",
            "fallback host backup.example.com",
        ]);
        assert_eq!(kinds(&iocs, IocKind::Domain), vec!["backup.example.com"]);
        assert_eq!(kinds(&iocs, IocKind::Url).len(), 1);
        assert_eq!(kinds(&iocs, IocKind::Email), vec!["ops@drop.example.org"]);
    }

    #[test]
    fn defangs() {
        assert_eq!(defang("http://evil.com"), "hxxp[://]evil[.]com");
    }

    #[test]
    fn rejects_bad_octets() {
        let iocs = extract(&["version 999.999.1.0 build"]);
        assert!(kinds(&iocs, IocKind::Ipv4).is_empty());
    }
}
