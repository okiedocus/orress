//! A small, pluggable config-extractor framework. Each extractor recognises a malware family's
//! embedded configuration (C2 servers, keys, campaign ids, mutexes) and returns it as labelled
//! fields. New families are added by implementing [`ConfigExtractor`]; two examples ship here —
//! one signature-based (a documented demo family) and one generic heuristic.
//!
//! **No real malware-family extractors ship yet.** The built-in set is the `ExampleRAT` demo
//! (which only matches samples built for it, such as ORRESS's own test fixtures) plus a
//! `host:port` endpoint heuristic, so an empty result says nothing about whether a sample carries
//! a config — it only means neither of those two recognisers fired.
//!
//! Static, read-only: extractors parse bytes/strings the analyst already has.

use std::sync::OnceLock;

use orress_loaders::BinaryInfo;
use regex::Regex;

/// One key/value field of an extracted configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigField {
    pub key: String,
    pub value: String,
}

/// A configuration recovered from a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub family: String,
    pub fields: Vec<ConfigField>,
    /// How the config was obtained (signature match, heuristic, …).
    pub note: String,
}

/// Recognises and extracts one family's configuration.
pub trait ConfigExtractor: Send + Sync {
    fn family(&self) -> &'static str;
    /// Returns the config if this sample matches the family.
    fn extract(&self, info: &BinaryInfo, data: &[u8], strings: &[&str]) -> Option<Config>;
}

/// Runs every registered extractor and collects the configs that matched.
pub fn run_all(info: &BinaryInfo, data: &[u8], strings: &[&str]) -> Vec<Config> {
    extractors()
        .iter()
        .filter_map(|e| e.extract(info, data, strings))
        .collect()
}

/// The built-in extractor set.
fn extractors() -> &'static [Box<dyn ConfigExtractor>] {
    static E: OnceLock<Vec<Box<dyn ConfigExtractor>>> = OnceLock::new();
    E.get_or_init(|| {
        vec![
            Box::new(ExampleRat) as Box<dyn ConfigExtractor>,
            Box::new(GenericC2Endpoints),
        ]
    })
    .as_slice()
}

fn field(key: &str, value: impl Into<String>) -> ConfigField {
    ConfigField {
        key: key.to_string(),
        value: value.into(),
    }
}

// --- Example 1: a signature-based extractor for a demo family -------------

/// Extractor for the demo family **ExampleRAT**. Its config is the marker `ORCFG`, a 2-byte
/// little-endian length, then that many `0x5A`-XOR-encoded bytes of `key=value;` text. Real
/// family extractors (AgentTesla, Remcos, …) follow this shape: find a signature, decode, parse.
struct ExampleRat;

const EXAMPLE_KEY: u8 = 0x5a;

impl ConfigExtractor for ExampleRat {
    fn family(&self) -> &'static str {
        "ExampleRAT (demo)"
    }

    fn extract(&self, _info: &BinaryInfo, data: &[u8], _strings: &[&str]) -> Option<Config> {
        let marker = b"ORCFG";
        let pos = data.windows(marker.len()).position(|w| w == marker)?;
        let start = pos + marker.len();
        let len_bytes = data.get(start..start + 2)?;
        let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        let blob = data.get(start + 2..start + 2 + len)?;
        let decoded: Vec<u8> = blob.iter().map(|b| b ^ EXAMPLE_KEY).collect();
        let text = String::from_utf8_lossy(&decoded);
        let fields: Vec<ConfigField> = text
            .split(';')
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (!k.trim().is_empty()).then(|| field(k.trim(), v.trim().to_string()))
            })
            .collect();
        (!fields.is_empty()).then(|| Config {
            family: self.family().to_string(),
            fields,
            note: format!("signature ORCFG at {pos:#x}, XOR 0x5A"),
        })
    }
}

// --- Example 2: a generic heuristic extractor -----------------------------

/// Pulls `host:port` network endpoints out of the sample's strings (IPs and domains with an
/// explicit port) — the actionable form a C2 config usually takes.
struct GenericC2Endpoints;

fn endpoint_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+):\d{2,5}\b",
        )
        .unwrap()
    })
}

impl ConfigExtractor for GenericC2Endpoints {
    fn family(&self) -> &'static str {
        "Network endpoints (heuristic)"
    }

    fn extract(&self, _info: &BinaryInfo, _data: &[u8], strings: &[&str]) -> Option<Config> {
        let re = endpoint_re();
        let mut seen = std::collections::BTreeSet::new();
        for s in strings {
            for m in re.find_iter(s) {
                let ep = m.as_str();
                // Drop obvious version strings like "1.2.3:4" where the port looks like a build.
                if valid_endpoint(ep) {
                    seen.insert(ep.to_string());
                }
            }
        }
        (!seen.is_empty()).then(|| Config {
            family: self.family().to_string(),
            fields: seen.into_iter().map(|ep| field("endpoint", ep)).collect(),
            note: "host:port patterns in strings".into(),
        })
    }
}

/// Accepts an endpoint only if its IPv4 octets (if any) and port are in range.
fn valid_endpoint(ep: &str) -> bool {
    let Some((host, port)) = ep.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u32>().is_ok_and(|p| p == 0 || p > 65535) {
        return false;
    }
    // If the host is dotted-decimal, validate octets.
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return host.split('.').count() == 4
            && host
                .split('.')
                .all(|o| o.parse::<u16>().is_ok_and(|n| n <= 255));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes an ExampleRAT config blob for testing (marker + len + XOR'd text).
    fn example_blob(text: &str) -> Vec<u8> {
        let mut out = b"junk before ORCFG".to_vec();
        let enc: Vec<u8> = text.bytes().map(|b| b ^ EXAMPLE_KEY).collect();
        out.extend_from_slice(&(enc.len() as u16).to_le_bytes());
        out.extend_from_slice(&enc);
        out.extend_from_slice(b"junk after");
        out
    }

    #[test]
    fn extracts_example_rat_config() {
        let data = example_blob("c2=evil.example.com;port=4444;campaign=spring2026;mutex=ORX-01");
        let info = BinaryInfo::default();
        let configs = run_all(&info, &data, &[]);
        let rat = configs
            .iter()
            .find(|c| c.family.starts_with("ExampleRAT"))
            .expect("ExampleRAT config");
        assert!(rat.fields.contains(&field("c2", "evil.example.com")));
        assert!(rat.fields.contains(&field("campaign", "spring2026")));
    }

    #[test]
    fn extracts_generic_endpoints() {
        let info = BinaryInfo::default();
        let strings = [
            "beacon 192.168.10.5:8080",
            "fallback: c2.bad.example:443",
            "ver 1.2.3",
        ];
        let configs = run_all(&info, &[], &strings);
        let net = configs
            .iter()
            .find(|c| c.family.starts_with("Network"))
            .expect("endpoints config");
        let values: Vec<&str> = net.fields.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"192.168.10.5:8080"));
        assert!(values.contains(&"c2.bad.example:443"));
    }

    #[test]
    fn no_config_in_benign_data() {
        let info = BinaryInfo::default();
        assert!(run_all(&info, b"nothing interesting here", &["hello world"]).is_empty());
    }
}
