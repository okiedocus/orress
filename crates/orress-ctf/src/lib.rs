//! CTF platform integration (M13): import a competition's challenges and submit flags from inside
//! ORRESS, so a team's triage, claims and flag submissions all live in one place. Supports the two
//! common self-hosted platforms — **CTFd** and **rCTF** — authenticated with an API token.
//!
//! Blocking `ureq` on a background thread (like the AI backends); the response parsers are pure and
//! unit-tested, and the request wiring is tested against a mock server.

use std::time::Duration;

use serde_json::Value;

/// Which platform's API shape to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Ctfd,
    Rctf,
}

/// A challenge as shown in the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Platform id (numeric on CTFd, opaque string on rCTF) — kept as a string so both fit.
    pub id: String,
    pub name: String,
    pub category: String,
    pub value: i64,
    pub solved: bool,
}

/// The result of submitting a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitOutcome {
    pub correct: bool,
    pub already_solved: bool,
    pub message: String,
}

/// A configured client for one platform instance.
pub struct CtfClient {
    platform: Platform,
    /// Base URL, e.g. `https://ctf.example.com` (no trailing slash).
    base: String,
    token: String,
}

impl CtfClient {
    pub fn new(platform: Platform, base: impl Into<String>, token: impl Into<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        Self {
            platform,
            base,
            token: token.into(),
        }
    }

    fn agent() -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build()
    }

    /// Adds the platform's auth header.
    fn auth(&self, req: ureq::Request) -> ureq::Request {
        match self.platform {
            Platform::Ctfd => req.set("Authorization", &format!("Token {}", self.token)),
            Platform::Rctf => req.set("Authorization", &format!("Bearer {}", self.token)),
        }
    }

    /// Lists the competition's challenges.
    pub fn challenges(&self) -> Result<Vec<Challenge>, String> {
        let path = match self.platform {
            Platform::Ctfd => "/api/v1/challenges",
            Platform::Rctf => "/api/v1/challs",
        };
        let url = format!("{}{path}", self.base);
        let value = into_json(self.auth(Self::agent().get(&url)).call())?;
        match self.platform {
            Platform::Ctfd => Ok(parse_ctfd_challenges(&value)),
            Platform::Rctf => {
                let mut challenges = parse_rctf_challenges(&value);
                // rCTF challenge objects carry no "solved" flag; the team's solves come from its
                // profile. Best-effort: if the profile cannot be fetched, nothing is marked solved.
                let me = format!("{}/api/v1/users/me", self.base);
                if let Ok(profile) = into_json(self.auth(Self::agent().get(&me)).call()) {
                    let solved = parse_rctf_solved_ids(&profile);
                    for c in &mut challenges {
                        c.solved |= solved.contains(&c.id);
                    }
                }
                Ok(challenges)
            }
        }
    }

    /// Submits `flag` for a challenge, returning the platform's verdict.
    pub fn submit(&self, challenge_id: &str, flag: &str) -> Result<SubmitOutcome, String> {
        match self.platform {
            Platform::Ctfd => {
                let url = format!("{}/api/v1/challenges/attempt", self.base);
                let body = serde_json::json!({ "challenge_id": numeric(challenge_id), "submission": flag });
                let value = into_json(self.auth(Self::agent().post(&url)).send_json(body))?;
                Ok(parse_ctfd_attempt(&value))
            }
            Platform::Rctf => {
                let url = format!(
                    "{}/api/v1/challs/{}/submit",
                    self.base,
                    encode_path_segment(challenge_id)
                );
                let body = serde_json::json!({ "flag": flag });
                // rCTF answers a wrong flag (400 `badFlag`) or a repeat solve (409
                // `badAlreadySolved`) with a non-2xx status *and* a normal JSON verdict body.
                let value = match self.auth(Self::agent().post(&url)).send_json(body) {
                    Err(ureq::Error::Status(code, r)) => {
                        let text = r.into_string().unwrap_or_default();
                        match serde_json::from_str::<Value>(&text) {
                            Ok(v) if is_rctf_verdict(&v) => v,
                            _ => {
                                let body: String = text.chars().take(300).collect();
                                return Err(format!("HTTP {code}: {body}"));
                            }
                        }
                    }
                    other => into_json(other)?,
                };
                Ok(parse_rctf_submit(&value))
            }
        }
    }
}

/// CTFd challenge ids are numeric; pass a number when the id parses, else the raw string.
fn numeric(id: &str) -> Value {
    id.parse::<i64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::from(id))
}

/// Whether an rCTF error body is a flag verdict (a wrong or repeated flag) rather than a real
/// failure such as a bad token.
fn is_rctf_verdict(v: &Value) -> bool {
    matches!(v["kind"].as_str(), Some("badFlag" | "badAlreadySolved"))
}

/// Percent-encodes `s` for use as one URL path segment (everything but RFC 3986 unreserved
/// characters), so an id cannot add path segments or a query.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Shared response handling: a non-2xx or network error becomes a readable message.
fn into_json(resp: Result<ureq::Response, ureq::Error>) -> Result<Value, String> {
    match resp {
        Ok(r) => r
            .into_json()
            .map_err(|e| format!("bad JSON from the CTF platform: {e}")),
        Err(ureq::Error::Status(code, r)) => {
            let body: String = r
                .into_string()
                .unwrap_or_default()
                .chars()
                .take(300)
                .collect();
            Err(format!("HTTP {code}: {body}"))
        }
        Err(e) => Err(format!("request failed: {e}")),
    }
}

pub fn parse_ctfd_challenges(v: &Value) -> Vec<Challenge> {
    v["data"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let id = c.get("id")?;
                    let id = id
                        .as_i64()
                        .map(|n| n.to_string())
                        .or_else(|| id.as_str().map(str::to_string))?;
                    Some(Challenge {
                        id,
                        name: c["name"].as_str().unwrap_or("").to_string(),
                        category: c["category"].as_str().unwrap_or("").to_string(),
                        value: c["value"].as_i64().unwrap_or(0),
                        solved: c["solved_by_me"].as_bool().unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_ctfd_attempt(v: &Value) -> SubmitOutcome {
    let status = v["data"]["status"].as_str().unwrap_or("");
    SubmitOutcome {
        correct: status == "correct",
        already_solved: status == "already_solved",
        message: v["data"]["message"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(status)
            .to_string(),
    }
}

pub fn parse_rctf_challenges(v: &Value) -> Vec<Challenge> {
    v["data"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    Some(Challenge {
                        id: c.get("id")?.as_str()?.to_string(),
                        name: c["name"].as_str().unwrap_or("").to_string(),
                        category: c["category"].as_str().unwrap_or("").to_string(),
                        value: c["points"].as_i64().unwrap_or(0),
                        solved: c["solved"].as_bool().unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The ids of the challenges the team has solved, from rCTF's `/api/v1/users/me` profile
/// (`data.solves[].id`).
pub fn parse_rctf_solved_ids(v: &Value) -> std::collections::HashSet<String> {
    v["data"]["solves"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("id")?.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_rctf_submit(v: &Value) -> SubmitOutcome {
    let kind = v["kind"].as_str().unwrap_or("");
    SubmitOutcome {
        correct: kind == "goodFlag",
        already_solved: kind == "badAlreadySolved",
        message: v["message"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(kind)
            .to_string(),
    }
}

#[cfg(test)]
mod tests;
