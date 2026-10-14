//! The authoring side of the CTF "Forge": scaffold a `challenge-kit` challenge from a template,
//! and submit its source + metadata to ctf.okiedocus.nl for review. The platform owns the flag, the
//! build and the challenge id — the author writes only the `check()` logic (see
//! `challenge_kit::assigned_id`), so nothing here touches flags.
//!
//! This crate is pure logic (template generation, file scaffolding, HTTP submit). The egui panel in
//! `orress-views` drives it and runs the build/submit on a background thread.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Everything about a challenge except its source.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    pub title: String,
    pub category: String,
    pub technique: String,
    /// Difficulty 1..=5.
    pub level: u8,
    pub brief: String,
    pub input_label: String,
    pub hints: Vec<String>,
    pub writeup: String,
    pub bonus_points: u32,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            title: "My Challenge".into(),
            category: "crackme".into(),
            technique: String::new(),
            level: 1,
            brief: "Find the secret and recover the flag.".into(),
            input_label: "Answer".into(),
            hints: Vec::new(),
            writeup: String::new(),
            bonus_points: 0,
        }
    }
}

/// The default source of the `challenge-kit` dependency used by a scaffolded project. A git URL so a
/// freshly scaffolded project builds anywhere; override with a local path if you have the CTF repo
/// checked out (faster, offline).
pub const DEFAULT_KIT_SOURCE: &str = "git = \"https://github.com/okiedocus/capture_the_flag\"";

/// The generated `main.rs` for a challenge, pre-filled from `meta`.
pub fn template(meta: &Meta) -> String {
    let title = rust_str(&meta.title);
    let brief = rust_str(&meta.brief);
    let label = rust_str(&meta.input_label);
    format!(
        r#"// Hide the Windows console in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! {title_comment}
//!
//! Write your reverse-engineering puzzle below. The player types an input; your `check()` decides
//! whether it is correct. On `Verdict::Accept` the platform reveals that player's personal flag —
//! you never see or set the flag. Keep `id()` returning `challenge_kit::assigned_id()`.

use challenge_kit::{{Challenge, Verdict}};

struct MyChallenge;

impl Challenge for MyChallenge {{
    // The platform assigns the id at build time — leave this as-is.
    fn id(&self) -> &str {{ challenge_kit::assigned_id() }}
    fn title(&self) -> &str {{ {title} }}
    fn brief(&self) -> &str {{ {brief} }}
    fn input_label(&self) -> &str {{ {label} }}

    fn check(&mut self, input: &str) -> Verdict {{
        // TODO: your logic. Return Verdict::Accept(..) when the input is correct.
        if input.trim() == "open-sesame" {{
            Verdict::Accept("Correct!".into())
        }} else {{
            Verdict::Reject("Not quite — keep reversing.".into())
        }}
    }}
}}

fn main() {{
    let _ = challenge_kit::run(MyChallenge);
}}
"#,
        title_comment = one_line(&meta.title),
    )
}

/// The generated `Cargo.toml` for a scaffolded challenge. `kit_source` is the dependency spec body
/// for `challenge-kit` (e.g. [`DEFAULT_KIT_SOURCE`] or `path = "..."`).
pub fn cargo_toml(kit_source: &str) -> String {
    format!(
        r#"[package]
name = "challenge"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "challenge"
path = "src/main.rs"

[dependencies]
challenge-kit = {{ {kit_source} }}
"#
    )
}

/// Scaffolds a challenge project at `dir`: `Cargo.toml`, `src/main.rs` (from the template) and a
/// `challenge.toml` snapshot of the metadata. Returns the path to `src/main.rs` (open it in the
/// editor). Does not overwrite an existing `src/main.rs`.
pub fn scaffold(dir: &Path, meta: &Meta, kit_source: &str) -> Result<PathBuf, String> {
    let src_dir = dir.join("src");
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| format!("could not create {}: {e}", src_dir.display()))?;
    write_if_absent(&dir.join("Cargo.toml"), &cargo_toml(kit_source))?;
    let main_rs = src_dir.join("main.rs");
    write_if_absent(&main_rs, &template(meta))?;
    // A metadata snapshot, for reference / re-submission.
    let meta_json = serde_json::to_string_pretty(meta).unwrap_or_default();
    let _ = std::fs::write(dir.join("challenge.json"), meta_json);
    Ok(main_rs)
}

fn write_if_absent(path: &Path, contents: &str) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    std::fs::write(path, contents).map_err(|e| format!("could not write {}: {e}", path.display()))
}

/// Submit a challenge's source + metadata to the site's Forge for review. Logs in with the given
/// credentials (session cookie kept on the agent), verifies the session, then posts the form.
pub fn submit(
    base_url: &str,
    username: &str,
    password: &str,
    meta: &Meta,
    source: &str,
) -> Result<String, String> {
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("set the CTF site URL first".into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(60))
        .build();

    // Log in (the 303 redirect carries the session cookie; the agent's cookie store keeps it).
    agent
        .post(&format!("{base}/login"))
        .send_form(&[("username", username), ("password", password)])
        .map_err(describe)?;
    // Confirm the session took (login failures redirect back without a usable cookie).
    match agent.get(&format!("{base}/api/me")).call() {
        Ok(_) => {}
        Err(_) => {
            return Err(
                "login failed — check your username/password, and that your email is verified"
                    .into(),
            );
        }
    }

    let level = meta.level.to_string();
    let bonus = meta.bonus_points.to_string();
    let hints = meta.hints.join("\n");
    let fields: Vec<(&str, &str)> = vec![
        ("title", meta.title.as_str()),
        ("category", meta.category.as_str()),
        ("technique", meta.technique.as_str()),
        ("brief", meta.brief.as_str()),
        ("level", level.as_str()),
        ("bonus_points", bonus.as_str()),
        ("hints", hints.as_str()),
        ("writeup", meta.writeup.as_str()),
        ("source", source),
    ];
    let resp = agent
        .post(&format!("{base}/forge/submit"))
        .send_form(&fields)
        .map_err(describe)?;
    // On success the site redirects to /forge?msg=submitted; validation errors bounce back to the
    // form (/forge/submit?msg=...).
    if resp.get_url().contains("/forge/submit") {
        return Err("the site rejected the submission — check the fields and that the source is a challenge-kit challenge".into());
    }
    Ok("Submitted for review. Track it on the site's Forge page.".into())
}

fn describe(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, r) => {
            let body: String = r
                .into_string()
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect();
            format!("HTTP {code}: {body}")
        }
        other => format!("request failed: {other}"),
    }
}

/// `s` made safe for a single `//!` comment line: newlines (which would end the comment and turn
/// the rest of the title into code) and other control characters (a bare CR is a compile error in
/// a doc comment) become spaces.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn rust_str(s: &str) -> String {
    format!("{s:?}") // debug-formats a &str into a valid Rust string literal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_bakes_in_metadata_and_uses_assigned_id() {
        let m = Meta {
            title: "Nibble \"Shuffle\"".into(),
            ..Meta::default()
        };
        let src = template(&m);
        assert!(src.contains("challenge_kit::assigned_id()"));
        // The title is embedded as a properly-escaped Rust string literal.
        assert!(src.contains(r#""Nibble \"Shuffle\"""#));
        assert!(src.contains("impl Challenge for MyChallenge"));
    }

    #[test]
    fn a_multiline_title_cannot_escape_the_doc_comment() {
        let m = Meta {
            title: "Line one\nfn evil() {}\r\nmore".into(),
            ..Meta::default()
        };
        let src = template(&m);
        assert!(src.contains("//! Line one fn evil() {}  more\n"), "{src}");
        // Every line that mentions `evil` is a comment or a string literal.
        for line in src.lines().filter(|l| l.contains("evil")) {
            let t = line.trim_start();
            assert!(t.starts_with("//!") || t.contains("\\n"), "{line}");
        }
    }

    #[test]
    fn cargo_toml_has_the_kit_dependency() {
        let toml = cargo_toml(DEFAULT_KIT_SOURCE);
        assert!(toml.contains("challenge-kit = {"));
        assert!(toml.contains("capture_the_flag"));
    }

    #[test]
    fn scaffold_writes_a_buildable_project_layout() {
        let dir = std::env::temp_dir().join(format!("orress-cw-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let meta = Meta::default();
        let main = scaffold(&dir, &meta, DEFAULT_KIT_SOURCE).expect("scaffold");
        assert!(main.ends_with("main.rs"));
        assert!(dir.join("Cargo.toml").exists());
        assert!(dir.join("src/main.rs").exists());
        assert!(dir.join("challenge.json").exists());
        let src = std::fs::read_to_string(&main).unwrap();
        assert!(src.contains("challenge_kit::assigned_id()"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
