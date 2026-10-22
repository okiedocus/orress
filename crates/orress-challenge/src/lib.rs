//! The authoring side of the CTF "Forge": scaffold a `challenge-kit` challenge from a template,
//! and submit its source + metadata to ctf.okiedocus.nl for review. The platform owns the flag, the
//! build and the challenge id — the author writes only the `check()` logic (see
//! `challenge_kit::assigned_id`), so nothing here touches flags.
//!
//! This crate is pure logic (template generation, file scaffolding, HTTP submit). The egui panel in
//! `orress-views` drives it and runs the build/submit on a background thread.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How the challenge's accepted answer is decided — the "protection seed" switch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Protection {
    /// A fixed answer, the same for every player. Simplest, but a player who shares the answer
    /// lets others skip the reversing (the platform still gives each player their own *flag*, but
    /// the input to reach it is identical for everyone).
    #[default]
    Fixed,
    /// Per-user ("protection seed"): the accepted answer is derived from each player's download
    /// seed, so a shared answer is useless to anyone else. The template generates a *keygen-me*
    /// skeleton that validates the serial for `challenge_kit::seed_name()` (this player's account).
    Seeded,
}

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
    /// Whether the generated check uses a fixed answer or a per-user (seeded) one.
    #[serde(default)]
    pub protection: Protection,
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
            protection: Protection::Fixed,
        }
    }
}

/// The bundled `challenge-kit` library source, vendored into a scaffolded project so it builds
/// offline, with no dependency on the (private) CTF platform repository.
const KIT_LIB_RS: &str = include_str!("../kit/lib.rs");
/// The bundled `challenge-kit` manifest (named `.in` so it is not itself a cargo manifest).
const KIT_CARGO_TOML: &str = include_str!("../kit/Cargo.toml.in");

/// The `challenge-kit` dependency spec body for a project that uses the vendored built-in kit.
pub const BUILTIN_KIT_DEP: &str = "path = \"challenge-kit\"";

/// Where a scaffolded challenge gets its `challenge-kit` dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum KitSource {
    /// Vendor the bundled kit into the project (a `challenge-kit/` subfolder) and depend on it by
    /// path. Self-contained and offline; the default.
    #[default]
    BuiltIn,
    /// A custom Cargo dependency spec body, e.g. `git = "https://…"` or `path = "../checkout"`,
    /// for authors who keep their own `challenge-kit` checkout.
    External(String),
}

impl KitSource {
    /// The dependency spec body to write into the project's `Cargo.toml`.
    fn dep_spec(&self) -> &str {
        match self {
            Self::BuiltIn => BUILTIN_KIT_DEP,
            Self::External(s) => s,
        }
    }
}

/// The generated `main.rs` for a challenge, pre-filled from `meta`. The body depends on
/// `meta.protection`: a fixed answer, or a per-user ("seeded") keygen-me skeleton.
pub fn template(meta: &Meta) -> String {
    let title = rust_str(&meta.title);
    let brief = rust_str(&meta.brief);
    let label = rust_str(&meta.input_label);
    // The protection note, any free helper functions, and the `check()` body differ by mode.
    let (mode_note, free_fns, check_body) = match meta.protection {
        Protection::Fixed => (
            "The accepted answer here is fixed — the same for every player.",
            String::new(),
            r#"        // TODO: your logic. Return Verdict::Accept(..) when the input is correct.
        if input.trim() == "open-sesame" {
            Verdict::Accept("Correct!".into())
        } else {
            Verdict::Reject("Not quite — keep reversing.".into())
        }"#
            .to_string(),
        ),
        Protection::Seeded => (
            "Protection seed ON — the accepted answer is per-user: it depends on this player's \
             account name (challenge_kit::seed_name(), derived from their download seed), so a \
             serial shared by one player is useless to anyone else. Change keygen() into your own \
             puzzle; the player must reverse it and run it on THEIR account name.",
            r#"/// The valid serial for an account name. This stub is a 32-bit FNV-1a hash in uppercase
/// hex — replace it with your own keygen so players have to reverse-engineer it.
fn keygen(name: &str) -> String {
    let mut h: u32 = 2_166_136_261;
    for b in name.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(16_777_619);
    }
    format!("{h:08X}")
}

"#
            .to_string(),
            r#"        // Per-user: validate the serial for THIS player's account name.
        let account = challenge_kit::seed_name();
        if input.trim().eq_ignore_ascii_case(&keygen(&account)) {
            Verdict::Accept("Valid serial.".into())
        } else {
            Verdict::Reject(format!("Invalid serial. Your account is {account} — generate its serial."))
        }"#
            .to_string(),
        ),
    };
    format!(
        r#"// Hide the Windows console in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! {title_comment}
//!
//! Write your reverse-engineering puzzle below. The player types an input; your `check()` decides
//! whether it is correct. On `Verdict::Accept` the platform reveals that player's personal flag —
//! you never see or set the flag. Keep `id()` returning `challenge_kit::assigned_id()`.
//!
//! {mode_note}

use challenge_kit::{{Challenge, Verdict}};

{free_fns}struct MyChallenge;

impl Challenge for MyChallenge {{
    // The platform assigns the id at build time — leave this as-is.
    fn id(&self) -> &str {{ challenge_kit::assigned_id() }}
    fn title(&self) -> &str {{ {title} }}
    fn brief(&self) -> &str {{ {brief} }}
    fn input_label(&self) -> &str {{ {label} }}

    fn check(&mut self, input: &str) -> Verdict {{
{check_body}
    }}
}}

fn main() {{
    let _ = challenge_kit::run(MyChallenge);
}}
"#,
        title_comment = one_line(&meta.title),
    )
}

/// The generated `Cargo.toml` for a scaffolded challenge. `kit_dep` is the dependency spec body
/// for `challenge-kit` (e.g. [`BUILTIN_KIT_DEP`] or `git = "..."`). The empty `[workspace]` table
/// makes the project its own workspace root, so it builds the same wherever it is placed (and the
/// vendored `challenge-kit` path dependency resolves without joining a surrounding workspace).
pub fn cargo_toml(kit_dep: &str) -> String {
    format!(
        r#"[package]
name = "challenge"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "challenge"
path = "src/main.rs"

[dependencies]
challenge-kit = {{ {kit_dep} }}

[workspace]
"#
    )
}

/// Scaffolds a challenge project at `dir`: `Cargo.toml`, `src/main.rs` (from the template), a
/// `challenge.json` snapshot of the metadata, and — when `kit` is [`KitSource::BuiltIn`] — a
/// vendored `challenge-kit/` so the project builds offline. Returns the path to `src/main.rs`
/// (open it in the editor). Does not overwrite an existing `src/main.rs`.
pub fn scaffold(dir: &Path, meta: &Meta, kit: &KitSource) -> Result<PathBuf, String> {
    let src_dir = dir.join("src");
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| format!("could not create {}: {e}", src_dir.display()))?;
    write_if_absent(&dir.join("Cargo.toml"), &cargo_toml(kit.dep_spec()))?;
    if *kit == KitSource::BuiltIn {
        vendor_kit(dir)?;
    }
    let main_rs = src_dir.join("main.rs");
    write_if_absent(&main_rs, &template(meta))?;
    // A metadata snapshot, for reference / re-submission.
    let meta_json = serde_json::to_string_pretty(meta).unwrap_or_default();
    let _ = std::fs::write(dir.join("challenge.json"), meta_json);
    Ok(main_rs)
}

/// Writes the bundled `challenge-kit` into `dir/challenge-kit/`, overwriting it so the vendored
/// copy always matches this build of ORRESS.
fn vendor_kit(dir: &Path) -> Result<(), String> {
    let kit_dir = dir.join("challenge-kit");
    let kit_src = kit_dir.join("src");
    std::fs::create_dir_all(&kit_src)
        .map_err(|e| format!("could not create {}: {e}", kit_src.display()))?;
    std::fs::write(kit_dir.join("Cargo.toml"), KIT_CARGO_TOML)
        .map_err(|e| format!("could not write the kit manifest: {e}"))?;
    std::fs::write(kit_src.join("lib.rs"), KIT_LIB_RS)
        .map_err(|e| format!("could not write the kit source: {e}"))?;
    Ok(())
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
    fn protection_mode_selects_the_check_body() {
        // Fixed (default) → a plain fixed-answer check, no seed usage.
        let fixed = template(&Meta::default());
        assert!(fixed.contains("open-sesame"));
        assert!(!fixed.contains("seed_name"));
        assert!(!fixed.contains("fn keygen"));

        // Seeded → a per-user keygen-me skeleton using seed_name(), and no fixed answer.
        let seeded = template(&Meta {
            protection: Protection::Seeded,
            ..Meta::default()
        });
        assert!(seeded.contains("challenge_kit::seed_name()"));
        assert!(seeded.contains("fn keygen(name: &str)"));
        assert!(!seeded.contains("open-sesame"));
        // Still a valid challenge-kit challenge with the platform-assigned id.
        assert!(seeded.contains("challenge_kit::assigned_id()"));
        assert!(seeded.contains("impl Challenge for MyChallenge"));
    }

    #[test]
    fn cargo_toml_uses_the_chosen_kit_dependency() {
        let builtin = cargo_toml(KitSource::BuiltIn.dep_spec());
        assert!(builtin.contains("challenge-kit = {"));
        assert!(builtin.contains(r#"path = "challenge-kit""#));
        assert!(builtin.contains("[workspace]"));
        // The built-in kit is vendored by path: it must not pull in any git repository.
        assert!(!builtin.contains("git ="));

        let external = cargo_toml(KitSource::External(r#"git = "https://x/y""#.into()).dep_spec());
        assert!(external.contains(r#"git = "https://x/y""#));
    }

    #[test]
    fn builtin_scaffold_vendors_the_kit_offline() {
        let dir = std::env::temp_dir().join(format!("orress-cw-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let meta = Meta::default();
        let main = scaffold(&dir, &meta, &KitSource::BuiltIn).expect("scaffold");
        assert!(main.ends_with("main.rs"));
        assert!(dir.join("Cargo.toml").exists());
        assert!(dir.join("src/main.rs").exists());
        assert!(dir.join("challenge.json").exists());
        // The kit is vendored in, so the project needs no external repo to build.
        let kit_lib = dir.join("challenge-kit/src/lib.rs");
        assert!(dir.join("challenge-kit/Cargo.toml").exists());
        assert!(kit_lib.exists());
        let kit = std::fs::read_to_string(&kit_lib).unwrap();
        assert!(kit.contains("pub trait Challenge"));
        assert!(kit.contains("pub fn assigned_id()"));
        let src = std::fs::read_to_string(&main).unwrap();
        assert!(src.contains("challenge_kit::assigned_id()"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Scaffolds a *seeded* challenge with the vendored kit and actually compiles it, so the
    /// vendored kit's seed API and the seeded template can never drift out of sync. Ignored by
    /// default (it shells out to `cargo build`); run with `cargo test -p orress-challenge -- --ignored`.
    #[test]
    #[ignore = "invokes cargo build on a scaffolded project"]
    fn seeded_scaffold_compiles_against_the_vendored_kit() {
        let dir = std::env::temp_dir().join(format!("orress-cw-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let meta = Meta {
            protection: Protection::Seeded,
            ..Meta::default()
        };
        scaffold(&dir, &meta, &KitSource::BuiltIn).expect("scaffold");
        let out = std::process::Command::new("cargo")
            .args(["build", "--quiet"])
            .current_dir(&dir)
            .output()
            .expect("run cargo build");
        assert!(
            out.status.success(),
            "seeded project failed to build:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn external_scaffold_does_not_vendor_the_kit() {
        let dir = std::env::temp_dir().join(format!("orress-cw-ext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let kit = KitSource::External(r#"path = "../my-kit""#.into());
        scaffold(&dir, &Meta::default(), &kit).expect("scaffold");
        let toml = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        assert!(toml.contains(r#"path = "../my-kit""#));
        assert!(!dir.join("challenge-kit").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
