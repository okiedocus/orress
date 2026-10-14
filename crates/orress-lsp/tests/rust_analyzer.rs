//! Live test against a real rust-analyzer in a small Cargo project (skipped if the
//! rust-analyzer component is not installed).
use std::sync::Arc;
use std::time::{Duration, Instant};

use orress_lsp::{LspManager, ServerSpec, Status};

fn ra_command() -> String {
    // Prefer the rustup proxy in CARGO_HOME/.cargo, else rely on PATH.
    if cfg!(windows)
        && let Ok(home) = std::env::var("USERPROFILE")
    {
        let p = format!("{home}/.cargo/bin/rust-analyzer.exe");
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }
    "rust-analyzer".to_string()
}

fn have_ra() -> bool {
    std::process::Command::new(ra_command())
        .arg("--version")
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("rust-analyzer"))
        .unwrap_or(false)
}

#[test]
fn rust_analyzer_diagnostics_in_cargo_project() {
    if !have_ra() {
        eprintln!("rust-analyzer not installed; skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("orress-ra-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    // `[workspace]` makes this an explicit workspace root: without it, cargo (and so
    // rust-analyzer's project load) walks up to `%TEMP%`/`$TMPDIR` and fails if any ancestor holds
    // a stray or malformed `Cargo.toml` — which the shared system temp dir may well contain. With
    // it, `cargo metadata` resolves here and flycheck can run.
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    let file = dir.join("src/main.rs");
    std::fs::write(&file, "fn main() {\n    let _y: &str = 10;\n}\n").unwrap();

    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let mut lsp = LspManager::new(notify);
    let spec = ServerSpec {
        key: "rust".into(),
        command: ra_command(),
        args: vec![],
        language_id: "rust".into(),
        ..ServerSpec::default()
    };
    let text = std::fs::read_to_string(&file).unwrap();

    // rust-analyzer reports a type error like this one via flycheck (`cargo check`, whose message
    // is rustc's "mismatched types"), which runs on save — so open, wait for readiness, then save.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut ready = false;
    let mut saved = false;
    while Instant::now() < deadline {
        lsp.sync(&spec, Some(&dir), &dir, &file, &text);
        match lsp.status("rust") {
            Status::Ready => ready = true,
            Status::Failed => panic!("rust-analyzer failed: {:?}", lsp.error("rust")),
            _ => {}
        }
        if ready && !saved {
            saved = true;
            lsp.did_save("rust", &file);
        }
        if ready
            && lsp
                .diagnostics("rust", &file)
                .iter()
                .any(|d| d.message.contains("mismatched types"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    assert!(ready, "rust-analyzer never became ready");
    let diags = lsp.diagnostics("rust", &file);
    eprintln!(
        "diagnostics: {:#?}",
        diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    assert!(
        diags.iter().any(|d| d.message.contains("mismatched types")),
        "expected a mismatched-types diagnostic, got {diags:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
