//! Build / run tasks for the open file, in the spirit of Zed's `tasks.json`: a small set
//! of commands derived from the file's language and project. Pure data — the editor view
//! spawns the processes and streams the output.
//!
//! A task is a *sequence* of commands run in order, stopping if one fails. That models
//! "compile, then run the result" (`rustc` then the produced executable) without any shell.

use std::path::{Path, PathBuf};

use crate::Language;

/// One command to execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

/// A named task: one or more commands run in sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    /// Shown on the button / in the menu, e.g. "cargo run".
    pub label: String,
    pub steps: Vec<Command>,
}

/// The nearest ancestor directory containing a `Cargo.toml`, if any.
fn cargo_root(path: &Path) -> Option<PathBuf> {
    let mut dir = path.parent();
    while let Some(d) = dir {
        if d.join("Cargo.toml").is_file() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

/// Tasks offered for a file, best/most-common first. Empty for files we cannot run.
pub fn tasks_for(path: &Path, language: Language) -> Vec<Task> {
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let file = path.to_string_lossy().into_owned();
    match language {
        Language::Rust => {
            if let Some(root) = cargo_root(path) {
                vec![
                    one("cargo run", "cargo", &["run"], &root),
                    one("cargo build", "cargo", &["build"], &root),
                    one("cargo test", "cargo", &["test"], &root),
                ]
            } else {
                // A standalone .rs file: compile next to it, then run the result.
                let out = standalone_output(path);
                let out_s = out.to_string_lossy().into_owned();
                vec![
                    Task {
                        label: "rustc & run".into(),
                        steps: vec![
                            cmd(
                                "rustc",
                                &[
                                    "--edition",
                                    "2024",
                                    "-C",
                                    "opt-level=0",
                                    &file,
                                    "-o",
                                    &out_s,
                                ],
                                &dir,
                            ),
                            cmd(&out_s, &[], &dir),
                        ],
                    },
                    one(
                        "rustc (check only)",
                        "rustc",
                        &["--edition", "2024", "--emit=metadata", &file],
                        &dir,
                    ),
                ]
            }
        }
        Language::Python => vec![one("python", "python", &[&file], &dir)],
        _ => Vec::new(),
    }
}

/// Where a standalone `.rs` file compiles to.
fn standalone_output(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    let mut out = path.with_file_name(stem);
    if cfg!(windows) {
        out.set_extension("exe");
    }
    out
}

fn cmd(program: &str, args: &[&str], cwd: &Path) -> Command {
    Command {
        program: program.into(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        cwd: cwd.to_path_buf(),
    }
}

fn one(label: &str, program: &str, args: &[&str], cwd: &Path) -> Task {
    Task {
        label: label.into(),
        steps: vec![cmd(program, args, cwd)],
    }
}
