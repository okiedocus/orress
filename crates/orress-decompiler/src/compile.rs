//! Optional self-contained compile check: feed a generated Rust port to `rustc` and
//! report whether it compiles.
//!
//! Enabled by the `compile-check` cargo feature, so the default build never shells out to
//! a compiler. The check is metadata-only (`--emit=metadata`): it type-checks the scaffold
//! without producing an object file, and it never panics — a missing `rustc` is reported
//! as [`CompileStatus::ToolMissing`], not an error.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use orress_analysis::Program;

use crate::{Convention, Error};

/// The outcome of running `rustc` over a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileStatus {
    /// `rustc` accepted the port.
    Compiles,
    /// `rustc` reported errors.
    Errors,
    /// No `rustc` on `PATH`, so the check could not run.
    ToolMissing,
}

/// A compile check's result: its [`CompileStatus`] and `rustc`'s diagnostics.
#[derive(Clone, Debug)]
pub struct CompileReport {
    pub status: CompileStatus,
    /// `rustc`'s stderr — the errors to fix (empty when it compiled or the tool is missing).
    pub diagnostics: String,
}

impl CompileReport {
    /// Whether the port compiled.
    pub fn ok(&self) -> bool {
        self.status == CompileStatus::Compiles
    }
}

/// Type-checks `src` as a library with `rustc` (edition 2021, metadata only) and reports
/// the result. Writes to a unique temporary directory that is removed afterwards.
pub fn check_source(src: &str) -> CompileReport {
    static N: AtomicUsize = AtomicUsize::new(0);
    let uniq = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("orress_compile_{}_{uniq}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("port.rs");
    let report = match std::fs::write(&file, src) {
        Ok(()) => {
            let out = Command::new("rustc")
                .args([
                    "--edition",
                    "2021",
                    "--crate-type",
                    "lib",
                    "--emit=metadata",
                    "-o",
                ])
                .arg(dir.join("port.meta"))
                .arg(&file)
                .output();
            match out {
                Ok(o) if o.status.success() => CompileReport {
                    status: CompileStatus::Compiles,
                    diagnostics: String::new(),
                },
                Ok(o) => CompileReport {
                    status: CompileStatus::Errors,
                    diagnostics: String::from_utf8_lossy(&o.stderr).into_owned(),
                },
                Err(_) => CompileReport {
                    status: CompileStatus::ToolMissing,
                    diagnostics: "rustc was not found on PATH".to_owned(),
                },
            }
        }
        Err(e) => CompileReport {
            status: CompileStatus::ToolMissing,
            diagnostics: format!("could not write a temporary file: {e}"),
        },
    };
    let _ = std::fs::remove_dir_all(&dir);
    report
}

/// Ports the function at `addr` and checks that the scaffold compiles, returning both the
/// port source and the report.
pub fn check_port(
    program: &Program,
    addr: u64,
    conv: Convention,
) -> Result<(String, CompileReport), Error> {
    let src = crate::port(program, addr, conv)?;
    let report = check_source(&src);
    Ok((src, report))
}
