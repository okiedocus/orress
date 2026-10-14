//! The Binary Diff tab (M14): compare the open binary against another (a different build, or a
//! malware variant) and see which functions are identical, changed, added or removed — BinDiff-style.
//!
//! The open binary ("A") is already analyzed; its function signatures are captured on the UI thread
//! (cheap), then the comparison binary ("B") is loaded, analyzed and diffed on a background thread
//! so the UI never blocks.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_ui::muted;

/// The finished comparison, ready to render.
struct DiffData {
    /// The open binary ("A") this comparison was made for; the result is dropped when another
    /// file becomes active.
    a_path: PathBuf,
    b_name: String,
    a_count: usize,
    b_count: usize,
    /// (identical, changed, added, removed).
    summary: (usize, usize, usize, usize),
    /// (name in A, name in B, similarity 0..1).
    changed: Vec<(String, String, f32)>,
    added: Vec<String>,
    removed: Vec<String>,
}

type Slot = Arc<Mutex<Option<Result<DiffData, String>>>>;

#[derive(Default)]
pub struct DiffView {
    result: Slot,
    busy: Arc<AtomicBool>,
    /// The file the current (or running) comparison belongs to.
    a_path: Option<PathBuf>,
}

/// Locks the result, recovering it if the worker panicked while holding the lock.
fn lock(slot: &Slot) -> std::sync::MutexGuard<'_, Option<Result<DiffData, String>>> {
    slot.lock().unwrap_or_else(|e| e.into_inner())
}

fn name_of(r: &orress_diff::FuncRef) -> String {
    r.name
        .clone()
        .unwrap_or_else(|| format!("sub_{:x}", r.entry))
}

pub fn diff_panel(ui: &mut Ui, view: &mut DiffView, docs: &DocStore) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Binary diff").strong());
        ui.label(muted(
            "BinDiff-style function matching between two binaries",
        ));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a binary, then compare it against another."));
        return;
    };
    let Some(program) = doc.program() else {
        ui.label(muted(
            "Analysis is still running (or this file has no native code).",
        ));
        return;
    };

    // A comparison belongs to the file it was made for.
    if view.a_path.as_deref() != Some(doc.path.as_path()) {
        view.a_path = Some(doc.path.clone());
        *lock(&view.result) = None;
    }

    let a_name = file_name(&doc.path);
    ui.label(format!(
        "A: {a_name}  ({} functions)",
        program.functions.len()
    ));

    let busy = view.busy.load(Ordering::Relaxed);
    if ui
        .add_enabled(!busy, egui::Button::new("Compare against another binary…"))
        .clicked()
        && let Some(path) = rfd::FileDialog::new()
            .set_title("Pick the binary to compare against")
            .pick_file()
    {
        compare(view, program, &doc.path, path, ui.ctx().clone());
    }
    if busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted("analyzing and diffing…"));
        });
    }

    let mut guard = lock(&view.result);
    // A comparison started for another file that finished after switching is not shown.
    if guard
        .as_ref()
        .is_some_and(|r| r.as_ref().is_ok_and(|d| d.a_path != doc.path))
    {
        *guard = None;
    }
    match guard.as_ref() {
        Some(Ok(data)) => render(ui, data),
        Some(Err(e)) => {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        None => {}
    }
}

/// Captures A's (owned, `Send`) signatures on the UI thread, then loads, analyzes and diffs B on a
/// background thread so the UI never blocks.
/// A panic in the worker is caught and reported, so `busy` is always cleared.
fn compare(
    view: &DiffView,
    program: &orress_analysis::Program,
    a_path: &Path,
    path: PathBuf,
    ctx: egui::Context,
) {
    let a_sigs = orress_diff::signatures(program);
    let a_count = program.functions.len();
    let a_path = a_path.to_path_buf();
    let result = Arc::clone(&view.result);
    let busy = Arc::clone(&view.busy);
    *lock(&result) = None;
    busy.store(true, Ordering::Relaxed);
    let spawned = std::thread::Builder::new()
        .name("binary diff".into())
        .spawn(move || {
            let data = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                analyze_and_diff(&a_sigs, a_count, &a_path, &path)
            }))
            .unwrap_or_else(|_| Err("the diff hit an internal error".into()));
            *lock(&result) = Some(data);
            busy.store(false, Ordering::Relaxed);
            ctx.request_repaint();
        });
    if let Err(e) = spawned {
        *lock(&view.result) = Some(Err(format!("could not start the diff thread: {e}")));
        view.busy.store(false, Ordering::Relaxed);
    }
}

/// Loads and analyzes the comparison binary, then diffs it against A's signatures.
fn analyze_and_diff(
    a_sigs: &[orress_diff::FuncSig],
    a_count: usize,
    a_path: &Path,
    path: &Path,
) -> Result<DiffData, String> {
    let bytes = std::sync::Arc::new(
        std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
    );
    let analysis = orress_project::Analysis::run(&bytes);
    let program = orress_analysis::Program::analyze(
        &analysis.info,
        std::sync::Arc::clone(&bytes),
        &analysis.strings,
    )
    .ok_or(
        "the comparison binary has no native code ORRESS can analyze (unsupported architecture)",
    )?;

    let b_sigs = orress_diff::signatures(&program);
    let diff = orress_diff::diff(a_sigs, &b_sigs);
    let changed = diff
        .matches
        .iter()
        .filter(|m| m.kind == orress_diff::MatchKind::Changed)
        .map(|m| (name_of(&m.a), name_of(&m.b), m.similarity))
        .collect();
    Ok(DiffData {
        a_path: a_path.to_path_buf(),
        b_name: file_name(path),
        a_count,
        b_count: program.functions.len(),
        summary: diff.summary(),
        changed,
        added: diff.added.iter().map(name_of).collect(),
        removed: diff.removed.iter().map(name_of).collect(),
    })
}

fn render(ui: &mut Ui, data: &DiffData) {
    let (identical, changed, added, removed) = data.summary;
    ui.add_space(4.0);
    ui.label(format!(
        "B: {}  ({} functions; compared with {} functions in A)",
        data.b_name, data.b_count, data.a_count
    ));
    ui.label(
        RichText::new(format!(
            "identical {identical}   changed {changed}   added {added}   removed {removed}"
        ))
        .strong(),
    );

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if !data.changed.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Changed").strong());
                for (a, b, sim) in &data.changed {
                    let label = if a == b {
                        format!("{a}  ~{:.0}%", sim * 100.0)
                    } else {
                        format!("{a} → {b}  ~{:.0}%", sim * 100.0)
                    };
                    ui.label(RichText::new(label).monospace());
                }
            }
            if !data.added.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Added (only in B)").strong());
                for n in &data.added {
                    ui.label(RichText::new(n).monospace());
                }
            }
            if !data.removed.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Removed (only in A)").strong());
                for n in &data.removed {
                    ui.label(RichText::new(n).monospace());
                }
            }
        });
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
