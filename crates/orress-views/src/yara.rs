//! The YARA workbench: write a YARA rule and test it live against the open file, powered by the
//! pure-Rust YARA-X engine (`orress-triage::yara`). Matches show their rule, pattern, offset and
//! a byte preview.

use std::sync::{Arc, Mutex};

use egui::{RichText, Ui};
use orress_debug::read_all_memory;
use orress_project::DocStore;
use orress_triage::yara::{generate_rule, scan, scan_dir, scan_regions_report};
use orress_triage::{LibHit, MemScan, YaraOutcome};
use orress_ui::muted;

/// Cap on how much of a process's memory to read for a scan.
const MEM_CAP: usize = 256 * 1024 * 1024;

const DEFAULT_RULE: &str = r#"rule example {
    meta:
        author = "analyst"
        description = "matches the PE DOS stub"
    strings:
        $dos = "This program cannot be run in DOS mode"
        $mz  = { 4D 5A }
    condition:
        $mz at 0 and $dos
}
"#;

/// Persistent UI state for the YARA tab.
pub struct YaraView {
    rule: String,
    outcome: Option<YaraOutcome>,
    scanned: String,
    /// Results of scanning the open file against a rule folder: (hits, errors).
    library: Option<(Vec<LibHit>, Vec<String>)>,
    library_dir: String,
    pid: String,
    /// The process-scan result plus per-region errors (timeouts, budget exhausted).
    mem: Option<MemResult>,
    /// Folder and process scans run on worker threads (they read many files or up to
    /// [`MEM_CAP`] of memory); these hold their results until they finish.
    library_job: Option<Slot<(Vec<LibHit>, Vec<String>)>>,
    mem_job: Option<Slot<MemResult>>,
}

type Slot<T> = Arc<Mutex<Option<T>>>;

/// A process scan: the hits plus per-region errors, or why memory couldn't be read.
type MemResult = Result<(MemScan, Vec<String>), String>;

/// Runs `work` on a worker thread; its result (or `on_panic()` if it panicked) lands in
/// the returned slot and a repaint is requested.
fn spawn_job<T: Send + 'static>(
    ctx: &egui::Context,
    work: impl FnOnce() -> T + Send + 'static,
    on_panic: impl FnOnce() -> T + Send + 'static,
) -> Slot<T> {
    let slot: Slot<T> = Arc::new(Mutex::new(None));
    let out = Arc::clone(&slot);
    let ctx = ctx.clone();
    // If the thread cannot start, the slot is never filled; `take_done` notices that nobody
    // else holds it and gives up waiting.
    let _ = std::thread::Builder::new()
        .name("yara scan".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .unwrap_or_else(|_| on_panic());
            *out.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
            ctx.request_repaint();
        });
    slot
}

/// Takes a finished job's result; clears `job` when it is done.
fn take_done<T>(job: &mut Option<Slot<T>>) -> Option<T> {
    let done = job
        .as_ref()?
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if done.is_some() || job.as_ref().is_some_and(|s| Arc::strong_count(s) == 1) {
        *job = None;
    }
    done
}

impl Default for YaraView {
    fn default() -> Self {
        Self {
            rule: DEFAULT_RULE.to_string(),
            outcome: None,
            scanned: String::new(),
            library: None,
            library_dir: String::new(),
            pid: String::new(),
            mem: None,
            library_job: None,
            mem_job: None,
        }
    }
}

pub fn yara_view(ui: &mut Ui, view: &mut YaraView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Yara", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("YARA workbench").strong());
        ui.label(muted("write a rule · scan the open file (YARA-X)"));
    });
    ui.separator();

    let file = docs
        .active()
        .map(|d| d.file_name())
        .unwrap_or_else(|| "no file".into());

    if let Some(done) = take_done(&mut view.library_job) {
        view.library = Some(done);
    }
    if let Some(done) = take_done(&mut view.mem_job) {
        view.mem = Some(done);
    }

    ui.label(muted("Rule:"));
    egui::ScrollArea::vertical()
        .max_height(240.0)
        .id_salt("yara-rule")
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut view.rule)
                    .code_editor()
                    .desired_rows(10)
                    .desired_width(f32::INFINITY),
            );
        });

    ui.horizontal(|ui| {
        let enabled = docs.active().and_then(|d| d.bytes()).is_some();
        if ui
            .add_enabled(enabled, egui::Button::new("▶ Scan open file"))
            .on_hover_text(format!("Scan {file} with this rule"))
            .clicked()
            && let Some(bytes) = docs.active().and_then(|d| d.bytes())
        {
            view.outcome = Some(scan(&view.rule, bytes));
            view.scanned = file.clone();
        }
        if ui
            .add_enabled(enabled, egui::Button::new("✨ Generate from strings"))
            .on_hover_text("Build a starter rule from the sample's distinctive strings")
            .clicked()
            && let Some(analysis) = docs.active().and_then(|d| d.analysis())
        {
            let strings: Vec<&str> = analysis.strings.iter().map(|s| s.text.as_str()).collect();
            view.rule = generate_rule(&file, &strings);
            view.outcome = None;
        }
        let library_busy = view.library_job.is_some();
        if ui
            .add_enabled(
                enabled && !library_busy,
                egui::Button::new("📁 Scan rule folder…"),
            )
            .on_hover_text("Scan the open file against every .yar/.yara rule in a folder")
            .clicked()
            && let Some(dir) = rfd::FileDialog::new()
                .set_title("Pick a YARA rule folder")
                .pick_folder()
            && let Some(bytes) = docs.active().and_then(|d| d.bytes()).cloned()
        {
            view.library_dir = dir.display().to_string();
            view.library = None;
            view.library_job = Some(spawn_job(
                ui.ctx(),
                move || scan_dir(&dir, &bytes),
                || {
                    (
                        Vec::new(),
                        vec!["the folder scan hit an internal error".to_string()],
                    )
                },
            ));
        }
        if library_busy {
            ui.spinner();
            ui.label(muted("scanning rule folder…"));
        }
        if !enabled {
            ui.label(muted("open a file to scan"));
        }
    });

    // In-memory scan of a running process (unpacks/decrypts show up in memory).
    ui.horizontal(|ui| {
        ui.label("Running process (PID)");
        ui.add(egui::TextEdit::singleline(&mut view.pid).desired_width(80.0));
        let mem_busy = view.mem_job.is_some();
        if ui
            .add_enabled(!mem_busy, egui::Button::new("🧠 Scan process memory"))
            .on_hover_text("Read the process's committed memory and scan it with this rule")
            .clicked()
        {
            match view.pid.trim().parse::<u32>() {
                Ok(pid) => {
                    let rule = view.rule.clone();
                    view.mem = None;
                    view.mem_job = Some(spawn_job(
                        ui.ctx(),
                        move || {
                            read_all_memory(pid, MEM_CAP).map(|regions| {
                                scan_regions_report(
                                    &rule,
                                    regions.iter().map(|r| (r.base, r.data.as_slice())),
                                )
                            })
                        },
                        || Err("the process scan hit an internal error".into()),
                    ));
                }
                Err(_) => view.mem = Some(Err("enter a numeric PID".into())),
            }
        }
        if mem_busy {
            ui.spinner();
            ui.label(muted("reading process memory…"));
        }
    });

    if let Some(mem) = &view.mem {
        ui.add_space(4.0);
        match mem {
            Err(e) => {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    format!("process scan failed: {e}"),
                );
            }
            Ok((MemScan::CompileError(e), _)) => {
                ui.colored_label(ui.visuals().error_fg_color, "Rule did not compile:");
                ui.label(RichText::new(e).monospace());
            }
            Ok((MemScan::Hits(hits), errors)) => {
                for e in errors.iter().take(20) {
                    ui.colored_label(ui.visuals().warn_fg_color, format!("  {e}"));
                }
                if hits.is_empty() {
                    ui.label(muted("No matches in process memory."));
                } else {
                    ui.label(
                        RichText::new(format!("{} match(es) in process memory", hits.len()))
                            .strong(),
                    );
                    for h in hits.iter().take(500) {
                        ui.label(
                            RichText::new(format!(
                                "  {} · {} @ {:#x}  {:?}",
                                h.rule, h.pattern, h.address, h.preview
                            ))
                            .monospace()
                            .weak(),
                        );
                    }
                }
            }
        }
    }

    if let Some((hits, errors)) = &view.library {
        ui.add_space(6.0);
        ui.separator();
        ui.label(RichText::new(format!("Library scan — {}", view.library_dir)).strong());
        if hits.is_empty() {
            ui.label(muted("No rules in the folder matched."));
        }
        for h in hits {
            ui.label(
                RichText::new(format!("  {} · {} ({} match)", h.file, h.rule, h.matches))
                    .monospace(),
            );
        }
        for e in errors {
            ui.colored_label(ui.visuals().warn_fg_color, format!("  {e}"));
        }
    }

    let Some(outcome) = &view.outcome else {
        return;
    };
    ui.add_space(6.0);
    ui.separator();
    match outcome {
        YaraOutcome::CompileError(e) => {
            ui.colored_label(ui.visuals().error_fg_color, "Rule did not compile:");
            ui.label(RichText::new(e).monospace());
        }
        YaraOutcome::ScanError(e) => {
            ui.colored_label(ui.visuals().error_fg_color, format!("Scan error: {e}"));
        }
        YaraOutcome::Hits(hits) => {
            if hits.is_empty() {
                ui.label(muted(format!("No rules matched {}.", view.scanned)));
                return;
            }
            ui.label(
                RichText::new(format!("{} rule(s) matched {}", hits.len(), view.scanned)).strong(),
            );
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for hit in hits {
                        ui.add_space(4.0);
                        ui.label(RichText::new(&hit.rule).strong().monospace());
                        for m in &hit.matches {
                            ui.label(
                                RichText::new(format!(
                                    "   {}  @ {:#x}  {:?}",
                                    m.pattern, m.range.start, m.preview
                                ))
                                .monospace()
                                .weak(),
                            );
                        }
                    }
                });
        }
    }
}
