//! The Triage view: a one-screen static malware triage of the active binary — risk flags,
//! capabilities grouped by behaviour (with MITRE ATT&CK), extracted IOCs (defanged), and
//! hashes — assembled by `orress-triage` from the already-computed analysis. Read-only; a
//! "Copy report" button exports the whole thing as Markdown.

use std::sync::{Arc, Mutex};

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_triage::hints::{Challenge, HintLevel};
use orress_triage::{IocKind, Report, build};
use orress_ui::muted;

/// Caches the report + challenge hints per file (keyed by SHA-256) so the analysis runs once.
#[derive(Default)]
pub struct TriageView {
    cache: Option<(String, Report, Challenge)>,
    /// VM-obfuscation findings, cached by SHA-256 (computed from the disassembled CFG, which is
    /// ready a little after the static report).
    vm: Option<(String, Vec<orress_vm::VmReport>)>,
    /// The concolically-recovered key per detected VM (index-aligned with `vm`), cached by SHA-256.
    /// The solve runs a sweep of symbolic executions, so it is computed once per file, never per
    /// frame.
    keys: Option<(String, Vec<Option<orress_vm::VmSolution>>)>,
    /// The VM scan + solve running on a worker thread, with the SHA-256 it is for.
    vm_job: Option<(String, VmSlot)>,
    /// How many graded hints the user has chosen to reveal.
    revealed: usize,
}

/// VM findings: the detected interpreters and the recovered key per interpreter.
type VmFindings = (Vec<orress_vm::VmReport>, Vec<Option<orress_vm::VmSolution>>);
type VmSlot = Arc<Mutex<Option<VmFindings>>>;

/// Scans for VM interpreters and solves each one on a worker thread (a sweep of symbolic
/// executions can take seconds, far too long for the UI thread).
fn spawn_vm_scan(program: Arc<orress_analysis::Program>, ctx: egui::Context) -> VmSlot {
    let slot: VmSlot = Arc::new(Mutex::new(None));
    let out = Arc::clone(&slot);
    let spawned = std::thread::Builder::new()
        .name("vm scan".into())
        .spawn(move || {
            let findings = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let reports = orress_vm::scan(&program);
                let keys = reports
                    .iter()
                    .map(|r| orress_vm::solve(&program, r))
                    .collect();
                (reports, keys)
            }))
            .unwrap_or_default();
            *out.lock().unwrap_or_else(|e| e.into_inner()) = Some(findings);
            ctx.request_repaint();
        });
    if spawned.is_err() {
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(Default::default());
    }
    slot
}

pub fn triage_view(ui: &mut Ui, view: &mut TriageView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Triage", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Triage").strong());
        ui.label(muted("static malware triage · IOCs · capabilities"));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a binary to triage it."));
        return;
    };
    let Some(analysis) = doc.analysis() else {
        ui.label(muted("Analysis is still running…"));
        return;
    };
    let sha = analysis.info.hashes.sha256.clone();
    if view.cache.as_ref().map(|(k, _, _)| k) != Some(&sha) {
        let strings: Vec<&str> = analysis.strings.iter().map(|s| s.text.as_str()).collect();
        let data: &[u8] = doc.bytes().map(|b| b.as_slice()).unwrap_or(&[]);
        let report = build(&analysis.info, &strings, data);
        let challenge = orress_triage::hints::analyze(&report, &analysis.info, &strings);
        view.cache = Some((sha.clone(), report, challenge));
        view.revealed = 0;
    }
    // VM-based obfuscation runs on the disassembled CFG, which finishes a little after the static
    // report; recompute (in the background) when it or the file changes.
    let mut scanning = false;
    if view.vm.as_ref().map(|(k, _)| k.as_str()) != Some(sha.as_str())
        && let Some(program) = doc.program()
    {
        if view.vm_job.as_ref().map(|(k, _)| k.as_str()) != Some(sha.as_str()) {
            let slot = spawn_vm_scan(Arc::clone(program), ui.ctx().clone());
            view.vm_job = Some((sha.clone(), slot));
        }
        let done = view
            .vm_job
            .as_ref()
            .and_then(|(_, slot)| slot.lock().unwrap_or_else(|e| e.into_inner()).take());
        match done {
            // One concolic solve per detected VM, cached alongside the reports (same SHA key).
            Some((reports, keys)) => {
                view.vm = Some((sha.clone(), reports));
                view.keys = Some((sha.clone(), keys));
                view.vm_job = None;
            }
            None => scanning = true,
        }
    }
    let vm: Vec<orress_vm::VmReport> = view
        .vm
        .as_ref()
        .filter(|(k, _)| *k == sha)
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let keys: Vec<Option<orress_vm::VmSolution>> = view
        .keys
        .as_ref()
        .filter(|(k, _)| *k == sha)
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let (_, report, challenge) = view.cache.as_ref().expect("report just built");

    if ui.button("📋 Copy report (Markdown)").clicked() {
        ui.ctx().copy_text(report_markdown(report, &vm, &keys));
    }
    ui.add_space(6.0);

    challenge_section(ui, challenge, &mut view.revealed);
    ui.add_space(6.0);
    if scanning {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted("Scanning for VM-based obfuscation…"));
        });
    }
    let report = &view.cache.as_ref().unwrap().1;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if !vm.is_empty() {
                ui.heading("VM-based obfuscation");
                let program = doc.program();
                for (i, r) in vm.iter().enumerate() {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        format!(
                            "⚠ Likely VM interpreter at {:#x} — dispatcher {:#x}, {} handlers ({:.0}% confidence)",
                            r.entry, r.dispatcher, r.handlers, r.confidence * 100.0
                        ),
                    );
                    // The concolically-recovered key: devirtualization's payoff, solved against the
                    // real bytecode (self-verifying when "verified").
                    if let Some(Some(sol)) = keys.get(i) {
                        let status = if sol.complete { "verified" } else { "partial" };
                        ui.horizontal(|ui| {
                            if ui.small_button("copy").clicked() {
                                ui.ctx().copy_text(String::from_utf8_lossy(&sol.key).into_owned());
                            }
                            ui.colored_label(
                                ui.visuals().text_color(),
                                format!(
                                    "🔑 recovered key ({status}, {} constraints): {:?}",
                                    sol.constraints,
                                    String::from_utf8_lossy(&sol.key)
                                ),
                            );
                        });
                        // The lifted per-byte logic the virtualized check performs (devirtualized
                        // by execution, so it is exact — not a guess).
                        if !sol.checks.is_empty() {
                            egui::CollapsingHeader::new("lifted checks")
                                .id_salt(("vm-checks", r.entry))
                                .show(ui, |ui| {
                                    for c in &sol.checks {
                                        ui.label(RichText::new(c).monospace().size(11.0));
                                    }
                                });
                        }
                    }
                    // The recovered instruction set and bytecode (devirtualization skeleton).
                    if let Some(p) = program {
                        egui::CollapsingHeader::new("opcode table & bytecode")
                            .id_salt(("vm", r.entry))
                            .show(ui, |ui| vm_detail(ui, p, r));
                    }
                }
                ui.add_space(8.0);
            }
            if !report.flags.is_empty() {
                ui.heading("Risk flags");
                for f in &report.flags {
                    ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {f}"));
                }
                ui.add_space(8.0);
            }

            if !report.configs.is_empty() {
                ui.heading("Extracted configuration");
                for c in &report.configs {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(&c.family).strong());
                        ui.label(muted(format!("({})", c.note)));
                    });
                    egui::Grid::new(format!("cfg-{}", c.family))
                        .num_columns(2)
                        .spacing([12.0, 2.0])
                        .show(ui, |ui| {
                            for f in &c.fields {
                                ui.label(muted(&f.key));
                                ui.horizontal(|ui| {
                                    if ui.small_button("copy").clicked() {
                                        ui.ctx().copy_text(f.value.clone());
                                    }
                                    ui.label(RichText::new(&f.value).monospace());
                                });
                                ui.end_row();
                            }
                        });
                    ui.add_space(4.0);
                }
                ui.add_space(8.0);
            }

            ui.heading("Capabilities");
            if report.capabilities.is_empty() {
                ui.label(muted("No higher-level capabilities detected."));
            }
            for c in &report.capabilities {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("• {}", c.name)).strong());
                    ui.label(muted(format!("({})", c.namespace)));
                    if !c.attack.is_empty() {
                        ui.label(muted(format!("[{}]", c.attack)));
                    }
                });
                ui.label(RichText::new(c.evidence.join(", ")).monospace().weak().size(11.0));
                ui.add_space(3.0);
            }
            ui.add_space(8.0);

            ui.heading("Imports by behaviour");
            if report.behaviors.is_empty() {
                ui.label(muted("No recognised library functions imported."));
            }
            for b in &report.behaviors {
                let title = if b.suspicious {
                    RichText::new(format!("⚠ {}", b.category.name())).strong()
                } else {
                    RichText::new(b.category.name()).strong()
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(title);
                    if !b.attack.is_empty() {
                        ui.label(muted(format!("[{}]", b.attack)));
                    }
                });
                ui.label(RichText::new(b.apis.join(", ")).monospace().weak());
                ui.add_space(4.0);
            }
            ui.add_space(8.0);

            ui.heading("Indicators (defanged)");
            if report.iocs.is_empty() {
                ui.label(muted("No IOCs found in strings."));
            }
            let mut current: Option<IocKind> = None;
            for i in &report.iocs {
                if current != Some(i.kind) {
                    ui.label(RichText::new(i.kind.label()).strong());
                    current = Some(i.kind);
                }
                ui.horizontal(|ui| {
                    let defanged = orress_triage::ioc::defang(&i.value);
                    if ui.small_button("copy").on_hover_text(&i.value).clicked() {
                        ui.ctx().copy_text(i.value.clone());
                    }
                    ui.label(RichText::new(defanged).monospace());
                });
            }
            ui.add_space(8.0);

            ui.heading("Hashes");
            let h = &analysis.info.hashes;
            egui::Grid::new("triage-hashes")
                .num_columns(2)
                .spacing([12.0, 2.0])
                .show(ui, |ui| {
                    for (label, value) in [
                        ("MD5", h.md5.as_str()),
                        ("SHA-1", h.sha1.as_str()),
                        ("SHA-256", h.sha256.as_str()),
                        ("Imphash", h.imphash.as_deref().unwrap_or("—")),
                        ("TLSH", report.fuzzy.tlsh.as_deref().unwrap_or("—")),
                        ("ssdeep", report.fuzzy.ssdeep.as_str()),
                    ] {
                        ui.label(muted(label));
                        ui.label(RichText::new(value).monospace());
                        ui.end_row();
                    }
                });
        });
}

/// Renders a detected VM's recovered opcode table and bytecode disassembly — the first stage of
/// devirtualization: the virtual instruction set and the virtual program the interpreter runs.
fn vm_detail(ui: &mut Ui, program: &orress_analysis::Program, report: &orress_vm::VmReport) {
    let dis = orress_vm::disassemble(program, report);
    if let Some(bc) = orress_vm::bytecode(program, report) {
        let prog_len = dis
            .as_ref()
            .and_then(|d| d.last())
            .map(|i| i.offset + 1 + i.operands.len());
        match prog_len.or(bc.len.map(|l| l as usize)) {
            Some(len) => ui.label(muted(format!("bytecode: {len} bytes at {:#x}", bc.base))),
            None => ui.label(muted(format!("bytecode at {:#x}", bc.base))),
        };
    }
    ui.label(RichText::new("opcode table").strong());
    for h in orress_vm::handlers(program, report) {
        ui.label(
            RichText::new(format!(
                "op {:>3}: {:<13} {:#x}  [{}]",
                h.opcode,
                orress_vm::operation(&h),
                h.address,
                h.ops.join(", ")
            ))
            .monospace()
            .size(11.0),
        );
    }
    if let Some(dis) = &dis {
        ui.add_space(4.0);
        ui.label(RichText::new("bytecode disassembly").strong());
        for ins in dis {
            let operands: Vec<String> = ins.operands.iter().map(|b| format!("{b:#04x}")).collect();
            ui.label(
                RichText::new(format!(
                    "{:04x}: op{:<3} {:<13} {}",
                    ins.offset,
                    ins.opcode,
                    ins.op,
                    operands.join(", ")
                ))
                .monospace()
                .size(11.0),
            );
        }
    }
}

/// The report's Markdown, with a VM-obfuscation section appended when any was detected (so the
/// exported report includes it too).
fn report_markdown(
    report: &Report,
    vm: &[orress_vm::VmReport],
    keys: &[Option<orress_vm::VmSolution>],
) -> String {
    let mut md = report.markdown.clone();
    if !vm.is_empty() {
        md.push_str("\n## VM-based obfuscation\n\n");
        for (i, r) in vm.iter().enumerate() {
            md.push_str(&format!(
                "- Likely VM interpreter at `{:#x}` — dispatcher `{:#x}`, {} handlers / {} blocks, {:.0}% confidence\n",
                r.entry, r.dispatcher, r.handlers, r.blocks, r.confidence * 100.0
            ));
            if let Some(Some(sol)) = keys.get(i) {
                let status = if sol.complete { "verified" } else { "partial" };
                md.push_str(&format!(
                    "  - Recovered key ({status}): `{}`\n",
                    String::from_utf8_lossy(&sol.key)
                ));
                for c in &sol.checks {
                    md.push_str(&format!("    - `{c}`\n"));
                }
            }
        }
    }
    md
}

/// The CTF/crackme hint panel: a classification, suggested techniques, and graded hints the user
/// reveals one at a time (so the answer isn't spoiled up front).
fn challenge_section(ui: &mut Ui, c: &Challenge, revealed: &mut usize) {
    ui.heading("Challenge hints");
    ui.label(RichText::new(&c.summary).strong());
    if !c.techniques.is_empty() {
        ui.label(muted(format!("Try: {}", c.techniques.join(", "))));
    }
    ui.add_space(4.0);

    let shown = (*revealed).min(c.hints.len());
    for h in &c.hints[..shown] {
        let color = match h.level {
            HintLevel::Nudge => ui.visuals().weak_text_color(),
            HintLevel::Direction => ui.visuals().text_color(),
            HintLevel::Solution => ui.visuals().warn_fg_color,
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("[{}]", h.level.label()))
                    .strong()
                    .color(color),
            );
            ui.label(RichText::new(&h.text).color(color));
        });
        ui.add_space(2.0);
    }

    if shown < c.hints.len() {
        let label = format!("💡 Reveal hint ({}/{})", shown + 1, c.hints.len());
        if ui
            .button(label)
            .on_hover_text("Graded: each hint gives a little more away")
            .clicked()
        {
            *revealed = shown + 1;
        }
    } else if !c.hints.is_empty() {
        ui.label(muted("All hints shown."));
    }
}
