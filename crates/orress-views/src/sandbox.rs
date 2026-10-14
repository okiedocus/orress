//! The Sandbox view: the safety gate for dynamic analysis. It shows whether ORRESS is running
//! inside a VM, the execution-guard decision, and — only once the guard allows (in a VM, with an
//! explicit confirmation) — lets you run the sample and watch its activity log. Running happens
//! on a background thread so the UI stays responsive.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egui::{RichText, Ui};
use orress_project::DocStore;
use orress_sandbox::vbox::{self, Vm};
use orress_sandbox::{
    ActivityEvent, Category, Decision, FakeNet, FakeNetConfig, Monitor, NetEvent, NetKind, Policy,
    RunEvent, RunLog, VmEvidence, detect, guard, run,
};
use orress_ui::muted;

/// Persistent UI state for the Sandbox tab.
pub struct SandboxView {
    policy: Policy,
    confirmed: bool,
    exe_path: String,
    args: String,
    timeout_secs: u32,
    vm: Option<VmEvidence>,
    result: Arc<Mutex<Option<RunLog>>>,
    running: Arc<AtomicBool>,
    fakenet: Option<FakeNet>,
    answer_ip: String,
    dns_port: u16,
    http_port: u16,
    // VirtualBox control
    /// Whether VBoxManage exists, checked once (it is a filesystem search).
    vbox_available: Option<bool>,
    vbox_loaded: bool,
    vbox_vms: Vec<Vm>,
    vbox_sel: usize,
    vbox_state: String,
    vbox_snaps: Vec<String>,
    vbox_snap_name: String,
    vbox_status: Arc<Mutex<String>>,
    vbox_busy: Arc<AtomicBool>,
    /// VM list, state and snapshots queried on a worker thread (VBoxManage is slow).
    vbox_info: Arc<Mutex<Option<VboxInfo>>>,
    // ETW activity monitor
    monitor: Option<Monitor>,
    monitor_error: Option<String>,
    monitor_filter_pid: String,
    /// The monitor's events, topped up periodically with only the new ones (copying up to 50k
    /// events every refresh is too slow), with the indices that pass the PID filter.
    etw_snapshot: Vec<ActivityEvent>,
    /// How many of the monitor's events have been read so far (for `events_since`).
    etw_seen: usize,
    etw_shown: Vec<usize>,
    etw_key: Option<(Instant, Option<u32>)>,
    /// The newest fake-network events, topped up periodically with only the new ones.
    net_snapshot: Vec<NetEvent>,
    /// How many fake-network events have been read so far (for `events_since`).
    net_seen: usize,
    net_at: Option<Instant>,
}

/// How often the activity logs are re-read while live.
const LOG_REFRESH: Duration = Duration::from_millis(500);
/// Fake-network log entries shown (the newest).
const MAX_NET_SHOWN: usize = 1_000;
/// Activity-monitor events kept for display (the monitor's own cap); beyond this the oldest fifth
/// is dropped.
const MAX_ETW_KEPT: usize = 50_000;

/// What VBoxManage reported for the VM list and the selected VM.
struct VboxInfo {
    vms: Vec<Vm>,
    selected: usize,
    state: String,
    snaps: Vec<String>,
}

/// Lists the VMs and reads the state and snapshots of `selected` (by name; the first VM if
/// it is gone). Runs VBoxManage several times, so call it off the UI thread.
fn vbox_query(selected: Option<&str>) -> VboxInfo {
    let vms = vbox::list_vms().unwrap_or_default();
    let selected = selected
        .and_then(|n| vms.iter().position(|v| v.name == n))
        .unwrap_or(0);
    let (state, snaps) = match vms.get(selected) {
        Some(vm) => (
            vbox::state(&vm.name).unwrap_or_else(|e| e),
            vbox::snapshots(&vm.name).unwrap_or_default(),
        ),
        None => (String::new(), Vec::new()),
    };
    VboxInfo {
        vms,
        selected,
        state,
        snaps,
    }
}

impl Default for SandboxView {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            confirmed: false,
            exe_path: String::new(),
            args: String::new(),
            timeout_secs: 20,
            vm: None,
            result: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            fakenet: None,
            answer_ip: "127.0.0.1".into(),
            dns_port: 53,
            http_port: 80,
            vbox_available: None,
            vbox_loaded: false,
            vbox_vms: Vec::new(),
            vbox_sel: 0,
            vbox_state: String::new(),
            vbox_snaps: Vec::new(),
            vbox_snap_name: "clean".into(),
            vbox_status: Arc::new(Mutex::new(String::new())),
            vbox_busy: Arc::new(AtomicBool::new(false)),
            vbox_info: Arc::new(Mutex::new(None)),
            monitor: None,
            monitor_error: None,
            monitor_filter_pid: String::new(),
            etw_snapshot: Vec::new(),
            etw_seen: 0,
            etw_shown: Vec::new(),
            etw_key: None,
            net_snapshot: Vec::new(),
            net_seen: 0,
            net_at: None,
        }
    }
}

pub fn sandbox_view(ui: &mut Ui, view: &mut SandboxView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Sandbox", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Sandbox").strong());
        ui.label(muted("safety gate · VM check · guarded run"));
    });
    ui.separator();

    let vm = view.vm.get_or_insert_with(detect);
    let in_vm = vm.looks_like_vm();

    // --- VM status -------------------------------------------------------
    if in_vm {
        let vendor = vm
            .vendor
            .clone()
            .unwrap_or_else(|| "guest additions".into());
        ui.colored_label(
            egui::Color32::from_rgb(90, 180, 90),
            format!("✔ Running inside a VM ({vendor})"),
        );
    } else if vm.ambiguous() {
        let vendor = vm.vendor.clone().unwrap_or_else(|| "unknown".into());
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!(
                "⚠ Hypervisor present ({vendor}) but this is NOT a confirmed VM — on Windows this \
                 is usually VBS on a physical host. Treating as bare metal."
            ),
        );
    } else {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            "⚠ No VM detected — this looks like a bare-metal host.",
        );
    }
    for hint in &vm.hints {
        ui.label(muted(format!("   • {hint}")));
    }
    ui.add_space(8.0);

    vbox_section(ui, view);
    ui.add_space(8.0);

    fakenet_section(ui, view);
    ui.add_space(8.0);

    monitor_section(ui, view);
    ui.add_space(8.0);

    // --- Policy ----------------------------------------------------------
    ui.heading("Policy");
    ui.checkbox(&mut view.policy.require_vm, "Refuse to run outside a VM");
    ui.checkbox(
        &mut view.confirmed,
        "I understand this runs the sample on this machine",
    );
    ui.add_space(8.0);

    // --- Target ----------------------------------------------------------
    ui.heading("Run");
    ui.label(muted(
        "Runs the sample as a normal process and records its output and exit. Richer monitoring \
         (file/registry/network) comes later. Only do this inside a disposable VM.",
    ));
    egui::Grid::new("sandbox-run")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            ui.label("Executable");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut view.exe_path);
                if ui.small_button("use open file").clicked()
                    && let Some(doc) = docs.active()
                {
                    view.exe_path = doc.path.display().to_string();
                }
                if ui.small_button("browse…").clicked()
                    && let Some(p) = rfd::FileDialog::new().pick_file()
                {
                    view.exe_path = p.display().to_string();
                }
            });
            ui.end_row();
            ui.label("Arguments");
            ui.text_edit_singleline(&mut view.args);
            ui.end_row();
            ui.label("Timeout (s)");
            ui.add(egui::DragValue::new(&mut view.timeout_secs).range(1..=600));
            ui.end_row();
        });

    let decision = guard(&view.policy, in_vm, view.confirmed);
    let running = view.running.load(Ordering::SeqCst);
    let color = match decision {
        Decision::Allowed => ui.visuals().text_color(),
        Decision::NeedsConfirmation => ui.visuals().warn_fg_color,
        Decision::RefusedNotInVm => ui.visuals().error_fg_color,
    };
    ui.colored_label(color, decision.explain());

    let can_run = decision.is_allowed() && !view.exe_path.trim().is_empty() && !running;
    if ui
        .add_enabled(can_run, egui::Button::new("▶ Run in sandbox"))
        .clicked()
    {
        start_run(view, ui.ctx().clone());
    }
    if running {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted("running…"));
        });
    }

    // --- Activity log ----------------------------------------------------
    if let Some(log) = lock(&view.result).as_ref() {
        ui.add_space(6.0);
        ui.separator();
        let status = if log.timed_out {
            "timed out".to_string()
        } else {
            log.exit_code
                .map(|c| format!("exited {c}"))
                .unwrap_or_else(|| "finished".into())
        };
        ui.label(
            RichText::new(format!(
                "Activity log — {status} in {:.1}s",
                log.duration.as_secs_f32()
            ))
            .strong(),
        );
        for ev in &log.events {
            let (txt, col) = match ev {
                RunEvent::Started(pid) => {
                    (format!("[start] pid {pid}"), ui.visuals().weak_text_color())
                }
                RunEvent::Stdout(s) => (format!("out: {s}"), ui.visuals().text_color()),
                RunEvent::Stderr(s) => (format!("err: {s}"), ui.visuals().warn_fg_color),
                RunEvent::Exited(c) => (format!("[exit {c}]"), ui.visuals().weak_text_color()),
                RunEvent::Timeout => ("[timeout — killed]".into(), ui.visuals().error_fg_color),
                RunEvent::Error(e) => (format!("[error] {e}"), ui.visuals().error_fg_color),
            };
            ui.label(RichText::new(txt).monospace().color(col));
        }
    }
}

fn vbox_section(ui: &mut Ui, view: &mut SandboxView) {
    ui.heading("VirtualBox control");
    if !*view.vbox_available.get_or_insert_with(vbox::available) {
        ui.label(muted(
            "VirtualBox not found. Install it (see \"Set up an analysis VM\" in the README) to \
             snapshot, revert and start an analysis VM from here.",
        ));
        return;
    }
    ui.label(muted(
        "Orchestrate an analysis VM: revert to a clean snapshot, run the sample inside it, then \
         revert again. Restore and power-off change the VM's state.",
    ));

    if let Some(info) = lock(&view.vbox_info).take() {
        view.vbox_vms = info.vms;
        view.vbox_sel = info.selected;
        view.vbox_state = info.state;
        view.vbox_snaps = info.snaps;
    }
    let busy = view.vbox_busy.load(Ordering::SeqCst);
    if !view.vbox_loaded && !busy {
        view.vbox_loaded = true;
        vbox_refresh(view, ui.ctx().clone(), None);
    }

    ui.horizontal(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("↻ Refresh"))
            .clicked()
        {
            let selected = view.vbox_vms.get(view.vbox_sel).map(|v| v.name.clone());
            vbox_refresh(view, ui.ctx().clone(), selected);
        }
        let current = view
            .vbox_vms
            .get(view.vbox_sel)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| "(no VM)".into());
        let before = view.vbox_sel;
        ui.add_enabled_ui(!busy, |ui| {
            egui::ComboBox::from_id_salt("vbox-vm")
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for (i, vm) in view.vbox_vms.iter().enumerate() {
                        ui.selectable_value(&mut view.vbox_sel, i, &vm.name);
                    }
                });
        });
        if view.vbox_sel != before {
            let selected = view.vbox_vms.get(view.vbox_sel).map(|v| v.name.clone());
            view.vbox_state.clear();
            view.vbox_snaps.clear();
            vbox_refresh(view, ui.ctx().clone(), selected);
        }
        if !view.vbox_state.is_empty() {
            ui.label(muted(format!("state: {}", view.vbox_state)));
        }
    });

    let Some(vm) = view.vbox_vms.get(view.vbox_sel).map(|v| v.name.clone()) else {
        return;
    };

    ui.horizontal(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("▶ Start (GUI)"))
            .clicked()
        {
            let v = vm.clone();
            vbox_action(view, ui.ctx().clone(), &vm, "start", move || {
                vbox::start(&v, false)
            });
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Start (headless)"))
            .clicked()
        {
            let v = vm.clone();
            vbox_action(view, ui.ctx().clone(), &vm, "start", move || {
                vbox::start(&v, true)
            });
        }
        if ui
            .add_enabled(!busy, egui::Button::new("⏹ Power off"))
            .clicked()
        {
            let v = vm.clone();
            vbox_action(view, ui.ctx().clone(), &vm, "poweroff", move || {
                vbox::poweroff(&v)
            });
        }
    });

    ui.horizontal(|ui| {
        ui.label("Snapshot");
        ui.text_edit_singleline(&mut view.vbox_snap_name);
        if ui
            .add_enabled(!busy, egui::Button::new("📷 Take"))
            .clicked()
        {
            let (v, n) = (vm.clone(), view.vbox_snap_name.clone());
            vbox_action(view, ui.ctx().clone(), &vm, "take snapshot", move || {
                vbox::take_snapshot(&v, &n)
            });
        }
        if ui
            .add_enabled(!busy, egui::Button::new("↩ Restore current"))
            .clicked()
        {
            let v = vm.clone();
            vbox_action(view, ui.ctx().clone(), &vm, "restore current", move || {
                vbox::restore_current(&v)
            });
        }
    });

    if !view.vbox_snaps.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(muted("snapshots:"));
            for snap in view.vbox_snaps.clone() {
                if ui
                    .add_enabled(!busy, egui::Button::new(format!("↩ {snap}")).small())
                    .clicked()
                {
                    let (v, s) = (vm.clone(), snap.clone());
                    vbox_action(view, ui.ctx().clone(), &vm, "restore", move || {
                        vbox::restore_snapshot(&v, &s)
                    });
                }
            }
        });
    }

    if busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted(lock(&view.vbox_status).clone()));
        });
    } else {
        let status = lock(&view.vbox_status).clone();
        if !status.is_empty() {
            ui.label(muted(status));
        }
    }
}

/// Re-reads the VM list and the state and snapshots of `selected` on a background thread.
fn vbox_refresh(view: &SandboxView, ctx: egui::Context, selected: Option<String>) {
    vbox_job(view, ctx, None, selected, || Ok(()));
}

/// Runs a (possibly slow) VBoxManage action on `vm` on a background thread, recording its
/// result, then re-reads the VM's state and snapshots (a Take adds one; a Restore changes the
/// state).
fn vbox_action(
    view: &SandboxView,
    ctx: egui::Context,
    vm: &str,
    label: &'static str,
    op: impl FnOnce() -> Result<(), String> + Send + 'static,
) {
    vbox_job(view, ctx, Some(label), Some(vm.to_owned()), op);
}

/// `op` then a fresh [`vbox_query`], on a worker thread. A `None` label is a silent refresh.
fn vbox_job(
    view: &SandboxView,
    ctx: egui::Context,
    label: Option<&'static str>,
    selected: Option<String>,
    op: impl FnOnce() -> Result<(), String> + Send + 'static,
) {
    let status = Arc::clone(&view.vbox_status);
    let busy = Arc::clone(&view.vbox_busy);
    let info = Arc::clone(&view.vbox_info);
    *lock(&status) = label.map_or_else(|| "querying VirtualBox…".into(), |l| format!("{l}…"));
    busy.store(true, Ordering::SeqCst);
    let spawned = std::thread::Builder::new()
        .name("vboxmanage".into())
        .spawn(move || {
            let outcome = op();
            let fresh = vbox_query(selected.as_deref());
            let msg = match (label, outcome) {
                (None, Ok(())) => String::new(),
                (None, Err(e)) => format!("query failed: {e}"),
                (Some(l), Ok(())) => format!("{l}: done"),
                (Some(l), Err(e)) => format!("{l} failed: {e}"),
            };
            *lock(&info) = Some(fresh);
            *lock(&status) = msg;
            busy.store(false, Ordering::SeqCst);
            ctx.request_repaint();
        });
    if let Err(e) = spawned {
        *lock(&view.vbox_status) = format!("could not start VBoxManage thread: {e}");
        view.vbox_busy.store(false, Ordering::SeqCst);
    }
}

/// Locks `m`, recovering the data if a worker panicked while holding it.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn fakenet_section(ui: &mut Ui, view: &mut SandboxView) {
    ui.heading("Fake network");
    ui.label(muted(
        "Point the VM's DNS and gateway here — every DNS query and HTTP request is answered and \
         logged, so the sample never reaches real infrastructure.",
    ));
    if let Some(net) = &view.fakenet {
        let mut stop = false;
        ui.horizontal(|ui| {
            if let Some(a) = net.dns_addr {
                ui.label(RichText::new(format!("DNS :{}", a.port())).monospace());
            }
            if let Some(a) = net.http_addr {
                ui.label(RichText::new(format!("HTTP :{}", a.port())).monospace());
            }
            if ui.button("Stop").clicked() {
                stop = true;
            }
        });
        for e in &net.errors {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!("bind failed: {e} (ports 53/80 need admin)"),
            );
        }
        if view.net_at.is_none_or(|t| t.elapsed() >= LOG_REFRESH) {
            // Copy only what arrived since the last refresh, and keep just the newest shown.
            let (new, seen) = net.events_since(view.net_seen);
            view.net_seen = seen;
            view.net_snapshot.extend(new);
            let excess = view.net_snapshot.len().saturating_sub(MAX_NET_SHOWN);
            view.net_snapshot.drain(..excess);
            view.net_at = Some(Instant::now());
        }
        let events = &view.net_snapshot;
        if events.is_empty() && net.errors.is_empty() {
            ui.label(muted("Waiting for the sample's network activity…"));
        }
        if view.net_seen > MAX_NET_SHOWN {
            ui.label(muted(format!(
                "{} event(s); showing the newest {MAX_NET_SHOWN}",
                view.net_seen
            )));
        }
        for ev in events {
            let tag = match ev.kind {
                NetKind::Dns => "DNS ",
                NetKind::Http => "HTTP",
            };
            ui.label(RichText::new(format!("{tag}  {}", ev.summary)).monospace());
        }
        // Refresh the log while the responder is live.
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        if stop {
            view.fakenet = None; // Drop stops the listeners
            view.net_snapshot.clear();
            view.net_seen = 0;
            view.net_at = None;
        }
    } else {
        egui::Grid::new("fakenet-cfg")
            .num_columns(2)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.label("Answer IP");
                ui.text_edit_singleline(&mut view.answer_ip);
                ui.end_row();
                ui.label("DNS port");
                ui.add(egui::DragValue::new(&mut view.dns_port));
                ui.end_row();
                ui.label("HTTP port");
                ui.add(egui::DragValue::new(&mut view.http_port));
                ui.end_row();
            });
        if ui.button("▶ Start fake network").clicked() {
            let answer_ip =
                Ipv4Addr::from_str(view.answer_ip.trim()).unwrap_or(Ipv4Addr::LOCALHOST);
            view.fakenet = Some(FakeNet::start(FakeNetConfig {
                answer_ip,
                dns_port: view.dns_port,
                http_port: view.http_port,
            }));
        }
    }
}

/// A colour for each activity category.
fn category_color(cat: Category) -> egui::Color32 {
    match cat {
        Category::Process => egui::Color32::from_rgb(120, 180, 240),
        Category::File => egui::Color32::from_rgb(130, 200, 140),
        Category::Registry => egui::Color32::from_rgb(220, 180, 100),
        Category::Network => egui::Color32::from_rgb(230, 130, 130),
        Category::Image => egui::Color32::from_rgb(180, 150, 220),
        Category::Other => egui::Color32::GRAY,
    }
}

fn monitor_section(ui: &mut Ui, view: &mut SandboxView) {
    ui.heading("Activity monitor (ETW)");
    ui.label(muted(
        "Kernel tracing of process, file, registry, network and image-load events while a sample \
         runs. Requires running ORRESS as administrator; filter by the sample's PID to cut noise.",
    ));

    if view.monitor.is_some() {
        let mut stop = false;
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted("tracing system activity…"));
            if ui.button("⏹ Stop").clicked() {
                stop = true;
            }
            ui.label("Filter PID");
            ui.add(egui::TextEdit::singleline(&mut view.monitor_filter_pid).desired_width(70.0))
                .on_hover_text("Show only this PID (blank = all)");
        });

        let filter = view.monitor_filter_pid.trim().parse::<u32>().ok();
        // Re-read the log periodically (or when the filter changes), not every frame.
        let reread = view
            .etw_key
            .is_none_or(|(at, _)| at.elapsed() >= LOG_REFRESH);
        if reread && let Some(monitor) = &view.monitor {
            // Copy only the events recorded since the last refresh.
            let (new, seen) = monitor.events_since(view.etw_seen);
            view.etw_seen = seen;
            view.etw_snapshot.extend(new);
            if view.etw_snapshot.len() > MAX_ETW_KEPT {
                let excess = view.etw_snapshot.len() - MAX_ETW_KEPT + MAX_ETW_KEPT / 5;
                view.etw_snapshot.drain(..excess);
            }
        }
        if reread || view.etw_key.map(|(_, f)| f) != Some(filter) {
            view.etw_shown = view
                .etw_snapshot
                .iter()
                .enumerate()
                .filter(|(_, e)| filter.is_none_or(|p| e.pid == p))
                .map(|(i, _)| i)
                .collect();
            let at = match view.etw_key {
                Some((at, _)) if !reread => at,
                _ => Instant::now(),
            };
            view.etw_key = Some((at, filter));
        }
        let events = &view.etw_snapshot;
        let shown = &view.etw_shown;
        ui.label(muted(format!(
            "{} event(s) captured{}",
            events.len(),
            match filter {
                Some(p) => format!(" · {} shown for PID {p}", shown.len()),
                None => String::new(),
            }
        )));

        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .id_salt("etw-log")
            .show_rows(ui, row_height, shown.len(), |ui, rows| {
                // Only the visible rows are laid out; oldest-first so the newest stays in view.
                for e in shown[rows].iter().filter_map(|&i| events.get(i)) {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{:>8}", e.category.label()))
                                .monospace()
                                .color(category_color(e.category)),
                        );
                        ui.label(
                            RichText::new(format!("pid {:>6}", e.pid))
                                .monospace()
                                .weak(),
                        );
                        ui.label(RichText::new(&e.op).monospace());
                        if !e.detail.is_empty() {
                            ui.label(RichText::new(&e.detail).monospace().weak());
                        }
                    });
                }
            });

        ui.ctx().request_repaint_after(Duration::from_millis(500));
        if stop {
            view.monitor = None; // Drop stops the trace.
            view.etw_snapshot.clear();
            view.etw_seen = 0;
            view.etw_shown.clear();
            view.etw_key = None;
        }
    } else {
        if ui.button("▶ Start monitoring").clicked() {
            match orress_sandbox::etw::start() {
                Ok(m) => {
                    view.monitor = Some(m);
                    view.monitor_error = None;
                }
                Err(e) => view.monitor_error = Some(e),
            }
        }
        if let Some(e) = &view.monitor_error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
    }
}

/// Spawns the run on a background thread so the UI stays responsive.
fn start_run(view: &SandboxView, ctx: egui::Context) {
    let exe = PathBuf::from(view.exe_path.trim());
    let args: Vec<String> = view.args.split_whitespace().map(str::to_string).collect();
    let timeout = Duration::from_secs(u64::from(view.timeout_secs));
    let result = Arc::clone(&view.result);
    let running = Arc::clone(&view.running);
    *lock(&result) = None;
    running.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        let log = run(&exe, &args, None, timeout);
        *lock(&result) = Some(log);
        running.store(false, Ordering::SeqCst);
        ctx.request_repaint();
    });
}
