//! Source-level debugging state and panel, built on `orress-dap`. The editor sets source
//! breakpoints (F9) and shows the stopped line; this panel starts a session and shows the
//! call stack, variables, program output and step controls.
//!
//! Needs a working DAP adapter (e.g. codelldb or a functional lldb-dap). When none is
//! available it degrades to a clear message — the debug *client* is still exercised by the
//! `orress-dap` tests.
//!
//! Starting a session (compiling with `rustc -g`, resolving an extension's adapter or locator in
//! WASM, spawning the adapter) runs on a worker thread; [`SourceDebug::poll`] adopts the session
//! when it is ready, so the UI never blocks on a compile.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError};

use egui::{RichText, Ui};
use orress_dap::{DapSession, DapState, LaunchConfig, Status};
use orress_ui::muted;
use serde_json::{Value, json};

/// What a worker thread hands back: the session, the source file it debugs (if a single file),
/// and a message to show.
type Launched = Result<(DapSession, Option<PathBuf>, Option<String>), String>;

type Notify = Arc<dyn Fn() + Send + Sync>;

/// A debugger command bound to a key (F5, F10, F11, …), for either debugger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugAction {
    Continue,
    StepOver,
    StepInto,
    StepOut,
    Pause,
    Stop,
}

/// A session being prepared on a worker thread.
struct Starting {
    rx: Receiver<Launched>,
    /// The breakpoints the session was launched with, to send any changes made meanwhile.
    sent: HashMap<PathBuf, Vec<u32>>,
}

/// Source-debug state the app owns.
#[derive(Default)]
pub struct SourceDebug {
    /// Breakpoints per file, 1-based line numbers.
    breakpoints: HashMap<PathBuf, BTreeSet<u32>>,
    session: Option<DapSession>,
    /// The program being debugged (its source file).
    debugged: Option<PathBuf>,
    message: Option<String>,
    starting: Option<Starting>,
}

impl SourceDebug {
    /// Toggles a breakpoint; during a live session the file's new set is sent to the adapter.
    pub fn toggle_breakpoint(&mut self, path: &Path, line: u32) {
        let set = self.breakpoints.entry(path.to_path_buf()).or_default();
        if !set.remove(&line) {
            set.insert(line);
        }
        let lines: Vec<u32> = set.iter().copied().collect();
        if let Some(session) = &self.session
            && session.state().is_alive()
        {
            session.set_breakpoints(path, lines);
        }
    }

    pub fn breakpoints(&self, path: &Path) -> Option<&BTreeSet<u32>> {
        self.breakpoints.get(path)
    }

    /// Whether a session is running or being started.
    pub fn is_active(&self) -> bool {
        self.starting.is_some() || self.session.as_ref().is_some_and(|s| s.state().is_alive())
    }

    pub fn state(&self) -> Option<DapState> {
        self.session.as_ref().map(DapSession::state)
    }

    /// Adopts a session the worker thread finished starting. Call once per frame.
    pub fn poll(&mut self) {
        let Some(starting) = &self.starting else {
            return;
        };
        let result = match starting.rx.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("the debugger could not be started".into()),
        };
        let sent = self.starting.take().map(|s| s.sent).unwrap_or_default();
        match result {
            Ok((session, debugged, message)) => {
                // Breakpoints toggled while it was starting: send each changed file's new set.
                let files: BTreeSet<&PathBuf> =
                    self.breakpoints.keys().chain(sent.keys()).collect();
                for file in files {
                    let now: Vec<u32> = self
                        .breakpoints
                        .get(file)
                        .map(|s| s.iter().copied().collect())
                        .unwrap_or_default();
                    if sent.get(file).map_or(!now.is_empty(), |was| *was != now) {
                        session.set_breakpoints(file, now);
                    }
                }
                self.session = Some(session);
                self.debugged = debugged;
                self.message = message;
            }
            Err(e) => self.message = Some(e),
        }
    }

    /// The current stopped line in `path`, if the debugger is stopped there.
    pub fn current_line(&self, path: &Path) -> Option<u32> {
        let st = self.state()?;
        if !st.is_stopped() {
            return None;
        }
        st.current
            .and_then(|(p, l)| (norm(&p) == norm(path)).then_some(l))
    }

    fn breakpoint_lists(&self) -> HashMap<PathBuf, Vec<u32>> {
        self.breakpoints
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
            .collect()
    }

    /// Runs `work` on a worker thread; its result is adopted by [`SourceDebug::poll`].
    fn spawn_start(
        &mut self,
        status: &str,
        notify: Notify,
        work: impl FnOnce(HashMap<PathBuf, Vec<u32>>, Notify) -> Launched + Send + 'static,
    ) {
        let bps = self.breakpoint_lists();
        let (tx, rx) = std::sync::mpsc::channel();
        self.starting = Some(Starting {
            rx,
            sent: bps.clone(),
        });
        self.session = None;
        self.message = Some(status.to_string());
        let spawned = std::thread::Builder::new()
            .name("orress-debug-start".into())
            .spawn(move || {
                let result = work(bps, Arc::clone(&notify));
                let _ = tx.send(result);
                notify();
            });
        if let Err(e) = spawned {
            self.starting = None;
            self.message = Some(format!("could not start the debugger: {e}"));
        }
    }

    /// Starts debugging a Rust source file: compiles it with debug info, finds a DAP
    /// adapter, and launches — on a worker thread. A native adapter (`lldb-dap`) is preferred;
    /// failing that, a debug adapter provided by an installed Zed extension (from `extensions_dir`)
    /// is resolved from its WASM. `settings` are the user's settings, handed to extensions.
    pub fn start(
        &mut self,
        src: &Path,
        extensions_dir: Option<PathBuf>,
        settings: Value,
        notify: Notify,
    ) {
        if self.starting.is_some() {
            return;
        }
        let src = src.to_path_buf();
        self.spawn_start(
            "Compiling with debug info…",
            notify,
            move |bps, notify| {
                let exe = exe_path(&src);
                let cwd = src.parent().map(Path::to_path_buf);
                let native = orress_dap::find_adapter();
                if native.is_none() && extensions_dir.is_none() {
                    return Err(NO_ADAPTER.into());
                }
                compile(&src, &exe)?;
                let config = match native {
                    Some((adapter, args)) => {
                        LaunchConfig::lldb(&adapter, &args, &exe, cwd.as_deref())
                    }
                    None => extensions_dir
                        .and_then(|dir| {
                            extension_launch(&dir, &src, &exe, cwd.as_deref(), &settings)
                        })
                        .ok_or_else(|| NO_ADAPTER.to_string())?,
                };
                DapSession::launch_with(config, bps, notify)
                    .map(|session| (session, Some(src), None))
                    .map_err(|e| format!("could not start the debugger: {e}"))
            },
        );
    }

    /// "Debug this task": turns a build/run `task` into a debug session via an extension-provided
    /// locator + debug adapter (on a worker thread). Finds a locator that handles the task
    /// (producing a scenario, the concrete program, and the adapter to spawn) and launches it.
    /// Degrades to a message when no installed extension can.
    pub fn debug_task(
        &mut self,
        task: &orress_editor::Task,
        extensions_dir: Option<PathBuf>,
        worktree: &Path,
        settings: Value,
        notify: Notify,
    ) {
        if self.starting.is_some() {
            return;
        }
        let Some(step) = task.steps.last() else {
            self.message = Some("This task has no command to debug.".into());
            return;
        };
        let Some(dir) = extensions_dir else {
            self.message =
                Some("No extensions directory — install a debug-adapter/locator extension.".into());
            return;
        };
        let template = orress_ext::DapTaskTemplate {
            label: task.label.clone(),
            command: step.program.clone(),
            args: step.args.clone(),
            env: Vec::new(),
            cwd: Some(step.cwd.display().to_string()),
        };
        let label = task.label.clone();
        let worktree = worktree.to_path_buf();
        self.spawn_start(
            &format!("Locating a debugger for \"{label}\"…"),
            notify,
            move |bps, notify| {
                let located =
                    match orress_ext::locate_debug_target(&dir, &template, &worktree, settings) {
                        Ok(Some(t)) => t,
                        Ok(None) => {
                            return Err(format!(
                                "No installed extension locator can debug \"{label}\"."
                            ));
                        }
                        Err(e) => return Err(format!("locator failed: {e}")),
                    };
                let config = located_launch(&located)?;
                let message = format!(
                    "Debugging \"{label}\" via the {} locator ({} adapter).",
                    located.locator_name, located.scenario.adapter
                );
                DapSession::launch_with(config, bps, notify)
                    .map(|session| (session, None, Some(message)))
                    .map_err(|e| format!("could not start the debugger: {e}"))
            },
        );
    }

    /// Runs a debugger command (from the F5/F10/F11 shortcuts) on the live session. Returns
    /// whether a session took it.
    pub fn command(&mut self, action: DebugAction) -> bool {
        let Some(s) = &self.session else {
            return false;
        };
        let state = s.state();
        if !state.is_alive() {
            return false;
        }
        let stopped = state.is_stopped();
        match action {
            DebugAction::Continue if stopped => s.resume(),
            DebugAction::StepOver if stopped => s.step_over(),
            DebugAction::StepInto if stopped => s.step_in(),
            DebugAction::StepOut if stopped => s.step_out(),
            DebugAction::Pause if state.status == Some(Status::Running) => s.pause(),
            DebugAction::Stop => self.stop(),
            _ => return false,
        }
        true
    }

    pub fn stop(&mut self) {
        if let Some(s) = &self.session {
            s.stop();
        }
        self.session = None;
        // Dropping the receiver abandons a start in progress; its session is dropped (and the
        // adapter killed) when the worker's send fails.
        if self.starting.take().is_some() {
            self.message = Some("Debug start cancelled.".into());
        }
    }
}

const NO_ADAPTER: &str = "No debug adapter found. Install a DAP adapter (e.g. codelldb), or a Zed \
     debug-adapter extension, for source debugging.";

/// Compiles a standalone `.rs` with debug info next to the source.
fn compile(src: &Path, exe: &Path) -> Result<(), String> {
    let output = std::process::Command::new("rustc")
        .args(["-g", "-C", "opt-level=0", "--edition", "2021"])
        .arg(src)
        .arg("-o")
        .arg(exe)
        .output()
        .map_err(|e| format!("could not run rustc: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "compile failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// A JSON object from an adapter configuration string (anything else gives an empty object).
fn config_object(config: &str) -> Value {
    match serde_json::from_str::<Value>(config) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({}),
    }
}

/// Resolves a debug adapter provided by an installed Zed extension into a launch configuration
/// for `program`: the adapter command, arguments, environment and working directory, its id, and
/// the launch arguments built from the configuration it returns. Takes the first
/// extension-provided adapter that yields a stdio command for a launch request.
fn extension_launch(
    extensions_dir: &Path,
    src: &Path,
    program: &Path,
    cwd: Option<&Path>,
    settings: &Value,
) -> Option<LaunchConfig> {
    let worktree = orress_ext::project_root(src);
    let mut wanted = json!({
        "request": "launch",
        "program": program.to_string_lossy(),
        "stopOnEntry": false,
    });
    if let Some(cwd) = cwd {
        wanted["cwd"] = json!(cwd.to_string_lossy());
    }
    for da in orress_ext::zed_debug_adapters(extensions_dir) {
        let def = orress_ext::DapTaskDefinition {
            label: "debug".to_string(),
            adapter: da.adapter_name.clone(),
            config: wanted.to_string(),
        };
        let Ok(bin) = orress_ext::resolve_dap_binary(
            &da.wasm,
            &da.adapter_name,
            &def,
            None,
            &worktree,
            settings.clone(),
        ) else {
            continue;
        };
        let Some(command) = bin.command else {
            continue; // TCP-only adapters are not supported by the launcher
        };
        if bin.request == orress_ext::DapRequestKind::Attach {
            continue;
        }
        // The adapter's own configuration, with our program filled in where it left it out.
        let mut args = config_object(&bin.configuration);
        if let (Some(map), Some(defaults)) = (args.as_object_mut(), wanted.as_object()) {
            for (k, v) in defaults {
                map.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        return Some(LaunchConfig {
            adapter: command,
            adapter_args: bin.arguments,
            adapter_env: bin.env,
            adapter_cwd: bin.cwd.map(PathBuf::from),
            adapter_id: da.adapter_name,
            launch_arguments: args,
        });
    }
    None
}

/// The launch configuration for a locator's target: the scenario's JSON config as the base, refined
/// by the adapter's own configuration (its keys win), then the concrete program, working directory,
/// arguments and environment from the locator's request. The adapter process gets the environment
/// and working directory its binary resolution asked for.
fn located_launch(located: &orress_ext::LocatedDebug) -> Result<LaunchConfig, String> {
    let (program, cwd, args, env) = match &located.request {
        orress_ext::DapRequest::Launch {
            program,
            cwd,
            args,
            env,
        } => (program, cwd, args, env),
        orress_ext::DapRequest::Attach { .. } => {
            return Err(
                "The locator produced an attach request, which the debugger does not support yet."
                    .into(),
            );
        }
    };
    let mut launch = config_object(&located.scenario.config);
    if let (Some(map), Value::Object(adapter)) = (
        launch.as_object_mut(),
        config_object(&located.adapter_configuration),
    ) {
        map.extend(adapter);
    }
    launch["request"] = json!("launch");
    launch["program"] = json!(program);
    if let Some(cwd) = cwd {
        launch["cwd"] = json!(cwd);
    }
    if !args.is_empty() {
        launch["args"] = json!(args);
    }
    if !env.is_empty() {
        let env: serde_json::Map<String, Value> =
            env.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        launch["env"] = Value::Object(env);
    }
    Ok(LaunchConfig {
        adapter: located.adapter_command.clone(),
        adapter_args: located.adapter_args.clone(),
        adapter_env: located.adapter_env.clone(),
        adapter_cwd: located.adapter_cwd.as_ref().map(PathBuf::from),
        adapter_id: located.scenario.adapter.clone(),
        launch_arguments: launch,
    })
}

fn exe_path(src: &Path) -> PathBuf {
    let stem = src
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    let mut p = src.with_file_name(stem);
    if cfg!(windows) {
        p.set_extension("exe");
    }
    p
}

fn norm(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) {
        s.to_lowercase().replace('\\', "/")
    } else {
        s.into_owned()
    }
}

/// The "Debug" bottom panel: controls, call stack, variables and output.
pub fn source_debug_panel(ui: &mut Ui, dbg: &mut SourceDebug) {
    dbg.poll();
    let state = dbg.state();
    ui.horizontal(|ui| {
        ui.label(RichText::new("Source debugger").strong());
        match &state {
            Some(s) => {
                let (label, color) = match s.status {
                    Some(Status::Starting) => {
                        ("starting…".to_string(), ui.visuals().weak_text_color())
                    }
                    Some(Status::Running) => ("running…".to_string(), ui.visuals().text_color()),
                    Some(Status::Stopped) => (
                        format!("stopped ({})", s.stop_reason.as_deref().unwrap_or("")),
                        ui.visuals().text_color(),
                    ),
                    Some(Status::Exited) => ("exited".to_string(), ui.visuals().weak_text_color()),
                    Some(Status::Failed) | None => {
                        ("failed".to_string(), ui.visuals().error_fg_color)
                    }
                };
                ui.separator();
                ui.colored_label(color, label);
            }
            None if dbg.starting.is_some() => {
                ui.separator();
                ui.spinner();
                ui.label(muted("starting…"));
                if ui.small_button("Cancel").clicked() {
                    dbg.stop();
                }
            }
            None => {
                ui.separator();
                ui.label(muted(
                    "idle — press Debug in the editor toolbar (needs a DAP adapter)",
                ));
            }
        }
    });
    if let Some(msg) = &dbg.message {
        ui.colored_label(ui.visuals().warn_fg_color, msg);
    }
    if let Some(err) = state.as_ref().and_then(|s| s.last_error.clone()) {
        ui.colored_label(ui.visuals().error_fg_color, err);
    }

    let Some(state) = state else {
        return;
    };

    let mut stop = false;
    ui.horizontal(|ui| {
        let stopped = state.is_stopped();
        let s = dbg.session.as_ref();
        if ui
            .add_enabled(stopped, egui::Button::new("▶ Continue"))
            .on_hover_text("F5")
            .clicked()
            && let Some(s) = s
        {
            s.resume();
        }
        if ui
            .add_enabled(stopped, egui::Button::new("↷ Step over"))
            .on_hover_text("F10")
            .clicked()
            && let Some(s) = s
        {
            s.step_over();
        }
        if ui
            .add_enabled(stopped, egui::Button::new("↓ Step in"))
            .on_hover_text("F11")
            .clicked()
            && let Some(s) = s
        {
            s.step_in();
        }
        if ui
            .add_enabled(stopped, egui::Button::new("↑ Step out"))
            .on_hover_text("Shift+F11")
            .clicked()
            && let Some(s) = s
        {
            s.step_out();
        }
        if ui
            .add_enabled(
                state.status == Some(Status::Running),
                egui::Button::new("⏸ Pause"),
            )
            .on_hover_text("Stop the running program where it is")
            .clicked()
            && let Some(s) = s
        {
            s.pause();
        }
        if ui
            .add_enabled(state.is_alive(), egui::Button::new("⏹ Stop"))
            .on_hover_text("Shift+F5")
            .clicked()
        {
            stop = true;
        }
    });
    if stop {
        dbg.stop();
    }
    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::CollapsingHeader::new("Variables")
                .default_open(true)
                .show(ui, |ui| {
                    if state.variables.is_empty() {
                        ui.label(muted("(no locals, or not stopped)"));
                    }
                    egui::Grid::new("dap-vars")
                        .num_columns(2)
                        .spacing([14.0, 2.0])
                        .show(ui, |ui| {
                            for v in &state.variables {
                                ui.label(RichText::new(&v.name).monospace());
                                let val = v.ty.as_ref().map_or_else(
                                    || v.value.clone(),
                                    |t| format!("{} : {t}", v.value),
                                );
                                ui.label(RichText::new(val).monospace().weak());
                                ui.end_row();
                            }
                        });
                });
            egui::CollapsingHeader::new("Call stack")
                .default_open(true)
                .show(ui, |ui| {
                    for f in &state.frames {
                        let loc = f
                            .source
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .map(|n| format!(" ({}:{})", n.to_string_lossy(), f.line))
                            .unwrap_or_default();
                        ui.label(RichText::new(format!("{}{loc}", f.name)).monospace());
                    }
                });
            egui::CollapsingHeader::new("Output")
                .default_open(false)
                .show(ui, |ui| {
                    for line in &state.output {
                        ui.label(RichText::new(line.trim_end()).monospace().weak());
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn located_launch_merges_scenario_config_with_the_request() {
        let located = orress_ext::LocatedDebug {
            adapter_command: "codelldb".into(),
            adapter_args: vec!["--port".into()],
            adapter_env: vec![("CODELLDB_LOG".into(), "info".into())],
            adapter_cwd: Some("/opt/codelldb".into()),
            adapter_configuration: r#"{"stopOnEntry": true, "program": "adapter"}"#.into(),
            request: orress_ext::DapRequest::Launch {
                program: "/p/target/debug/app".into(),
                cwd: Some("/p".into()),
                args: vec!["--fast".into()],
                env: vec![("RUST_LOG".into(), "debug".into())],
            },
            scenario: orress_ext::DapScenario {
                label: "app".into(),
                adapter: "CodeLLDB".into(),
                build: None,
                config: r#"{"sourceLanguages": ["rust"], "program": "placeholder"}"#.into(),
                tcp: None,
            },
            locator_name: "cargo".into(),
        };
        let config = located_launch(&located).unwrap();
        assert_eq!(config.adapter_id, "CodeLLDB");
        let args = &config.launch_arguments;
        assert_eq!(args["sourceLanguages"][0], "rust"); // scenario config kept
        assert_eq!(args["program"], "/p/target/debug/app"); // request wins
        assert_eq!(args["cwd"], "/p");
        assert_eq!(args["args"][0], "--fast");
        assert_eq!(args["env"]["RUST_LOG"], "debug");
        assert_eq!(args["request"], "launch");
        assert_eq!(args["stopOnEntry"], true); // adapter configuration merged in
        assert_eq!(
            config.adapter_env,
            vec![("CODELLDB_LOG".to_string(), "info".to_string())]
        );
        assert_eq!(config.adapter_cwd, Some(PathBuf::from("/opt/codelldb")));
    }
}
