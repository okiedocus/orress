//! The debugger: a bottom-dock panel with run controls, registers, flags, the stack and
//! breakpoints, plus the glue that marks the current instruction and breakpoints in the
//! disassembly.
//!
//! [`DebugSession`] is the long-lived state the app owns; the panel and the disassembly
//! view both read and drive it. Addresses the user sees are file virtual addresses (based
//! on the file's preferred load address); the target runs at a possibly different base
//! (ASLR), so the session translates between the two.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use egui::{RichText, Ui};
use orress_debug::{DebugState, Debugger, Registers, Status, StopReason};
use orress_project::Document;
use orress_ui::{ExplainExt as _, muted};

const EXPLAIN: &str = "The debugger runs the program under ORRESS's control. Set breakpoints (F9 in the \
    disassembly, or click the gutter) to stop at an address; then step one instruction at a time and \
    watch the registers, flags and stack change. You can even change a register or a byte of memory \
    and continue. Debugging runs the real program, so only debug code you trust.";

/// No breakpoints (returned for a file that has none).
static NO_BREAKPOINTS: BTreeSet<u64> = BTreeSet::new();

/// Debugger state the app keeps between frames.
#[derive(Default)]
pub struct DebugSession {
    active: Option<Active>,
    /// Breakpoints the user has set, per binary, as file virtual addresses. Kept even when no
    /// target is running, so Start re-applies them.
    breakpoints: BTreeMap<PathBuf, BTreeSet<u64>>,
    /// The file the path-less accessors ([`DebugSession::breakpoints`],
    /// [`DebugSession::toggle_breakpoint`]) refer to: the binary a view last asked about via
    /// [`DebugSession::current_file_rip`] or [`DebugSession::set_current_file`].
    current: Option<PathBuf>,
}

struct Active {
    path: PathBuf,
    dbg: Debugger,
    state: DebugState,
    /// The file's preferred load address, to translate file <-> runtime addresses.
    preferred_base: u64,
    /// Whether the user's breakpoints have been applied to this run.
    applied: bool,
    /// The generation we last reacted to (to refresh the stack read on each stop).
    seen_generation: u64,
}

impl DebugSession {
    /// Starts debugging `path`. `preferred_base` comes from the file's analysis.
    pub fn start(&mut self, path: &Path, preferred_base: u64, notify: Arc<dyn Fn() + Send + Sync>) {
        let dbg = Debugger::launch(path.to_path_buf(), Vec::new(), notify);
        self.active = Some(Active {
            path: path.to_path_buf(),
            dbg,
            state: DebugState {
                status: Status::Starting,
                ..empty_state()
            },
            preferred_base,
            applied: false,
            seen_generation: 0,
        });
    }

    pub fn is_active_for(&self, path: &Path) -> bool {
        self.active.as_ref().is_some_and(|a| a.path == path)
    }

    pub fn is_running_somewhere(&self) -> bool {
        self.active.as_ref().is_some_and(|a| a.state.is_alive())
    }

    /// Makes `path` the file the path-less breakpoint accessors refer to.
    pub fn set_current_file(&mut self, path: &Path) {
        if self.current.as_deref() != Some(path) {
            self.current = Some(path.to_path_buf());
        }
    }

    /// The breakpoints (file VAs) of the current file (see [`DebugSession::set_current_file`]).
    pub fn breakpoints(&self) -> &BTreeSet<u64> {
        match &self.current {
            Some(path) => self.breakpoints_for(path),
            None => &NO_BREAKPOINTS,
        }
    }

    /// The breakpoints (file VAs) set in `path`.
    pub fn breakpoints_for(&self, path: &Path) -> &BTreeSet<u64> {
        self.breakpoints.get(path).unwrap_or(&NO_BREAKPOINTS)
    }

    /// The runtime instruction pointer translated to a file VA, if stopped in `path`. Also makes
    /// `path` the current file, so a view's following `breakpoints()` / `toggle_breakpoint()`
    /// calls act on the binary it shows.
    pub fn current_file_rip(&mut self, path: &Path) -> Option<u64> {
        self.set_current_file(path);
        let a = self.active.as_ref()?;
        if a.path != path || !a.state.is_stopped() {
            return None;
        }
        a.runtime_to_file(a.state.registers.rip)
    }

    /// Toggles a breakpoint at a file VA of the current file (see
    /// [`DebugSession::set_current_file`]); does nothing when no file is current.
    pub fn toggle_breakpoint(&mut self, file_va: u64) {
        if let Some(path) = self.current.clone() {
            self.toggle_breakpoint_in(&path, file_va);
        }
    }

    /// Toggles a breakpoint at a file VA of `path`; applies it immediately if that binary is the
    /// one being debugged.
    pub fn toggle_breakpoint_in(&mut self, path: &Path, file_va: u64) {
        let set = self.breakpoints.entry(path.to_path_buf()).or_default();
        let added = set.insert(file_va);
        if !added {
            set.remove(&file_va);
        }
        if set.is_empty() {
            self.breakpoints.remove(path);
        }
        if let Some(a) = &self.active
            && a.path == path
            && let Some(rt) = a.file_to_runtime(file_va)
        {
            if added {
                a.dbg.add_breakpoint(rt);
            } else {
                a.dbg.remove_breakpoint(rt);
            }
        }
    }

    /// Runs a debugger command (from the F5/F10/F11 shortcuts) on the running target. Both step
    /// commands execute one instruction (machine code has no source lines to step over). Returns
    /// whether a target took it.
    pub fn command(&mut self, action: crate::DebugAction) -> bool {
        use crate::DebugAction;
        let Some(a) = &self.active else {
            return false;
        };
        let stopped = a.state.is_stopped();
        match action {
            DebugAction::Continue if stopped => a.dbg.resume(),
            DebugAction::StepOver | DebugAction::StepInto if stopped => a.dbg.step(),
            DebugAction::Pause if a.state.status == Status::Running => a.dbg.pause(),
            DebugAction::Stop if a.state.is_alive() => a.dbg.kill(),
            _ => return false,
        }
        true
    }

    /// Pulls the latest target state and reacts to a new stop (apply breakpoints, read
    /// the stack). Call once per frame before drawing.
    pub fn refresh(&mut self) {
        let Some(a) = &mut self.active else {
            return;
        };
        a.state = a.dbg.state();
        // Apply the user's breakpoints for this binary as soon as the runtime base is known.
        if !a.applied && a.state.image_base.is_some() {
            for &va in self.breakpoints.get(&a.path).unwrap_or(&NO_BREAKPOINTS) {
                if let Some(rt) = a.file_to_runtime(va) {
                    a.dbg.add_breakpoint(rt);
                }
            }
            a.applied = true;
        }
        // On each new stop, refresh the stack and the memory pane.
        if a.state.generation != a.seen_generation && a.state.is_stopped() {
            a.seen_generation = a.state.generation;
            a.dbg.read_stack(a.state.registers.rsp, 128);
        }
    }
}

fn empty_state() -> DebugState {
    // DebugState has no public constructor; make one via a throwaway debugger would spawn
    // a thread, so build the fields we need directly through Default-like values.
    DebugState {
        status: Status::Starting,
        reason: None,
        registers: Registers::default(),
        prev_registers: Registers::default(),
        modules: Vec::new(),
        image_base: None,
        breakpoints: std::collections::BTreeMap::new(),
        last_error: None,
        memory: None,
        stack: None,
        generation: 0,
    }
}

impl Active {
    fn file_to_runtime(&self, va: u64) -> Option<u64> {
        let base = self.state.image_base?;
        Some(va.wrapping_sub(self.preferred_base).wrapping_add(base))
    }

    fn runtime_to_file(&self, rt: u64) -> Option<u64> {
        let base = self.state.image_base?;
        Some(rt.wrapping_sub(base).wrapping_add(self.preferred_base))
    }
}

/// Draws the debugger panel for the active document.
pub fn debugger_panel(ui: &mut Ui, session: &mut DebugSession, doc: Option<&mut Document>) {
    session.refresh();
    let Some(doc) = doc else {
        ui.label("Open a program to debug it.");
        return;
    };
    let path = doc.path.clone();
    session.set_current_file(&path);

    // A run that ended (exited, stopped or failed) shows the start screen again, with how
    // the last run ended, so the program can be debugged as many times as needed.
    let ended = session
        .active
        .as_ref()
        .filter(|a| a.path == path && !a.state.is_alive())
        .map(|a| a.state.clone());
    if !session.is_active_for(&path) || ended.is_some() {
        if let Some(last) = &ended {
            ui.horizontal(|ui| {
                ui.label(muted("Last run:"));
                status_line(ui, last);
            });
            ui.separator();
        }
        start_screen(ui, session, doc);
        return;
    }

    // `state` is a cheap clone so we do not hold a borrow of `session` across the
    // breakpoint list, which needs `&mut session`.
    let state = session.active.as_ref().expect("active").state.clone();

    if let Some(a) = &session.active {
        controls(ui, &a.dbg, &state);
    }
    status_line(ui, &state);
    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if let Some(a) = &session.active {
                registers(ui, &state);
                edit_register(ui, &a.dbg, &state);
                ui.add_space(6.0);
                flags(ui, &state);
                ui.add_space(6.0);
                egui::CollapsingHeader::new("Stack")
                    .default_open(true)
                    .show(ui, |ui| {
                        stack_view(ui, &state);
                    });
                egui::CollapsingHeader::new("Memory")
                    .default_open(false)
                    .show(ui, |ui| {
                        memory_view(ui, &a.dbg, a.preferred_base, &state);
                    });
                ui.label(muted(
                    "F5 continue · F10/F11 step one instruction · Shift+F5 stop (with this panel focused)",
                ));
            }
            egui::CollapsingHeader::new("Breakpoints")
                .default_open(true)
                .show(ui, |ui| {
                    breakpoints_list(ui, session, doc);
                });
        });
}

fn start_screen(ui: &mut Ui, session: &mut DebugSession, doc: &mut Document) {
    ui.add_space(4.0);
    ui.label(RichText::new("Debugger").strong())
        .note("Debugger", EXPLAIN);
    ui.label(muted(EXPLAIN));
    ui.add_space(8.0);

    let base = doc.analysis().map(|a| a.info.image_base);
    let main = doc.program().and_then(|p| p.main);
    let is_exe = doc
        .analysis()
        .map(|a| {
            matches!(
                a.info.format,
                orress_loaders::Format::Pe | orress_loaders::Format::Coff
            )
        })
        .unwrap_or(false);

    if !cfg!(windows) {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            "Native debugging is available on Windows. ptrace (Linux) and GDB-remote back ends are planned.",
        );
        return;
    }
    if !is_exe {
        ui.label(muted(
            "Open a Windows program (.exe) to debug it. Other formats come with later back ends.",
        ));
    }

    let path = doc.path.clone();
    ui.horizontal(|ui| {
        let start = ui
            .button(RichText::new("▶ Start debugging").strong())
            .explain(
                "Start debugging",
                "Launches the program under the debugger and stops at the first breakpoint.",
            );
        if start.clicked()
            && let Some(base) = base
        {
            // If the user set no breakpoints, stop at main so they are not lost at once.
            if session.breakpoints_for(&path).is_empty()
                && let Some(main) = main
            {
                session.toggle_breakpoint_in(&path, main);
            }
            let ctx = ui.ctx().clone();
            let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || ctx.request_repaint());
            session.start(&path, base, notify);
        }
    });
    if main.is_some() {
        ui.label(muted(
            "The program will stop at main. Set more breakpoints with F9 in the disassembly.",
        ));
    }
}

fn controls(ui: &mut Ui, dbg: &Debugger, state: &DebugState) {
    ui.horizontal(|ui| {
        let stopped = state.is_stopped();
        let running = state.status == Status::Running;
        if ui
            .add_enabled(stopped, egui::Button::new("▶ Continue"))
            .on_hover_text("F5 (with the Debugger panel focused)")
            .clicked()
        {
            dbg.resume();
        }
        if ui
            .add_enabled(stopped, egui::Button::new("↷ Step"))
            .on_hover_text("One instruction (F10 or F11, with the Debugger panel focused)")
            .clicked()
        {
            dbg.step();
        }
        if ui
            .add_enabled(running, egui::Button::new("⏸ Pause"))
            .clicked()
        {
            dbg.pause();
        }
        if ui
            .add_enabled(state.is_alive(), egui::Button::new("⏹ Stop"))
            .on_hover_text("Shift+F5")
            .clicked()
        {
            dbg.kill();
        }
    });
}

fn status_line(ui: &mut Ui, state: &DebugState) {
    let text = match &state.reason {
        Some(r) => r.summary(),
        None => match state.status {
            Status::Starting => "starting…".into(),
            Status::Running => "running…".into(),
            Status::Exited => "the program has ended".into(),
            Status::Failed => "the debugger could not start".into(),
            Status::Stopped => "stopped".into(),
        },
    };
    let color = match state.status {
        Status::Failed => ui.visuals().error_fg_color,
        Status::Exited => ui.visuals().weak_text_color(),
        _ if matches!(state.reason, Some(StopReason::Exception { .. })) => {
            ui.visuals().error_fg_color
        }
        _ => ui.visuals().text_color(),
    };
    ui.colored_label(color, text);
    if let Some(e) = &state.last_error
        && state.status != Status::Failed
    {
        ui.colored_label(ui.visuals().warn_fg_color, e);
    }
}

fn registers(ui: &mut Ui, state: &DebugState) {
    let changed = state.is_stopped() && state.generation > 1;
    egui::Grid::new("dbg-regs")
        .num_columns(4)
        .spacing([14.0, 2.0])
        .show(ui, |ui| {
            let gp = state.registers.gp();
            let prev = state.prev_registers.gp();
            for (i, (name, value)) in gp.iter().enumerate() {
                let differ = changed && prev[i].1 != *value;
                reg_cell(ui, name, *value, differ);
                if i % 2 == 1 {
                    ui.end_row();
                }
            }
            reg_cell(
                ui,
                "rip",
                state.registers.rip,
                changed && state.prev_registers.rip != state.registers.rip,
            );
            reg_cell(ui, "rsp", state.registers.rsp, false);
            ui.end_row();
        });
}

fn reg_cell(ui: &mut Ui, name: &str, value: u64, changed: bool) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{name:>3}")).monospace().weak());
        let color = if changed {
            ui.visuals().warn_fg_color
        } else {
            ui.visuals().text_color()
        };
        ui.label(
            RichText::new(format!("{value:016x}"))
                .monospace()
                .color(color),
        )
        .on_hover_text(format!("{value} (decimal)"));
    });
}

/// A compact "set a register" row: pick a register, type a hex value, apply.
fn edit_register(ui: &mut Ui, dbg: &Debugger, state: &DebugState) {
    if !state.is_stopped() {
        return;
    }
    let reg_id = ui.id().with("dbg-edit-reg");
    let val_id = ui.id().with("dbg-edit-val");
    let mut reg = ui.memory_mut(|m| {
        m.data
            .get_temp::<String>(reg_id)
            .unwrap_or_else(|| "rax".into())
    });
    let mut val = ui.memory_mut(|m| m.data.get_temp::<String>(val_id).unwrap_or_default());
    ui.horizontal(|ui| {
        ui.label(muted("set"));
        egui::ComboBox::from_id_salt(reg_id)
            .width(52.0)
            .selected_text(reg.clone())
            .show_ui(ui, |ui| {
                for name in orress_debug::GP_NAMES.iter().chain(&["rip", "rsp"]) {
                    ui.selectable_value(&mut reg, (*name).to_string(), *name);
                }
            });
        ui.label("=");
        let field = ui.add(
            egui::TextEdit::singleline(&mut val)
                .hint_text("hex")
                .desired_width(120.0),
        );
        let submit = ui.button("Set").clicked()
            || (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
        if submit && let Ok(v) = u64::from_str_radix(val.trim().trim_start_matches("0x"), 16) {
            dbg.set_register(reg.clone(), v);
            val.clear();
        }
    });
    ui.memory_mut(|m| {
        m.data.insert_temp(reg_id, reg);
        m.data.insert_temp(val_id, val);
    });
}

fn flags(ui: &mut Ui, state: &DebugState) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("flags").monospace().weak());
        for f in &orress_debug::FLAGS {
            let on = orress_debug::flag_set(state.registers.rflags, f.bit);
            let color = if on {
                ui.visuals().warn_fg_color
            } else {
                ui.visuals().weak_text_color()
            };
            ui.label(RichText::new(f.short).monospace().color(color))
                .on_hover_text(format!(
                    "{} ({}): {}\nnow {}",
                    f.name,
                    f.short,
                    f.meaning,
                    if on { "set" } else { "clear" }
                ));
        }
    });
}

fn stack_view(ui: &mut Ui, state: &DebugState) {
    let Some((base, bytes)) = &state.stack else {
        ui.label(muted("(stops to show the stack)"));
        return;
    };
    let rsp = state.registers.rsp;
    egui::Grid::new("dbg-stack")
        .num_columns(2)
        .spacing([14.0, 2.0])
        .show(ui, |ui| {
            for (i, chunk) in bytes.chunks(8).enumerate() {
                let Ok(eight) = <[u8; 8]>::try_from(chunk) else {
                    break;
                };
                let addr = base + (i * 8) as u64;
                let value = u64::from_le_bytes(eight);
                let mark = if addr == rsp { "rsp>" } else { "    " };
                ui.label(
                    RichText::new(format!("{mark}{addr:016x}"))
                        .monospace()
                        .weak(),
                );
                ui.label(RichText::new(format!("{value:016x}")).monospace());
                ui.end_row();
            }
        });
}

fn memory_view(ui: &mut Ui, dbg: &Debugger, preferred_base: u64, state: &DebugState) {
    if !state.is_stopped() {
        ui.label(muted("(stops to read memory)"));
        return;
    }
    let base = match state.image_base {
        Some(b) => b,
        None => return,
    };
    let addr_id = ui.id().with("dbg-mem-addr");
    let gen_id = ui.id().with("dbg-mem-gen");
    let file_id = ui.id().with("dbg-mem-file");
    // Default to the instruction pointer, by name, so it is read as a runtime address.
    let mut addr_text = ui.memory_mut(|m| {
        m.data
            .get_temp::<String>(addr_id)
            .unwrap_or_else(|| "rip".into())
    });
    let mut request: Option<MemAddr> = None;
    ui.horizontal(|ui| {
        ui.label(muted("address"));
        let field = ui.add(
            egui::TextEdit::singleline(&mut addr_text)
                .desired_width(140.0)
                .hint_text("hex file address or register"),
        );
        let submit = ui.button("Show").clicked()
            || (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
        if submit && let Some(addr) = parse_addr(&addr_text, &state.registers) {
            request = Some(addr);
        }
    });
    // Re-read whenever the target stops again, so the view stays live.
    let last_gen = ui.memory_mut(|m| m.data.get_temp::<u64>(gen_id).unwrap_or(0));
    if last_gen != state.generation
        && let Some(addr) = parse_addr(&addr_text, &state.registers)
    {
        request = Some(addr);
    }
    if let Some(addr) = request {
        // A register value is already a runtime address; typed hex is a file VA, so it moves
        // with the image (ASLR).
        let rt = match addr {
            MemAddr::Runtime(rt) => rt,
            MemAddr::File(va) => va.wrapping_sub(preferred_base).wrapping_add(base),
        };
        ui.memory_mut(|m| {
            m.data
                .insert_temp(file_id, matches!(addr, MemAddr::File(_)))
        });
        dbg.read_memory(rt, 128);
    }
    let as_file = ui.memory_mut(|m| m.data.get_temp::<bool>(file_id).unwrap_or(false));
    ui.memory_mut(|m| {
        m.data.insert_temp(addr_id, addr_text);
        m.data.insert_temp(gen_id, state.generation);
    });
    if let Some((rt_addr, bytes)) = &state.memory {
        if as_file {
            let file_addr = rt_addr.wrapping_sub(base).wrapping_add(preferred_base);
            ui.label(muted("addresses: file (as in the disassembly)"));
            hex_dump(ui, file_addr, bytes);
        } else {
            ui.label(muted("addresses: runtime (where the program is loaded)"));
            hex_dump(ui, *rt_addr, bytes);
        }
    }
}

/// An address typed into the memory pane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemAddr {
    /// A register's value: an address in the running process.
    Runtime(u64),
    /// Typed hex: a file virtual address (as shown in the disassembly).
    File(u64),
}

/// A hex + ASCII dump, 16 bytes per row, starting at address `start`.
fn hex_dump(ui: &mut Ui, start: u64, bytes: &[u8]) {
    egui::Grid::new("dbg-mem-grid")
        .num_columns(3)
        .spacing([14.0, 2.0])
        .show(ui, |ui| {
            for (row, chunk) in bytes.chunks(16).enumerate() {
                let addr = start + (row * 16) as u64;
                ui.label(RichText::new(format!("{addr:016x}")).monospace().weak());
                let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                ui.label(RichText::new(hex).monospace());
                let ascii: String = chunk
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() || *b == b' ' {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                ui.label(RichText::new(ascii).monospace().weak());
                ui.end_row();
            }
        });
}

/// Parses a register name (a runtime address) or a hex file virtual address.
fn parse_addr(text: &str, regs: &Registers) -> Option<MemAddr> {
    let t = text.trim();
    if let Some(v) = regs.get(&t.to_ascii_lowercase()) {
        return Some(MemAddr::Runtime(v));
    }
    u64::from_str_radix(t.trim_start_matches("0x"), 16)
        .ok()
        .map(MemAddr::File)
}

fn breakpoints_list(ui: &mut Ui, session: &mut DebugSession, doc: &mut Document) {
    let bps: Vec<u64> = session.breakpoints_for(&doc.path).iter().copied().collect();
    if bps.is_empty() {
        ui.label(muted(
            "None yet. In the disassembly, press F9 or click the gutter.",
        ));
        return;
    }
    let program = doc.program().cloned();
    let mut remove = None;
    let mut go = None;
    for va in bps {
        ui.horizontal(|ui| {
            if ui.small_button("✕").on_hover_text("Remove").clicked() {
                remove = Some(va);
            }
            let label = program
                .as_ref()
                .map(|p| code_describe(doc, p, va))
                .unwrap_or_else(|| format!("0x{va:x}"));
            if ui.link(RichText::new(label).monospace()).clicked() {
                go = Some(va);
            }
        });
    }
    if let Some(va) = remove {
        session.toggle_breakpoint_in(&doc.path, va);
    }
    if let Some(va) = go {
        doc.navigate_to_address(va);
    }
}

fn code_describe(doc: &Document, program: &orress_project::Program, va: u64) -> String {
    crate::code::describe_address(doc, program, va)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoints_are_kept_per_binary() {
        let mut s = DebugSession::default();
        let (a, b) = (Path::new("a.exe"), Path::new("b.exe"));
        // A view showing a.exe asks about it first (as the disassembly does), then toggles.
        assert_eq!(s.current_file_rip(a), None);
        s.toggle_breakpoint(0x401000);
        assert!(s.breakpoints().contains(&0x401000));
        // Switching to b.exe shows its own (empty) set; a.exe's breakpoint is not leaked.
        s.current_file_rip(b);
        assert!(s.breakpoints().is_empty());
        s.toggle_breakpoint(0x402000);
        assert_eq!(s.breakpoints_for(a).len(), 1);
        assert!(s.breakpoints_for(b).contains(&0x402000));
        // Toggling again removes it.
        s.toggle_breakpoint_in(a, 0x401000);
        assert!(s.breakpoints_for(a).is_empty());
    }

    #[test]
    fn register_names_are_runtime_addresses() {
        let regs = Registers {
            rip: 0x7ff6_1234_0000,
            ..Registers::default()
        };
        assert_eq!(
            parse_addr("rip", &regs),
            Some(MemAddr::Runtime(0x7ff6_1234_0000))
        );
        assert_eq!(parse_addr("0x401000", &regs), Some(MemAddr::File(0x401000)));
        assert_eq!(parse_addr("zz", &regs), None);
    }
}
