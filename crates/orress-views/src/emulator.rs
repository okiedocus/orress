//! The Emulator view: run a function from the loaded binary with arguments ("run this
//! function" — the string-decryptor / check-function workhorse), and recover an input
//! byte-by-byte with the instruction-counting side-channel solver. Built on `orress-emu`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use egui::{RichText, Ui};
use orress_analysis::Program;
use orress_arch::Isa;
use orress_emu::{Abi, Emulator, Trace, solve_by_count};
use orress_project::DocStore;
use orress_ui::muted;

/// Where the scratch buffer (the emulated input) lives in the guest address space.
const SCRATCH: u64 = 0x5000_0000;
const SCRATCH_SIZE: u64 = 0x1_0000;
/// Longest input the scratch buffer holds (one byte stays free for the NUL terminator).
const MAX_INPUT: usize = SCRATCH_SIZE as usize - 1;

/// Persistent UI state for the Emulator tab.
#[derive(Default)]
pub struct EmulatorView {
    addr: String,
    input: String,
    pass_len: bool,
    run: Option<RunReport>,
    /// Time-travel debugging: a recorded trace and the step currently being inspected.
    trace: Option<Trace>,
    trace_error: Option<String>,
    scrub: usize,
    solve_len: String,
    charset: Charset,
    solve: Option<SolveReport>,
    sym_target: String,
    sym_avoid: String,
    sym: Option<SymReport>,
    /// The job running on the worker thread, if any (emulation can take seconds).
    pending: Option<Pending>,
    /// The file the results above belong to; switching files clears them.
    doc: Option<PathBuf>,
}

/// The inputs a job needs, copied out of the view so the worker owns them.
#[derive(Clone)]
struct Params {
    addr: String,
    input: String,
    pass_len: bool,
    solve_len: String,
    charset: Charset,
    sym_target: String,
    sym_avoid: String,
}

#[derive(Clone, Copy)]
enum JobKind {
    Run,
    Record,
    Solve,
    Symbolic,
    AutoVm,
}

impl JobKind {
    fn label(self) -> &'static str {
        match self {
            Self::Run => "Running the function",
            Self::Record => "Recording a trace",
            Self::Solve => "Solving by instruction counting",
            Self::Symbolic => "Solving symbolically",
            Self::AutoVm => "Scanning for a VM and solving it",
        }
    }

    /// The output that reports `msg` as this job's error.
    fn failed(self, msg: &str) -> JobOutput {
        match self {
            Self::Run => JobOutput::Run(err_report(msg)),
            Self::Record => JobOutput::Record(Err(msg.to_string())),
            Self::Solve => JobOutput::Solve(SolveReport::error(msg)),
            Self::Symbolic | Self::AutoVm => JobOutput::Sym(SymReport::error(msg)),
        }
    }
}

/// What a finished job produced.
enum JobOutput {
    Run(RunReport),
    // The trace is boxed: a `Trace` carries a CPU snapshot (now including the 128-bit SSE
    // registers), so it dwarfs the other variants if stored inline.
    Record(Result<Box<Trace>, String>),
    Solve(SolveReport),
    Sym(SymReport),
}

/// A job on the worker thread. The UI polls `slot` each frame; Cancel drops the job (its
/// output is discarded) and asks the side-channel solver to stop early.
struct Pending {
    kind: JobKind,
    cancel: Arc<AtomicBool>,
    slot: Arc<Mutex<Option<JobOutput>>>,
}

impl EmulatorView {
    fn params(&self) -> Params {
        Params {
            addr: self.addr.clone(),
            input: self.input.clone(),
            pass_len: self.pass_len,
            solve_len: self.solve_len.clone(),
            charset: self.charset,
            sym_target: self.sym_target.clone(),
            sym_avoid: self.sym_avoid.clone(),
        }
    }

    fn busy(&self) -> bool {
        self.pending.is_some()
    }

    /// Stops waiting for the running job (and asks it to stop).
    fn cancel(&mut self) {
        if let Some(p) = self.pending.take() {
            p.cancel.store(true, Ordering::SeqCst);
        }
    }

    /// Clears results that belong to another file.
    fn reset_results(&mut self) {
        self.cancel();
        self.run = None;
        self.trace = None;
        self.trace_error = None;
        self.scrub = 0;
        self.solve = None;
        self.sym = None;
    }

    fn apply(&mut self, out: JobOutput) {
        match out {
            JobOutput::Run(r) => self.run = Some(r),
            JobOutput::Record(Ok(t)) => {
                let t = *t;
                self.scrub = t.len().saturating_sub(1);
                self.trace = Some(t);
                self.trace_error = None;
            }
            JobOutput::Record(Err(e)) => {
                self.trace = None;
                self.trace_error = Some(e);
            }
            JobOutput::Solve(s) => self.solve = Some(s),
            JobOutput::Sym(s) => self.sym = Some(s),
        }
    }

    /// Moves a finished job's output into the view.
    fn poll(&mut self) {
        let Some(p) = &self.pending else {
            return;
        };
        let done = p.slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(out) = done {
            self.pending = None;
            self.apply(out);
        }
    }
}

/// Starts `kind` on a worker thread so the UI stays responsive while it emulates.
fn start(view: &mut EmulatorView, ctx: &egui::Context, program: &Arc<Program>, kind: JobKind) {
    if view.busy() {
        return;
    }
    let params = view.params();
    let program = Arc::clone(program);
    let cancel = Arc::new(AtomicBool::new(false));
    let slot = Arc::new(Mutex::new(None));
    let (worker_cancel, worker_slot, ctx) = (Arc::clone(&cancel), Arc::clone(&slot), ctx.clone());
    let spawned = std::thread::Builder::new()
        .name("emulator".into())
        .spawn(move || {
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_job(kind, &params, &program, &worker_cancel)
            }))
            .unwrap_or_else(|_| kind.failed("the emulator hit an internal error"));
            *worker_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(out);
            ctx.request_repaint();
        });
    match spawned {
        Ok(_) => view.pending = Some(Pending { kind, cancel, slot }),
        Err(e) => view.apply(kind.failed(&format!("could not start the emulator thread: {e}"))),
    }
}

fn run_job(kind: JobKind, params: &Params, program: &Program, cancel: &AtomicBool) -> JobOutput {
    match kind {
        JobKind::Run => JobOutput::Run(run_once(params, program)),
        JobKind::Record => JobOutput::Record(record_once(params, program).map(Box::new)),
        JobKind::Solve => JobOutput::Solve(solve_once(params, program, cancel)),
        JobKind::Symbolic => JobOutput::Sym(symbolic_solve_once(params, program)),
        JobKind::AutoVm => JobOutput::Sym(auto_vm_solve(program)),
    }
}

/// Parses the "Input length" field: 1 up to what the scratch buffer holds.
fn parse_len(s: &str) -> Result<usize, String> {
    match s.trim().parse::<usize>() {
        Ok(n) if (1..=MAX_INPUT).contains(&n) => Ok(n),
        _ => Err(format!("Enter an input length from 1 to {MAX_INPUT}.")),
    }
}

struct SymReport {
    input: Vec<u8>,
    complete: bool,
    message: String,
    constraints: usize,
    smt2: String,
    error: Option<String>,
}

impl SymReport {
    fn error(msg: &str) -> Self {
        Self {
            input: Vec::new(),
            complete: false,
            message: String::new(),
            constraints: 0,
            smt2: String::new(),
            error: Some(msg.to_string()),
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Charset {
    #[default]
    Printable,
    Alnum,
    Digits,
}

impl Charset {
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Printable => (0x20u8..=0x7e).collect(),
            Self::Alnum => (b'0'..=b'9')
                .chain(b'A'..=b'Z')
                .chain(b'a'..=b'z')
                .collect(),
            Self::Digits => (b'0'..=b'9').collect(),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Printable => "printable",
            Self::Alnum => "alphanumeric",
            Self::Digits => "digits",
        }
    }
}

struct RunReport {
    rax: u64,
    steps: u64,
    status: String,
    error: bool,
    /// The input buffer after the run (shows in-place decryptors' output).
    scratch: Vec<u8>,
    /// A C-string at RAX, if it points into mapped memory (shows pointer-returning decoders).
    ret_str: Option<String>,
}

struct SolveReport {
    recovered: Vec<u8>,
    rows: Vec<(usize, u8, u64, u64)>,
    error: Option<String>,
}

impl SolveReport {
    fn error(msg: &str) -> Self {
        Self {
            recovered: Vec::new(),
            rows: Vec::new(),
            error: Some(msg.to_string()),
        }
    }
}

pub fn emulator_view(ui: &mut Ui, view: &mut EmulatorView, docs: &DocStore) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Emulator", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Emulator").strong());
        ui.label(muted("run a function · side-channel solve"));
    });
    ui.separator();

    let Some(doc) = docs.active() else {
        ui.label(muted("Open a binary to emulate one of its functions."));
        return;
    };
    let Some(program) = doc.program() else {
        ui.label(muted(
            "Analysis is still running (or this file has no code).",
        ));
        return;
    };
    if program.isa != Isa::X64 {
        ui.label(muted(
            "The emulator currently supports x86-64 only; this binary is a different architecture.",
        ));
        return;
    }
    let cursor = doc.cursor_address();
    if view.doc.as_deref() != Some(doc.path.as_path()) {
        view.reset_results();
        view.doc = Some(doc.path.clone());
    }

    view.poll();
    if let Some(p) = &view.pending {
        let kind = p.kind;
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(muted(format!("{}…", kind.label())));
            if ui.button("Cancel").clicked() {
                view.cancel();
            }
        });
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            run_function_section(ui, view, program, cursor);
            ui.add_space(12.0);
            ui.separator();
            solve_section(ui, view, program, cursor);
            ui.add_space(12.0);
            ui.separator();
            symbolic_section(ui, view, program, cursor);
        });
}

fn run_function_section(
    ui: &mut Ui,
    view: &mut EmulatorView,
    program: &Arc<Program>,
    cursor: Option<u64>,
) {
    ui.heading("Run function");
    ui.label(muted(
        "Write the input string to a scratch buffer and call the function with a pointer to it.",
    ));
    egui::Grid::new("emu-run-form")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            ui.label("Function address");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut view.addr);
                if ui.small_button("use cursor's function").clicked()
                    && let Some(f) = cursor.and_then(|a| program.function_containing(a))
                {
                    view.addr = format!("{:#x}", f.entry);
                }
            });
            ui.end_row();
            ui.label("Input (arg0 → pointer)");
            ui.text_edit_singleline(&mut view.input);
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut view.pass_len, "pass input length as arg1");
            ui.end_row();
        });

    let idle = !view.busy();
    ui.horizontal(|ui| {
        if ui.add_enabled(idle, egui::Button::new("▶ Run")).clicked() {
            start(view, ui.ctx(), program, JobKind::Run);
        }
        if ui
            .add_enabled(idle, egui::Button::new("⏺ Record"))
            .on_hover_text("Run and record every instruction, then scrub backward and forward through the execution (time-travel debugging).")
            .clicked()
        {
            start(view, ui.ctx(), program, JobKind::Record);
        }
    });

    trace_panel(ui, view);

    if let Some(r) = &view.run {
        ui.add_space(6.0);
        let color = if r.error {
            ui.visuals().error_fg_color
        } else {
            ui.visuals().text_color()
        };
        ui.colored_label(color, &r.status);
        if !r.error {
            egui::Grid::new("emu-run-result")
                .num_columns(2)
                .spacing([10.0, 2.0])
                .show(ui, |ui| {
                    ui.label("RAX");
                    ui.label(
                        RichText::new(format!("{:#x}  ({}, {})", r.rax, r.rax, r.rax as i64))
                            .monospace(),
                    );
                    ui.end_row();
                    ui.label("instructions");
                    ui.label(RichText::new(r.steps.to_string()).monospace());
                    ui.end_row();
                    if let Some(s) = &r.ret_str {
                        ui.label("string at RAX");
                        ui.label(RichText::new(format!("{s:?}")).monospace());
                        ui.end_row();
                    }
                });
            ui.label("Scratch buffer after run:");
            ui.label(RichText::new(hex_ascii(&r.scratch)).monospace());
        }
    }
}

fn solve_section(
    ui: &mut Ui,
    view: &mut EmulatorView,
    program: &Arc<Program>,
    cursor: Option<u64>,
) {
    ui.heading("Side-channel solve");
    ui.label(muted(
        "Recover the input byte-by-byte by maximising executed instructions (instruction counting).",
    ));
    egui::Grid::new("emu-solve-form")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            ui.label("Function address");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut view.addr);
                if ui.small_button("use cursor's function").clicked()
                    && let Some(f) = cursor.and_then(|a| program.function_containing(a))
                {
                    view.addr = format!("{:#x}", f.entry);
                }
            });
            ui.end_row();
            ui.label("Input length");
            ui.text_edit_singleline(&mut view.solve_len);
            ui.end_row();
            ui.label("Charset");
            ui.horizontal(|ui| {
                for cs in [Charset::Printable, Charset::Alnum, Charset::Digits] {
                    ui.selectable_value(&mut view.charset, cs, cs.label());
                }
            });
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut view.pass_len, "pass length as arg1");
            ui.end_row();
        });

    if ui
        .add_enabled(!view.busy(), egui::Button::new("🔑 Solve"))
        .clicked()
    {
        start(view, ui.ctx(), program, JobKind::Solve);
    }

    if let Some(s) = &view.solve {
        ui.add_space(6.0);
        if let Some(e) = &s.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
            return;
        }
        ui.label("Recovered input:");
        ui.label(RichText::new(format!("{:?}", String::from_utf8_lossy(&s.recovered))).monospace());
        ui.label(RichText::new(hex_ascii(&s.recovered)).monospace());
        ui.add_space(4.0);
        ui.collapsing("per-position instruction counts", |ui| {
            egui::Grid::new("emu-solve-rows")
                .num_columns(4)
                .striped(true)
                .spacing([14.0, 2.0])
                .show(ui, |ui| {
                    ui.label(muted("pos"));
                    ui.label(muted("byte"));
                    ui.label(muted("count"));
                    ui.label(muted("runner-up"));
                    ui.end_row();
                    for (i, b, c, r) in &s.rows {
                        ui.label(RichText::new(i.to_string()).monospace());
                        ui.label(RichText::new(format!("{:?}", *b as char)).monospace());
                        ui.label(RichText::new(c.to_string()).monospace());
                        ui.label(RichText::new(r.to_string()).monospace().weak());
                        ui.end_row();
                    }
                });
        });
    }
}

fn symbolic_section(
    ui: &mut Ui,
    view: &mut EmulatorView,
    program: &Arc<Program>,
    cursor: Option<u64>,
) {
    ui.heading("Symbolic solve");
    ui.label(muted(
        "Treat the input as symbolic and find a value that reaches the target block, avoiding the \
         ones you mark. Solves byte-wise transform-and-compare checks (xor/add/sub/… then equal).",
    ));
    egui::Grid::new("emu-sym-form")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            ui.label("Function address");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut view.addr);
                if ui.small_button("use cursor's function").clicked()
                    && let Some(f) = cursor.and_then(|a| program.function_containing(a))
                {
                    view.addr = format!("{:#x}", f.entry);
                }
            });
            ui.end_row();
            ui.label("Input length");
            ui.text_edit_singleline(&mut view.solve_len);
            ui.end_row();
            ui.label("Target address");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut view.sym_target);
                if ui.small_button("use cursor").clicked()
                    && let Some(a) = cursor
                {
                    view.sym_target = format!("{a:#x}");
                }
            });
            ui.end_row();
            ui.label("Avoid addresses");
            ui.text_edit_singleline(&mut view.sym_avoid)
                .on_hover_text("comma- or space-separated hex addresses of the \"wrong\" blocks");
            ui.end_row();
        });

    let idle = !view.busy();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(idle, egui::Button::new("∑ Solve symbolically"))
            .clicked()
        {
            start(view, ui.ctx(), program, JobKind::Symbolic);
        }
        if ui
            .add_enabled(idle, egui::Button::new("⚙ Solve detected VM (auto)"))
            .on_hover_text(
                "If a bytecode VM is detected, recover its key automatically — no addresses needed.",
            )
            .clicked()
        {
            start(view, ui.ctx(), program, JobKind::AutoVm);
        }
    });

    if let Some(s) = &view.sym {
        ui.add_space(6.0);
        if let Some(err) = &s.error {
            ui.colored_label(ui.visuals().error_fg_color, format!("stopped: {err}"));
        } else {
            let color = if s.complete {
                ui.visuals().text_color()
            } else {
                ui.visuals().warn_fg_color
            };
            ui.colored_label(
                color,
                format!("{} ({} constraints)", s.message, s.constraints),
            );
            ui.label("Input:");
            ui.label(RichText::new(format!("{:?}", String::from_utf8_lossy(&s.input))).monospace());
            ui.label(RichText::new(hex_ascii(&s.input)).monospace());
        }
        ui.collapsing("SMT-LIB2 (for external z3)", |ui| {
            ui.label(RichText::new(&s.smt2).monospace());
        });
    }
}

// --- engine glue ----------------------------------------------------------

fn abi_of(program: &Program) -> Abi {
    if program.memory.is_elf {
        Abi::SysV
    } else {
        Abi::Win64
    }
}

/// Seeds an emulator from the program image (regions plus zeroed `.bss` slack, so guest writes to
/// globals don't fault) and stubs imports.
fn seed(program: &Program) -> Emulator {
    let mut emu = Emulator::new();
    emu.mem = orress_vm::emu_image(program);
    for (addr, stub) in orress_vm::import_hooks(program) {
        emu.hook(addr, stub);
    }
    emu.mem.map_zeroed(SCRATCH, SCRATCH_SIZE);
    emu
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse().ok(), |h| u64::from_str_radix(h, 16).ok())
}

/// General-purpose register names in the emulator's (iced-x86) index order.
const REG_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// The maximum instructions recorded for time-travel (each step keeps a small CPU snapshot).
const TRACE_LIMIT: usize = 100_000;

/// Records a time-travel trace of the function, with the same input/stack setup as `run_once`.
fn record_once(view: &Params, program: &Program) -> Result<Trace, String> {
    let func = parse_u64(&view.addr).ok_or("Enter a function address (hex, e.g. 0x401000).")?;
    let bytes = view.input.as_bytes();
    if bytes.len() > MAX_INPUT {
        return Err(format!("The input is longer than {MAX_INPUT} bytes."));
    }
    let mut emu = seed(program);
    emu.map(SCRATCH, bytes);
    emu.mem.write_bytes(SCRATCH + bytes.len() as u64, &[0]);
    let mut args = vec![SCRATCH];
    if view.pass_len {
        args.push(bytes.len() as u64);
    }
    // A fault mid-run keeps the steps leading up to it (`trace.fault`) — that's what you scrub.
    emu.record_call_with_fault(func, &args, abi_of(program), TRACE_LIMIT)
        .map_err(|e| format!("{e}"))
}

/// The time-travel scrubber: a slider over the recorded steps, showing the instruction executed and
/// the register file at that point, with the registers that changed at this step highlighted.
fn trace_panel(ui: &mut Ui, view: &mut EmulatorView) {
    if let Some(e) = &view.trace_error {
        ui.colored_label(ui.visuals().error_fg_color, e);
        return;
    }
    let Some(trace) = &view.trace else {
        return;
    };
    if trace.is_empty() {
        ui.label(muted(
            "Recorded an empty trace (the function returned immediately).",
        ));
        return;
    }
    ui.add_space(6.0);
    ui.label(RichText::new("Time-travel").strong());
    let last = trace.len() - 1;
    view.scrub = view.scrub.min(last);

    ui.horizontal(|ui| {
        if ui.small_button("⏮").on_hover_text("first").clicked() {
            view.scrub = 0;
        }
        if ui.small_button("◀").on_hover_text("step back").clicked() {
            view.scrub = view.scrub.saturating_sub(1);
        }
        if ui.small_button("▶").on_hover_text("step forward").clicked() && view.scrub < last {
            view.scrub += 1;
        }
        if ui.small_button("⏭").on_hover_text("last").clicked() {
            view.scrub = last;
        }
        ui.add(egui::Slider::new(&mut view.scrub, 0..=last).text("step"));
    });

    let i = view.scrub;
    let changed: std::collections::HashSet<usize> =
        trace.changed_regs(i).into_iter().map(|(r, _)| r).collect();
    let addr = trace.addr_at(i).unwrap_or(0);
    ui.label(RichText::new(format!("step {i} / {last}   @ {addr:#x}")).monospace());

    let cpu = trace.cpu_at(i);
    egui::Grid::new("emu-ttd-regs")
        .num_columns(4)
        .spacing([14.0, 2.0])
        .show(ui, |ui| {
            for (r, name) in REG_NAMES.iter().enumerate() {
                let text = RichText::new(format!("{name} {:>#18x}", cpu.regs[r])).monospace();
                let text = if changed.contains(&r) {
                    text.strong().color(ui.visuals().warn_fg_color)
                } else {
                    text
                };
                ui.label(text);
                if r % 4 == 3 {
                    ui.end_row();
                }
            }
        });
    match &trace.fault {
        Some(e) => ui.colored_label(ui.visuals().error_fg_color, format!("stopped: {e}")),
        None => ui.label(muted(format!("stop: {:?}", trace.stop))),
    };
}

fn run_once(view: &Params, program: &Program) -> RunReport {
    let Some(func) = parse_u64(&view.addr) else {
        return err_report("Enter a function address (hex, e.g. 0x401000).");
    };
    let bytes = view.input.as_bytes();
    if bytes.len() > MAX_INPUT {
        return err_report(&format!("The input is longer than {MAX_INPUT} bytes."));
    }
    let mut emu = seed(program);
    emu.map(SCRATCH, bytes);
    emu.mem.write_bytes(SCRATCH + bytes.len() as u64, &[0]); // NUL-terminate
    let mut args = vec![SCRATCH];
    if view.pass_len {
        args.push(bytes.len() as u64);
    }
    match emu.call(func, &args, abi_of(program)) {
        Ok(rax) => {
            let scratch = emu
                .mem
                .read_vec(SCRATCH, bytes.len().max(1))
                .unwrap_or_default();
            let ret_str = emu
                .mem
                .is_mapped(rax)
                .then(|| String::from_utf8_lossy(&emu.read_cstr(rax, 256)).into_owned())
                .filter(|s| !s.is_empty());
            RunReport {
                rax,
                steps: emu.steps,
                status: format!("returned after {} instructions", emu.steps),
                error: false,
                scratch,
                ret_str,
            }
        }
        Err(e) => err_report(&format!("stopped: {e}")),
    }
}

fn solve_once(view: &Params, program: &Program, cancel: &AtomicBool) -> SolveReport {
    let Some(func) = parse_u64(&view.addr) else {
        return SolveReport::error("Enter a function address (hex, e.g. 0x401000).");
    };
    let len = match parse_len(&view.solve_len) {
        Ok(len) => len,
        Err(e) => return SolveReport::error(&e),
    };
    let abi = abi_of(program);
    let pass_len = view.pass_len;
    let mut emu = seed(program);
    let candidates = view.charset.bytes();
    let solution = solve_by_count(len, &candidates, |input| {
        // A cancelled solve finishes the sweep without emulating; its output is discarded.
        if cancel.load(Ordering::Relaxed) {
            return 0;
        }
        emu.cpu = orress_emu::Cpu::new();
        emu.mem.write_bytes(SCRATCH, input);
        let mut args = vec![SCRATCH];
        if pass_len {
            args.push(len as u64);
        }
        let _ = emu.call(func, &args, abi);
        emu.steps
    });
    SolveReport {
        rows: solution
            .steps
            .iter()
            .map(|s| (s.index, s.byte, s.count, s.runner_up))
            .collect(),
        recovered: solution.input,
        error: None,
    }
}

/// Recovers the key of a detected bytecode VM with one click: finds the interpreter, derives the
/// success/avoid blocks and input from the CFG, and solves — no addresses to enter. Runs on the
/// worker thread (the VM scan + solve sweep takes a while).
fn auto_vm_solve(program: &Program) -> SymReport {
    let empty = SymReport::error;
    let Some(report) = orress_vm::scan(program).into_iter().next() else {
        return empty("No bytecode VM detected in this binary.");
    };
    match orress_vm::try_solve(program, &report) {
        Ok(sol) => SymReport {
            input: sol.key,
            complete: sol.complete,
            message: if sol.complete { "solved" } else { "partial" }.to_string(),
            constraints: sol.constraints,
            smt2: sol.smt2,
            error: None,
        },
        Err(e) => empty(&format!("Found a VM but could not solve it: {e}")),
    }
}

fn symbolic_solve_once(view: &Params, program: &Program) -> SymReport {
    let empty = SymReport::error;
    let Some(func) = parse_u64(&view.addr) else {
        return empty("enter a function address");
    };
    let len = match parse_len(&view.solve_len) {
        // MAX_INPUT fits in u32.
        Ok(len) => len as u32,
        Err(e) => return empty(&e),
    };
    let target = parse_u64(&view.sym_target).unwrap_or(0);
    let avoid: Vec<u64> = view
        .sym_avoid
        .split([',', ' ', '\t'])
        .filter_map(parse_u64)
        .collect();
    // A fresh concrete image seeds the symbolic executor; the input lives at SCRATCH.
    let mem = seed(program).mem;
    let hooks = orress_vm::import_hooks(program);
    match orress_sym::solve_check(
        mem,
        func,
        &[SCRATCH],
        SCRATCH,
        len,
        target,
        avoid,
        hooks,
        abi_of(program),
    ) {
        Ok(found) => SymReport {
            input: found.result.input,
            complete: found.result.complete,
            message: found.result.message,
            constraints: found.constraints,
            smt2: found.smt2,
            error: None,
        },
        Err(e) => empty(&e.to_string()),
    }
}

fn err_report(msg: &str) -> RunReport {
    RunReport {
        rax: 0,
        steps: 0,
        status: msg.to_string(),
        error: true,
        scratch: Vec::new(),
        ret_str: None,
    }
}

/// A compact hex + ASCII rendering of a small buffer.
fn hex_ascii(bytes: &[u8]) -> String {
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let ascii: String = bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{}  |{}|", hex.join(" "), ascii)
}
