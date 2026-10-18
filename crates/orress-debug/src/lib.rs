//! The ORRESS debugger.
//!
//! Native debugging has a hard rule on Windows: the thread that creates the debuggee is
//! the only one allowed to wait for and continue its debug events. So the debugger runs
//! on its own thread, which owns the [`Backend`]. The UI holds a [`Debugger`] handle and
//! talks to that thread through a command channel; the thread publishes the target's
//! state into a shared snapshot and calls `notify` so the UI repaints.
//!
//! Back ends (x86-64 only): a native Windows one (the Win32 Debug API) and a Linux one
//! (`ptrace`); GDB-remote is planned. Other platforms/architectures get a clean
//! "unsupported" error. A [`MockTarget`] drives the controller in tests on any platform.
//!
//! Start-up: every back end's first stop is reported through `poll`. The Linux back end
//! reports the exec stop as `Paused` (set breakpoints, then continue); the Windows back end
//! runs through the loader breakpoint to the first user breakpoint (or exit).

mod backend;
mod mock;
pub mod procmem;
mod regs;

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

#[cfg(test)]
mod tests;

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub use backend::{Backend, DebugError, Event, Module, StopReason, Unsupported};
pub use mock::MockTarget;
pub use procmem::{MapRegion, MemRegion, memory_map, read_all_memory, read_mem};
pub use regs::{FLAGS, FlagInfo, GP_NAMES, Registers, flag_set};

/// Where the target is in its life cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Starting up (the back end is being created).
    Starting,
    /// Executing.
    Running,
    /// Stopped and ready to inspect.
    Stopped,
    /// The process has ended.
    Exited,
    /// The back end failed; see `last_error`.
    Failed,
}

/// A snapshot of the target for the UI. Cloned out of the shared state each frame.
#[derive(Clone, Debug)]
pub struct DebugState {
    pub status: Status,
    pub reason: Option<StopReason>,
    pub registers: Registers,
    /// Previous registers, so the UI can highlight what just changed.
    pub prev_registers: Registers,
    pub modules: Vec<Module>,
    pub image_base: Option<u64>,
    /// The target process id, once launched (for pid-based memory reads).
    pub pid: Option<u32>,
    /// Breakpoint address -> enabled.
    pub breakpoints: std::collections::BTreeMap<u64, bool>,
    pub last_error: Option<String>,
    /// A cached block of target memory the UI last asked for: (address, bytes).
    pub memory: Option<(u64, Vec<u8>)>,
    /// A cached block around the stack pointer: (address, bytes).
    pub stack: Option<(u64, Vec<u8>)>,
    /// Bumps on every change, so the UI can tell when to refresh derived data.
    pub generation: u64,
}

impl DebugState {
    fn new() -> Self {
        Self {
            status: Status::Starting,
            reason: None,
            registers: Registers::default(),
            prev_registers: Registers::default(),
            modules: Vec::new(),
            image_base: None,
            pid: None,
            breakpoints: std::collections::BTreeMap::new(),
            last_error: None,
            memory: None,
            stack: None,
            generation: 0,
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.status == Status::Stopped
    }

    pub fn is_alive(&self) -> bool {
        matches!(
            self.status,
            Status::Starting | Status::Running | Status::Stopped
        )
    }
}

enum Command {
    Continue,
    Step,
    Pause,
    AddBreakpoint(u64),
    RemoveBreakpoint(u64),
    SetRegister(String, u64),
    WriteMemory(u64, Vec<u8>),
    ReadMemory(u64, usize),
    ReadStack(u64, usize),
    Kill,
    Shutdown,
}

/// A factory that builds the back end on the debugger thread.
type Factory = Box<dyn FnOnce() -> backend::Result<Box<dyn Backend>> + Send>;

/// A handle to a running (or finished) debug session.
pub struct Debugger {
    tx: Sender<Command>,
    shared: Arc<Mutex<DebugState>>,
    thread: Option<JoinHandle<()>>,
}

impl Debugger {
    /// Starts a debug session on a native target. `notify` is called whenever the
    /// target's state changes, so the UI can repaint.
    pub fn launch(
        path: std::path::PathBuf,
        args: Vec<String>,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::spawn(Box::new(move || native_backend(&path, &args)), notify)
    }

    /// Starts a session against a caller-provided back end (used for the mock target).
    pub fn with_backend(
        make: impl FnOnce() -> backend::Result<Box<dyn Backend>> + Send + 'static,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::spawn(Box::new(make), notify)
    }

    fn spawn(make: Factory, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        let shared = Arc::new(Mutex::new(DebugState::new()));
        let (tx, rx) = channel();
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("orress-debug".into())
            .spawn(move || run(make, rx, thread_shared, notify))
            .expect("spawn debugger thread");
        Self {
            tx,
            shared,
            thread: Some(thread),
        }
    }

    /// The current state of the target.
    pub fn state(&self) -> DebugState {
        self.shared.lock().expect("debug state lock").clone()
    }

    pub fn resume(&self) {
        let _ = self.tx.send(Command::Continue);
    }
    pub fn step(&self) {
        let _ = self.tx.send(Command::Step);
    }
    pub fn pause(&self) {
        let _ = self.tx.send(Command::Pause);
    }
    pub fn add_breakpoint(&self, addr: u64) {
        let _ = self.tx.send(Command::AddBreakpoint(addr));
    }
    pub fn remove_breakpoint(&self, addr: u64) {
        let _ = self.tx.send(Command::RemoveBreakpoint(addr));
    }
    pub fn set_register(&self, name: impl Into<String>, value: u64) {
        let _ = self.tx.send(Command::SetRegister(name.into(), value));
    }
    pub fn write_memory(&self, addr: u64, data: Vec<u8>) {
        let _ = self.tx.send(Command::WriteMemory(addr, data));
    }
    /// Asks the thread to cache `len` bytes of memory at `addr` into the snapshot.
    pub fn read_memory(&self, addr: u64, len: usize) {
        let _ = self.tx.send(Command::ReadMemory(addr, len));
    }
    /// Caches `len` bytes around the stack pointer into the snapshot.
    pub fn read_stack(&self, addr: u64, len: usize) {
        let _ = self.tx.send(Command::ReadStack(addr, len));
    }
    pub fn kill(&self) {
        let _ = self.tx.send(Command::Kill);
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Kill);
        let _ = self.tx.send(Command::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn native_backend(path: &std::path::Path, args: &[String]) -> backend::Result<Box<dyn Backend>> {
    Ok(Box::new(windows::WindowsBackend::launch(path, args)?))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn native_backend(path: &std::path::Path, args: &[String]) -> backend::Result<Box<dyn Backend>> {
    Ok(Box::new(linux::LinuxBackend::launch(path, args)?))
}

#[cfg(not(any(
    all(windows, target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64")
)))]
fn native_backend(_path: &std::path::Path, _args: &[String]) -> backend::Result<Box<dyn Backend>> {
    Err(DebugError::Unsupported("this platform"))
}

/// Updates the shared snapshot and asks the UI to repaint.
fn publish(shared: &Mutex<DebugState>, notify: &dyn Fn(), f: impl FnOnce(&mut DebugState)) {
    {
        let mut s = shared.lock().expect("debug state lock");
        f(&mut s);
        s.generation += 1;
    }
    notify();
}

fn snapshot(
    backend: &mut dyn Backend,
    shared: &Mutex<DebugState>,
    notify: &dyn Fn(),
    reason: StopReason,
) {
    let regs = backend.registers().unwrap_or_default();
    let modules = backend.modules();
    let image_base = backend.image_base();
    let pid = backend.pid();
    let exited = reason.is_exit();
    publish(shared, notify, |s| {
        s.prev_registers = s.registers;
        s.registers = regs;
        s.modules = modules;
        s.image_base = image_base;
        s.pid = pid;
        s.status = if exited {
            Status::Exited
        } else {
            Status::Stopped
        };
        s.reason = Some(reason);
        // A clean stop clears any earlier transient warning.
        s.last_error = None;
    });
}

fn run(
    make: Factory,
    rx: Receiver<Command>,
    shared: Arc<Mutex<DebugState>>,
    notify: Arc<dyn Fn() + Send + Sync>,
) {
    let mut backend = match make() {
        Ok(b) => b,
        Err(e) => {
            publish(&shared, &*notify, |s| {
                s.status = Status::Failed;
                s.last_error = Some(e.to_string());
            });
            return;
        }
    };
    // The target starts suspended at the initial breakpoint the OS reports; drive it to
    // that first stop so the user sees registers immediately.
    let mut running = true;
    loop {
        if running {
            match backend.poll(50) {
                Ok(Event::Running) => {
                    // Still executing: handle commands that are safe while the target
                    // runs (breakpoints, memory, pause, kill). Run/step wait for a stop.
                    while let Ok(cmd) = rx.try_recv() {
                        match cmd {
                            Command::Pause => {
                                let _ = backend.request_pause();
                            }
                            Command::AddBreakpoint(addr) => {
                                let ok =
                                    report_err(&backend.add_breakpoint(addr), &shared, &*notify);
                                if ok {
                                    publish(&shared, &*notify, |s| {
                                        s.breakpoints.insert(addr, true);
                                    });
                                }
                            }
                            Command::RemoveBreakpoint(addr) => {
                                let _ = backend.remove_breakpoint(addr);
                                publish(&shared, &*notify, |s| {
                                    s.breakpoints.remove(&addr);
                                });
                            }
                            Command::WriteMemory(addr, data) => {
                                report_err(&backend.write_memory(addr, &data), &shared, &*notify);
                            }
                            Command::Kill | Command::Shutdown => {
                                let _ = backend.kill();
                                publish(&shared, &*notify, |s| s.status = Status::Exited);
                                return;
                            }
                            _ => {} // continue/step/edit-register wait until the target stops
                        }
                    }
                    // The image base and module list become known while running; publish
                    // them so the UI can place breakpoints by runtime address.
                    let base = backend.image_base();
                    let mods = backend.modules();
                    let changed = {
                        let s = shared.lock().expect("debug state lock");
                        s.image_base != base || s.modules.len() != mods.len()
                    };
                    if changed {
                        publish(&shared, &*notify, |s| {
                            s.image_base = base;
                            s.modules = mods;
                        });
                    }
                }
                Ok(Event::Stopped(reason)) => {
                    running = false;
                    snapshot(&mut *backend, &shared, &*notify, reason);
                }
                Err(e) => {
                    running = false;
                    publish(&shared, &*notify, |s| {
                        s.status = Status::Failed;
                        s.last_error = Some(e.to_string());
                    });
                }
            }
            continue;
        }
        // Stopped: block until the user asks for something.
        let Ok(cmd) = rx.recv() else {
            let _ = backend.kill();
            return;
        };
        match cmd {
            Command::Continue => {
                if report_err(&backend_resume(&mut *backend), &shared, &*notify) {
                    set_running(&shared, &*notify);
                    running = true;
                }
            }
            Command::Step => {
                if report_err(&backend.step(), &shared, &*notify) {
                    running = true;
                }
            }
            Command::Pause => {}
            Command::AddBreakpoint(addr) => {
                let ok = report_err(&backend.add_breakpoint(addr), &shared, &*notify);
                if ok {
                    publish(&shared, &*notify, |s| {
                        s.breakpoints.insert(addr, true);
                    });
                }
            }
            Command::RemoveBreakpoint(addr) => {
                let _ = backend.remove_breakpoint(addr);
                publish(&shared, &*notify, |s| {
                    s.breakpoints.remove(&addr);
                });
            }
            Command::SetRegister(name, value) => {
                if report_err(&backend.set_register(&name, value), &shared, &*notify) {
                    let regs = backend.registers().unwrap_or_default();
                    publish(&shared, &*notify, |s| s.registers = regs);
                }
            }
            Command::WriteMemory(addr, data) => {
                report_err(&backend.write_memory(addr, &data), &shared, &*notify);
            }
            Command::ReadMemory(addr, len) => match backend.read_memory(addr, len) {
                Ok(bytes) => publish(&shared, &*notify, |s| s.memory = Some((addr, bytes))),
                Err(e) => publish(&shared, &*notify, |s| s.last_error = Some(e.to_string())),
            },
            Command::ReadStack(addr, len) => {
                if let Ok(bytes) = backend.read_memory(addr, len) {
                    publish(&shared, &*notify, |s| s.stack = Some((addr, bytes)));
                }
            }
            Command::Kill => {
                let _ = backend.kill();
                publish(&shared, &*notify, |s| s.status = Status::Exited);
            }
            Command::Shutdown => {
                let _ = backend.kill();
                return;
            }
        }
    }
}

fn set_running(shared: &Mutex<DebugState>, notify: &dyn Fn()) {
    publish(shared, notify, |s| {
        s.status = Status::Running;
        s.reason = None;
    });
}

/// `resume` is its own fn so the `report_err` borrow is clean.
fn backend_resume(backend: &mut dyn Backend) -> backend::Result<()> {
    backend.resume()
}

/// Records an error in the snapshot. Returns true on success.
fn report_err<T>(r: &backend::Result<T>, shared: &Mutex<DebugState>, notify: &dyn Fn()) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => {
            let msg = e.to_string();
            publish(shared, notify, |s| s.last_error = Some(msg));
            false
        }
    }
}
