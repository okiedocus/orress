//! The Linux debugger back end, built on `ptrace(2)` (via `nix` and raw `libc`). It launches the
//! target under trace, plants `int3` software breakpoints, single-steps with `PTRACE_SINGLESTEP`,
//! and reads/writes the live process through `/proc/<pid>/mem` — the same primitives as the
//! Windows back end, so the controller in `lib.rs` drives it identically. `unsafe` is confined
//! here (the `fork`/`exec`, raw `waitpid` and raw `ptrace` resume calls), as the workspace allows
//! for a platform back end. x86-64 only (the register file is x86-64's).
//!
//! Breakpoint protocol (standard, gdb-style): save the original byte, write `0xCC`. When an
//! `int3` traps (`si_code == SI_KERNEL`) the instruction pointer is one past it, so we rewind it
//! to the breakpoint address. To run past a breakpoint we are sitting on, restore the original
//! byte, single-step that one instruction, then re-plant `0xCC` when the step completes. A
//! single-step trap (`si_code == TRAP_TRACE`) is never rewound: a step that *lands* on a planted
//! breakpoint just records that we are sitting on it.
//!
//! Signals: a fault the program caused (SIGSEGV, SIGILL, …) is reported first and then
//! **delivered** on the next continue/step, so the program's own handlers run (and an unhandled
//! fault terminates it, as it would without a debugger) instead of re-faulting forever.
//! Housekeeping signals (SIGCHLD, SIGALRM, SIGWINCH, real-time signals …) are passed through
//! silently. A user pause is a `SIGSTOP` we send and then swallow.
//!
//! Threads: `PTRACE_O_TRACECLONE` auto-attaches every new thread, so a breakpoint hit in any
//! thread is caught and reported with that thread's registers. The model is "non-stop": only the
//! thread that reported the stop is halted; other threads keep running. While a breakpoint's
//! byte is restored for a step-over, another thread can run through that address without
//! stopping. `fork`ed child processes are not traced (and inherit any planted `0xCC` bytes).
//! `PTRACE_O_EXITKILL` makes the kernel kill the target if the debugger itself dies.

use std::collections::{HashMap, HashSet};
use std::ffi::{CString, c_char, c_void};
use std::fs::{File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::libc;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::Signal;
use nix::unistd::{ForkResult, Pid, fork};

use crate::backend::{Backend, DebugError, Event, Module, Result, StopReason};
use crate::regs::Registers;

impl From<nix::errno::Errno> for DebugError {
    fn from(e: nix::errno::Errno) -> Self {
        DebugError::Os(e.to_string())
    }
}

/// `si_code` of a `SIGTRAP` raised by an `int3` instruction.
const SI_KERNEL: i32 = libc::SI_KERNEL;
/// `PTRACE_EVENT_*` codes (the high byte of a stop status).
const EVENT_CLONE: i32 = libc::PTRACE_EVENT_CLONE;
const EVENT_EXEC: i32 = libc::PTRACE_EVENT_EXEC;

/// How a `SIGTRAP` was raised, from its `si_code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrapKind {
    /// An `int3` executed (ours or the program's).
    Int3,
    /// A hardware debug trap — for us, a completed single step.
    Trace,
    /// Sent by a process (`kill`/`raise`/`tgkill`): a genuine signal for the program.
    User,
}

pub struct LinuxBackend {
    /// The process (thread-group leader).
    pid: Pid,
    /// `/proc/<pid>/mem`, opened read+write (ptrace access reaches read-only code pages).
    mem: File,
    exe: PathBuf,
    image_base: Option<u64>,
    /// addr -> the original byte we overwrote with `0xCC`.
    breakpoints: HashMap<u64, u8>,
    /// Every traced thread (the leader included).
    threads: Vec<Pid>,
    /// New threads whose initial `SIGSTOP` has not been consumed yet.
    fresh: HashSet<Pid>,
    /// The thread of the current stop: registers are read from / written to it, and it is the
    /// one resumed by continue/step.
    current: Pid,
    /// We are stopped exactly on this breakpoint (its `0xCC` is still in memory); the next resume
    /// must step over it.
    at_bp: Option<u64>,
    /// A thread is single-stepping over this breakpoint (its original byte is in memory);
    /// re-plant `0xCC` once that thread stops again.
    step_over: Option<(Pid, u64)>,
    /// The user asked this thread for one instruction; its next trace trap is a `Step` stop.
    user_step: Option<Pid>,
    /// Signals to deliver to a thread when it is next resumed (faults we reported, or
    /// pass-through signals that arrived mid-step).
    pending_signal: HashMap<Pid, i32>,
    /// The process is still in its exec stop and the first poll has not reported it yet.
    pending_initial_stop: bool,
    /// The user asked to pause; the next `SIGSTOP` is ours and is reported as `Paused`.
    pause_requested: bool,
    /// True after a `cont`/`step`, until the target stops again.
    running: bool,
    exited: bool,
}

/// `waitpid` on one thread (`__WALL`, so clone children count), retrying on `EINTR`. Returns the
/// raw status, or `None` if `nohang` and the thread has nothing to report.
fn wait_raw(tid: Pid, nohang: bool) -> std::result::Result<Option<i32>, Errno> {
    let flags = libc::__WALL | if nohang { libc::WNOHANG } else { 0 };
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: plain waitpid on a specific pid with a valid out-pointer.
        let r = unsafe { libc::waitpid(tid.as_raw(), &mut status, flags) };
        match r {
            -1 => match Errno::last() {
                Errno::EINTR => continue,
                e => return Err(e),
            },
            0 => return Ok(None),
            _ => return Ok(Some(status)),
        }
    }
}

/// Resumes a stopped tracee, either running or single-stepping, delivering `sig` (0 = none).
/// Raw `libc` so real-time signals (which `nix::Signal` cannot represent) can be delivered.
fn ptrace_resume(tid: Pid, step: bool, sig: i32) -> Result<()> {
    let req = if step {
        libc::PTRACE_SINGLESTEP
    } else {
        libc::PTRACE_CONT
    };
    // SAFETY: a resume request on a ptrace-stopped tracee of ours; `addr` is ignored and `data`
    // carries the signal number, exactly as ptrace(2) specifies. No memory is passed.
    let r = unsafe {
        libc::ptrace(
            req,
            tid.as_raw(),
            std::ptr::null_mut::<c_void>(),
            std::ptr::without_provenance_mut::<c_void>(sig as usize),
        )
    };
    Errno::result(r).map(drop).map_err(Into::into)
}

/// Signals that are routine process housekeeping: pass them to the program without stopping.
fn is_passthrough(sig: i32) -> bool {
    // glibc uses real-time signals internally (thread cancellation, setxid), so all of them
    // must reach the program.
    sig >= 32
        || [
            libc::SIGCHLD,
            libc::SIGWINCH,
            libc::SIGALRM,
            libc::SIGVTALRM,
            libc::SIGPROF,
            libc::SIGURG,
            libc::SIGIO,
            libc::SIGCONT,
        ]
        .contains(&sig)
}

/// Stop signals we must not deliver: they would put the whole process into a group-stop.
fn is_job_control_stop(sig: i32) -> bool {
    [libc::SIGSTOP, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU].contains(&sig)
}

fn signal_name(sig: i32) -> String {
    Signal::try_from(sig).map_or_else(|_| format!("signal {sig}"), |s| s.as_str().to_string())
}

impl LinuxBackend {
    pub fn launch(path: &Path, args: &[String]) -> Result<Self> {
        // Build every C string and the argv pointer array *before* forking: the debugger is a
        // multi-threaded process, so after `fork` the child may only call async-signal-safe
        // functions — no allocation (another thread may have held the malloc lock at the fork).
        let abs = std::fs::canonicalize(path)
            .map_err(|e| DebugError::Launch(format!("{}: {e}", path.display())))?;
        let c_path = CString::new(abs.as_os_str().as_bytes())
            .map_err(|e| DebugError::Launch(e.to_string()))?;
        let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 1);
        argv.push(c_path.clone());
        for a in args {
            argv.push(CString::new(a.as_bytes()).map_err(|e| DebugError::Launch(e.to_string()))?);
        }
        let argv_ptrs: Vec<*const c_char> = argv
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // SAFETY: the child branch below only makes raw syscalls that are async-signal-safe
        // (ptrace, personality, execv, _exit) on memory prepared before the fork; it never
        // allocates, locks, or returns into Rust code that could.
        match unsafe { fork() }.map_err(|e| DebugError::Launch(e.to_string()))? {
            ForkResult::Child => {
                // SAFETY: async-signal-safe syscalls only (see above). `c_path`/`argv_ptrs` are
                // valid, NUL-terminated, and outlive the exec.
                unsafe {
                    // Become traceable, drop ASLR so addresses are stable across runs, then exec.
                    libc::ptrace(
                        libc::PTRACE_TRACEME,
                        0,
                        std::ptr::null_mut::<c_void>(),
                        std::ptr::null_mut::<c_void>(),
                    );
                    let current = libc::personality(0xffff_ffff);
                    if current != -1 {
                        libc::personality(
                            (current as libc::c_ulong) | libc::ADDR_NO_RANDOMIZE as libc::c_ulong,
                        );
                    }
                    libc::execv(c_path.as_ptr(), argv_ptrs.as_ptr());
                    // execv only returns on failure.
                    libc::_exit(127);
                }
            }
            ForkResult::Parent { child } => {
                // The child stops with SIGTRAP at the execve; wait for it.
                let status = wait_raw(child, false)
                    .map_err(|e| DebugError::Launch(e.to_string()))?
                    .unwrap_or(0);
                if libc::WIFEXITED(status) {
                    let code = libc::WEXITSTATUS(status);
                    let why = if code == 127 {
                        " (could not execute it)"
                    } else {
                        ""
                    };
                    return Err(DebugError::Launch(format!(
                        "exited early with code {code}{why}"
                    )));
                }
                if !(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP) {
                    return Err(DebugError::Launch(format!(
                        "unexpected start (wait status {status:#x})"
                    )));
                }
                // Follow new threads and new images, and have the kernel kill the target if the
                // debugger dies. EXITKILL needs Linux 3.8; fall back without it.
                let follow = Options::PTRACE_O_TRACECLONE | Options::PTRACE_O_TRACEEXEC;
                if ptrace::setoptions(child, follow | Options::PTRACE_O_EXITKILL).is_err() {
                    let _ = ptrace::setoptions(child, follow);
                }
                let mem = open_mem(child)?;
                let mut me = Self {
                    pid: child,
                    mem,
                    exe: abs,
                    image_base: None,
                    breakpoints: HashMap::new(),
                    threads: vec![child],
                    fresh: HashSet::new(),
                    current: child,
                    at_bp: None,
                    step_over: None,
                    user_step: None,
                    pending_signal: HashMap::new(),
                    pending_initial_stop: true,
                    pause_requested: false,
                    running: false,
                    exited: false,
                };
                me.image_base = me.find_image_base();
                Ok(me)
            }
        }
    }

    /// The load address of the main executable, from `/proc/<pid>/maps` (the lowest mapping backed
    /// by the executable's own path).
    fn find_image_base(&self) -> Option<u64> {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).ok()?;
        let exe = self.exe.to_string_lossy();
        maps.lines()
            .filter(|l| l.ends_with(exe.as_ref()))
            .filter_map(|l| l.split('-').next())
            .filter_map(|a| u64::from_str_radix(a, 16).ok())
            .min()
    }

    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.mem
            .read_exact_at(buf, addr)
            .map_err(|e| DebugError::Os(format!("read {addr:#x}: {e}")))
    }

    fn write_raw(&self, addr: u64, data: &[u8]) -> Result<()> {
        self.mem
            .write_all_at(data, addr)
            .map_err(|e| DebugError::Os(format!("write {addr:#x}: {e}")))
    }

    fn get_regs(&self, tid: Pid) -> Result<Registers> {
        let r = ptrace::getregs(tid)?;
        Ok(Registers {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            rsp: r.rsp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.eflags,
        })
    }

    /// Whether `tid` is in the middle of a single step (a user step or a breakpoint step-over).
    fn is_stepping(&self, tid: Pid) -> bool {
        self.user_step == Some(tid) || self.step_over.is_some_and(|(t, _)| t == tid)
    }

    /// `tid` stopped for some reason other than its step finishing: if it was stepping over a
    /// breakpoint, put the `0xCC` back now (and note we're sitting on it if `rip` is still
    /// there), and forget any user step.
    fn abandon_step(&mut self, tid: Pid, rip: Option<u64>) {
        if let Some((t, addr)) = self.step_over
            && t == tid
        {
            self.step_over = None;
            if self.breakpoints.contains_key(&addr) {
                let _ = self.write_raw(addr, &[0xCC]);
                if rip == Some(addr) {
                    self.at_bp = Some(addr);
                }
            }
        }
        if self.user_step == Some(tid) {
            self.user_step = None;
        }
    }

    /// Records a reported stop on `tid` and builds the event.
    fn stop(&mut self, tid: Pid, reason: StopReason) -> Option<Event> {
        self.running = false;
        self.current = tid;
        Some(Event::Stopped(reason))
    }

    /// The process has gone (exited, killed, or lost).
    fn gone(&mut self, code: i32) -> Option<Event> {
        self.exited = true;
        self.running = false;
        self.at_bp = None;
        self.step_over = None;
        self.user_step = None;
        self.threads.clear();
        self.fresh.clear();
        Some(Event::Stopped(StopReason::Exited(code)))
    }

    /// The process replaced its image (execve): the old breakpoints, threads and memory handle
    /// are gone with the old address space.
    fn on_exec(&mut self) -> Option<Event> {
        // After a multi-threaded exec the surviving thread takes over the leader's id; the other
        // threads are gone and get reaped (or dropped on ECHILD) by the next sweeps.
        if !self.threads.contains(&self.pid) {
            self.threads.push(self.pid);
        }
        self.fresh.clear();
        self.pending_signal.clear();
        self.breakpoints.clear();
        self.at_bp = None;
        self.step_over = None;
        self.user_step = None;
        if let Ok(mem) = open_mem(self.pid) {
            self.mem = mem;
        }
        if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", self.pid)) {
            self.exe = exe;
        }
        self.image_base = self.find_image_base();
        let address = ptrace::getregs(self.pid).map(|r| r.rip).unwrap_or(0);
        self.stop(
            self.pid,
            StopReason::Exception {
                code: libc::SIGTRAP as u32,
                address,
                text: "the program started a new executable (execve); its breakpoints were cleared"
                    .into(),
            },
        )
    }

    /// Classifies a `SIGTRAP` stop of `tid` by its `si_code`.
    fn trap_kind(&self, tid: Pid) -> TrapKind {
        match ptrace::getsiginfo(tid) {
            Ok(info) if info.si_code == SI_KERNEL => TrapKind::Int3,
            Ok(info) if info.si_code > 0 => TrapKind::Trace,
            Ok(_) => TrapKind::User,
            // No siginfo: fall back on what we asked the thread to do.
            Err(_) if self.is_stepping(tid) => TrapKind::Trace,
            Err(_) => TrapKind::Int3,
        }
    }

    /// Handles one wait status from `tid`. Returns the event to report, or `None` if the
    /// target keeps running (the status was consumed internally).
    fn handle_status(&mut self, tid: Pid, status: i32) -> Result<Option<Event>> {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            };
            if tid == self.pid {
                return Ok(self.gone(code));
            }
            // A thread ended.
            self.threads.retain(|&t| t != tid);
            self.fresh.remove(&tid);
            self.pending_signal.remove(&tid);
            self.abandon_step(tid, None);
            return Ok(None);
        }
        if !libc::WIFSTOPPED(status) {
            return Ok(None);
        }
        let sig = libc::WSTOPSIG(status);
        let event = status >> 16;

        // ptrace event stops.
        if sig == libc::SIGTRAP && event != 0 {
            if event == EVENT_EXEC {
                return Ok(self.on_exec());
            }
            if event == EVENT_CLONE
                && let Ok(new) = ptrace::getevent(tid)
            {
                let new = Pid::from_raw(new as libc::pid_t);
                if !self.threads.contains(&new) {
                    self.threads.push(new);
                    self.fresh.insert(new);
                }
            }
            // Resume the creator in whatever mode it was in.
            ptrace_resume(tid, self.is_stepping(tid), 0)?;
            return Ok(None);
        }

        // A new thread's initial stop: let it run.
        if sig == libc::SIGSTOP && self.fresh.remove(&tid) {
            ptrace_resume(tid, false, 0)?;
            return Ok(None);
        }

        let rip = ptrace::getregs(tid).map(|r| r.rip).ok();

        if sig == libc::SIGTRAP {
            match self.trap_kind(tid) {
                TrapKind::Int3 => {
                    let bp = rip.unwrap_or(0).wrapping_sub(1);
                    // Stepping over a breakpoint placed on a genuine `int3` byte executes the
                    // program's own int3: that one must not be rewound (it would loop forever).
                    let own_int3 = self.step_over == Some((tid, bp));
                    self.abandon_step(tid, rip);
                    if !own_int3
                        && self.breakpoints.contains_key(&bp)
                        && let Ok(mut r) = ptrace::getregs(tid)
                    {
                        r.rip = bp;
                        ptrace::setregs(tid, r)?;
                        self.at_bp = Some(bp);
                        return Ok(self.stop(tid, StopReason::Breakpoint(bp)));
                    }
                    // The program's own int3: report it; continuing resumes after it (as on
                    // Windows).
                    return Ok(self.stop(
                        tid,
                        StopReason::Exception {
                            code: libc::SIGTRAP as u32,
                            address: bp,
                            text: "a breakpoint (int3) in the program".into(),
                        },
                    ));
                }
                TrapKind::Trace if self.is_stepping(tid) => {
                    // A completed single step: re-plant the breakpoint we stepped over.
                    if let Some((t, addr)) = self.step_over
                        && t == tid
                    {
                        self.step_over = None;
                        if self.breakpoints.contains_key(&addr) {
                            self.write_raw(addr, &[0xCC])?;
                        }
                    }
                    if self.user_step == Some(tid) {
                        self.user_step = None;
                        // Landing *on* a planted breakpoint: don't rewind (nothing executed it),
                        // just remember we're on it so the next resume steps over it.
                        if let Some(r) = rip
                            && self.breakpoints.contains_key(&r)
                        {
                            self.at_bp = Some(r);
                            return Ok(self.stop(tid, StopReason::Breakpoint(r)));
                        }
                        return Ok(self.stop(tid, StopReason::Step));
                    }
                    // The step only moved us off a breakpoint: carry on with the continue.
                    let pending = self.pending_signal.remove(&tid).unwrap_or(0);
                    ptrace_resume(tid, false, pending)?;
                    return Ok(None);
                }
                TrapKind::Trace => {
                    // A trace trap we didn't ask for: the program set the trap flag itself.
                    // Report it and hand the SIGTRAP to the program, as the CPU/kernel would.
                    self.pending_signal.insert(tid, libc::SIGTRAP);
                    return Ok(self.stop(
                        tid,
                        StopReason::Exception {
                            code: libc::SIGTRAP as u32,
                            address: rip.unwrap_or(0),
                            text: "a trace trap (the program set the trap flag)".into(),
                        },
                    ));
                }
                TrapKind::User => {
                    self.abandon_step(tid, rip);
                    self.pending_signal.insert(tid, libc::SIGTRAP);
                    return Ok(self.stop(
                        tid,
                        StopReason::Exception {
                            code: libc::SIGTRAP as u32,
                            address: rip.unwrap_or(0),
                            text: "SIGTRAP sent to the program".into(),
                        },
                    ));
                }
            }
        }

        if sig == libc::SIGSTOP && self.pause_requested {
            // Our own pause: swallow the SIGSTOP.
            self.pause_requested = false;
            self.abandon_step(tid, rip);
            return Ok(self.stop(tid, StopReason::Paused));
        }

        if is_passthrough(sig) {
            if self.is_stepping(tid) {
                // Keep the step on its instruction; deliver the signal on the next resume.
                self.pending_signal.insert(tid, sig);
                ptrace_resume(tid, true, 0)?;
            } else {
                ptrace_resume(tid, false, sig)?;
            }
            return Ok(None);
        }

        // A real fault (SIGSEGV, SIGILL, SIGFPE, SIGBUS…) or another stopping signal: report it
        // with the faulting address and deliver it on the next resume (job-control stops are
        // swallowed — delivering them would freeze the whole process).
        self.abandon_step(tid, rip);
        if !is_job_control_stop(sig) {
            self.pending_signal.insert(tid, sig);
        }
        let text = match sig {
            libc::SIGSEGV => "segmentation fault (invalid memory access)".to_string(),
            libc::SIGILL => "illegal instruction".to_string(),
            libc::SIGFPE => "arithmetic exception (e.g. divide by zero)".to_string(),
            libc::SIGBUS => "bus error (misaligned or bad memory access)".to_string(),
            libc::SIGABRT => "aborted".to_string(),
            _ => format!("stopped by {}", signal_name(sig)),
        };
        Ok(self.stop(
            tid,
            StopReason::Exception {
                code: sig as u32,
                address: rip.unwrap_or(0),
                text,
            },
        ))
    }

    /// One non-blocking sweep over every traced thread. Returns the first reportable event.
    fn sweep(&mut self) -> Result<Option<Event>> {
        let tids = self.threads.clone();
        for tid in tids {
            match wait_raw(tid, true) {
                Ok(Some(status)) => {
                    if let Some(ev) = self.handle_status(tid, status)? {
                        return Ok(Some(ev));
                    }
                }
                Ok(None) => {}
                Err(Errno::ECHILD) => {
                    // Not (or no longer) ours to wait for.
                    if tid == self.pid {
                        return Ok(self.gone(-1));
                    }
                    self.threads.retain(|&t| t != tid);
                    self.fresh.remove(&tid);
                    self.abandon_step(tid, None);
                }
                Err(e) => return Err(e.into()),
            }
            if self.exited {
                break;
            }
        }
        Ok(None)
    }
}

fn open_mem(pid: Pid) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{pid}/mem"))
        .map_err(|e| DebugError::Os(format!("open /proc/{pid}/mem: {e}")))
}

impl Backend for LinuxBackend {
    fn add_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.breakpoints.contains_key(&addr) {
            return Ok(());
        }
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        let mut orig = [0u8; 1];
        self.read_raw(addr, &mut orig)?;
        self.write_raw(addr, &[0xCC])?;
        self.breakpoints.insert(addr, orig[0]);
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        if let Some(orig) = self.breakpoints.remove(&addr) {
            // Only restore if the target is alive; a dead process has no memory.
            if !self.exited {
                let _ = self.write_raw(addr, &[orig]);
            }
            if self.at_bp == Some(addr) {
                self.at_bp = None;
            }
        }
        Ok(())
    }

    fn poll(&mut self, timeout_ms: u32) -> Result<Event> {
        if self.pending_initial_stop && !self.exited {
            // The target is parked at its exec stop: report that first so the controller leaves
            // its start-up state and the user can set breakpoints before running.
            self.pending_initial_stop = false;
            self.running = false;
            return Ok(Event::Stopped(StopReason::Paused));
        }
        if self.exited || !self.running {
            return Ok(Event::Running);
        }
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            if let Some(ev) = self.sweep()? {
                return Ok(ev);
            }
            if self.exited || Instant::now() >= deadline {
                return Ok(Event::Running);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn resume(&mut self) -> Result<()> {
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        self.pending_initial_stop = false;
        let tid = self.current;
        if let Some(addr) = self.at_bp.take()
            && let Some(&orig) = self.breakpoints.get(&addr)
        {
            // Step the real instruction first; the step's completion re-plants the 0xCC and
            // continues (delivering any pending signal then).
            self.write_raw(addr, &[orig])?;
            self.step_over = Some((tid, addr));
            ptrace_resume(tid, true, 0)?;
        } else {
            let sig = self.pending_signal.remove(&tid).unwrap_or(0);
            ptrace_resume(tid, false, sig)?;
        }
        self.running = true;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        self.pending_initial_stop = false;
        let tid = self.current;
        // If on a breakpoint, restore the real byte for this one instruction and re-plant after.
        if let Some(addr) = self.at_bp.take()
            && let Some(&orig) = self.breakpoints.get(&addr)
        {
            self.write_raw(addr, &[orig])?;
            self.step_over = Some((tid, addr));
        }
        self.user_step = Some(tid);
        let sig = self.pending_signal.remove(&tid).unwrap_or(0);
        ptrace_resume(tid, true, sig)?;
        self.running = true;
        Ok(())
    }

    fn request_pause(&mut self) -> Result<()> {
        if !self.exited && self.running {
            self.pause_requested = true;
            let _ = nix::sys::signal::kill(self.pid, Signal::SIGSTOP);
        }
        Ok(())
    }

    fn registers(&mut self) -> Result<Registers> {
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        self.get_regs(self.current)
    }

    fn set_register(&mut self, name: &str, value: u64) -> Result<()> {
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        let mut r = ptrace::getregs(self.current)?;
        match name {
            "rax" => r.rax = value,
            "rbx" => r.rbx = value,
            "rcx" => r.rcx = value,
            "rdx" => r.rdx = value,
            "rsi" => r.rsi = value,
            "rdi" => r.rdi = value,
            "rbp" => r.rbp = value,
            "rsp" => r.rsp = value,
            "r8" => r.r8 = value,
            "r9" => r.r9 = value,
            "r10" => r.r10 = value,
            "r11" => r.r11 = value,
            "r12" => r.r12 = value,
            "r13" => r.r13 = value,
            "r14" => r.r14 = value,
            "r15" => r.r15 = value,
            "rip" | "pc" => r.rip = value,
            "rflags" | "eflags" => r.eflags = value,
            _ => return Err(DebugError::Os(format!("unknown register {name}"))),
        }
        ptrace::setregs(self.current, r)?;
        if matches!(name, "rip" | "pc") && self.at_bp.is_some_and(|a| a != value) {
            // Moved off the breakpoint we were sitting on.
            self.at_bp = None;
        }
        Ok(())
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let end = addr
            .checked_add(len as u64)
            .ok_or_else(|| DebugError::Os(format!("read {addr:#x}+{len:#x}: address overflow")))?;
        let mut bytes = vec![0u8; len];
        self.read_raw(addr, &mut bytes)?;
        // Show the real instructions, not our planted 0xCC bytes.
        for (&a, &orig) in &self.breakpoints {
            if a >= addr && a < end {
                bytes[(a - addr) as usize] = orig;
            }
        }
        Ok(bytes)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.write_raw(addr, data)
    }

    fn modules(&self) -> Vec<Module> {
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) else {
            return Vec::new();
        };
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for line in maps.lines() {
            // addr-range perms offset dev inode path
            let mut it = line.split_whitespace();
            let range = it.next().unwrap_or("");
            let path = it.nth(4).unwrap_or("");
            if path.is_empty() || path.starts_with('[') {
                continue;
            }
            if let Some(base) = range
                .split('-')
                .next()
                .and_then(|a| u64::from_str_radix(a, 16).ok())
                && seen.insert(path.to_string())
            {
                let name = path.rsplit('/').next().unwrap_or(path).to_string();
                out.push(Module { name, base });
            }
        }
        out
    }

    fn image_base(&self) -> Option<u64> {
        self.image_base
    }

    fn kill(&mut self) -> Result<()> {
        if self.exited {
            return Ok(());
        }
        // SIGKILL works whether the tracee is running or ptrace-stopped (PTRACE_KILL does not
        // on a running tracee). Then reap every thread, bounded so a lost thread can't hang us.
        let _ = nix::sys::signal::kill(self.pid, Signal::SIGKILL);
        let deadline = Instant::now() + Duration::from_secs(2);
        'reap: while Instant::now() < deadline {
            // Threads we haven't seen a clone event for yet are still ours to reap.
            if let Ok(dir) = std::fs::read_dir(format!("/proc/{}/task", self.pid)) {
                for e in dir.flatten() {
                    if let Some(t) = e.file_name().to_str().and_then(|s| s.parse().ok()) {
                        let t = Pid::from_raw(t);
                        if !self.threads.contains(&t) {
                            self.threads.push(t);
                        }
                    }
                }
            }
            // Non-leader threads first: the leader is only reported once they are reaped.
            let mut tids = self.threads.clone();
            tids.sort_by_key(|&t| t == self.pid);
            for tid in tids {
                match wait_raw(tid, true) {
                    Ok(Some(st)) if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) => {
                        if tid == self.pid {
                            break 'reap;
                        }
                        self.threads.retain(|&t| t != tid);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        if tid == self.pid {
                            break 'reap;
                        }
                        self.threads.retain(|&t| t != tid);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let _ = self.gone(-1);
        Ok(())
    }
}

impl Drop for LinuxBackend {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
