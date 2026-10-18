//! The native Windows debugger back end, built on the Win32 Debug API.
//!
//! All `unsafe` in the crate lives here: the Debug API is raw FFI. Each call documents
//! why it is sound. The rule the API enforces — only the thread that created the debuggee
//! may wait for and continue its events — is satisfied because the controller creates and
//! drives this back end entirely on the debugger thread.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{BOOL, CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW};
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_FLAGS, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WaitForDebugEventEx, WriteProcessMemory,
};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DEBUG_ONLY_THIS_PROCESS, IsWow64Process, PROCESS_INFORMATION, STARTUPINFOW,
    TerminateProcess,
};
use windows::core::{PCWSTR, PWSTR};

use crate::backend::{Backend, DebugError, Event, Module, Result, StopReason};
use crate::regs::Registers;

// Debug event codes.
const EXCEPTION_DEBUG_EVENT: u32 = 1;
const CREATE_THREAD_DEBUG_EVENT: u32 = 2;
const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
const EXIT_THREAD_DEBUG_EVENT: u32 = 4;
const EXIT_PROCESS_DEBUG_EVENT: u32 = 5;
const LOAD_DLL_DEBUG_EVENT: u32 = 6;

// Exception codes.
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
const EXCEPTION_STACK_OVERFLOW: u32 = 0xC000_00FD;

// Continue statuses.
const DBG_CONTINUE: NTSTATUS = NTSTATUS(0x0001_0002u32 as i32);
const DBG_EXCEPTION_NOT_HANDLED: NTSTATUS = NTSTATUS(0x8001_0001u32 as i32);

// CONTEXT_AMD64 | CONTROL | INTEGER | SEGMENTS | FLOATING_POINT: GPRs, rip and rflags.
const CONTEXT_AMD64_FULL: CONTEXT_FLAGS = CONTEXT_FLAGS(0x0010_000F);
const TRAP_FLAG: u64 = 0x100;

const WAIT_TIMEOUT: u32 = 258;

/// One planted software breakpoint and the byte it replaced.
struct Bp {
    original: u8,
    planted: bool,
}

pub struct WindowsBackend {
    process: HANDLE,
    pid: u32,
    image_path: String,
    image_base: Option<u64>,
    /// Thread id -> handle, for register access.
    threads: HashMap<u32, HANDLE>,
    /// The thread of the current stop.
    current_tid: u32,
    breakpoints: HashMap<u64, Bp>,
    modules: Vec<Module>,
    /// A debug event waiting for `ContinueDebugEvent`: (tid, status).
    pending_continue: Option<(u32, NTSTATUS)>,
    /// A breakpoint whose original byte is temporarily restored and must be re-planted
    /// after the next single step.
    rearm_after_step: Option<u64>,
    /// The user asked for one instruction; the next single-step is a `Step` stop.
    user_stepping: bool,
    /// The breakpoint we are currently stopped on (its byte is still 0xCC in memory).
    stopped_at_bp: Option<u64>,
    /// The loader (system) breakpoint has been consumed.
    loader_bp_seen: bool,
    /// The user asked to pause; the next foreign breakpoint (the one `DebugBreakProcess`
    /// injects) is reported as `Paused`.
    pause_requested: bool,
}

/// Turns a path and args into a UTF-16 command line (`"path" arg1 arg2`), quoting each
/// argument so the program's C runtime splits it back into exactly the same `argv`.
fn command_line(path: &Path, args: &[String]) -> Vec<u16> {
    // A Windows path cannot contain `"`, so plain quotes around it are always correct.
    let mut s = String::from("\"");
    s.push_str(&path.to_string_lossy());
    s.push('"');
    for a in args {
        s.push(' ');
        quote_arg(a, &mut s);
    }
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Appends `arg` to a command line using the MSVCRT / `CommandLineToArgvW` rules: wrap in
/// quotes when it is empty or contains whitespace or a quote; inside the quotes, a `"` becomes
/// `\"`, and backslashes are doubled only where they precede a quote (including the closing
/// one) — elsewhere they are literal.
fn quote_arg(arg: &str, out: &mut String) {
    let needs_quotes = arg.is_empty() || arg.contains([' ', '\t', '\n', '\x0b', '"']);
    if !needs_quotes {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Escape the run of backslashes and the quote itself.
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Backslashes before the closing quote must be doubled so it stays a delimiter.
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
}

/// The file name (no directory) of an open file handle, e.g. a loaded DLL's.
fn file_name_of_handle(h: HANDLE) -> Option<String> {
    if h.is_invalid() {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `h` is a live file handle from the debug event; `buf` is a writable buffer
        // whose length the wrapper passes along.
        let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, FILE_NAME_NORMALIZED) } as usize;
        if n == 0 {
            return None;
        }
        if n < buf.len() {
            let path = String::from_utf16_lossy(&buf[..n]);
            let name = path.rsplit(['\\', '/']).next().unwrap_or(&path);
            return (!name.is_empty()).then(|| name.to_string());
        }
        // Too small: `n` is the size needed (including the NUL).
        if n > 32 * 1024 {
            return None;
        }
        buf.resize(n + 1, 0);
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl WindowsBackend {
    pub fn launch(path: &Path, args: &[String]) -> Result<Self> {
        let app = wide(&path.to_string_lossy());
        let mut cmd = command_line(path, args);
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: `app` and `cmd` are valid, NUL-terminated UTF-16 buffers that outlive
        // the call; `startup`/`info` are correctly sized. DEBUG_ONLY_THIS_PROCESS makes
        // this thread the debugger for the new process.
        let r = unsafe {
            CreateProcessW(
                PCWSTR(app.as_ptr()),
                Some(PWSTR(cmd.as_mut_ptr())),
                None,
                None,
                false,
                DEBUG_ONLY_THIS_PROCESS,
                None,
                PCWSTR::null(),
                &startup,
                &mut info,
            )
        };
        if let Err(e) = r {
            return Err(DebugError::Launch(e.message()));
        }
        // This back end reads x64 thread contexts; a 32-bit (WOW64) target would need the
        // Wow64 context APIs and raises WOW64-specific breakpoint codes. Refuse it cleanly
        // rather than show garbage registers.
        let mut wow64 = BOOL(0);
        // SAFETY: `info.hProcess` is the live process handle CreateProcessW just returned;
        // `wow64` is a valid out-pointer.
        let is_wow64 =
            unsafe { IsWow64Process(info.hProcess, &mut wow64) }.is_ok() && wow64.as_bool();
        if is_wow64 {
            // SAFETY: terminating and detaching from the process we just created; both
            // handles are valid and closed exactly once below.
            unsafe {
                let _ = TerminateProcess(info.hProcess, 1);
                let _ = DebugActiveProcessStop(info.dwProcessId);
            }
        }
        // The initial thread handle arrives again via the CREATE_PROCESS event; close
        // the duplicate handles CreateProcessW returned to avoid leaks.
        // SAFETY: both handles are valid, owned, and not used afterwards.
        unsafe {
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(info.hProcess);
        }
        if is_wow64 {
            return Err(DebugError::Launch(
                "32-bit targets aren't supported by the debugger yet; use the emulator".into(),
            ));
        }
        Ok(Self {
            process: HANDLE::default(),
            pid: info.dwProcessId,
            image_path: path.to_string_lossy().into_owned(),
            image_base: None,
            threads: HashMap::new(),
            current_tid: 0,
            breakpoints: HashMap::new(),
            modules: Vec::new(),
            pending_continue: None,
            rearm_after_step: None,
            user_stepping: false,
            stopped_at_bp: None,
            loader_bp_seen: false,
            pause_requested: false,
        })
    }

    fn thread(&self, tid: u32) -> Result<HANDLE> {
        self.threads
            .get(&tid)
            .copied()
            .ok_or(DebugError::NotRunning)
    }

    fn get_context(&self, tid: u32) -> Result<CONTEXT> {
        let h = self.thread(tid)?;
        let mut ctx = CONTEXT {
            ContextFlags: CONTEXT_AMD64_FULL,
            ..Default::default()
        };
        // SAFETY: `h` is a live thread handle; `ctx` is a correctly aligned CONTEXT with
        // ContextFlags set, as GetThreadContext requires.
        unsafe { GetThreadContext(h, &mut ctx) }.map_err(|e| DebugError::Os(e.message()))?;
        Ok(ctx)
    }

    fn set_context(&self, tid: u32, ctx: &CONTEXT) -> Result<()> {
        let h = self.thread(tid)?;
        // SAFETY: `h` is a live thread handle and `ctx` was filled by GetThreadContext.
        unsafe { SetThreadContext(h, ctx) }.map_err(|e| DebugError::Os(e.message()))
    }

    fn set_trap_flag(&self, tid: u32, on: bool) -> Result<()> {
        let mut ctx = self.get_context(tid)?;
        if on {
            ctx.EFlags |= TRAP_FLAG as u32;
        } else {
            ctx.EFlags &= !(TRAP_FLAG as u32);
        }
        self.set_context(tid, &ctx)
    }

    fn read_raw(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read = 0usize;
        // SAFETY: `self.process` is a live process handle; `buf` has `len` bytes and
        // `read` receives the count. A short/failed read is reported via the Result.
        let r = unsafe {
            ReadProcessMemory(
                self.process,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                len,
                Some(&mut read),
            )
        };
        // A read running into an unmapped page fails with ERROR_PARTIAL_COPY but still
        // copies the readable prefix: keep it.
        if let Err(e) = r
            && read == 0
        {
            return Err(DebugError::Os(e.message()));
        }
        buf.truncate(read);
        Ok(buf)
    }

    fn write_raw(&self, addr: u64, data: &[u8]) -> Result<()> {
        // Code pages may be read-only; make the range writable for the poke, then restore.
        let mut old = PAGE_PROTECTION_FLAGS(0);
        // SAFETY: valid process handle and range; `old` receives the previous protection.
        let protected = unsafe {
            VirtualProtectEx(
                self.process,
                addr as *const c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        }
        .is_ok();
        let mut written = 0usize;
        // SAFETY: valid process handle; `data` is `data.len()` bytes; `written` receives
        // the count.
        let res = unsafe {
            WriteProcessMemory(
                self.process,
                addr as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut written),
            )
        }
        .map_err(|e| DebugError::Os(e.message()));
        if protected {
            // SAFETY: restoring the protection we just changed on the same range.
            unsafe {
                let _ = VirtualProtectEx(
                    self.process,
                    addr as *const c_void,
                    data.len(),
                    old,
                    &mut old,
                );
            }
        }
        res?;
        // SAFETY: flushing the instruction cache for the modified range is always sound.
        unsafe {
            let _ = FlushInstructionCache(self.process, Some(addr as *const c_void), data.len());
        }
        Ok(())
    }

    fn plant(&mut self, addr: u64) -> Result<()> {
        if self.process.is_invalid() {
            return Ok(()); // process not created yet; planted on the CREATE_PROCESS event
        }
        let original = match self.breakpoints.get(&addr) {
            Some(bp) if bp.planted => return Ok(()),
            Some(bp) => bp.original,
            None => {
                let byte = self.read_raw(addr, 1)?;
                *byte.first().ok_or(DebugError::NotRunning)?
            }
        };
        self.write_raw(addr, &[0xCC])?;
        self.breakpoints.insert(
            addr,
            Bp {
                original,
                planted: true,
            },
        );
        Ok(())
    }

    fn unplant(&mut self, addr: u64) -> Result<()> {
        if let Some(bp) = self.breakpoints.get(&addr)
            && bp.planted
        {
            let original = bp.original;
            self.write_raw(addr, &[original])?;
            if let Some(bp) = self.breakpoints.get_mut(&addr) {
                bp.planted = false;
            }
        }
        Ok(())
    }

    /// (Re)plants every known breakpoint; used after the process image is available.
    fn plant_all(&mut self) {
        let addrs: Vec<u64> = self.breakpoints.keys().copied().collect();
        for a in addrs {
            let _ = self.plant(a);
        }
    }

    fn do_continue(&mut self, status: NTSTATUS) -> Result<()> {
        if let Some((tid, _)) = self.pending_continue.take() {
            // SAFETY: pid/tid name the process and thread of the pending debug event.
            unsafe { ContinueDebugEvent(self.pid, tid, status) }
                .map_err(|e| DebugError::Os(e.message()))?;
        }
        Ok(())
    }

    /// Handles one debug event into either a stop reason or "keep running".
    fn handle_event(&mut self, event: &DEBUG_EVENT) -> Result<Event> {
        let code = event.dwDebugEventCode.0;
        let tid = event.dwThreadId;
        self.current_tid = tid;
        self.pending_continue = Some((tid, DBG_CONTINUE));

        match code {
            CREATE_PROCESS_DEBUG_EVENT => {
                // SAFETY: the union holds CreateProcessInfo for this event code.
                let cp = unsafe { event.u.CreateProcessInfo };
                self.process = cp.hProcess;
                self.threads.insert(tid, cp.hThread);
                let base = cp.lpBaseOfImage as u64;
                self.image_base = Some(base);
                let name = Path::new(&self.image_path).file_name().map_or_else(
                    || self.image_path.clone(),
                    |n| n.to_string_lossy().into_owned(),
                );
                self.modules.push(Module { name, base });
                // SAFETY: the file handle from the event is owned by us; close it.
                unsafe {
                    let _ = CloseHandle(cp.hFile);
                }
                self.plant_all();
                self.do_continue(DBG_CONTINUE)?;
                Ok(Event::Running)
            }
            CREATE_THREAD_DEBUG_EVENT => {
                // SAFETY: union holds CreateThread for this code.
                let ct = unsafe { event.u.CreateThread };
                self.threads.insert(tid, ct.hThread);
                self.do_continue(DBG_CONTINUE)?;
                Ok(Event::Running)
            }
            EXIT_THREAD_DEBUG_EVENT => {
                self.threads.remove(&tid);
                self.do_continue(DBG_CONTINUE)?;
                Ok(Event::Running)
            }
            LOAD_DLL_DEBUG_EVENT => {
                // SAFETY: union holds LoadDll for this code.
                let dll = unsafe { event.u.LoadDll };
                let base = dll.lpBaseOfDll as u64;
                let name =
                    file_name_of_handle(dll.hFile).unwrap_or_else(|| format!("module@0x{base:x}"));
                self.modules.push(Module { name, base });
                // SAFETY: the DLL file handle is owned by us; close it (after naming it).
                unsafe {
                    let _ = CloseHandle(dll.hFile);
                }
                self.do_continue(DBG_CONTINUE)?;
                Ok(Event::Running)
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                // SAFETY: union holds ExitProcess for this code.
                let ep = unsafe { event.u.ExitProcess };
                let code = ep.dwExitCode as i32;
                self.do_continue(DBG_CONTINUE)?;
                self.pending_continue = None;
                Ok(Event::Stopped(StopReason::Exited(code)))
            }
            EXCEPTION_DEBUG_EVENT => {
                // SAFETY: union holds Exception for this code.
                let er = unsafe { event.u.Exception.ExceptionRecord };
                let ecode = er.ExceptionCode.0 as u32;
                let addr = er.ExceptionAddress as u64;
                self.handle_exception(ecode, addr)
            }
            _ => {
                self.do_continue(DBG_CONTINUE)?;
                Ok(Event::Running)
            }
        }
    }

    fn handle_exception(&mut self, ecode: u32, addr: u64) -> Result<Event> {
        match ecode {
            EXCEPTION_BREAKPOINT => {
                if self.breakpoints.contains_key(&addr) {
                    // A user breakpoint: rip is past the int3; rewind it to the address.
                    let mut ctx = self.get_context(self.current_tid)?;
                    ctx.Rip = addr;
                    self.set_context(self.current_tid, &ctx)?;
                    self.stopped_at_bp = Some(addr);
                    Ok(Event::Stopped(StopReason::Breakpoint(addr)))
                } else if !self.loader_bp_seen {
                    // The loader (system) breakpoint: the program is now ready. Plant
                    // breakpoints and run on so execution reaches the user's first one.
                    self.loader_bp_seen = true;
                    self.plant_all();
                    self.do_continue(DBG_CONTINUE)?;
                    Ok(Event::Running)
                } else if self.pause_requested {
                    // The int3 DebugBreakProcess injected for the user's pause.
                    self.pause_requested = false;
                    Ok(Event::Stopped(StopReason::Paused))
                } else {
                    Ok(Event::Stopped(StopReason::Exception {
                        code: ecode,
                        address: addr,
                        text: "a breakpoint (int3) in the program".into(),
                    }))
                }
            }
            EXCEPTION_SINGLE_STEP => {
                if let Some(bp) = self.rearm_after_step.take() {
                    let _ = self.plant(bp);
                }
                if self.user_stepping {
                    self.user_stepping = false;
                    // Clear the trap flag so a later continue runs freely.
                    self.set_trap_flag(self.current_tid, false)?;
                    // Landing *on* a planted breakpoint: nothing executed its int3, so don't
                    // rewind — just remember we're on it so the next resume steps over it
                    // (otherwise the same breakpoint would be reported a second time).
                    if self.breakpoints.get(&addr).is_some_and(|bp| bp.planted) {
                        self.stopped_at_bp = Some(addr);
                        return Ok(Event::Stopped(StopReason::Breakpoint(addr)));
                    }
                    Ok(Event::Stopped(StopReason::Step))
                } else {
                    // A step done only to move off a breakpoint: keep going.
                    self.set_trap_flag(self.current_tid, false)?;
                    self.do_continue(DBG_CONTINUE)?;
                    Ok(Event::Running)
                }
            }
            other => {
                // A real fault. Let the program's own handler (if any) see it on continue.
                self.pending_continue = Some((self.current_tid, DBG_EXCEPTION_NOT_HANDLED));
                Ok(Event::Stopped(StopReason::Exception {
                    code: other,
                    address: addr,
                    text: fault_text(other).into(),
                }))
            }
        }
    }

    /// Before resuming off a breakpoint, restore its byte and arrange to re-plant it
    /// after one step. Returns whether a single step was set up.
    fn step_off_breakpoint(&mut self) -> Result<bool> {
        if let Some(addr) = self.stopped_at_bp.take() {
            self.unplant(addr)?;
            self.set_trap_flag(self.current_tid, true)?;
            self.rearm_after_step = Some(addr);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn fault_text(code: u32) -> &'static str {
    match code {
        EXCEPTION_ACCESS_VIOLATION => "memory access violation (bad pointer)",
        EXCEPTION_ILLEGAL_INSTRUCTION => "illegal instruction",
        EXCEPTION_INT_DIVIDE_BY_ZERO => "integer divide by zero",
        EXCEPTION_STACK_OVERFLOW => "stack overflow",
        _ => "an unhandled exception",
    }
}

impl Backend for WindowsBackend {
    fn add_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.plant(addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.unplant(addr)?;
        self.breakpoints.remove(&addr);
        Ok(())
    }

    fn poll(&mut self, timeout_ms: u32) -> Result<Event> {
        let mut event = DEBUG_EVENT::default();
        // SAFETY: `event` is a valid, owned DEBUG_EVENT for the API to fill.
        let r = unsafe { WaitForDebugEventEx(&mut event, timeout_ms) };
        if let Err(e) = r {
            if e.code().0 as u32 & 0xffff == WAIT_TIMEOUT
                || e.code() == windows::core::HRESULT::from_win32(WAIT_TIMEOUT)
            {
                return Ok(Event::Running);
            }
            // A timeout surfaces as this error too; treat any wait error as "still running".
            return Ok(Event::Running);
        }
        self.handle_event(&event)
    }

    fn resume(&mut self) -> Result<()> {
        self.stepped_off_and_continue()
    }

    fn step(&mut self) -> Result<()> {
        self.user_stepping = true;
        if !self.step_off_breakpoint()? {
            self.set_trap_flag(self.current_tid, true)?;
        }
        self.do_continue(DBG_CONTINUE)
    }

    fn request_pause(&mut self) -> Result<()> {
        if self.process.is_invalid() {
            return Ok(());
        }
        // SAFETY: valid process handle; DebugBreakProcess injects a breakpoint thread.
        unsafe { windows::Win32::System::Diagnostics::Debug::DebugBreakProcess(self.process) }
            .map_err(|e| DebugError::Os(e.message()))?;
        self.pause_requested = true;
        Ok(())
    }

    fn registers(&mut self) -> Result<Registers> {
        let ctx = self.get_context(self.current_tid)?;
        Ok(Registers {
            rax: ctx.Rax,
            rbx: ctx.Rbx,
            rcx: ctx.Rcx,
            rdx: ctx.Rdx,
            rsi: ctx.Rsi,
            rdi: ctx.Rdi,
            rbp: ctx.Rbp,
            rsp: ctx.Rsp,
            r8: ctx.R8,
            r9: ctx.R9,
            r10: ctx.R10,
            r11: ctx.R11,
            r12: ctx.R12,
            r13: ctx.R13,
            r14: ctx.R14,
            r15: ctx.R15,
            rip: ctx.Rip,
            rflags: u64::from(ctx.EFlags),
        })
    }

    fn set_register(&mut self, name: &str, value: u64) -> Result<()> {
        let mut ctx = self.get_context(self.current_tid)?;
        match name {
            "rax" => ctx.Rax = value,
            "rbx" => ctx.Rbx = value,
            "rcx" => ctx.Rcx = value,
            "rdx" => ctx.Rdx = value,
            "rsi" => ctx.Rsi = value,
            "rdi" => ctx.Rdi = value,
            "rbp" => ctx.Rbp = value,
            "rsp" => ctx.Rsp = value,
            "r8" => ctx.R8 = value,
            "r9" => ctx.R9 = value,
            "r10" => ctx.R10 = value,
            "r11" => ctx.R11 = value,
            "r12" => ctx.R12 = value,
            "r13" => ctx.R13 = value,
            "r14" => ctx.R14 = value,
            "r15" => ctx.R15 = value,
            "rip" | "pc" => ctx.Rip = value,
            "rflags" | "eflags" => ctx.EFlags = value as u32,
            _ => return Err(DebugError::Os(format!("no register named {name}"))),
        }
        self.set_context(self.current_tid, &ctx)
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        // Show the real instructions, not our 0xCC breakpoint bytes.
        let mut bytes = self.read_raw(addr, len)?;
        for (a, bp) in &self.breakpoints {
            if bp.planted && *a >= addr && (*a - addr) < bytes.len() as u64 {
                bytes[(*a - addr) as usize] = bp.original;
            }
        }
        Ok(bytes)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.write_raw(addr, data)
    }

    fn modules(&self) -> Vec<Module> {
        self.modules.clone()
    }

    fn image_base(&self) -> Option<u64> {
        self.image_base
    }

    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn kill(&mut self) -> Result<()> {
        if self.process.is_invalid() {
            return Ok(());
        }
        // SAFETY: valid process handle; terminating the debuggee.
        unsafe { TerminateProcess(self.process, 1) }.map_err(|e| DebugError::Os(e.message()))?;
        // Drain the exit event so the OS releases the debug port.
        let _ = self.do_continue(DBG_CONTINUE);
        Ok(())
    }
}

impl WindowsBackend {
    fn stepped_off_and_continue(&mut self) -> Result<()> {
        // If stopped on a breakpoint, single-step off it first (it re-plants itself).
        let _ = self.step_off_breakpoint()?;
        self.do_continue(DBG_CONTINUE)
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        if !self.process.is_invalid() {
            // SAFETY: valid handle; best-effort terminate on teardown.
            unsafe {
                let _ = TerminateProcess(self.process, 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(arg: &str) -> String {
        let mut s = String::new();
        quote_arg(arg, &mut s);
        s
    }

    #[test]
    fn plain_args_are_left_alone() {
        assert_eq!(q("abc"), "abc");
        assert_eq!(q(r"C:\dir\file.txt"), r"C:\dir\file.txt");
        assert_eq!(q(r"a\\b"), r"a\\b");
    }

    #[test]
    fn spaces_and_empty_args_are_quoted() {
        assert_eq!(q(""), r#""""#);
        assert_eq!(q("hello world"), r#""hello world""#);
        assert_eq!(q("tab\there"), "\"tab\there\"");
    }

    #[test]
    fn quotes_and_backslashes_follow_msvcrt_rules() {
        // A quote is escaped; backslashes before it are doubled, plus one for the quote.
        assert_eq!(q(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(q(r#"a\"b"#), r#""a\\\"b""#);
        // Backslashes not followed by a quote stay literal...
        assert_eq!(q(r"C:\Program Files\x"), r#""C:\Program Files\x""#);
        // ...except before the closing quote, where they are doubled.
        assert_eq!(q(r"C:\Program Files\"), r#""C:\Program Files\\""#);
    }

    #[test]
    fn command_line_quotes_each_argument() {
        let cmd = command_line(
            Path::new(r"C:\t\a.exe"),
            &["x y".to_string(), "z".to_string()],
        );
        let s = String::from_utf16_lossy(&cmd[..cmd.len() - 1]);
        assert_eq!(s, r#""C:\t\a.exe" "x y" z"#);
    }
}
