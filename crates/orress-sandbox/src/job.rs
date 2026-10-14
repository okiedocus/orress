//! Windows Job Objects, so a sample's whole process tree can be contained and killed. The rest
//! of this crate forbids `unsafe`; this module is the one place that opts in, because Job
//! Objects are only reachable through raw Win32 FFI. Every call documents why it is sound.

#![allow(unsafe_code)]

use std::os::windows::io::AsRawHandle;
use std::process::Child;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};
use windows::core::PCWSTR;

/// `CREATE_SUSPENDED`, for `CommandExt::creation_flags`.
pub const CREATE_SUSPENDED: u32 = 0x0000_0004;

/// An anonymous job object that kills every process in it when terminated or closed.
pub struct Job(HANDLE);

// The handle is a plain kernel object handle; using it from another thread is fine.
unsafe impl Send for Job {}

impl Job {
    /// Creates a kill-on-close job, or `None` if the OS refuses.
    pub fn new() -> Option<Job> {
        // SAFETY: default security, no name; the returned handle is owned by `Job`.
        let h = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.ok()?;
        let job = Job(h);
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is a correctly sized, initialized extended-limit struct for this
        // information class, and outlives the call.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .ok()?;
        Some(job)
    }

    /// Puts `child` (and, from now on, everything it spawns) into the job.
    pub fn assign(&self, child: &Child) -> bool {
        let process = HANDLE(child.as_raw_handle());
        // SAFETY: both handles are live: the job is owned by `self`, the process by `child`.
        unsafe { AssignProcessToJobObject(self.0, process) }.is_ok()
    }

    /// Kills every process in the job.
    pub fn terminate(&self) {
        // SAFETY: `self.0` is a live job handle.
        unsafe {
            let _ = TerminateJobObject(self.0, 1);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: closing the handle we own, exactly once. KILL_ON_JOB_CLOSE then ends any
        // process still in the job.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Resumes every thread of a process started with `CREATE_SUSPENDED` (std's `Child` doesn't
/// expose the primary thread handle, so find its threads by snapshot).
pub fn resume_process(pid: u32) {
    // SAFETY: a thread snapshot of the whole system; the handle is closed below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }) else {
        return;
    };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    // SAFETY: `snap` is a live snapshot handle and `entry` has `dwSize` set as required.
    let mut more = unsafe { Thread32First(snap, &mut entry) }.is_ok();
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: opening a thread of our own child just to resume it; the handle is
            // closed right after.
            if let Ok(t) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) } {
                // SAFETY: `t` is the live thread handle just opened; closed exactly once.
                unsafe {
                    ResumeThread(t);
                    let _ = CloseHandle(t);
                }
            }
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snap, &mut entry) }.is_ok();
    }
    // SAFETY: closing the snapshot handle we own, exactly once.
    unsafe {
        let _ = CloseHandle(snap);
    }
}
