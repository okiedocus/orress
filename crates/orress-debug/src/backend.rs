//! The platform-agnostic debugger back end: the small set of primitives every target
//! (a native Windows process now; ptrace and GDB-remote later) must provide. The
//! controller in `lib.rs` drives one of these on its own thread.

use std::fmt;

use crate::regs::Registers;

pub type Result<T> = std::result::Result<T, DebugError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugError {
    /// This platform has no native debugger yet.
    Unsupported(&'static str),
    /// The target is not running (already exited, or never launched).
    NotRunning,
    /// The program file could not be started.
    Launch(String),
    /// An OS call failed, with its message.
    Os(String),
}

impl fmt::Display for DebugError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(p) => write!(f, "debugging is not supported on {p} yet"),
            Self::NotRunning => write!(f, "the program is not running"),
            Self::Launch(e) => write!(f, "could not start the program: {e}"),
            Self::Os(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DebugError {}

/// A loaded module (the executable or a DLL / shared object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub base: u64,
}

/// Why the target stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Hit a breakpoint the user set, at this address.
    Breakpoint(u64),
    /// Completed a single instruction step.
    Step,
    /// Paused by the user.
    Paused,
    /// An exception the debugger did not plant (access violation, divide by zero …),
    /// with a plain-language description.
    Exception {
        code: u32,
        address: u64,
        text: String,
    },
    /// The process exited with this code.
    Exited(i32),
}

impl StopReason {
    /// A short, friendly description for the status line.
    pub fn summary(&self) -> String {
        match self {
            Self::Breakpoint(a) => format!("stopped at breakpoint 0x{a:x}"),
            Self::Step => "stepped one instruction".into(),
            Self::Paused => "paused".into(),
            Self::Exception { text, address, .. } => format!("{text} at 0x{address:x}"),
            Self::Exited(code) => format!("the program exited (code {code})"),
        }
    }

    pub fn is_exit(&self) -> bool {
        matches!(self, Self::Exited(_))
    }
}

/// What a back end's `poll` produced.
pub enum Event {
    /// The target stopped and is ready for inspection.
    Stopped(StopReason),
    /// The target is still running; nothing to report yet.
    Running,
}

/// The primitives a debugger back end provides. Every method is called only from the
/// controller thread, so implementations need not be `Sync`.
pub trait Backend {
    /// Plants a software breakpoint. It takes effect on the next resume.
    fn add_breakpoint(&mut self, addr: u64) -> Result<()>;
    /// Removes a software breakpoint.
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()>;
    /// Advances the OS debug loop, waiting up to `timeout_ms`. Returns `Running` if the
    /// target is still going, or `Stopped` with the reason.
    fn poll(&mut self, timeout_ms: u32) -> Result<Event>;
    /// Lets the target run until the next event.
    fn resume(&mut self) -> Result<()>;
    /// Executes a single instruction, then stops.
    fn step(&mut self) -> Result<()>;
    /// Asks a running target to stop as soon as possible.
    fn request_pause(&mut self) -> Result<()>;
    fn registers(&mut self) -> Result<Registers>;
    fn set_register(&mut self, name: &str, value: u64) -> Result<()>;
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()>;
    fn modules(&self) -> Vec<Module>;
    /// The base address the main executable was loaded at, once known.
    fn image_base(&self) -> Option<u64>;
    /// The target process id, for pid-based memory reads (`None` for back ends without one).
    fn pid(&self) -> Option<u32> {
        None
    }
    /// Terminates the target.
    fn kill(&mut self) -> Result<()>;
}

/// The back end used on platforms without native debugging yet. Every call fails with a
/// clear message so the UI can explain the situation.
pub struct Unsupported(pub &'static str);

impl Backend for Unsupported {
    fn add_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn poll(&mut self, _timeout_ms: u32) -> Result<Event> {
        Err(DebugError::Unsupported(self.0))
    }
    fn resume(&mut self) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn step(&mut self) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn request_pause(&mut self) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn registers(&mut self) -> Result<Registers> {
        Err(DebugError::Unsupported(self.0))
    }
    fn set_register(&mut self, _name: &str, _value: u64) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn read_memory(&mut self, _addr: u64, _len: usize) -> Result<Vec<u8>> {
        Err(DebugError::Unsupported(self.0))
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
    fn modules(&self) -> Vec<Module> {
        Vec::new()
    }
    fn image_base(&self) -> Option<u64> {
        None
    }
    fn kill(&mut self) -> Result<()> {
        Err(DebugError::Unsupported(self.0))
    }
}
