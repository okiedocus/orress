//! A fake target for tests and for platforms without a native back end. It "runs" a
//! scripted trace of addresses, so the controller's breakpoint, step and continue logic
//! can be tested deterministically on any OS.

use std::collections::{BTreeMap, HashSet};

use crate::backend::{Backend, DebugError, Event, Module, Result, StopReason};
use crate::regs::Registers;

pub struct MockTarget {
    /// The instruction addresses the program executes, in order.
    trace: Vec<u64>,
    /// How far through `trace` we are.
    pc: usize,
    exit_code: i32,
    breakpoints: HashSet<u64>,
    memory: BTreeMap<u64, u8>,
    regs: Registers,
    running: bool,
    step_mode: bool,
    started: bool,
    exited: bool,
}

impl MockTarget {
    /// A target that will execute `trace` and then exit with `exit_code`.
    pub fn new(trace: Vec<u64>, exit_code: i32) -> Self {
        let rip = trace.first().copied().unwrap_or(0);
        Self {
            trace,
            pc: 0,
            exit_code,
            breakpoints: HashSet::new(),
            memory: BTreeMap::new(),
            regs: Registers {
                rip,
                rsp: 0x7000,
                ..Registers::default()
            },
            running: false,
            step_mode: false,
            started: false,
            exited: false,
        }
    }

    fn at_end(&self) -> bool {
        self.pc >= self.trace.len()
    }

    /// Advances one step of the trace, updating rip. Returns the new stop, if any.
    fn advance(&mut self, honor_breakpoints: bool) -> StopReason {
        loop {
            if self.at_end() {
                self.exited = true;
                return StopReason::Exited(self.exit_code);
            }
            self.pc += 1;
            if self.at_end() {
                self.exited = true;
                return StopReason::Exited(self.exit_code);
            }
            let addr = self.trace[self.pc];
            self.regs.rip = addr;
            // rax counts instructions executed, so tests can read a changing register.
            self.regs.rax = self.pc as u64;
            if honor_breakpoints && self.breakpoints.contains(&addr) {
                return StopReason::Breakpoint(addr);
            }
            if !honor_breakpoints {
                return StopReason::Step;
            }
        }
    }
}

impl Backend for MockTarget {
    fn add_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.breakpoints.insert(addr);
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.breakpoints.remove(&addr);
        Ok(())
    }

    fn poll(&mut self, _timeout_ms: u32) -> Result<Event> {
        if !self.started {
            // Like a real target that the loader leaves stopped at its entry.
            self.started = true;
            return Ok(Event::Stopped(StopReason::Step));
        }
        if !self.running {
            return Ok(Event::Running);
        }
        self.running = false;
        let reason = if self.step_mode {
            self.advance(false)
        } else {
            self.advance(true)
        };
        Ok(Event::Stopped(reason))
    }

    fn resume(&mut self) -> Result<()> {
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        self.running = true;
        self.step_mode = false;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        if self.exited {
            return Err(DebugError::NotRunning);
        }
        self.running = true;
        self.step_mode = true;
        Ok(())
    }

    fn request_pause(&mut self) -> Result<()> {
        Ok(())
    }

    fn registers(&mut self) -> Result<Registers> {
        Ok(self.regs)
    }

    fn set_register(&mut self, name: &str, value: u64) -> Result<()> {
        if self.regs.set(name, value) {
            Ok(())
        } else {
            Err(DebugError::Os(format!("no register named {name}")))
        }
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        Ok((0..len as u64)
            .map(|i| self.memory.get(&(addr + i)).copied().unwrap_or(0))
            .collect())
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        for (i, b) in data.iter().enumerate() {
            self.memory.insert(addr + i as u64, *b);
        }
        Ok(())
    }

    fn modules(&self) -> Vec<Module> {
        vec![Module {
            name: "mock.exe".into(),
            base: 0x1000,
        }]
    }

    fn image_base(&self) -> Option<u64> {
        Some(0x1000)
    }

    fn kill(&mut self) -> Result<()> {
        self.exited = true;
        self.running = false;
        Ok(())
    }
}
