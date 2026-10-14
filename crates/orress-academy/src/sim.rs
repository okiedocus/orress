//! A tiny x86-64 CPU simulator for lessons.
//!
//! It runs assembly text directly (no machine code), one instruction per line, so
//! learners can type a few instructions and watch registers, flags and the stack
//! change step by step. It supports the instructions the early lessons need, with
//! Intel syntax as shown in ORRESS's disassembly:
//!
//! ```text
//! start:
//!     mov rax, 5          ; comments start with ;
//!     add rax, 0x10
//!     cmp rax, 21
//!     je done
//!     push rax
//!     call double
//! done:
//!     ret
//! double:
//!     add rax, rax
//!     ret
//! ```

use std::collections::{BTreeSet, HashMap};

pub const REGS: [&str; 16] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const RSP: usize = 7;
/// The stack lives at the top of this small memory region.
pub const STACK_BASE: u64 = 0x7fff_f000;
pub const STACK_SIZE: u64 = 0x1000;
pub const STACK_TOP: u64 = STACK_BASE + STACK_SIZE;
/// Return address pushed for the outermost `ret`: returning there ends the program.
const EXIT_ADDRESS: u64 = 0xdead_0000;
const MAX_STEPS: usize = 10_000;
const MAX_HISTORY: usize = 2_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Q,
    D,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Reg(usize, Width),
    Imm(i64),
    /// `[reg + disp]`
    Mem {
        base: usize,
        disp: i64,
    },
    Label(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instr {
    pub line: usize,
    pub op: String,
    pub args: Vec<Operand>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// Zero flag: the result was 0 (after cmp: the values were equal).
    pub zf: bool,
    /// Sign flag: the result was negative (top bit set).
    pub sf: bool,
    /// Carry flag: unsigned overflow / borrow (after cmp: first < second, unsigned).
    pub cf: bool,
    /// Overflow flag: signed overflow.
    pub of: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

#[derive(Clone)]
struct Snapshot {
    regs: [u64; 16],
    flags: Flags,
    stack: Vec<u8>,
    pc: usize,
    halted: Option<String>,
    steps: usize,
}

#[derive(Clone)]
pub struct Cpu {
    pub regs: [u64; 16],
    pub flags: Flags,
    pub stack: Vec<u8>,
    program: Vec<Instr>,
    labels: HashMap<String, usize>,
    /// Index into `program` of the next instruction.
    pub pc: usize,
    /// Why the program stopped (`Some` once finished or failed).
    pub halted: Option<String>,
    pub error: bool,
    pub steps: usize,
    /// Registers written by the last step, for highlighting.
    pub changed: BTreeSet<usize>,
    history: Vec<Snapshot>,
}

const MNEMONICS: &[&str] = &[
    "mov", "add", "sub", "inc", "dec", "neg", "imul", "xor", "and", "or", "not", "shl", "shr",
    "cmp", "test", "lea", "push", "pop", "call", "ret", "jmp", "je", "jz", "jne", "jnz", "jg",
    "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "js", "jns", "nop", "hlt",
];

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, &cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

fn parse_number(text: &str) -> Option<i64> {
    let t = text.trim();
    if let Some(c) = t.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        let mut chars = c.chars();
        let ch = chars.next()?;
        return chars.next().is_none().then_some(ch as i64);
    }
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let value = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()? as i64
    } else if let Some(hex) = t
        .strip_suffix('h')
        .filter(|h| h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        u64::from_str_radix(hex, 16).ok()? as i64
    } else if let Some(bin) = t.strip_prefix("0b") {
        u64::from_str_radix(bin, 2).ok()? as i64
    } else {
        t.parse::<i64>().ok()?
    };
    Some(if neg { value.wrapping_neg() } else { value })
}

fn parse_register(name: &str) -> Option<(usize, Width)> {
    if let Some(i) = REGS.iter().position(|r| *r == name) {
        return Some((i, Width::Q));
    }
    let d = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    d.iter().position(|r| *r == name).map(|i| (i, Width::D))
}

fn parse_operand(text: &str, line: usize) -> Result<Operand, ParseError> {
    let t = text.trim();
    let err = |message: String| ParseError { line, message };
    let t = t
        .strip_prefix("qword ptr")
        .or_else(|| t.strip_prefix("qword"))
        .map_or(t, str::trim);
    if let Some(inner) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let inner = inner.replace(' ', "");
        let (reg, disp) = match inner.find(['+', '-']) {
            Some(i) => {
                let disp = parse_number(&inner[i..].replace('+', ""))
                    .ok_or_else(|| err(format!("`{}` is not a number", &inner[i..])))?;
                (&inner[..i], disp)
            }
            None => (inner.as_str(), 0),
        };
        let (base, width) =
            parse_register(reg).ok_or_else(|| err(format!("`{reg}` is not a register")))?;
        if width != Width::Q {
            return Err(err(
                "memory addresses need a 64-bit register, like [rsp+8]".into()
            ));
        }
        return Ok(Operand::Mem { base, disp });
    }
    if let Some((r, w)) = parse_register(&t.to_ascii_lowercase()) {
        return Ok(Operand::Reg(r, w));
    }
    if let Some(n) = parse_number(t) {
        return Ok(Operand::Imm(n));
    }
    if t.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && !t.is_empty()
    {
        return Ok(Operand::Label(t.to_owned()));
    }
    Err(err(format!("cannot understand `{t}`")))
}

pub fn parse(source: &str) -> Result<(Vec<Instr>, HashMap<String, usize>), ParseError> {
    let mut program = Vec::new();
    let mut labels = HashMap::new();
    for (index, raw) in source.lines().enumerate() {
        let line = index + 1;
        let mut text = raw.split(';').next().unwrap_or("").trim();
        if let Some((label, rest)) = text.split_once(':')
            && !label.contains(' ')
            && !label.contains('[')
        {
            if labels
                .insert(label.trim().to_owned(), program.len())
                .is_some()
            {
                return Err(ParseError {
                    line,
                    message: format!("the label `{label}` is defined twice"),
                });
            }
            text = rest.trim();
        }
        if text.is_empty() {
            continue;
        }
        let (op, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
        let op = op.to_ascii_lowercase();
        if !MNEMONICS.contains(&op.as_str()) {
            let suggestion = MNEMONICS
                .iter()
                .min_by_key(|m| edit_distance(&op, m))
                .filter(|m| edit_distance(&op, m) <= 2)
                .map(|m| format!(" Did you mean `{m}`?"))
                .unwrap_or_default();
            return Err(ParseError {
                line,
                message: format!("`{op}` is not an instruction this simulator knows.{suggestion}"),
            });
        }
        let args = if rest.trim().is_empty() {
            Vec::new()
        } else {
            rest.split(',')
                .map(|a| parse_operand(a, line))
                .collect::<Result<_, _>>()?
        };
        let expected = match op.as_str() {
            "ret" | "nop" | "hlt" => 0..=0,
            "inc" | "dec" | "neg" | "not" | "push" | "pop" | "call" | "jmp" | "je" | "jz"
            | "jne" | "jnz" | "jg" | "jge" | "jl" | "jle" | "ja" | "jae" | "jb" | "jbe" | "js"
            | "jns" => 1..=1,
            _ => 2..=2,
        };
        if !expected.contains(&args.len()) {
            return Err(ParseError {
                line,
                message: format!(
                    "`{op}` takes {} operand{}, found {}",
                    expected.start(),
                    if *expected.start() == 1 { "" } else { "s" },
                    args.len()
                ),
            });
        }
        program.push(Instr { line, op, args });
    }
    for instr in &program {
        for arg in &instr.args {
            if let Operand::Label(l) = arg
                && !labels.contains_key(l)
            {
                return Err(ParseError {
                    line: instr.line,
                    message: format!("there is no label called `{l}`"),
                });
            }
        }
    }
    Ok((program, labels))
}

impl Cpu {
    pub fn new(source: &str) -> Result<Self, ParseError> {
        let (program, labels) = parse(source)?;
        let mut cpu = Self {
            regs: [0; 16],
            flags: Flags::default(),
            stack: vec![0; STACK_SIZE as usize],
            program,
            labels,
            pc: 0,
            halted: None,
            error: false,
            steps: 0,
            changed: BTreeSet::new(),
            history: Vec::new(),
        };
        cpu.regs[RSP] = STACK_TOP;
        // The outermost `ret` returns to this address, which ends the program.
        cpu.regs[RSP] -= 8;
        cpu.write_mem(cpu.regs[RSP], EXIT_ADDRESS)
            .expect("stack top is valid");
        if cpu.program.is_empty() {
            cpu.halted = Some("The program is empty. Type some instructions.".into());
        }
        Ok(cpu)
    }

    pub fn line(&self) -> Option<usize> {
        self.program.get(self.pc).map(|i| i.line)
    }

    pub fn instructions(&self) -> &[Instr] {
        &self.program
    }

    pub fn reg(&self, name: &str) -> Option<u64> {
        REGS.iter().position(|r| *r == name).map(|i| self.regs[i])
    }

    pub fn read_mem(&self, addr: u64) -> Result<u64, String> {
        if !(STACK_BASE..=STACK_TOP - 8).contains(&addr) {
            return Err(format!(
                "memory address 0x{addr:x} is outside the stack (0x{STACK_BASE:x}–0x{STACK_TOP:x})"
            ));
        }
        let i = (addr - STACK_BASE) as usize;
        Ok(u64::from_le_bytes(
            self.stack[i..i + 8].try_into().expect("8 bytes"),
        ))
    }

    fn write_mem(&mut self, addr: u64, value: u64) -> Result<(), String> {
        self.read_mem(addr)?;
        let i = (addr - STACK_BASE) as usize;
        self.stack[i..i + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn get(&self, op: &Operand) -> Result<u64, String> {
        match op {
            Operand::Reg(r, Width::Q) => Ok(self.regs[*r]),
            Operand::Reg(r, Width::D) => Ok(self.regs[*r] & 0xffff_ffff),
            Operand::Imm(v) => Ok(*v as u64),
            Operand::Mem { base, disp } => {
                self.read_mem(self.regs[*base].wrapping_add_signed(*disp))
            }
            Operand::Label(l) => Err(format!("`{l}` is a label, not a value")),
        }
    }

    fn set(&mut self, op: &Operand, value: u64) -> Result<(), String> {
        match op {
            Operand::Reg(r, w) => {
                // Writing a 32-bit register clears the upper half, like on a real CPU.
                self.regs[*r] = if *w == Width::D {
                    value & 0xffff_ffff
                } else {
                    value
                };
                self.changed.insert(*r);
                Ok(())
            }
            Operand::Mem { base, disp } => {
                self.write_mem(self.regs[*base].wrapping_add_signed(*disp), value)
            }
            Operand::Imm(_) => Err(
                "cannot write to a number; the first operand must be a register or memory".into(),
            ),
            Operand::Label(_) => Err("cannot write to a label".into()),
        }
    }

    fn set_logic_flags(&mut self, result: u64) {
        self.flags = Flags {
            zf: result == 0,
            sf: (result as i64) < 0,
            cf: false,
            of: false,
        };
    }

    fn set_sub_flags(&mut self, a: u64, b: u64) -> u64 {
        let (result, borrow) = a.overflowing_sub(b);
        let (_, overflow) = (a as i64).overflowing_sub(b as i64);
        self.flags = Flags {
            zf: result == 0,
            sf: (result as i64) < 0,
            cf: borrow,
            of: overflow,
        };
        result
    }

    fn set_add_flags(&mut self, a: u64, b: u64) -> u64 {
        let (result, carry) = a.overflowing_add(b);
        let (_, overflow) = (a as i64).overflowing_add(b as i64);
        self.flags = Flags {
            zf: result == 0,
            sf: (result as i64) < 0,
            cf: carry,
            of: overflow,
        };
        result
    }

    fn condition(&self, op: &str) -> bool {
        let f = self.flags;
        match op {
            "je" | "jz" => f.zf,
            "jne" | "jnz" => !f.zf,
            "jg" => !f.zf && f.sf == f.of,
            "jge" => f.sf == f.of,
            "jl" => f.sf != f.of,
            "jle" => f.zf || f.sf != f.of,
            "ja" => !f.cf && !f.zf,
            "jae" => !f.cf,
            "jb" => f.cf,
            "jbe" => f.cf || f.zf,
            "js" => f.sf,
            "jns" => !f.sf,
            _ => true,
        }
    }

    fn label_target(&self, op: &Operand) -> Result<usize, String> {
        match op {
            Operand::Label(l) => self
                .labels
                .get(l)
                .copied()
                .ok_or_else(|| format!("no label `{l}`")),
            _ => Err("jumps and calls need a label, like `jmp loop`".into()),
        }
    }

    /// Executes one instruction. Returns `false` once the program has stopped.
    pub fn step(&mut self) -> bool {
        if self.halted.is_some() {
            return false;
        }
        if self.history.len() >= MAX_HISTORY {
            self.history.remove(0);
        }
        self.history.push(Snapshot {
            regs: self.regs,
            flags: self.flags,
            stack: self.stack.clone(),
            pc: self.pc,
            halted: self.halted.clone(),
            steps: self.steps,
        });
        self.changed.clear();
        let Some(instr) = self.program.get(self.pc).cloned() else {
            self.halted = Some("Reached the end of the program.".into());
            return false;
        };
        self.steps += 1;
        if let Err(message) = self.execute(&instr) {
            self.halted = Some(format!("Line {}: {message}", instr.line));
            self.error = true;
            return false;
        }
        if self.halted.is_none() && self.steps >= MAX_STEPS {
            self.halted = Some(format!(
                "Stopped after {MAX_STEPS} steps. Is there a loop that never ends?"
            ));
            self.error = true;
        }
        if self.halted.is_none() && self.pc >= self.program.len() {
            self.halted = Some("Reached the end of the program.".into());
        }
        self.halted.is_none()
    }

    fn execute(&mut self, instr: &Instr) -> Result<(), String> {
        let a = instr.args.first();
        let b = instr.args.get(1);
        let mut next = self.pc + 1;
        match instr.op.as_str() {
            "mov" => {
                let v = self.get(b.expect("2 args"))?;
                self.set(a.expect("2 args"), v)?;
            }
            "lea" => {
                let Some(Operand::Mem { base, disp }) = b else {
                    return Err("lea needs a memory operand like [rbp-8]".into());
                };
                let v = self.regs[*base].wrapping_add_signed(*disp);
                self.set(a.expect("2 args"), v)?;
            }
            "add" => {
                let (x, y) = (self.get(a.expect("args"))?, self.get(b.expect("args"))?);
                let r = self.set_add_flags(x, y);
                self.set(a.expect("args"), r)?;
            }
            "sub" => {
                let (x, y) = (self.get(a.expect("args"))?, self.get(b.expect("args"))?);
                let r = self.set_sub_flags(x, y);
                self.set(a.expect("args"), r)?;
            }
            "cmp" => {
                let (x, y) = (self.get(a.expect("args"))?, self.get(b.expect("args"))?);
                self.set_sub_flags(x, y);
            }
            "inc" | "dec" => {
                let x = self.get(a.expect("arg"))?;
                let carry = self.flags.cf; // inc/dec leave CF alone
                let r = if instr.op == "inc" {
                    self.set_add_flags(x, 1)
                } else {
                    self.set_sub_flags(x, 1)
                };
                self.flags.cf = carry;
                self.set(a.expect("arg"), r)?;
            }
            "neg" => {
                let x = self.get(a.expect("arg"))?;
                let r = self.set_sub_flags(0, x);
                self.set(a.expect("arg"), r)?;
            }
            "imul" => {
                let (x, y) = (self.get(a.expect("args"))?, self.get(b.expect("args"))?);
                let (r, overflow) = (x as i64).overflowing_mul(y as i64);
                self.set_logic_flags(r as u64);
                self.flags.of = overflow;
                self.flags.cf = overflow;
                self.set(a.expect("args"), r as u64)?;
            }
            "xor" | "and" | "or" | "test" => {
                let (x, y) = (self.get(a.expect("args"))?, self.get(b.expect("args"))?);
                let r = match instr.op.as_str() {
                    "xor" => x ^ y,
                    "or" => x | y,
                    _ => x & y,
                };
                self.set_logic_flags(r);
                if instr.op != "test" {
                    self.set(a.expect("args"), r)?;
                }
            }
            "not" => {
                let x = self.get(a.expect("arg"))?;
                self.set(a.expect("arg"), !x)?;
            }
            "shl" | "shr" => {
                let x = self.get(a.expect("args"))?;
                let n = (self.get(b.expect("args"))? & 63) as u32;
                let r = if instr.op == "shl" { x << n } else { x >> n };
                self.set_logic_flags(r);
                self.set(a.expect("args"), r)?;
            }
            "push" => {
                let v = self.get(a.expect("arg"))?;
                self.regs[RSP] = self.regs[RSP].wrapping_sub(8);
                self.changed.insert(RSP);
                self.write_mem(self.regs[RSP], v)
                    .map_err(|_| "stack overflow: too many pushes".to_owned())?;
            }
            "pop" => {
                let v = self
                    .read_mem(self.regs[RSP])
                    .map_err(|_| "nothing left on the stack to pop".to_owned())?;
                self.regs[RSP] = self.regs[RSP].wrapping_add(8);
                self.changed.insert(RSP);
                self.set(a.expect("arg"), v)?;
            }
            "call" => {
                let target = self.label_target(a.expect("arg"))?;
                self.regs[RSP] = self.regs[RSP].wrapping_sub(8);
                self.changed.insert(RSP);
                // Return "address": the index of the next instruction.
                self.write_mem(self.regs[RSP], next as u64)
                    .map_err(|_| "stack overflow: too many nested calls".to_owned())?;
                next = target;
            }
            "ret" => {
                let ret = self
                    .read_mem(self.regs[RSP])
                    .map_err(|_| "ret with an empty stack".to_owned())?;
                self.regs[RSP] = self.regs[RSP].wrapping_add(8);
                self.changed.insert(RSP);
                if ret == EXIT_ADDRESS {
                    self.halted = Some("The program returned from its last function. Done!".into());
                } else if (ret as usize) <= self.program.len() {
                    next = ret as usize;
                } else {
                    return Err(format!(
                        "ret jumped to 0x{ret:x}, which is not a return address. Did a push/pop pair not match?"
                    ));
                }
            }
            "jmp" => next = self.label_target(a.expect("arg"))?,
            "nop" => {}
            "hlt" => self.halted = Some("hlt: the program stopped.".into()),
            op => {
                if self.condition(op) {
                    next = self.label_target(a.expect("arg"))?;
                }
            }
        }
        self.pc = next;
        Ok(())
    }

    /// Runs until the program stops.
    pub fn run(&mut self) {
        while self.step() {}
    }

    pub fn can_step_back(&self) -> bool {
        !self.history.is_empty()
    }

    pub fn step_back(&mut self) {
        if let Some(s) = self.history.pop() {
            self.regs = s.regs;
            self.flags = s.flags;
            self.stack = s.stack;
            self.pc = s.pc;
            self.halted = s.halted;
            self.steps = s.steps;
            self.error = false;
            self.changed.clear();
        }
    }

    /// Whether the program uses an instruction (for lesson checks like "use push").
    pub fn uses(&self, mnemonic: &str) -> bool {
        self.program.iter().any(|i| i.op == mnemonic)
    }

    /// Finished normally (not stopped by an error).
    pub fn finished_ok(&self) -> bool {
        self.halted.is_some() && !self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> Cpu {
        let mut cpu = Cpu::new(src).unwrap();
        cpu.run();
        cpu
    }

    #[test]
    fn arithmetic_and_flags() {
        let cpu = run("mov rax, 10\nadd rax, 20\nsub rax, 5\ncmp rax, 25");
        assert_eq!(cpu.reg("rax"), Some(25));
        assert!(cpu.flags.zf);
        assert!(cpu.finished_ok());
        let cpu = run("mov rax, 1\nsub rax, 2");
        assert_eq!(cpu.reg("rax"), Some(u64::MAX));
        assert!(cpu.flags.sf && cpu.flags.cf);
    }

    #[test]
    fn numbers_in_many_forms() {
        let cpu = run("mov rax, 0x10\nmov rbx, 10h\nmov rcx, 0b101\nmov rdx, 'A'\nmov rsi, -1");
        assert_eq!(cpu.reg("rax"), Some(16));
        assert_eq!(cpu.reg("rbx"), Some(16));
        assert_eq!(cpu.reg("rcx"), Some(5));
        assert_eq!(cpu.reg("rdx"), Some(65));
        assert_eq!(cpu.reg("rsi"), Some(u64::MAX));
    }

    #[test]
    fn loop_sums_one_to_five() {
        let cpu = run(
            "    xor rax, rax\n    mov rcx, 1\nloop:\n    add rax, rcx\n    inc rcx\n    cmp rcx, 6\n    jne loop\n",
        );
        assert_eq!(cpu.reg("rax"), Some(15));
    }

    #[test]
    fn stack_swap_and_calls() {
        let cpu = run("mov rax, 1\nmov rbx, 2\npush rax\npush rbx\npop rax\npop rbx");
        assert_eq!((cpu.reg("rax"), cpu.reg("rbx")), (Some(2), Some(1)));
        assert_eq!(cpu.reg("rsp"), Some(STACK_TOP - 8));

        let cpu = run("mov rax, 3\ncall double\nret\ndouble:\n  add rax, rax\n  ret");
        assert_eq!(cpu.reg("rax"), Some(6));
        assert!(cpu.halted.as_deref().unwrap().contains("Done"));
    }

    #[test]
    fn memory_operands_and_lea() {
        let cpu = run("sub rsp, 16\nmov qword ptr [rsp+8], 42\nmov rax, [rsp+8]\nlea rbx, [rsp+8]");
        assert_eq!(cpu.reg("rax"), Some(42));
        assert_eq!(cpu.reg("rbx"), Some(STACK_TOP - 8 - 16 + 8));
    }

    #[test]
    fn thirty_two_bit_writes_clear_upper_half() {
        let cpu = run("mov rax, -1\nmov eax, 5");
        assert_eq!(cpu.reg("rax"), Some(5));
    }

    #[test]
    fn signed_and_unsigned_jumps() {
        let cpu = run("mov rax, -1\ncmp rax, 1\njl less\nmov rbx, 1\nret\nless:\nmov rbx, 2\nret");
        assert_eq!(cpu.reg("rbx"), Some(2), "-1 < 1 signed");
        let cpu =
            run("mov rax, -1\ncmp rax, 1\nja above\nmov rbx, 1\nret\nabove:\nmov rbx, 2\nret");
        assert_eq!(cpu.reg("rbx"), Some(2), "0xffff... > 1 unsigned");
    }

    #[test]
    fn friendly_errors() {
        let e = Cpu::new("mvo rax, 1").err().unwrap();
        assert!(e.message.contains("Did you mean `mov`"), "{}", e.message);
        assert_eq!(e.line, 1);
        assert!(
            Cpu::new("jmp nowhere")
                .err()
                .unwrap()
                .message
                .contains("no label")
        );
        assert!(
            Cpu::new("add rax")
                .err()
                .unwrap()
                .message
                .contains("2 operands")
        );
        let cpu = run("pop rax\npop rax");
        assert!(cpu.error, "second pop has nothing to pop");
        let cpu = run("x:\njmp x");
        assert!(cpu.error && cpu.halted.unwrap().contains("never ends"));
    }

    #[test]
    fn step_back_restores_state() {
        let mut cpu = Cpu::new("mov rax, 1\nadd rax, 1").unwrap();
        cpu.step();
        cpu.step();
        assert_eq!(cpu.reg("rax"), Some(2));
        cpu.step_back();
        assert_eq!(cpu.reg("rax"), Some(1));
        assert_eq!(cpu.line(), Some(2));
    }
}
