//! A CFG-directed symbolic executor over the emulator's instruction subset. Input-buffer bytes
//! are symbolic variables; registers hold symbolic expressions; addresses and loop counters
//! stay concrete (the usual shape of a byte-wise check). At an input-dependent conditional jump
//! it picks the direction toward the target (away from the `avoid` blocks) and records the
//! branch condition as a constraint. When it reaches the target, the collected constraints
//! describe every input that gets there.
//!
//! Soundness over coverage: anything the executor cannot model exactly — an unmodelled
//! instruction that touches symbolic data, a branch on a flag the last instruction left
//! undefined, a read of unmapped memory — stops the run with a [`SymError`] rather than
//! silently producing constraints that don't describe the real program.

use std::collections::HashMap;

use iced_x86::{
    Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register, RflagsBits,
};
use orress_emu::{Abi, Memory};

use crate::cc::Cc;
use crate::expr::{self, Expr, Node, Op, Rel};

/// Why symbolic execution stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymError {
    Unsupported { addr: u64, what: String },
    SymbolicAddress(u64),
    Fault(u64),
    BudgetExhausted,
    HitAvoid(u64),
}

impl std::fmt::Display for SymError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { addr, what } => write!(f, "unsupported {what} at {addr:#x}"),
            Self::SymbolicAddress(a) => write!(f, "symbolic memory address at {a:#x}"),
            Self::Fault(a) => write!(f, "memory fault at {a:#x}"),
            Self::BudgetExhausted => write!(f, "step budget exhausted (wrong path?)"),
            Self::HitAvoid(a) => write!(f, "forced into an avoided block at {a:#x}"),
        }
    }
}

impl std::error::Error for SymError {}

/// Lazily-modelled flags: what the last flag-setting instruction compared or produced.
#[derive(Clone)]
enum Flags {
    /// Unknown: an unmodelled instruction (or one whose flags we don't track, e.g. `imul`,
    /// `rol`) wrote them. Any condition read from here is an error, never a guess.
    None,
    /// A CMP/SUB/NEG of (a, b) at `w` bits — gives exact signed/unsigned relations.
    Cmp(Expr, Expr, u32),
    /// A result `r` at `w` bits (ZF/SF/PF derive from it) plus CF and OF as boolean
    /// expressions, `None` where the instruction leaves the flag undefined or unmodelled.
    Res {
        r: Expr,
        w: u32,
        cf: Option<Expr>,
        of: Option<Expr>,
    },
}

const SENTINEL: u64 = 0x1337_0000_0000_0000;
/// Where the symbolic `malloc` model hands out memory (far from images, stacks and inputs).
const HEAP_BASE: u64 = 0x5000_0000_0000;
/// Upper bound on bytes a modelled libc stub copies/sets/allocates, so a bogus size can't spin.
const STUB_MAX_BYTES: u64 = 1 << 20;
/// Upper bound on a NUL-terminated string a stub walks.
const MAX_CSTR: u64 = 1 << 16;

pub struct SymExec {
    regs: [Expr; 16],
    rip: u64,
    mem: Memory,
    /// Symbolic bytes written to concrete addresses (overrides concrete memory).
    sym_mem: HashMap<u64, Expr>,
    input_base: u64,
    input_len: u32,
    flags: Flags,
    pub constraints: Vec<Expr>,
    target: u64,
    avoid: Vec<u64>,
    budget: u64,
    /// Import stubs (strcmp/memcmp model their comparison symbolically).
    hooks: HashMap<u64, orress_emu::Stub>,
    /// The calling convention of the run (how stubs read their arguments).
    abi: Abi,
    /// The next address the `malloc` model hands out.
    heap: u64,
    /// FS / GS segment bases (the thread block mapped by [`orress_emu::setup_tls`]).
    fs_base: u64,
    gs_base: u64,
}

impl SymExec {
    /// `mem` must already hold the code and any constant data. The input buffer occupies
    /// `[input_base, input_base + input_len)` and reads there yield symbolic variables.
    pub fn new(mem: Memory, input_base: u64, input_len: u32, target: u64, avoid: Vec<u64>) -> Self {
        Self {
            regs: std::array::from_fn(|_| expr::konst(0, 64)),
            rip: 0,
            mem,
            sym_mem: HashMap::new(),
            input_base,
            input_len,
            flags: Flags::None,
            constraints: Vec::new(),
            target,
            avoid,
            budget: 2_000_000,
            hooks: HashMap::new(),
            abi: Abi::SysV,
            heap: HEAP_BASE,
            fs_base: 0,
            gs_base: 0,
        }
    }

    /// Registers import stubs (by the address a call reaches, or the import slot it loads).
    pub fn set_hooks(&mut self, hooks: HashMap<u64, orress_emu::Stub>) {
        self.hooks = hooks;
    }

    fn in_input(&self, addr: u64) -> bool {
        addr >= self.input_base && addr - self.input_base < u64::from(self.input_len)
    }

    /// Whether `addr` holds symbolic data (a stored symbolic byte or an input byte).
    fn is_symbolic_byte(&self, addr: u64) -> bool {
        self.in_input(addr) || self.sym_mem.get(&addr).is_some_and(|e| !e.is_concrete())
    }

    /// Byte-wise equality of `n` bytes at `a` and `b`, as a memcmp-style result expression
    /// (0 when all equal). The input bytes contribute symbolic equalities.
    fn cmp_expr(&self, a: u64, b: u64, n: usize) -> Result<Expr, SymError> {
        let mut all = expr::konst(1, 1);
        for i in 0..n as u64 {
            let eq = expr::rel(
                Rel::Eq,
                self.byte_at(a.wrapping_add(i))?,
                self.byte_at(b.wrapping_add(i))?,
            );
            all = expr::band(all, eq);
        }
        let all = fold(all);
        Ok(fold(expr::ite(all, expr::konst(0, 64), expr::konst(1, 64))))
    }

    /// The NUL-terminated length of whichever of `a`/`b` is the concrete (non-input) string.
    fn concrete_strlen(&self, a: u64, b: u64) -> usize {
        let base = if self.in_input(a) { b } else { a };
        let mut n = 0usize;
        while n < (1 << 16) {
            match self.mem.read_u8(base.wrapping_add(n as u64)) {
                Ok(0) | Err(_) => break,
                Ok(_) => n += 1,
            }
        }
        n
    }

    /// Argument `i` of the current call under the run's ABI.
    fn arg(&self, i: usize) -> Expr {
        self.abi
            .arg_reg(i)
            .map_or_else(|| expr::konst(0, 64), |r| self.reg(r))
    }

    /// Argument `i`, which must be concrete (a pointer or a size).
    fn concrete_arg(&self, i: usize) -> Result<u64, SymError> {
        let e = self.arg(i);
        if e.is_concrete() {
            Ok(e.eval(&[]))
        } else {
            Err(SymError::SymbolicAddress(self.rip))
        }
    }

    /// A concrete stub size, capped so a bogus value can't spin.
    fn stub_size(&self, i: usize, what: &str) -> Result<u64, SymError> {
        let n = self.concrete_arg(i)?;
        if n > STUB_MAX_BYTES {
            return Err(SymError::Unsupported {
                addr: self.rip,
                what: format!("{what} of {n:#x} bytes"),
            });
        }
        Ok(n)
    }

    /// The bytes of the NUL-terminated string at `addr`, *including* the terminator. Symbolic
    /// bytes are taken to be non-NUL (the input model: the input is a C string of exactly
    /// `input_len` non-NUL bytes).
    fn cstr_exprs(&self, addr: u64) -> Result<Vec<Expr>, SymError> {
        let mut out = Vec::new();
        for i in 0..MAX_CSTR {
            let b = self.byte_at(addr.wrapping_add(i))?;
            let end = b.is_concrete() && b.eval(&[]) == 0;
            out.push(b);
            if end {
                return Ok(out);
            }
        }
        Err(SymError::Unsupported {
            addr: self.rip,
            what: "unterminated string in a libc stub".into(),
        })
    }

    /// Applies an import stub symbolically and returns to the caller. Arguments come from the
    /// run's ABI registers and are only demanded concrete where the model needs them to be.
    fn apply_stub_sym(&mut self, stub: &orress_emu::Stub) -> Result<(), SymError> {
        use orress_emu::Stub as S;
        let rax = match stub {
            S::Return(v) => expr::konst(*v, 64),
            S::Strlen => {
                let a = self.concrete_arg(0)?;
                if self.in_input(a) {
                    expr::konst(u64::from(self.input_len) - (a - self.input_base), 64)
                } else {
                    let n = self.cstr_exprs(a)?.len() as u64 - 1;
                    expr::konst(n, 64)
                }
            }
            S::Memcmp | S::Strncmp => {
                let (a, b, n) = (
                    self.concrete_arg(0)?,
                    self.concrete_arg(1)?,
                    self.stub_size(2, "memcmp")?,
                );
                self.cmp_expr(a, b, n as usize)?
            }
            S::Strcmp => {
                let (a, b) = (self.concrete_arg(0)?, self.concrete_arg(1)?);
                let n = self.concrete_strlen(a, b);
                self.cmp_expr(a, b, n)?
            }
            S::Memcpy => {
                let (dst, src) = (self.concrete_arg(0)?, self.concrete_arg(1)?);
                let n = self.stub_size(2, "memcpy")?;
                let bytes = (0..n)
                    .map(|i| self.byte_at(src.wrapping_add(i)))
                    .collect::<Result<Vec<_>, _>>()?;
                for (i, b) in bytes.into_iter().enumerate() {
                    self.sym_mem.insert(dst.wrapping_add(i as u64), b);
                }
                expr::konst(dst, 64)
            }
            S::Strcpy => {
                let (dst, src) = (self.concrete_arg(0)?, self.concrete_arg(1)?);
                for (i, b) in self.cstr_exprs(src)?.into_iter().enumerate() {
                    self.sym_mem.insert(dst.wrapping_add(i as u64), b);
                }
                expr::konst(dst, 64)
            }
            S::Memset => {
                let dst = self.concrete_arg(0)?;
                let c = fold(expr::extract(resize(self.arg(1), 64), 7, 0));
                let n = self.stub_size(2, "memset")?;
                for i in 0..n {
                    self.sym_mem.insert(dst.wrapping_add(i), c.clone());
                }
                expr::konst(dst, 64)
            }
            S::Atoi => {
                let s = self.cstr_exprs(self.concrete_arg(0)?)?;
                if s.iter().any(|b| !b.is_concrete()) {
                    return Err(SymError::Unsupported {
                        addr: self.rip,
                        what: "atoi of symbolic input".into(),
                    });
                }
                let bytes: Vec<u8> = s.iter().map(|b| b.eval(&[]) as u8).collect();
                expr::konst(orress_emu::parse_atoi(&bytes) as u64, 64)
            }
            S::Malloc => {
                let size = self.stub_size(0, "malloc")?.max(1);
                let addr = self.heap;
                self.heap = self.heap.wrapping_add(size).wrapping_add(15) & !15;
                self.mem.map_zeroed(addr, size);
                expr::konst(addr, 64)
            }
        };
        let sp = self.concrete_reg(Register::RSP)?;
        let ret = self.load(sp, 8)?;
        self.set_reg(Register::RSP, expr::konst(sp.wrapping_add(8), 64));
        self.set_reg(Register::RAX, rax);
        self.rip = if ret.is_concrete() {
            ret.eval(&[])
        } else {
            SENTINEL
        };
        Ok(())
    }

    /// Sets up a call `func(args...)` under `abi`, then runs until the target is reached.
    pub fn run_check(&mut self, func: u64, args: &[u64], abi: Abi) -> Result<(), SymError> {
        self.abi = abi;
        for (i, &a) in args.iter().enumerate() {
            if let Some(r) = abi.arg_reg(i) {
                self.set_reg(r, expr::konst(a, 64));
            }
        }
        let top = 0x7fff_0000u64;
        self.mem.map_zeroed(top - 0x10000, 0x10000);
        let (fs, gs) = orress_emu::setup_tls(&mut self.mem);
        self.fs_base = fs;
        self.gs_base = gs;
        let sp = (top - 0x100) & !0xf;
        self.mem.write(sp - 8, SENTINEL, 8).ok();
        self.set_reg(Register::RSP, expr::konst(sp - 8, 64));
        self.rip = func;
        self.run()
    }

    fn run(&mut self) -> Result<(), SymError> {
        for _ in 0..self.budget {
            if self.rip == self.target {
                return Ok(());
            }
            if self.avoid.contains(&self.rip) {
                return Err(SymError::HitAvoid(self.rip));
            }
            if self.rip == SENTINEL {
                // Returned without reaching the target.
                return Ok(());
            }
            self.step()?;
        }
        Err(SymError::BudgetExhausted)
    }

    fn step(&mut self) -> Result<(), SymError> {
        let ip = self.rip;
        let mut buf = [0u8; 16];
        let mut n = 0;
        while n < 16 {
            match self.mem.read_u8(ip.wrapping_add(n as u64)) {
                Ok(b) => {
                    buf[n] = b;
                    n += 1;
                }
                Err(_) => break,
            }
        }
        if n == 0 {
            return Err(SymError::Fault(ip));
        }
        let mut dec = iced_x86::Decoder::with_ip(64, &buf[..n], ip, iced_x86::DecoderOptions::NONE);
        let instr = dec.decode();
        if instr.is_invalid() {
            return Err(SymError::Fault(ip));
        }
        self.rip = instr.next_ip();
        self.exec(&instr)
    }

    // --- memory -----------------------------------------------------------

    /// The byte at `addr`: a stored symbolic byte, an input variable, or concrete memory.
    /// Unmapped memory is a fault (not a silent 0, which would fabricate constraints).
    fn byte_at(&self, addr: u64) -> Result<Expr, SymError> {
        if let Some(e) = self.sym_mem.get(&addr) {
            return Ok(e.clone());
        }
        if self.in_input(addr) {
            return Ok(expr::var((addr - self.input_base) as u32));
        }
        self.mem
            .read_u8(addr)
            .map(|b| expr::konst(u64::from(b), 8))
            .map_err(|_| SymError::Fault(addr))
    }

    fn load(&self, addr: u64, size: usize) -> Result<Expr, SymError> {
        let mut acc = expr::konst(0, (size * 8) as u32);
        for j in 0..size {
            let byte = zext(
                self.byte_at(addr.wrapping_add(j as u64))?,
                (size * 8) as u32,
            );
            let shifted = if j == 0 {
                byte
            } else {
                expr::bin(
                    Op::Shl,
                    byte,
                    expr::konst((8 * j) as u64, (size * 8) as u32),
                )
            };
            acc = expr::bin(Op::Or, acc, shifted);
        }
        Ok(fold(acc))
    }

    fn store(&mut self, addr: u64, val: &Expr, size: usize) {
        for j in 0..size {
            let byte = fold(expr::extract(
                val.clone(),
                (8 * j + 7) as u32,
                (8 * j) as u32,
            ));
            self.sym_mem.insert(addr.wrapping_add(j as u64), byte);
        }
    }

    /// The concrete linear address of a memory operand (fails if it is symbolic), including the
    /// FS/GS segment base.
    fn ea(&self, instr: &Instruction) -> Result<u64, SymError> {
        let seg = match instr.memory_segment() {
            Register::FS => self.fs_base,
            Register::GS => self.gs_base,
            _ => 0,
        };
        Ok(self.offset(instr)?.wrapping_add(seg))
    }

    /// The segment-relative offset of a memory operand — what `lea` computes.
    fn offset(&self, instr: &Instruction) -> Result<u64, SymError> {
        let base = instr.memory_base();
        let disp = instr.memory_displacement64();
        if base == Register::RIP || base == Register::EIP {
            return Ok(disp);
        }
        let mut addr = disp;
        if base != Register::None {
            addr = addr.wrapping_add(self.concrete_reg(base)?);
        }
        let index = instr.memory_index();
        if index != Register::None {
            let scale = u64::from(instr.memory_index_scale());
            addr = addr.wrapping_add(self.concrete_reg(index)?.wrapping_mul(scale));
        }
        Ok(addr)
    }

    /// The concrete value of a register as `UsedMemory::virtual_address` asks for it (segment
    /// registers resolve to their base; vector (VSIB) indexes are not modelled).
    fn addr_reg_value(&self, r: Register, vsib_size: usize) -> Option<u64> {
        match r {
            Register::FS => Some(self.fs_base),
            Register::GS => Some(self.gs_base),
            Register::ES | Register::CS | Register::SS | Register::DS => Some(0),
            _ if vsib_size != 0 => None,
            _ => {
                let e = self.reg(r);
                e.is_concrete().then(|| e.eval(&[]))
            }
        }
    }

    fn concrete_reg(&self, r: Register) -> Result<u64, SymError> {
        let e = self.reg(r);
        if e.is_concrete() {
            Ok(e.eval(&[]))
        } else {
            Err(SymError::SymbolicAddress(self.rip))
        }
    }

    // --- registers --------------------------------------------------------

    fn reg(&self, r: Register) -> Expr {
        if r == Register::RIP || r == Register::EIP {
            return expr::konst(self.rip, 64);
        }
        let Some(idx) = gpr_index(r.full_register()) else {
            return expr::konst(0, 64);
        };
        let cont = self.regs[idx].clone();
        if is_high_byte(r) {
            return fold(expr::extract(cont, 15, 8));
        }
        match r.size() {
            1 => fold(expr::extract(cont, 7, 0)),
            2 => fold(expr::extract(cont, 15, 0)),
            4 => fold(expr::extract(cont, 31, 0)),
            _ => cont,
        }
    }

    fn set_reg(&mut self, r: Register, val: Expr) {
        if r == Register::RIP || r == Register::EIP {
            if val.is_concrete() {
                self.rip = val.eval(&[]);
            }
            return;
        }
        let Some(idx) = gpr_index(r.full_register()) else {
            return;
        };
        let v = resize(val, 64);
        let cont = self.regs[idx].clone();
        let new = if is_high_byte(r) {
            let lo = zext(expr::extract(v, 7, 0), 64);
            let shifted = expr::bin(Op::Shl, lo, expr::konst(8, 64));
            expr::bin(
                Op::Or,
                expr::bin(Op::And, cont, expr::konst(!0xff00u64, 64)),
                shifted,
            )
        } else {
            match r.size() {
                1 => keep_low(cont, v, 0xff, 8),
                2 => keep_low(cont, v, 0xffff, 16),
                4 => zext(expr::extract(v, 31, 0), 64), // 32-bit write zeroes upper 32
                _ => v,
            }
        };
        self.regs[idx] = fold(new);
    }

    // --- operands ---------------------------------------------------------

    fn width_bits(&self, instr: &Instruction) -> u32 {
        (match instr.op0_kind() {
            OpKind::Register => instr.op_register(0).size(),
            OpKind::Memory => instr.memory_size().size(),
            _ => 8,
        } as u32)
            * 8
    }

    fn read_op(&self, instr: &Instruction, i: u32, bits: u32) -> Result<Expr, SymError> {
        Ok(match instr.op_kind(i) {
            OpKind::Register => resize(self.reg(instr.op_register(i)), bits),
            OpKind::Memory => self.load(self.ea(instr)?, (bits / 8) as usize)?,
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                expr::konst(instr.near_branch_target(), 64)
            }
            _ => expr::konst(instr.immediate(i), bits),
        })
    }

    fn write_op(
        &mut self,
        instr: &Instruction,
        i: u32,
        val: Expr,
        bits: u32,
    ) -> Result<(), SymError> {
        match instr.op_kind(i) {
            OpKind::Register => self.set_reg(instr.op_register(i), val),
            OpKind::Memory => {
                let ea = self.ea(instr)?;
                self.store(ea, &val, (bits / 8) as usize);
            }
            _ => {}
        }
        Ok(())
    }

    /// The stub for an indirect `call`/`jmp` through a hooked import slot: `call [IAT slot]`
    /// loads the slot's contents (a hint/name RVA or lazy PLT address in the file image), so
    /// the slot address itself must be matched or the hook never fires.
    fn slot_hook(&self, instr: &Instruction) -> Result<Option<orress_emu::Stub>, SymError> {
        if instr.op0_kind() != OpKind::Memory || self.hooks.is_empty() {
            return Ok(None);
        }
        Ok(self.hooks.get(&self.ea(instr)?).cloned())
    }

    /// Pushes the return address (`self.rip`, already past the call).
    fn push_ret(&mut self) -> Result<(), SymError> {
        let sp = self.concrete_reg(Register::RSP)?.wrapping_sub(8);
        self.store(sp, &expr::konst(self.rip, 64), 8);
        self.set_reg(Register::RSP, expr::konst(sp, 64));
        Ok(())
    }

    // --- dispatch ---------------------------------------------------------

    fn exec(&mut self, instr: &Instruction) -> Result<(), SymError> {
        use Mnemonic as M;
        let bits = self.width_bits(instr);
        let addr = instr.ip();

        if let Some(cc) = crate::cc::jcc(instr.mnemonic()) {
            return self.branch(instr, cc);
        }
        if let Some(cc) = crate::cc::setcc(instr.mnemonic()) {
            let v = zext(self.cond(cc, addr)?, bits);
            return self.write_op(instr, 0, v, bits);
        }

        match instr.mnemonic() {
            M::Mov => {
                let v = self.read_op(instr, 1, bits)?;
                self.write_op(instr, 0, v, bits)?;
            }
            M::Movzx => {
                let sb = self.src_bits(instr);
                let v = zext(self.read_op(instr, 1, sb)?, bits);
                self.write_op(instr, 0, v, bits)?;
            }
            M::Movsx | M::Movsxd => {
                let sb = self.src_bits(instr);
                let v = expr::sext(self.read_op(instr, 1, sb)?, bits);
                self.write_op(instr, 0, v, bits)?;
            }
            M::Lea => {
                let a = self.offset(instr)?;
                self.write_op(instr, 0, expr::konst(a, 64), bits)?;
            }
            M::Add => self.add(instr, bits)?,
            M::Sub => self.sub_like(instr, bits, true)?,
            M::Cmp => self.sub_like(instr, bits, false)?,
            M::Xor => self.logic(instr, bits, Op::Xor)?,
            M::And => self.logic(instr, bits, Op::And)?,
            M::Or => self.logic(instr, bits, Op::Or)?,
            M::Test => {
                let a = self.read_op(instr, 0, bits)?;
                // `test reg, reg` (same register) is just the value — keeps the result simple so
                // a memcmp-style condition stays decomposable.
                let same = instr.op0_kind() == OpKind::Register
                    && instr.op_kind(1) == OpKind::Register
                    && instr.op_register(0) == instr.op_register(1);
                let r = if same {
                    a
                } else {
                    fold(expr::bin(Op::And, a, self.read_op(instr, 1, bits)?))
                };
                self.flags = logic_flags(r, bits);
            }
            M::Not => {
                let a = self.read_op(instr, 0, bits)?;
                self.write_op(instr, 0, fold(expr::not(a)), bits)?;
            }
            M::Neg => {
                // neg a == 0 - a, with exactly SUB's flags (CF = a != 0, OF = a == MIN).
                let a = self.read_op(instr, 0, bits)?;
                let r = fold(expr::neg(a.clone()));
                self.flags = Flags::Cmp(expr::konst(0, bits), a, bits);
                self.write_op(instr, 0, r, bits)?;
            }
            M::Inc => self.incdec(instr, bits, true)?,
            M::Dec => self.incdec(instr, bits, false)?,
            M::Shl | M::Sal => self.shift(instr, bits, Op::Shl)?,
            M::Shr => self.shift(instr, bits, Op::Lshr)?,
            M::Sar => self.shift(instr, bits, Op::Ashr)?,
            M::Rol => self.rotate(instr, bits, true)?,
            M::Ror => self.rotate(instr, bits, false)?,
            M::Imul if instr.op_count() == 2 => {
                let a = self.read_op(instr, 0, bits)?;
                let b = self.read_op(instr, 1, bits)?;
                self.write_op(instr, 0, fold(expr::bin(Op::Mul, a, b)), bits)?;
                self.flags = Flags::None; // CF/OF (overflow) not modelled
            }
            M::Imul if instr.op_count() == 3 => {
                let a = self.read_op(instr, 1, bits)?;
                let b = expr::konst(instr.immediate(2), bits);
                self.write_op(instr, 0, fold(expr::bin(Op::Mul, a, b)), bits)?;
                self.flags = Flags::None;
            }
            M::Cdqe => {
                let v = expr::sext(self.reg(Register::EAX), 64);
                self.set_reg(Register::RAX, v);
            }
            M::Push => {
                let v = self.read_op(instr, 0, 64)?;
                let sp = self.concrete_reg(Register::RSP)?.wrapping_sub(8);
                self.store(sp, &v, 8);
                self.set_reg(Register::RSP, expr::konst(sp, 64));
            }
            M::Pop => {
                let sp = self.concrete_reg(Register::RSP)?;
                let v = self.load(sp, 8)?;
                self.set_reg(Register::RSP, expr::konst(sp.wrapping_add(8), 64));
                self.write_op(instr, 0, v, 64)?;
            }
            M::Call => {
                if let Some(stub) = self.slot_hook(instr)? {
                    // `call [import slot]`: push the return address, then model the import.
                    self.push_ret()?;
                    return self.apply_stub_sym(&stub);
                }
                let target = self.read_op(instr, 0, 64)?;
                if !target.is_concrete() {
                    return Err(SymError::SymbolicAddress(addr));
                }
                let t = target.eval(&[]);
                self.push_ret()?;
                if let Some(stub) = self.hooks.get(&t).cloned() {
                    // A direct call to a hooked thunk: model the import's effect symbolically.
                    return self.apply_stub_sym(&stub);
                }
                self.rip = t;
            }
            M::Ret => {
                let sp = self.concrete_reg(Register::RSP)?;
                let v = self.load(sp, 8)?;
                let extra = if instr.op_count() == 1 {
                    instr.immediate(0)
                } else {
                    0
                };
                self.set_reg(
                    Register::RSP,
                    expr::konst(sp.wrapping_add(8).wrapping_add(extra), 64),
                );
                self.rip = if v.is_concrete() {
                    v.eval(&[])
                } else {
                    SENTINEL
                };
            }
            M::Jmp => {
                if let Some(stub) = self.slot_hook(instr)? {
                    // `jmp [GOT/IAT slot]` (PLT stub / tail call): the return address is
                    // already on the stack.
                    return self.apply_stub_sym(&stub);
                }
                let t = self.read_op(instr, 0, 64)?;
                if t.is_concrete() {
                    self.rip = t.eval(&[]);
                } else {
                    return Err(SymError::SymbolicAddress(addr));
                }
            }
            M::Leave => {
                let rbp = self.concrete_reg(Register::RBP)?;
                self.set_reg(Register::RSP, expr::konst(rbp, 64));
                let v = self.load(rbp, 8)?;
                self.set_reg(Register::RSP, expr::konst(rbp.wrapping_add(8), 64));
                self.set_reg(Register::RBP, v);
            }
            M::Nop | M::Endbr64 | M::Endbr32 => {}
            other => self.skip_unmodelled(instr, other)?,
        }
        Ok(())
    }

    /// Instructions we don't model symbolically are tolerated only when they can't affect the
    /// check's data flow: they write no general-purpose register (conditional writes such as
    /// `cmovcc` count), and every memory byte they read or write is concrete — so SSE/x87 setup
    /// and the prologue's constant stack-zeroing (e.g. `movaps [rsp+40h],xmm0` over a
    /// not-yet-symbolic slot) are skipped, while a `movdqu xmm0,[input]` or a shuffle over a stack
    /// slot holding input bails. Memory operands are located with iced's per-access addresses, so
    /// string instructions (`[rsi]`/`[rdi]`) are checked at the bytes they really touch. If the
    /// instruction writes an arithmetic flag, the lazy flags become unknown, so a later branch on
    /// them errors instead of reading stale flags.
    fn skip_unmodelled(&mut self, instr: &Instruction, m: Mnemonic) -> Result<(), SymError> {
        let addr = instr.ip();
        let bail = || SymError::Unsupported {
            addr,
            what: format!("{m:?}"),
        };
        let is_write = |a: OpAccess| {
            matches!(
                a,
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            )
        };
        let is_read = |a: OpAccess| {
            matches!(
                a,
                OpAccess::Read | OpAccess::ReadWrite | OpAccess::CondRead | OpAccess::ReadCondWrite
            )
        };
        let mut info = InstructionInfoFactory::new();
        let ii = info.info(instr);
        if ii
            .used_registers()
            .iter()
            .any(|u| is_write(u.access()) && u.register().is_gpr())
        {
            return Err(bail());
        }
        for um in ii.used_memory() {
            let access = um.access();
            if !is_write(access) && !is_read(access) {
                continue; // e.g. `lea`-style NoMemAccess operands
            }
            // A symbolic (or VSIB) address can't be proven clear of symbolic memory.
            let Some(a) = um.virtual_address(0, |r, _, vsib| self.addr_reg_value(r, vsib)) else {
                return Err(bail());
            };
            let sz = um.memory_size().size().max(1) as u64;
            let bytes = (0..sz).map(|i| a.wrapping_add(i));
            // Reading symbolic data into an unmodelled result loses it; overwriting any byte the
            // executor tracks (symbolic or a stored concrete value) would leave a stale copy.
            let reads_sym = is_read(access) && bytes.clone().any(|x| self.is_symbolic_byte(x));
            let clobbers = is_write(access)
                && bytes
                    .clone()
                    .any(|x| self.in_input(x) || self.sym_mem.contains_key(&x));
            if reads_sym || clobbers {
                return Err(bail());
            }
        }
        const ARITH: u32 = RflagsBits::OF
            | RflagsBits::SF
            | RflagsBits::ZF
            | RflagsBits::AF
            | RflagsBits::CF
            | RflagsBits::PF;
        if (instr.rflags_modified() & ARITH) != 0 {
            self.flags = Flags::None;
        }
        Ok(())
    }

    fn add(&mut self, instr: &Instruction, bits: u32) -> Result<(), SymError> {
        let a = self.read_op(instr, 0, bits)?;
        let b = self.read_op(instr, 1, bits)?;
        let r = fold(expr::bin(Op::Add, a.clone(), b.clone()));
        // CF: the unsigned sum wrapped (r < a). OF: both operands' signs differ from the result's.
        let cf = expr::rel(Rel::Ult, r.clone(), a.clone());
        let of = msb(
            fold(expr::bin(
                Op::And,
                expr::bin(Op::Xor, a, r.clone()),
                expr::bin(Op::Xor, b, r.clone()),
            )),
            bits,
        );
        self.flags = Flags::Res {
            r: r.clone(),
            w: bits,
            cf: Some(cf),
            of: Some(of),
        };
        self.write_op(instr, 0, r, bits)
    }

    fn sub_like(&mut self, instr: &Instruction, bits: u32, write: bool) -> Result<(), SymError> {
        let a = self.read_op(instr, 0, bits)?;
        let b = self.read_op(instr, 1, bits)?;
        self.flags = Flags::Cmp(a.clone(), b.clone(), bits);
        if write {
            let r = fold(expr::bin(Op::Sub, a, b));
            self.write_op(instr, 0, r, bits)?;
        }
        Ok(())
    }

    fn logic(&mut self, instr: &Instruction, bits: u32, op: Op) -> Result<(), SymError> {
        let a = self.read_op(instr, 0, bits)?;
        let b = self.read_op(instr, 1, bits)?;
        let r = fold(expr::bin(op, a, b));
        self.flags = logic_flags(r.clone(), bits);
        self.write_op(instr, 0, r, bits)
    }

    /// The current carry flag as a boolean expression, if known (INC/DEC preserve it).
    fn carry(&self) -> Option<Expr> {
        match &self.flags {
            Flags::None => None,
            Flags::Cmp(a, b, _) => Some(expr::rel(Rel::Ult, a.clone(), b.clone())),
            Flags::Res { cf, .. } => cf.clone(),
        }
    }

    fn incdec(&mut self, instr: &Instruction, bits: u32, inc: bool) -> Result<(), SymError> {
        let a = self.read_op(instr, 0, bits)?;
        let op = if inc { Op::Add } else { Op::Sub };
        let r = fold(expr::bin(op, a, expr::konst(1, bits)));
        // OF: inc overflows exactly when the result is MIN, dec when the result is MAX.
        let min = 1u64 << (bits - 1);
        let edge = if inc { min } else { min - 1 };
        let of = expr::rel(Rel::Eq, r.clone(), expr::konst(edge, bits));
        self.flags = Flags::Res {
            r: r.clone(),
            w: bits,
            cf: self.carry(),
            of: Some(of),
        };
        self.write_op(instr, 0, r, bits)
    }

    fn shift(&mut self, instr: &Instruction, bits: u32, op: Op) -> Result<(), SymError> {
        let a = self.read_op(instr, 0, bits)?;
        // x86 masks the count to 5 bits (6 for 64-bit operands).
        let count_mask: u64 = if bits == 64 { 0x3f } else { 0x1f };
        let cnt = self.read_op(instr, 1, 8)?;
        if !cnt.is_concrete() {
            let c = fold(expr::bin(
                Op::And,
                resize(cnt, bits),
                expr::konst(count_mask, bits),
            ));
            let r = fold(expr::bin(op, a, c));
            // A possibly-zero count leaves the flags unchanged, otherwise sets them: unknown.
            self.flags = Flags::None;
            return self.write_op(instr, 0, r, bits);
        }
        let c = (cnt.eval(&[]) & count_mask) as u32;
        if c == 0 {
            // No shift and no flag change (the write keeps a 32-bit destination's zero-extension).
            return self.write_op(instr, 0, a, bits);
        }
        let r = fold(expr::bin(op, a.clone(), expr::konst(u64::from(c), bits)));
        let bit = |e: &Expr, i: u32| {
            expr::rel(Rel::Eq, expr::extract(e.clone(), i, i), expr::konst(1, 1))
        };
        let falsy = || expr::konst(0, 1);
        // CF = the last bit shifted out.
        let cf = match op {
            Op::Shl if c <= bits => bit(&a, bits - c),
            Op::Lshr if c <= bits => bit(&a, c - 1),
            Op::Ashr => bit(&a, (c - 1).min(bits - 1)),
            _ => falsy(),
        };
        // OF is defined only for 1-bit shifts.
        let of = (c == 1).then(|| match op {
            Op::Shl => xor_b(msb(r.clone(), bits), cf.clone()),
            Op::Lshr => msb(a.clone(), bits),
            _ => falsy(),
        });
        self.flags = Flags::Res {
            r: r.clone(),
            w: bits,
            cf: Some(cf),
            of,
        };
        self.write_op(instr, 0, r, bits)
    }

    /// `rol`/`ror` by a concrete count: `(a << k) | (a >> (w-k))` (mirrored for `ror`). A
    /// symbolic count is rare in these checks and bails rather than guess. Rotates leave ZF/SF
    /// untouched and set CF/OF, which aren't modelled — so the flags become unknown.
    fn rotate(&mut self, instr: &Instruction, bits: u32, left: bool) -> Result<(), SymError> {
        let a = self.read_op(instr, 0, bits)?;
        let cnt = self.read_op(instr, 1, 8)?;
        if !cnt.is_concrete() {
            return Err(SymError::Unsupported {
                addr: instr.ip(),
                what: "rotate by symbolic count".into(),
            });
        }
        let count_mask: u64 = if bits == 64 { 0x3f } else { 0x1f };
        let masked = (cnt.eval(&[]) & count_mask) as u32;
        let k = masked & (bits - 1); // widths are powers of two
        let r = if k == 0 {
            a
        } else {
            let kk = if left { k } else { bits - k };
            let lo = expr::bin(Op::Shl, a.clone(), expr::konst(u64::from(kk), bits));
            let hi = expr::bin(Op::Lshr, a, expr::konst(u64::from(bits - kk), bits));
            expr::bin(Op::Or, lo, hi)
        };
        let r = fold(r);
        if masked != 0 {
            self.flags = Flags::None;
        }
        self.write_op(instr, 0, r, bits)
    }

    fn src_bits(&self, instr: &Instruction) -> u32 {
        (match instr.op_kind(1) {
            OpKind::Register => instr.op_register(1).size(),
            OpKind::Memory => instr.memory_size().size(),
            _ => 1,
        } as u32)
            * 8
    }

    // --- branches ---------------------------------------------------------

    /// The branch condition as a boolean expression, from the lazy flags. A condition the flags
    /// can't give exactly (unknown flags, an undefined CF/OF) is an error, never a guess.
    fn cond(&self, cc: Cc, addr: u64) -> Result<Expr, SymError> {
        let unsupported = |why: &str| SymError::Unsupported {
            addr,
            what: format!("condition {cc:?} {why}"),
        };
        let (zf, sf, cf, of, pf) = match &self.flags {
            Flags::None => return Err(unsupported("on flags an unmodelled instruction set")),
            Flags::Cmp(a, b, w) => {
                let (a, b, w) = (a.clone(), b.clone(), *w);
                // The relational forms keep constraints in the solver-friendly shape.
                match cc {
                    Cc::E => return Ok(expr::rel(Rel::Eq, a, b)),
                    Cc::Ne => return Ok(expr::bnot(expr::rel(Rel::Eq, a, b))),
                    Cc::B => return Ok(expr::rel(Rel::Ult, a, b)),
                    Cc::Ae => return Ok(expr::bnot(expr::rel(Rel::Ult, a, b))),
                    Cc::Be => return Ok(expr::rel(Rel::Ule, a, b)),
                    Cc::A => return Ok(expr::bnot(expr::rel(Rel::Ule, a, b))),
                    Cc::L => return Ok(expr::rel(Rel::Slt, a, b)),
                    Cc::Ge => return Ok(expr::bnot(expr::rel(Rel::Slt, a, b))),
                    Cc::Le => return Ok(expr::rel(Rel::Sle, a, b)),
                    Cc::G => return Ok(expr::bnot(expr::rel(Rel::Sle, a, b))),
                    _ => {}
                }
                let r = fold(expr::bin(Op::Sub, a.clone(), b.clone()));
                // SUB overflows when the operands' signs differ and the result's sign differs
                // from the minuend's.
                let of = msb(
                    fold(expr::bin(
                        Op::And,
                        expr::bin(Op::Xor, a.clone(), b.clone()),
                        expr::bin(Op::Xor, a.clone(), r.clone()),
                    )),
                    w,
                );
                (
                    is_zero(&r, w),
                    msb(r.clone(), w),
                    Some(expr::rel(Rel::Ult, a, b)),
                    Some(of),
                    parity(&r),
                )
            }
            Flags::Res { r, w, cf, of } => (
                is_zero(r, *w),
                msb(r.clone(), *w),
                cf.clone(),
                of.clone(),
                parity(r),
            ),
        };
        let cf = || {
            cf.clone()
                .ok_or_else(|| unsupported("on an unmodelled carry flag"))
        };
        let of = || {
            of.clone()
                .ok_or_else(|| unsupported("on an undefined overflow flag"))
        };
        Ok(match cc {
            Cc::E => zf,
            Cc::Ne => expr::bnot(zf),
            Cc::S => sf,
            Cc::Ns => expr::bnot(sf),
            Cc::P => pf,
            Cc::Np => expr::bnot(pf),
            Cc::O => of()?,
            Cc::No => expr::bnot(of()?),
            Cc::B => cf()?,
            Cc::Ae => expr::bnot(cf()?),
            Cc::Be => or_b(cf()?, zf),
            Cc::A => expr::bnot(or_b(cf()?, zf)),
            Cc::L => xor_b(sf, of()?),
            Cc::Ge => expr::bnot(xor_b(sf, of()?)),
            Cc::Le => or_b(zf, xor_b(sf, of()?)),
            Cc::G => expr::bnot(or_b(zf, xor_b(sf, of()?))),
        })
    }

    fn branch(&mut self, instr: &Instruction, cc: Cc) -> Result<(), SymError> {
        let cond = self.cond(cc, instr.ip())?;
        let taken = instr.near_branch_target();
        let fall = instr.next_ip();
        if cond.is_concrete() {
            self.rip = if cond.eval(&[]) != 0 { taken } else { fall };
            return Ok(());
        }
        // Input-dependent: steer toward the target, away from the avoided blocks.
        let go_taken = if self.avoid.contains(&taken) {
            false
        } else if self.avoid.contains(&fall) {
            true
        } else {
            taken == self.target
        };
        if go_taken {
            self.add_constraint(cond);
            self.rip = taken;
        } else {
            self.add_constraint(expr::bnot(cond));
            self.rip = fall;
        }
        Ok(())
    }

    /// Simplifies a branch condition and splits conjunctions, so a combined result (e.g. from a
    /// symbolic memcmp) decomposes into independent per-byte constraints the solver can handle.
    fn add_constraint(&mut self, e: Expr) {
        flatten(simplify(e), &mut self.constraints);
    }
}

// --- flag helpers ---------------------------------------------------------

/// Flags after a bitwise op: CF = OF = 0, ZF/SF/PF from the result.
fn logic_flags(r: Expr, w: u32) -> Flags {
    Flags::Res {
        r,
        w,
        cf: Some(expr::konst(0, 1)),
        of: Some(expr::konst(0, 1)),
    }
}

/// The sign bit of `e` (at `w` bits) as a boolean.
fn msb(e: Expr, w: u32) -> Expr {
    expr::rel(Rel::Eq, expr::extract(e, w - 1, w - 1), expr::konst(1, 1))
}

fn is_zero(r: &Expr, w: u32) -> Expr {
    expr::rel(Rel::Eq, r.clone(), expr::konst(0, w))
}

/// PF: even parity of the result's low byte.
fn parity(r: &Expr) -> Expr {
    let mut x = expr::extract(r.clone(), 0, 0);
    for i in 1..8 {
        x = expr::bin(Op::Xor, x, expr::extract(r.clone(), i, i));
    }
    expr::rel(Rel::Eq, fold(x), expr::konst(0, 1))
}

/// Boolean OR, folding a constant side away (keeps logic-op conditions as simple as before).
fn or_b(a: Expr, b: Expr) -> Expr {
    match (a.is_concrete(), b.is_concrete()) {
        (true, _) if a.eval(&[]) != 0 => expr::konst(1, 1),
        (true, _) => b,
        (_, true) if b.eval(&[]) != 0 => expr::konst(1, 1),
        (_, true) => a,
        _ => expr::bor(a, b),
    }
}

/// Boolean XOR (e.g. SF != OF), folding a constant side away.
fn xor_b(a: Expr, b: Expr) -> Expr {
    match (a.is_concrete(), b.is_concrete()) {
        (_, true) if b.eval(&[]) == 0 => a,
        (_, true) => expr::bnot(a),
        (true, _) if a.eval(&[]) == 0 => b,
        (true, _) => expr::bnot(b),
        _ => expr::bnot(expr::rel(Rel::Eq, a, b)),
    }
}

/// Peels `Extract`/`Eq` over an `Ite(cond, const, const)` back to `cond`, and collapses double
/// negation — enough to recover the boolean a memcmp-style result encodes.
fn simplify(e: Expr) -> Expr {
    match &*e {
        Node::BoolNot(a) => {
            let s = simplify(a.clone());
            match &*s {
                Node::BoolNot(b) => b.clone(),
                _ => expr::bnot(s),
            }
        }
        Node::Extract(inner, hi, lo) => {
            let si = simplify(inner.clone());
            if let Node::Ite(c, a, b) = &*si
                && a.is_concrete()
                && b.is_concrete()
            {
                return expr::ite(
                    c.clone(),
                    fold(expr::extract(a.clone(), *hi, *lo)),
                    fold(expr::extract(b.clone(), *hi, *lo)),
                );
            }
            expr::extract(si, *hi, *lo)
        }
        Node::Rel(Rel::Eq, l, r) => {
            let sl = simplify(l.clone());
            if let Node::Ite(c, a, b) = &*sl
                && a.is_concrete()
                && b.is_concrete()
                && r.is_concrete()
            {
                let (k, av, bv) = (r.eval(&[]), a.eval(&[]), b.eval(&[]));
                if av == k && bv != k {
                    return simplify(c.clone());
                }
                if bv == k && av != k {
                    return simplify(expr::bnot(c.clone()));
                }
            }
            expr::rel(Rel::Eq, sl, r.clone())
        }
        _ => e,
    }
}

/// Splits a conjunction into its parts, dropping trivially-true constants.
fn flatten(e: Expr, out: &mut Vec<Expr>) {
    match &*e {
        Node::BoolAnd(a, b) => {
            flatten(a.clone(), out);
            flatten(b.clone(), out);
        }
        _ => {
            if e.is_concrete() && e.eval(&[]) != 0 {
                return; // trivially satisfied
            }
            out.push(e);
        }
    }
}

// --- helpers --------------------------------------------------------------

/// Collapses a variable-free expression to a constant, keeping concrete registers small.
fn fold(e: Expr) -> Expr {
    if e.is_concrete() {
        expr::konst(e.eval(&[]), e.width())
    } else {
        e
    }
}

/// Resizes an expression to `bits` (zero-extend or truncate).
fn resize(e: Expr, bits: u32) -> Expr {
    match e.width().cmp(&bits) {
        std::cmp::Ordering::Equal => e,
        std::cmp::Ordering::Less => zext(e, bits),
        std::cmp::Ordering::Greater => fold(expr::extract(e, bits - 1, 0)),
    }
}

fn zext(e: Expr, bits: u32) -> Expr {
    if e.width() >= bits {
        resize(e, bits)
    } else {
        fold(expr::zext(e, bits))
    }
}

/// `(cont & !mask) | (val & mask)` for a sub-register write.
fn keep_low(cont: Expr, val: Expr, mask: u64, bits: u32) -> Expr {
    let lo = zext(expr::extract(val, bits - 1, 0), 64);
    expr::bin(Op::Or, expr::bin(Op::And, cont, expr::konst(!mask, 64)), lo)
}

// Register-index helpers (mirrors the concrete emulator).
fn gpr_index(full: Register) -> Option<usize> {
    use Register::*;
    Some(match full {
        RAX => 0,
        RCX => 1,
        RDX => 2,
        RBX => 3,
        RSP => 4,
        RBP => 5,
        RSI => 6,
        RDI => 7,
        R8 => 8,
        R9 => 9,
        R10 => 10,
        R11 => 11,
        R12 => 12,
        R13 => 13,
        R14 => 14,
        R15 => 15,
        _ => return Option::None,
    })
}

fn is_high_byte(r: Register) -> bool {
    matches!(r, Register::AH | Register::CH | Register::DH | Register::BH)
}

// Keep `Node` referenced for the width() calls the executor relies on.
const _: fn(&Node) -> u32 = Node::width;
