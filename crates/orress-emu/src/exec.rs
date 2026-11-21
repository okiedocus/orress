//! The instruction interpreter: operand access, flag computation, and the per-mnemonic
//! dispatch. Covers the integer/branch/stack/memory subset that real check and decryption
//! routines use; anything else returns [`EmuError::Unsupported`] so gaps are visible.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::{EmuError, Emulator};

/// A condition code, shared by the Jcc / SETcc / CMOVcc families.
#[derive(Clone, Copy)]
enum Cc {
    O,
    No,
    B,
    Ae,
    E,
    Ne,
    Be,
    A,
    S,
    Ns,
    P,
    Np,
    L,
    Ge,
    Le,
    G,
}

fn mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// Operand size of a string instruction, from its mnemonic suffix.
fn str_size(instr: &Instruction) -> usize {
    use iced_x86::Mnemonic as M;
    match instr.mnemonic() {
        M::Movsb | M::Stosb | M::Lodsb | M::Scasb | M::Cmpsb => 1,
        M::Movsw | M::Stosw | M::Lodsw | M::Scasw | M::Cmpsw => 2,
        M::Movsq | M::Stosq | M::Lodsq | M::Scasq | M::Cmpsq => 8,
        _ => 4, // the `*d` forms
    }
}

/// Whether either operand is an XMM register — what separates SSE `movsd`/`cmpsd` from the
/// identically-named string instructions.
fn touches_xmm(instr: &Instruction) -> bool {
    (0..instr.op_count())
        .any(|i| instr.op_kind(i) == OpKind::Register && instr.op_register(i).is_xmm())
}

fn sign_bit(size: usize) -> u64 {
    1u64 << (size * 8 - 1)
}

/// Even parity of the low byte (x86 PF is computed on the low 8 bits only).
fn parity(v: u64) -> bool {
    (v as u8).count_ones().is_multiple_of(2)
}

/// Sign-extends the low `size` bytes of `v` to a full i64.
fn sign_extend(v: u64, size: usize) -> i64 {
    if size >= 8 {
        return v as i64;
    }
    let shift = 64 - size * 8;
    ((v << shift) as i64) >> shift
}

/// Sign-extends the low `bits` bits of a u128 to a full i128 (for the double-width DIV dividend).
fn sign_extend128(v: u128, bits: u32) -> i128 {
    if bits >= 128 {
        return v as i128;
    }
    let shift = 128 - bits;
    ((v << shift) as i128) >> shift
}

impl Emulator {
    /// How many *different* values one compare site may test the numeric input against before it is
    /// treated as a table scan rather than a key check. See [`Emulator::note_int_cmp`].
    pub(crate) const MAX_SITE_EXPECTED: usize = 3;

    // --- operands ---------------------------------------------------------

    /// The linear address of a memory operand: its offset plus the FS/GS segment base when the
    /// operand uses one (`fs:[0x28]` canary loads, `gs:[0x30]` TEB access). Other segments have
    /// a zero base in 64-bit mode.
    fn ea(&self, instr: &Instruction) -> u64 {
        let seg = match instr.memory_segment() {
            Register::FS => self.cpu.fs_base,
            Register::GS => self.cpu.gs_base,
            _ => 0,
        };
        self.offset(instr).wrapping_add(seg)
    }

    /// The offset (segment-relative address) of a memory operand — what `lea` computes, since
    /// `lea` never applies a segment base.
    fn offset(&self, instr: &Instruction) -> u64 {
        let base = instr.memory_base();
        let disp = instr.memory_displacement64();
        if base == Register::RIP || base == Register::EIP {
            return disp; // iced resolves RIP-relative to an absolute address
        }
        let mut addr = disp;
        if base != Register::None {
            addr = addr.wrapping_add(self.cpu.reg(base));
        }
        let index = instr.memory_index();
        if index != Register::None {
            let scale = u64::from(instr.memory_index_scale());
            addr = addr.wrapping_add(self.cpu.reg(index).wrapping_mul(scale));
        }
        // 32-bit addressing WRAPS at 4 GiB. `[ebp-0xc4]` carries a displacement of 0xffffff3c, so
        // without this mask the carry out of bit 31 lands above the 32-bit address space and every
        // access to a local variable faults — i.e. no 32-bit function with a frame could run.
        if self.abi.ptr_size() == 4 {
            addr &= 0xffff_ffff;
        }
        addr
    }

    /// The operation width in bytes, taken from operand 0 (the destination for binary ops,
    /// the operand itself for unary ops).
    fn width(&self, instr: &Instruction) -> usize {
        match instr.op0_kind() {
            OpKind::Register => instr.op_register(0).size(),
            OpKind::Memory => instr.memory_size().size(),
            _ => 8,
        }
    }

    fn read_op(&self, instr: &Instruction, i: u32, size: usize) -> Result<u64, EmuError> {
        Ok(match instr.op_kind(i) {
            OpKind::Register => self.cpu.reg(instr.op_register(i)),
            OpKind::Memory => self.mem.read(self.ea(instr), size)?,
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                instr.near_branch_target()
            }
            _ => instr.immediate(i) & mask(size),
        })
    }

    fn write_op(
        &mut self,
        instr: &Instruction,
        i: u32,
        val: u64,
        size: usize,
    ) -> Result<(), EmuError> {
        match instr.op_kind(i) {
            OpKind::Register => {
                let r = instr.op_register(i);
                self.cpu.set_reg(r, val);
                // Writing a register clears any input-byte taint it held; a qualifying byte load
                // from the input re-tags it (see `taint_from_load`).
                if !self.reg_taint.is_empty() {
                    self.reg_taint.remove(&r.full_register());
                }
                if !self.reg_num.is_empty() {
                    self.reg_num.remove(&r.full_register());
                }
            }
            OpKind::Memory => self.mem.write(self.ea(instr), val & mask(size), size)?,
            _ => {}
        }
        Ok(())
    }

    /// After a `mov`/`movzx`/`movsx` into a register, tag that register with the input-buffer byte
    /// offset it now holds, so a later `cmp reg, key` reveals the expected byte for that offset
    /// (inline, no library call). Two sources carry input taint:
    ///   * a single byte loaded from the seeded input (`movzx eax, byte [input+i]`); and
    ///   * a **register copy** of an already-tainted byte (`mov ecx, eax`) — compilers routinely
    ///     stage the loaded byte through another register before the compare, and without
    ///     propagating taint across the copy the comparison looks untainted and is missed.
    ///
    /// (`write_op` has already cleared the destination's old taint, so a copy from an untainted
    /// source correctly leaves it untainted.)
    ///
    /// Also maintains the *numeric* input's location: a store of the tainted number moves the tag
    /// to that slot, and a store of anything else over it clears the tag, because the compiler has
    /// reused the slot and what it holds now is not the input.
    fn taint_from_load(&mut self, instr: &Instruction) {
        if !self.record_compares {
            return;
        }
        // The numeric input stored to memory (`mov [rbp-4], eax` after `atoi`): remember the slot,
        // so a later load of it is still recognised as the input. (The store already happened.)
        if instr.op0_kind() == OpKind::Memory && instr.memory_size().size() >= 2 {
            let width = instr.memory_size().size();
            let ea = self.ea(instr);
            if instr.op1_kind() == OpKind::Register
                && self.reg_num.contains(&instr.op_register(1).full_register())
            {
                self.num_input = Some((ea, width));
            } else if let Some((addr, w)) = self.num_input
                && ea < addr.saturating_add(w as u64)
                && addr < ea.saturating_add(width as u64)
            {
                // The slot holding the number is being overwritten with something that is NOT the
                // number: the compiler has reused the stack slot for a pointer, a loop counter, or
                // an unrelated local. Keeping the tag made every later load of that slot read as
                // "the input", so an unrelated `cmp` recorded its operand as the expected key —
                // and at confirm time that bogus key compared equal to itself, which looks exactly
                // like a satisfied check. Three of the corpus's "solves" were input-buffer
                // addresses recovered this way. A later store of the real number re-tags the slot.
                self.num_input = None;
            }
        }
        if instr.op0_kind() != OpKind::Register {
            return;
        }
        let dst = instr.op_register(0).full_register();
        match instr.op1_kind() {
            OpKind::Memory if instr.memory_size().size() == 1 => {
                if let Some(off) = self.input_offset(self.ea(instr)) {
                    self.reg_taint.insert(dst, off);
                }
            }
            OpKind::Register => {
                if let Some(&off) = self.reg_taint.get(&instr.op_register(1).full_register()) {
                    self.reg_taint.insert(dst, off);
                }
            }
            _ => {}
        }
        // Whole-value taint for the numeric input: a load of the parsed integer (`mov eax, [n]`)
        // or a register copy of it, so a later `cmp eax, 25711` reveals the expected number.
        let carries_num = match instr.op1_kind() {
            OpKind::Memory => self
                .num_input
                .is_some_and(|(a, w)| self.ea(instr) == a && instr.memory_size().size() == w),
            OpKind::Register => self.reg_num.contains(&instr.op_register(1).full_register()),
            _ => false,
        };
        if carries_num {
            self.reg_num.insert(dst);
        }
    }

    /// Records one whole-value comparison against the numeric input, unless its site is **scanning**.
    ///
    /// A single instruction that compares the input against many different values in one run is
    /// walking a table (`cmp eax, [tbl + i*4]`), not testing it against a stored key. Every entry
    /// of that table would otherwise become an "expected number", so any input appearing anywhere
    /// in it compares equal and would confirm — which is exactly how three unrelated MSVC GUI
    /// crackmes all reported the key `252`: their scanned tables contain `0xfc`. Once a site is
    /// recognised as a scan, its earlier entries are withdrawn too, because the first few look
    /// indistinguishable from a real gate until the loop goes round again.
    ///
    /// A genuine equality gate records ONE value per site (`cmp eax, 1234h`), so the threshold only
    /// has to be above the handful a real check can produce by being entered twice.
    fn note_int_cmp(&mut self, site: u64, pair: (u64, u64)) {
        if self.int_scan_sites.contains(&site) {
            return;
        }
        let distinct = self
            .int_sites
            .iter()
            .zip(&self.int_expect)
            .filter(|(s, _)| **s == site)
            .map(|(_, (_, want))| *want)
            .chain(std::iter::once(pair.1))
            .collect::<std::collections::HashSet<_>>()
            .len();
        if distinct > Self::MAX_SITE_EXPECTED {
            self.int_scan_sites.insert(site);
            // Withdraw this site's entries: retain only those recorded elsewhere.
            let keep: Vec<bool> = self.int_sites.iter().map(|s| *s != site).collect();
            let mut i = 0;
            self.int_expect.retain(|_| {
                let k = keep[i];
                i += 1;
                k
            });
            self.int_sites.retain(|s| *s != site);
            return;
        }
        self.int_expect.push(pair);
        self.int_sites.push(site);
    }

    /// Records an inline comparison against the seeded input: if one `cmp` operand is a byte loaded
    /// from the input (a tainted register) or the input memory itself, the other operand is the
    /// expected byte(s) for that input offset. Collected into `byte_expect` → [`Emulator::inline_key`].
    fn note_cmp(&mut self, instr: &Instruction, size: usize, a: u64, b: u64) {
        if !self.record_compares || (self.input_region.is_none() && self.num_input.is_none()) {
            return;
        }
        // Whole-value check against a *numeric* input (`scanf("%d")`/`atoi`): one operand is the
        // parsed integer, so the other is the number the check expects. Recorded as a pair rather
        // than per byte — see [`Emulator::int_compares`].
        if size >= 2 && (self.num_input.is_some() || !self.reg_num.is_empty()) {
            let is_num = |i: u32| match instr.op_kind(i) {
                OpKind::Register => self.reg_num.contains(&instr.op_register(i).full_register()),
                OpKind::Memory => self
                    .num_input
                    .is_some_and(|(addr, w)| self.ea(instr) == addr && w == size),
                _ => false,
            };
            // Exactly one side must be the input: `cmp eax, ecx` with both tainted compares the
            // input against itself and says nothing about the key. And the flags must be consumed
            // as an equality test, so an ordering check (`if (n >= 100)`) can't pass off its bound
            // as the key.
            let (a_num, b_num) = (is_num(0), is_num(1));
            if a_num != b_num && self.is_equality_use(instr.next_ip()) {
                let pair = if a_num { (a, b) } else { (b, a) };
                self.note_int_cmp(instr.ip(), pair);
            }
        }
        // Length gate: a value equal to the seeded input's length compared against a *different*
        // small constant is `strlen(input) == N` (or `len != N`). Record N so the caller can re-seed
        // to that length and get past the gate to the byte-compare loop behind it. (`strlen` is
        // stubbed to return the real seed length, so the gate sees our length on one side.)
        if let Some((lo, hi)) = self.input_region {
            let seedlen = hi - lo;
            if seedlen != 0 {
                for (x, y) in [(a, b), (b, a)] {
                    if x == seedlen
                        && y != seedlen
                        && (1..=256).contains(&y)
                        && !self.wanted_lens.contains(&y)
                    {
                        self.wanted_lens.push(y);
                    }
                }
            }
        }
        // Input byte sitting in a register (byte-granular taint) → a 1-byte comparison.
        if size == 1 {
            if instr.op0_kind() == OpKind::Register
                && let Some(&off) = self.reg_taint.get(&instr.op_register(0).full_register())
            {
                self.byte_expect.push((off, b as u8));
            }
            if instr.op1_kind() == OpKind::Register
                && let Some(&off) = self.reg_taint.get(&instr.op_register(1).full_register())
            {
                self.byte_expect.push((off, a as u8));
            }
        }
        // Input compared directly in memory (`cmp [input+i], imm32`) → up to `size` little-endian
        // bytes of the other operand.
        if instr.op0_kind() == OpKind::Memory
            && let Some(off) = self.input_offset(self.ea(instr))
        {
            for k in 0..size {
                self.byte_expect.push((off + k, (b >> (8 * k)) as u8));
            }
        }
        if instr.op1_kind() == OpKind::Memory
            && let Some(off) = self.input_offset(self.ea(instr))
        {
            for k in 0..size {
                self.byte_expect.push((off + k, (a >> (8 * k)) as u8));
            }
        }
    }

    // --- SSE / 128-bit operands -------------------------------------------

    /// Reads a 128-bit (xmmword) operand: a whole XMM register, or 16 bytes of memory.
    fn read_xmm(&self, instr: &Instruction, i: u32) -> Result<u128, EmuError> {
        match instr.op_kind(i) {
            OpKind::Register => Ok(self.cpu.xmm(instr.op_register(i))),
            OpKind::Memory => self.read128(self.ea(instr)),
            _ => Ok(0),
        }
    }

    /// Writes a 128-bit (xmmword) operand: a whole XMM register, or 16 bytes of memory.
    fn write_xmm(&mut self, instr: &Instruction, i: u32, val: u128) -> Result<(), EmuError> {
        match instr.op_kind(i) {
            OpKind::Register => self.cpu.set_xmm(instr.op_register(i), val),
            OpKind::Memory => self.write128(self.ea(instr), val)?,
            _ => {}
        }
        Ok(())
    }

    /// Reads 16 bytes little-endian (an XMM-width memory load).
    fn read128(&self, addr: u64) -> Result<u128, EmuError> {
        let lo = self.mem.read(addr, 8)?;
        let hi = self.mem.read(addr.wrapping_add(8), 8)?;
        Ok((u128::from(hi) << 64) | u128::from(lo))
    }

    /// Writes 16 bytes little-endian (an XMM-width memory store).
    fn write128(&mut self, addr: u64, val: u128) -> Result<(), EmuError> {
        self.mem.write(addr, val as u64, 8)?;
        self.mem
            .write(addr.wrapping_add(8), (val >> 64) as u64, 8)?;
        Ok(())
    }

    /// Reads a scalar operand (`bytes` wide) that may be a GPR, an XMM register (its low bytes),
    /// memory, or an immediate — for MOVD/MOVQ, which shuttle 4 or 8 bytes between an XMM and a
    /// GPR, memory or another XMM.
    fn read_scalar(&self, instr: &Instruction, i: u32, bytes: usize) -> Result<u64, EmuError> {
        Ok(match instr.op_kind(i) {
            OpKind::Register => {
                let r = instr.op_register(i);
                if r.is_xmm() {
                    (self.cpu.xmm(r) as u64) & mask(bytes)
                } else {
                    self.cpu.reg(r) & mask(bytes)
                }
            }
            OpKind::Memory => self.mem.read(self.ea(instr), bytes)?,
            _ => instr.immediate(i) & mask(bytes),
        })
    }

    /// Writes a scalar operand (`bytes` wide) that may be a GPR, an XMM register (zero-extending
    /// the rest of the 128 bits), or memory — the destination side of MOVD/MOVQ.
    fn write_scalar(
        &mut self,
        instr: &Instruction,
        i: u32,
        val: u64,
        bytes: usize,
    ) -> Result<(), EmuError> {
        match instr.op_kind(i) {
            OpKind::Register => {
                let r = instr.op_register(i);
                if r.is_xmm() {
                    self.cpu.set_xmm(r, u128::from(val & mask(bytes))); // zero-extends xmm
                } else {
                    self.cpu.set_reg(r, val); // set_reg applies the register's own width rules
                }
            }
            OpKind::Memory => self.mem.write(self.ea(instr), val & mask(bytes), bytes)?,
            _ => {}
        }
        Ok(())
    }

    /// One string instruction, including the `rep`/`repe`/`repne` loop around it. The operand
    /// size comes from the mnemonic (`stosb` 1 … `stosq` 8); the pointers walk forward, or backward
    /// when the direction flag is set, and the address registers wrap at the address size.
    ///
    /// A `cmps` iteration also feeds the compare-hook: when one side is the seeded input, the byte
    /// on the other side is the expected key byte for that offset — which is how a `repe cmpsb`
    /// password check gives up its key with no library call to hook.
    fn string_op(&mut self, instr: &Instruction, size: usize) -> Result<(), EmuError> {
        use iced_x86::Mnemonic as M;
        let m = instr.mnemonic();
        let narrow = self.ptr() == 4;
        let addr = |v: u64| if narrow { v & 0xffff_ffff } else { v };
        let acc = match size {
            1 => Register::AL,
            2 => Register::AX,
            4 => Register::EAX,
            _ => Register::RAX,
        };
        // F3 is REP on movs/stos/lods and REPE on cmps/scas; F2 is REPNE. iced reports F3 through
        // both `has_rep_prefix` and `has_repe_prefix`, so the ZF test is applied per mnemonic
        // rather than per prefix.
        let repeated = instr.has_rep_prefix() || instr.has_repne_prefix();
        let compares = matches!(
            m,
            M::Cmpsb | M::Cmpsw | M::Cmpsd | M::Cmpsq | M::Scasb | M::Scasw | M::Scasd | M::Scasq
        );
        // A guest-controlled RCX could otherwise spin for billions of iterations; every real
        // crackme buffer is tiny. Each iteration is also charged to the step budget.
        const MAX_ITERS: u64 = 1 << 20;

        for _ in 0..MAX_ITERS {
            if repeated && addr(self.cpu.reg(Register::RCX)) == 0 {
                return Ok(());
            }
            let si = addr(self.cpu.reg(Register::RSI));
            let di = addr(self.cpu.reg(Register::RDI));
            let (mut moves_si, mut moves_di) = (false, false);
            match m {
                M::Movsb | M::Movsw | M::Movsd | M::Movsq => {
                    let v = self.mem.read(si, size)?;
                    self.mem.write(di, v, size)?;
                    (moves_si, moves_di) = (true, true);
                }
                M::Stosb | M::Stosw | M::Stosd | M::Stosq => {
                    let v = self.cpu.reg(acc);
                    self.mem.write(di, v, size)?;
                    moves_di = true;
                }
                M::Lodsb | M::Lodsw | M::Lodsd | M::Lodsq => {
                    let v = self.mem.read(si, size)?;
                    self.cpu.set_reg(acc, v);
                    moves_si = true;
                }
                M::Scasb | M::Scasw | M::Scasd | M::Scasq => {
                    let a = self.cpu.reg(acc) & mask(size);
                    let b = self.mem.read(di, size)?;
                    self.do_sub(a, b, size);
                    moves_di = true;
                }
                M::Cmpsb | M::Cmpsw | M::Cmpsd | M::Cmpsq => {
                    let a = self.mem.read(si, size)?;
                    let b = self.mem.read(di, size)?;
                    self.do_sub(a, b, size);
                    self.note_string_cmp(si, di, size, a, b);
                    (moves_si, moves_di) = (true, true);
                }
                _ => return Ok(()),
            }
            let delta = if self.cpu.flags.df {
                (size as u64).wrapping_neg()
            } else {
                size as u64
            };
            if moves_si {
                let v = addr(self.cpu.reg(Register::RSI).wrapping_add(delta));
                self.cpu
                    .set_reg(if narrow { Register::ESI } else { Register::RSI }, v);
            }
            if moves_di {
                let v = addr(self.cpu.reg(Register::RDI).wrapping_add(delta));
                self.cpu
                    .set_reg(if narrow { Register::EDI } else { Register::RDI }, v);
            }
            if !repeated {
                return Ok(());
            }
            let left = addr(self.cpu.reg(Register::RCX)).wrapping_sub(1);
            self.cpu.set_reg(
                if narrow { Register::ECX } else { Register::RCX },
                addr(left),
            );
            self.steps += 1; // a long rep is work, and the budget should see it
            if compares {
                // REPE stops at the first mismatch, REPNE at the first match.
                if instr.has_repne_prefix() && self.cpu.flags.zf {
                    return Ok(());
                }
                if instr.has_rep_prefix() && !self.cpu.flags.zf {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Records a `cmps` byte against the seeded input (see [`note_cmp`] for the `cmp` equivalent):
    /// whichever side lies in the input buffer, the other side is the expected byte there.
    fn note_string_cmp(&mut self, si: u64, di: u64, size: usize, a: u64, b: u64) {
        if !self.record_compares || size != 1 {
            return;
        }
        if let Some(off) = self.input_offset(si) {
            self.byte_expect.push((off, b as u8));
        }
        if let Some(off) = self.input_offset(di) {
            self.byte_expect.push((off, a as u8));
        }
    }

    // --- stack ------------------------------------------------------------

    fn push(&mut self, val: u64) -> Result<(), EmuError> {
        let ptr = self.ptr();
        let sp = self.cpu.rsp().wrapping_sub(ptr);
        self.mem.write(sp, val, ptr as usize)?;
        self.cpu.set_rsp(sp);
        Ok(())
    }

    fn pop(&mut self) -> Result<u64, EmuError> {
        let ptr = self.ptr();
        let sp = self.cpu.rsp();
        let val = self.mem.read(sp, ptr as usize)?;
        self.cpu.set_rsp(sp.wrapping_add(ptr));
        Ok(val)
    }

    // --- flag helpers -----------------------------------------------------

    fn set_szp(&mut self, res: u64, size: usize) {
        let r = res & mask(size);
        self.cpu.flags.zf = r == 0;
        self.cpu.flags.sf = r & sign_bit(size) != 0;
        self.cpu.flags.pf = parity(r);
    }

    /// `a + b`, setting all arithmetic flags.
    fn do_add(&mut self, a: u64, b: u64, size: usize) -> u64 {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let sum = u128::from(a) + u128::from(b);
        let res = (sum as u64) & m;
        let f = &mut self.cpu.flags;
        f.cf = (sum >> (size * 8)) & 1 == 1;
        f.af = ((a & 0xf) + (b & 0xf)) > 0xf;
        f.of = (!(a ^ b) & (a ^ res) & sign_bit(size)) != 0;
        self.set_szp(res, size);
        res
    }

    /// `a - b`, setting all arithmetic flags (shared by SUB and CMP).
    fn do_sub(&mut self, a: u64, b: u64, size: usize) -> u64 {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let res = a.wrapping_sub(b) & m;
        let f = &mut self.cpu.flags;
        f.cf = a < b;
        f.af = (a & 0xf) < (b & 0xf);
        f.of = ((a ^ b) & (a ^ res) & sign_bit(size)) != 0;
        self.set_szp(res, size);
        res
    }

    /// `a + b + carry`, setting all arithmetic flags for the full three-input add (OF/AF must
    /// reflect `a + b + carry`, not just one of two chained adds).
    fn do_adc(&mut self, a: u64, b: u64, carry: u64, size: usize) -> u64 {
        let m = mask(size);
        let (a, b, c) = (a & m, b & m, carry & 1);
        let sum = u128::from(a) + u128::from(b) + u128::from(c);
        let res = (sum as u64) & m;
        let f = &mut self.cpu.flags;
        f.cf = (sum >> (size * 8)) & 1 == 1;
        f.af = ((a & 0xf) + (b & 0xf) + c) > 0xf;
        f.of = (!(a ^ b) & (a ^ res) & sign_bit(size)) != 0;
        self.set_szp(res, size);
        res
    }

    /// `a - b - borrow`, setting all arithmetic flags for the full three-input subtract.
    fn do_sbb(&mut self, a: u64, b: u64, borrow: u64, size: usize) -> u64 {
        let m = mask(size);
        let (a, b, c) = (a & m, b & m, borrow & 1);
        let res = a.wrapping_sub(b).wrapping_sub(c) & m;
        let f = &mut self.cpu.flags;
        f.cf = u128::from(a) < u128::from(b) + u128::from(c);
        f.af = (a & 0xf) < (b & 0xf) + c;
        f.of = ((a ^ b) & (a ^ res) & sign_bit(size)) != 0;
        self.set_szp(res, size);
        res
    }

    /// Bitwise result flags (AND/OR/XOR/TEST): CF = OF = 0, AF cleared, SF/ZF/PF from result.
    fn do_logic(&mut self, res: u64, size: usize) {
        self.cpu.flags.cf = false;
        self.cpu.flags.of = false;
        self.cpu.flags.af = false;
        self.set_szp(res, size);
    }

    fn eval_cc(&self, cc: Cc) -> bool {
        let f = &self.cpu.flags;
        match cc {
            Cc::O => f.of,
            Cc::No => !f.of,
            Cc::B => f.cf,
            Cc::Ae => !f.cf,
            Cc::E => f.zf,
            Cc::Ne => !f.zf,
            Cc::Be => f.cf || f.zf,
            Cc::A => !f.cf && !f.zf,
            Cc::S => f.sf,
            Cc::Ns => !f.sf,
            Cc::P => f.pf,
            Cc::Np => !f.pf,
            Cc::L => f.sf != f.of,
            Cc::Ge => f.sf == f.of,
            Cc::Le => f.zf || (f.sf != f.of),
            Cc::G => !f.zf && (f.sf == f.of),
        }
    }

    // --- dispatch ---------------------------------------------------------

    pub(crate) fn exec(&mut self, instr: &Instruction) -> Result<(), EmuError> {
        use Mnemonic as M;
        let size = self.width(instr);
        let addr = instr.ip();

        if let Some(cc) = jcc(instr.mnemonic()) {
            if self.eval_cc(cc) {
                self.cpu.rip = instr.near_branch_target();
            }
            return Ok(());
        }
        if let Some(cc) = setcc(instr.mnemonic()) {
            let v = u64::from(self.eval_cc(cc));
            return self.write_op(instr, 0, v, 1);
        }
        if let Some(cc) = cmovcc(instr.mnemonic()) {
            if self.eval_cc(cc) {
                let v = self.read_op(instr, 1, size)?;
                self.write_op(instr, 0, v, size)?;
            } else if size == 4 {
                // A 32-bit CMOVcc writes its destination even when the condition is false, so
                // the upper 32 bits are zeroed regardless (rewriting the low half does exactly that).
                let r = instr.op_register(0);
                self.cpu.set_reg(r, self.cpu.reg(r));
            }
            return Ok(());
        }

        match instr.mnemonic() {
            M::Mov => {
                let v = self.read_op(instr, 1, size)?;
                self.write_op(instr, 0, v, size)?;
                self.taint_from_load(instr);
            }
            M::Movzx => {
                let src = self.src_size(instr);
                let v = self.read_op(instr, 1, src)? & mask(src);
                self.write_op(instr, 0, v, size)?;
                self.taint_from_load(instr);
            }
            M::Movsx | M::Movsxd => {
                let src = self.src_size(instr);
                let v = self.read_op(instr, 1, src)?;
                let ext = sign_extend(v, src) as u64;
                self.write_op(instr, 0, ext, size)?;
                self.taint_from_load(instr);
            }
            M::Lea => {
                let a = self.offset(instr);
                self.write_op(instr, 0, a, size)?;
            }
            M::Add => {
                let (a, b) = self.two(instr, size)?;
                let r = self.do_add(a, b, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Sub => {
                let (a, b) = self.two(instr, size)?;
                let r = self.do_sub(a, b, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Cmp => {
                let (a, b) = self.two(instr, size)?;
                self.do_sub(a, b, size);
                self.note_cmp(instr, size, a, b);
            }
            M::Adc => {
                let (a, b) = self.two(instr, size)?;
                let carry = u64::from(self.cpu.flags.cf);
                let r = self.do_adc(a, b, carry, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Sbb => {
                let (a, b) = self.two(instr, size)?;
                let borrow = u64::from(self.cpu.flags.cf);
                let r = self.do_sbb(a, b, borrow, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::And => {
                let (a, b) = self.two(instr, size)?;
                let r = a & b;
                self.do_logic(r, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Or => {
                let (a, b) = self.two(instr, size)?;
                let r = a | b;
                self.do_logic(r, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Xor => {
                let (a, b) = self.two(instr, size)?;
                let r = a ^ b;
                self.do_logic(r, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Test => {
                let (a, b) = self.two(instr, size)?;
                self.do_logic(a & b, size);
            }
            M::Not => {
                let a = self.read_op(instr, 0, size)?;
                self.write_op(instr, 0, !a, size)?;
            }
            M::Neg => {
                let a = self.read_op(instr, 0, size)?;
                let r = self.do_sub(0, a, size);
                self.write_op(instr, 0, r, size)?;
            }
            M::Inc => {
                let a = self.read_op(instr, 0, size)?;
                let saved_cf = self.cpu.flags.cf;
                let r = self.do_add(a, 1, size);
                self.cpu.flags.cf = saved_cf; // INC preserves CF
                self.write_op(instr, 0, r, size)?;
            }
            M::Dec => {
                let a = self.read_op(instr, 0, size)?;
                let saved_cf = self.cpu.flags.cf;
                let r = self.do_sub(a, 1, size);
                self.cpu.flags.cf = saved_cf; // DEC preserves CF
                self.write_op(instr, 0, r, size)?;
            }
            M::Shl | M::Sal => self.shift(instr, size, Shift::Left)?,
            M::Shr => self.shift(instr, size, Shift::Right)?,
            M::Sar => self.shift(instr, size, Shift::Arith)?,
            M::Rol => self.rotate(instr, size, true)?,
            M::Ror => self.rotate(instr, size, false)?,
            M::Imul => self.imul(instr, size)?,
            M::Mul => self.mul(instr, size)?,
            M::Div => self.div(instr, size, false)?,
            M::Idiv => self.div(instr, size, true)?,
            M::Clc => self.cpu.flags.cf = false,
            M::Stc => self.cpu.flags.cf = true,
            M::Cmc => self.cpu.flags.cf = !self.cpu.flags.cf,
            M::Cdqe => {
                let v = sign_extend(self.cpu.reg(Register::EAX), 4) as u64;
                self.cpu.set_reg(Register::RAX, v);
            }
            M::Cwde => {
                let v = (sign_extend(self.cpu.reg(Register::AX), 2) as u64) & 0xffff_ffff;
                self.cpu.set_reg(Register::EAX, v);
            }
            M::Cdq => {
                let rax = self.cpu.reg(Register::EAX);
                let hi = if rax & 0x8000_0000 != 0 {
                    0xffff_ffff
                } else {
                    0
                };
                self.cpu.set_reg(Register::EDX, hi);
            }
            M::Cqo => {
                let hi = if self.cpu.rax() & sign_bit(8) != 0 {
                    u64::MAX
                } else {
                    0
                };
                self.cpu.set_reg(Register::RDX, hi);
            }
            M::Push => {
                let ptr = self.ptr() as usize;
                let v = self.read_op(instr, 0, ptr)?;
                self.push(v)?;
            }
            M::Pop => {
                let ptr = self.ptr() as usize;
                let v = self.pop()?;
                self.write_op(instr, 0, v, ptr)?;
            }
            M::Call => {
                let slot_stub = self.slot_hook(instr);
                let target = if slot_stub.is_some() {
                    0
                } else {
                    self.read_op(instr, 0, self.ptr() as usize)?
                };
                self.push(self.cpu.rip)?; // RIP already points past the call
                match slot_stub {
                    // `call [IAT slot]`: run the import's stub (it pops the return address).
                    Some(stub) => self.apply_stub(&stub)?,
                    None => self.cpu.rip = target,
                }
            }
            M::Jmp => match self.slot_hook(instr) {
                // `jmp [GOT/IAT slot]` (a PLT stub or tail call): the caller's return address is
                // already on the stack, so the stub returns straight to it.
                Some(stub) => self.apply_stub(&stub)?,
                None => self.cpu.rip = self.read_op(instr, 0, 8)?,
            },
            M::Ret => {
                let ret = self.pop()?;
                self.cpu.rip = ret;
                if instr.op_count() == 1 {
                    let extra = instr.immediate(0);
                    self.cpu.set_rsp(self.cpu.rsp().wrapping_add(extra));
                }
            }
            M::Leave => {
                let rbp = self.cpu.reg(Register::RBP);
                self.cpu.set_rsp(rbp);
                let v = self.pop()?;
                self.cpu.set_reg(Register::RBP, v);
            }
            // --- SSE2 (128-bit) ---
            // Every 128-bit move is the same here: copy 16 bytes, reg or memory, either way.
            // (Alignment is not enforced, so movdqa/movaps on unaligned memory do not fault.)
            M::Movdqu | M::Movdqa | M::Movups | M::Movaps | M::Movupd | M::Movapd => {
                let v = self.read_xmm(instr, 1)?;
                self.write_xmm(instr, 0, v)?;
            }
            // MOVD moves 4 bytes, MOVQ 8, between an XMM register and a GPR, memory or XMM.
            M::Movd | M::Movq => {
                let bytes = if instr.mnemonic() == M::Movq { 8 } else { 4 };
                let v = self.read_scalar(instr, 1, bytes)?;
                self.write_scalar(instr, 0, v, bytes)?;
            }
            M::Pxor | M::Xorps | M::Xorpd => {
                let r = self.read_xmm(instr, 0)? ^ self.read_xmm(instr, 1)?;
                self.write_xmm(instr, 0, r)?;
            }
            M::Pand | M::Andps | M::Andpd => {
                let r = self.read_xmm(instr, 0)? & self.read_xmm(instr, 1)?;
                self.write_xmm(instr, 0, r)?;
            }
            M::Por | M::Orps | M::Orpd => {
                let r = self.read_xmm(instr, 0)? | self.read_xmm(instr, 1)?;
                self.write_xmm(instr, 0, r)?;
            }
            // PANDN: dest = (NOT dest) AND src.
            M::Pandn => {
                let r = !self.read_xmm(instr, 0)? & self.read_xmm(instr, 1)?;
                self.write_xmm(instr, 0, r)?;
            }
            // Packed compare-equal: each lane becomes all-ones on a match, all-zeros otherwise.
            M::Pcmpeqb => self.pcmpeq(instr, 1)?,
            M::Pcmpeqw => self.pcmpeq(instr, 2)?,
            M::Pcmpeqd => self.pcmpeq(instr, 4)?,
            // PMOVMSKB: gather the top bit of each of the 16 bytes into a GPR.
            M::Pmovmskb => {
                let v = self.read_xmm(instr, 1)?;
                let mut m = 0u64;
                for k in 0..16 {
                    if (v >> (k * 8 + 7)) & 1 == 1 {
                        m |= 1u64 << k;
                    }
                }
                self.write_op(instr, 0, m, size)?;
            }
            // String instructions, with their REP prefixes. `cld; rep stosd` is the standard
            // inlined buffer-zeroing prologue, so these sit in front of the very code a check
            // needs to reach — and `repe cmpsb` IS the key comparison in hand-written asm crackmes.
            M::Movsb | M::Movsw | M::Movsq => return self.string_op(instr, str_size(instr)),
            M::Stosb | M::Stosw | M::Stosd | M::Stosq => {
                return self.string_op(instr, str_size(instr));
            }
            M::Lodsb | M::Lodsw | M::Lodsd | M::Lodsq => {
                return self.string_op(instr, str_size(instr));
            }
            M::Scasb | M::Scasw | M::Scasd | M::Scasq => {
                return self.string_op(instr, str_size(instr));
            }
            M::Cmpsb | M::Cmpsw | M::Cmpsq => return self.string_op(instr, str_size(instr)),
            // `movsd`/`cmpsd` are ambiguous in iced: the string form and the SSE scalar-double
            // form share a mnemonic. Only the string form addresses memory through RSI/RDI with no
            // XMM operand, so that is what tells them apart.
            M::Movsd | M::Cmpsd if !touches_xmm(instr) => {
                return self.string_op(instr, 4);
            }
            // Direction flag. A `cld` sits in front of most inlined string loops, so leaving it
            // unimplemented stopped ~11% of corpus binaries dead at the first one.
            M::Cld => self.cpu.flags.df = false,
            M::Std => self.cpu.flags.df = true,
            // Flag and register block moves (32-bit asm crackmes use these constantly).
            M::Pushfd | M::Pushf | M::Pushfq => {
                let v = self.cpu.flags.to_rflags();
                self.push(v)?;
            }
            M::Popfd | M::Popf | M::Popfq => {
                let v = self.pop()?;
                self.cpu.flags = crate::cpu::Flags::from_rflags(v);
            }
            // PUSHAD/POPAD: all eight 32-bit GPRs, in the architectural order, with the pushed ESP
            // being the value from *before* the push block.
            M::Pushad | M::Pusha => {
                use Register::*;
                let sp = self.cpu.rsp();
                for r in [EAX, ECX, EDX, EBX] {
                    let v = self.cpu.reg(r);
                    self.push(v)?;
                }
                self.push(sp)?;
                for r in [EBP, ESI, EDI] {
                    let v = self.cpu.reg(r);
                    self.push(v)?;
                }
            }
            M::Popad | M::Popa => {
                use Register::*;
                for r in [EDI, ESI, EBP] {
                    let v = self.pop()?;
                    self.cpu.set_reg(r, v);
                }
                let _discarded_esp = self.pop()?; // POPAD ignores the saved ESP slot
                for r in [EBX, EDX, ECX, EAX] {
                    let v = self.pop()?;
                    self.cpu.set_reg(r, v);
                }
            }
            // Exchanges.
            M::Xchg => {
                let (a, b) = self.two(instr, size)?;
                self.write_op(instr, 0, b, size)?;
                self.write_op(instr, 1, a, size)?;
            }
            M::Xadd => {
                let (a, b) = self.two(instr, size)?;
                let sum = self.do_add(a, b, size);
                self.write_op(instr, 1, a, size)?;
                self.write_op(instr, 0, sum, size)?;
            }
            M::Cmpxchg => {
                // acc == dst ? dst = src, ZF=1 : acc = dst, ZF=0
                let acc_reg = match size {
                    1 => Register::AL,
                    2 => Register::AX,
                    4 => Register::EAX,
                    _ => Register::RAX,
                };
                let acc = self.cpu.reg(acc_reg) & mask(size);
                let dst = self.read_op(instr, 0, size)? & mask(size);
                self.do_sub(acc, dst, size); // sets the flags, ZF included
                if acc == dst {
                    let src = self.read_op(instr, 1, size)?;
                    self.write_op(instr, 0, src, size)?;
                } else {
                    self.cpu.set_reg(acc_reg, dst);
                }
            }
            // Anti-debug breakpoints: under emulation nothing is attached, so the handler a real
            // debugger would take never runs — stepping over them matches "no debugger present".
            M::Int3 | M::Int | M::Int1 => {}
            // CPUID: report a blank, featureless CPU. Anti-VM checks read the hypervisor bit and
            // the vendor string from here, and all-zero is the least suspicious answer available.
            M::Cpuid => {
                for r in [Register::RAX, Register::RBX, Register::RCX, Register::RDX] {
                    self.cpu.set_reg(r, 0);
                }
            }
            // Bit test (and its set/reset/complement forms): CF takes the selected bit. Exact,
            // not a stub — the bit index is taken modulo the operand width, as the hardware does
            // for a register destination.
            M::Bt | M::Bts | M::Btr | M::Btc => {
                let (val, idx) = self.two(instr, size)?;
                let bits = (size * 8) as u64;
                let bit = idx % bits;
                self.cpu.flags.cf = (val >> bit) & 1 == 1;
                let updated = match instr.mnemonic() {
                    M::Bts => Some(val | (1 << bit)),
                    M::Btr => Some(val & !(1 << bit)),
                    M::Btc => Some(val ^ (1 << bit)),
                    _ => None, // plain BT only reads
                };
                if let Some(v) = updated {
                    self.write_op(instr, 0, v, size)?;
                }
            }
            // x87 CONTROL instructions only. A compiled prologue initialises the FPU and saves or
            // loads its control word even when the check itself never does floating-point work, so
            // these otherwise stop a run before it reaches the comparison.
            //
            // Deliberately NOT extended to x87 data movement or arithmetic (`fld`, `fstp`, `fdiv`,
            // …): treating those as no-ops would let a check that really computes in floating point
            // run on garbage and "accept" a wrong key. Leaving them unsupported stops the run
            // instead, which costs a sample but never invents a solve.
            M::Fninit | M::Fnclex | M::Fclex | M::Fldcw => {}
            M::Fnstcw | M::Fstcw => {
                // The x87 reset control word: 0x037f (all exceptions masked, round to nearest,
                // extended precision) — what a just-initialised FPU would report.
                let addr = self.ea(instr);
                self.mem.write(addr, 0x037f, 2)?;
            }
            M::Fnstsw | M::Fstsw => {
                // Status word of an idle FPU: no exceptions pending, stack empty.
                match instr.op0_kind() {
                    OpKind::Register => self.cpu.set_reg(instr.op_register(0), 0),
                    _ => {
                        let addr = self.ea(instr);
                        self.mem.write(addr, 0, 2)?;
                    }
                }
            }
            M::Fnstenv | M::Fstenv => {
                // The 28-byte protected-mode environment block, zeroed. Anti-debug code reads the
                // saved FPU instruction pointer from here; zero reads as "nothing happened".
                let addr = self.ea(instr);
                for i in 0..28u64 {
                    self.mem.write_u8(addr.wrapping_add(i), 0)?;
                }
            }
            M::Nop | M::Endbr64 | M::Endbr32 | M::Pause | M::Wait => {}
            other => {
                return Err(EmuError::Unsupported {
                    addr,
                    mnemonic: format!("{other:?}"),
                });
            }
        }
        Ok(())
    }

    /// The stub for an indirect `call`/`jmp` through a hooked import slot. Import names are keyed
    /// by the IAT/GOT *slot* address, but `call [slot]` loads the slot's contents — in the file
    /// image that is a hint/name RVA (PE) or a lazy-binding PLT address (ELF), not code — so the
    /// slot address itself has to be matched here or the hook would never fire.
    fn slot_hook(&self, instr: &Instruction) -> Option<crate::Stub> {
        if instr.op0_kind() != OpKind::Memory || self.hooks.is_empty() {
            return None;
        }
        self.hooks.get(&self.ea(instr)).cloned()
    }

    /// Reads both operands of a binary instruction (dst, src), at the operation width.
    fn two(&self, instr: &Instruction, size: usize) -> Result<(u64, u64), EmuError> {
        Ok((self.read_op(instr, 0, size)?, self.read_op(instr, 1, size)?))
    }

    /// Packed compare-equal over `lane`-byte lanes (PCMPEQB/W/D): each lane of the destination
    /// becomes all-ones when the two lanes are equal, all-zeros otherwise.
    fn pcmpeq(&mut self, instr: &Instruction, lane: usize) -> Result<(), EmuError> {
        let a = self.read_xmm(instr, 0)?;
        let b = self.read_xmm(instr, 1)?;
        let lane_mask = (1u128 << (lane * 8)) - 1;
        let mut res = 0u128;
        let mut k = 0;
        while k < 16 {
            let shift = k * 8;
            if (a >> shift) & lane_mask == (b >> shift) & lane_mask {
                res |= lane_mask << shift;
            }
            k += lane;
        }
        self.write_xmm(instr, 0, res)
    }

    /// The width of the *source* operand (for MOVZX/MOVSX, where it differs from the dest).
    fn src_size(&self, instr: &Instruction) -> usize {
        match instr.op_kind(1) {
            OpKind::Register => instr.op_register(1).size(),
            OpKind::Memory => instr.memory_size().size(),
            _ => 1,
        }
    }

    fn shift(&mut self, instr: &Instruction, size: usize, kind: Shift) -> Result<(), EmuError> {
        let a = self.read_op(instr, 0, size)? & mask(size);
        let bits = (size * 8) as u32;
        // x86 masks the count to 5 bits for 8/16/32-bit operands, 6 bits only for 64-bit.
        let count_mask = if size >= 8 { 0x3f } else { 0x1f };
        let cnt = (self.read_op(instr, 1, 1)? & count_mask) as u32;
        if cnt == 0 {
            return Ok(());
        }
        let (res, cf) = match kind {
            Shift::Left => {
                // Guard bits - cnt: a left shift by >= width shifts every bit out (CF = 0),
                // and `bits - cnt` would otherwise underflow and panic in debug builds.
                let cf = if cnt <= bits {
                    (a >> (bits - cnt)) & 1 == 1
                } else {
                    false
                };
                (a.wrapping_shl(cnt) & mask(size), cf)
            }
            Shift::Right => {
                // a has only `bits` significant bits, so `a >> cnt` is 0 once cnt >= bits (cnt < 64).
                let cf = if cnt <= bits {
                    (a >> (cnt - 1)) & 1 == 1
                } else {
                    false
                };
                (a >> cnt, cf)
            }
            Shift::Arith => {
                let cf = (a >> (cnt - 1).min(bits - 1)) & 1 == 1;
                ((sign_extend(a, size) >> cnt) as u64 & mask(size), cf)
            }
        };
        self.cpu.flags.cf = cf;
        // OF is defined by x86 only for a 1-bit shift; it is left undefined (unchanged) otherwise.
        if cnt == 1 {
            self.cpu.flags.of = match kind {
                Shift::Left => cf ^ (res & sign_bit(size) != 0),
                Shift::Right => a & sign_bit(size) != 0,
                Shift::Arith => false,
            };
        }
        self.set_szp(res, size);
        self.write_op(instr, 0, res, size)
    }

    /// `rol`/`ror`: rotate `op0` by the count in `op1` (masked), setting CF to the bit rotated
    /// out. The rotate amount wraps to the operand width (`cnt % bits`).
    fn rotate(&mut self, instr: &Instruction, size: usize, left: bool) -> Result<(), EmuError> {
        let a = self.read_op(instr, 0, size)? & mask(size);
        let bits = (size * 8) as u32;
        let cnt = (self.read_op(instr, 1, 1)? & 0x3f) as u32 % bits;
        if cnt == 0 {
            return Ok(());
        }
        let res = if left {
            ((a << cnt) | (a >> (bits - cnt))) & mask(size)
        } else {
            ((a >> cnt) | (a << (bits - cnt))) & mask(size)
        };
        // CF = the bit that wrapped around (LSB after rol, MSB after ror).
        self.cpu.flags.cf = if left {
            res & 1 == 1
        } else {
            (res >> (bits - 1)) & 1 == 1
        };
        self.write_op(instr, 0, res, size)
    }

    fn imul(&mut self, instr: &Instruction, size: usize) -> Result<(), EmuError> {
        match instr.op_count() {
            1 => {
                // RDX:RAX = RAX * src (signed)
                let src = sign_extend(self.read_op(instr, 0, size)?, size) as i128;
                let a = sign_extend(self.cpu.reg(acc(size)), size) as i128;
                let full = a * src;
                self.store_wide(full as u128, size);
                let truncated = sign_extend(full as u64, size) as i128;
                self.cpu.flags.cf = full != truncated;
                self.cpu.flags.of = self.cpu.flags.cf;
            }
            2 => {
                let a = sign_extend(self.read_op(instr, 0, size)?, size) as i128;
                let b = sign_extend(self.read_op(instr, 1, size)?, size) as i128;
                let full = a * b;
                self.write_op(instr, 0, full as u64, size)?;
                let truncated = sign_extend(full as u64, size) as i128;
                self.cpu.flags.cf = full != truncated;
                self.cpu.flags.of = self.cpu.flags.cf;
            }
            _ => {
                let a = sign_extend(self.read_op(instr, 1, size)?, size) as i128;
                let b = sign_extend(instr.immediate(2), size) as i128;
                let full = a * b;
                self.write_op(instr, 0, full as u64, size)?;
                let truncated = sign_extend(full as u64, size) as i128;
                self.cpu.flags.cf = full != truncated;
                self.cpu.flags.of = self.cpu.flags.cf;
            }
        }
        Ok(())
    }

    fn mul(&mut self, instr: &Instruction, size: usize) -> Result<(), EmuError> {
        let src = self.read_op(instr, 0, size)? & mask(size);
        let a = self.cpu.reg(acc(size)) & mask(size);
        let full = u128::from(a) * u128::from(src);
        self.store_wide(full, size);
        let hi_nonzero = (full >> (size * 8)) != 0;
        self.cpu.flags.cf = hi_nonzero;
        self.cpu.flags.of = hi_nonzero;
        Ok(())
    }

    /// Stores a double-width product into RAX (low) and RDX (high), or AX for byte ops.
    fn store_wide(&mut self, full: u128, size: usize) {
        let m = mask(size) as u128;
        let lo = (full & m) as u64;
        let hi = ((full >> (size * 8)) & m) as u64;
        if size == 1 {
            self.cpu.set_reg(Register::AX, (hi << 8) | lo);
        } else {
            self.cpu.set_reg(acc(size), lo);
            self.cpu.set_reg(hireg(size), hi);
        }
    }

    fn div(&mut self, instr: &Instruction, size: usize, signed: bool) -> Result<(), EmuError> {
        let ip = instr.ip();
        let divisor = self.read_op(instr, 0, size)? & mask(size);
        if divisor == 0 {
            return Err(EmuError::DivideByZero(ip));
        }
        let bits = (size * 8) as u32;
        if size == 1 {
            // 8-bit: dividend is AX (16-bit), quotient -> AL, remainder -> AH.
            let dividend = self.cpu.reg(Register::AX) & 0xffff;
            let (q, r) = if signed {
                let d = dividend as i16 as i32;
                let v = sign_extend(divisor, 1) as i32;
                let q = d.checked_div(v).ok_or(EmuError::DivideOverflow(ip))?;
                if q < i32::from(i8::MIN) || q > i32::from(i8::MAX) {
                    return Err(EmuError::DivideOverflow(ip));
                }
                ((q as u64) & 0xff, (d % v) as u64 & 0xff)
            } else {
                let q = dividend / divisor;
                if q > 0xff {
                    return Err(EmuError::DivideOverflow(ip));
                }
                (q, dividend % divisor)
            };
            self.cpu.set_reg(Register::AL, q);
            self.cpu.set_reg(Register::AH, r);
            return Ok(());
        }
        // 16/32/64-bit: dividend is the double-width hi:lo (DX:AX / EDX:EAX / RDX:RAX).
        let lo = self.cpu.reg(acc(size)) & mask(size);
        let hi = self.cpu.reg(hireg(size)) & mask(size);
        let dividend = (u128::from(hi) << (size * 8)) | u128::from(lo);
        let (q, r) = if signed {
            // The dividend is a signed value of 2*bits width — sign-extend it (not zero-extend,
            // which silently made negative DX:AX / EDX:EAX dividends positive).
            let d = sign_extend128(dividend, bits * 2);
            let v = i128::from(sign_extend(divisor, size));
            // checked_div/rem trap INT_MIN / -1 as #DE instead of panicking.
            let q = d.checked_div(v).ok_or(EmuError::DivideOverflow(ip))?;
            let r = d.checked_rem(v).ok_or(EmuError::DivideOverflow(ip))?;
            let qmin = -(1i128 << (bits - 1));
            let qmax = (1i128 << (bits - 1)) - 1;
            if q < qmin || q > qmax {
                return Err(EmuError::DivideOverflow(ip));
            }
            (q as u128, r as u128)
        } else {
            let v = u128::from(divisor);
            let q = dividend / v;
            if q > u128::from(mask(size)) {
                return Err(EmuError::DivideOverflow(ip));
            }
            (q, dividend % v)
        };
        self.cpu.set_reg(acc(size), (q as u64) & mask(size));
        self.cpu.set_reg(hireg(size), (r as u64) & mask(size));
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Shift {
    Left,
    Right,
    Arith,
}

/// The accumulator register of a given width (AL/AX/EAX/RAX).
fn acc(size: usize) -> Register {
    match size {
        1 => Register::AL,
        2 => Register::AX,
        4 => Register::EAX,
        _ => Register::RAX,
    }
}

/// The high register for wide mul/div (DX/EDX/RDX).
fn hireg(size: usize) -> Register {
    match size {
        2 => Register::DX,
        4 => Register::EDX,
        _ => Register::RDX,
    }
}

fn jcc(m: Mnemonic) -> Option<Cc> {
    use Mnemonic as M;
    Some(match m {
        M::Jo => Cc::O,
        M::Jno => Cc::No,
        M::Jb => Cc::B,
        M::Jae => Cc::Ae,
        M::Je => Cc::E,
        M::Jne => Cc::Ne,
        M::Jbe => Cc::Be,
        M::Ja => Cc::A,
        M::Js => Cc::S,
        M::Jns => Cc::Ns,
        M::Jp => Cc::P,
        M::Jnp => Cc::Np,
        M::Jl => Cc::L,
        M::Jge => Cc::Ge,
        M::Jle => Cc::Le,
        M::Jg => Cc::G,
        _ => return None,
    })
}

fn setcc(m: Mnemonic) -> Option<Cc> {
    use Mnemonic as M;
    Some(match m {
        M::Seto => Cc::O,
        M::Setno => Cc::No,
        M::Setb => Cc::B,
        M::Setae => Cc::Ae,
        M::Sete => Cc::E,
        M::Setne => Cc::Ne,
        M::Setbe => Cc::Be,
        M::Seta => Cc::A,
        M::Sets => Cc::S,
        M::Setns => Cc::Ns,
        M::Setp => Cc::P,
        M::Setnp => Cc::Np,
        M::Setl => Cc::L,
        M::Setge => Cc::Ge,
        M::Setle => Cc::Le,
        M::Setg => Cc::G,
        _ => return None,
    })
}

fn cmovcc(m: Mnemonic) -> Option<Cc> {
    use Mnemonic as M;
    Some(match m {
        M::Cmovo => Cc::O,
        M::Cmovno => Cc::No,
        M::Cmovb => Cc::B,
        M::Cmovae => Cc::Ae,
        M::Cmove => Cc::E,
        M::Cmovne => Cc::Ne,
        M::Cmovbe => Cc::Be,
        M::Cmova => Cc::A,
        M::Cmovs => Cc::S,
        M::Cmovns => Cc::Ns,
        M::Cmovp => Cc::P,
        M::Cmovnp => Cc::Np,
        M::Cmovl => Cc::L,
        M::Cmovge => Cc::Ge,
        M::Cmovle => Cc::Le,
        M::Cmovg => Cc::G,
        _ => return None,
    })
}
