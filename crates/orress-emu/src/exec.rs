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
            OpKind::Register => self.cpu.set_reg(instr.op_register(i), val),
            OpKind::Memory => self.mem.write(self.ea(instr), val & mask(size), size)?,
            _ => {}
        }
        Ok(())
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

    // --- stack ------------------------------------------------------------

    fn push(&mut self, val: u64) -> Result<(), EmuError> {
        let sp = self.cpu.rsp().wrapping_sub(8);
        self.mem.write(sp, val, 8)?;
        self.cpu.set_rsp(sp);
        Ok(())
    }

    fn pop(&mut self) -> Result<u64, EmuError> {
        let sp = self.cpu.rsp();
        let val = self.mem.read(sp, 8)?;
        self.cpu.set_rsp(sp.wrapping_add(8));
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
            }
            M::Movzx => {
                let src = self.src_size(instr);
                let v = self.read_op(instr, 1, src)? & mask(src);
                self.write_op(instr, 0, v, size)?;
            }
            M::Movsx | M::Movsxd => {
                let src = self.src_size(instr);
                let v = self.read_op(instr, 1, src)?;
                let ext = sign_extend(v, src) as u64;
                self.write_op(instr, 0, ext, size)?;
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
                let v = self.read_op(instr, 0, 8)?;
                self.push(v)?;
            }
            M::Pop => {
                let v = self.pop()?;
                self.write_op(instr, 0, v, 8)?;
            }
            M::Call => {
                let slot_stub = self.slot_hook(instr);
                let target = if slot_stub.is_some() {
                    0
                } else {
                    self.read_op(instr, 0, 8)?
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
            M::Nop | M::Endbr64 | M::Endbr32 | M::Pause => {}
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
