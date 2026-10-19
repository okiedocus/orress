//! FLIRT-style function signatures: recognise known library functions (libc, the MSVC/Rust
//! runtime, …) in a stripped binary by matching the first bytes of each function against a
//! library of patterns. Bytes that a relocation or a relative branch makes binary-specific are
//! masked, so the same function matches wherever it is linked.
//!
//! Workflow: [`generate`] a [`Library`] from a binary that still has symbols, save it as JSON,
//! then [`identify`] names the matching functions in a stripped binary. Pure Rust.

use std::collections::BTreeMap;

use orress_analysis::{Flow, FunctionKind, NameKind, Program};
use serde::{Deserialize, Serialize};

/// How many leading bytes of a function form its signature.
pub const SIG_LEN: usize = 32;
/// A signature needs at least this many fixed (non-masked) bytes to be worth keeping or trusting,
/// so tiny or almost-entirely-relocated prologues do not match everything.
pub const MIN_FIXED: usize = 8;

/// One function's signature: the leading bytes, with a mask marking the ones a relocation or a
/// relative branch makes binary-specific (so they are ignored when matching).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub name: String,
    /// Leading function bytes (at most [`SIG_LEN`]).
    pub bytes: Vec<u8>,
    /// `mask[i] == true` means byte `i` is a wildcard.
    pub mask: Vec<bool>,
}

impl Signature {
    /// Whether these function bytes match this signature: every fixed byte equal, wildcards
    /// ignored. The candidate must be at least as long as the pattern.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.bytes.len()
            && self
                .bytes
                .iter()
                .zip(&self.mask)
                .enumerate()
                .all(|(i, (b, masked))| *masked || bytes[i] == *b)
    }

    fn fixed_count(&self) -> usize {
        self.mask.iter().filter(|m| !**m).count()
    }
}

/// A collection of signatures, serialised as JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Library {
    pub signatures: Vec<Signature>,
}

impl Library {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("library serialises")
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

/// Builds a signature library from a program that still has real function symbols: one signature
/// per named, non-thunk function (auto-generated `sub_*` names are skipped).
pub fn generate(program: &Program) -> Library {
    let mut signatures = Vec::new();
    for (&entry, f) in &program.functions {
        if f.kind == FunctionKind::Thunk {
            continue;
        }
        // Only functions with a real symbol name are worth a signature — not entry/main
        // (`Detected`), imports, or auto-generated `sub_*` (`Auto`) names.
        let Some(name) = program
            .name(entry)
            .filter(|n| n.kind == NameKind::Symbol)
            .map(|n| n.text.clone())
        else {
            continue;
        };
        if let Some(sig) = signature_for(program, entry, name) {
            signatures.push(sig);
        }
    }
    Library { signatures }
}

/// The signature of the function at `entry`, or `None` if it is too short or too relocated.
fn signature_for(program: &Program, entry: u64, name: String) -> Option<Signature> {
    let bytes = program.memory.read(entry, SIG_LEN)?.to_vec();
    if bytes.len() < MIN_FIXED {
        return None;
    }
    let mut mask = vec![false; bytes.len()];
    let end = entry + bytes.len() as u64;
    let mut addr = entry;
    while addr < end {
        let Some(insn) = program.decode(addr) else {
            break;
        };
        // Relative call/jump targets are encoded as an offset from the next instruction, so they
        // differ wherever the function is linked: mask the operand bytes.
        if matches!(insn.flow, Flow::Call(_) | Flow::Jump(_) | Flow::CondJump(_)) {
            let off = (addr - entry) as usize;
            let (start, len) = rel_operand(insn.len as usize);
            for i in start..start + len {
                if let Some(m) = mask.get_mut(off + i) {
                    *m = true;
                }
            }
        }
        addr += u64::from(insn.len.max(1));
    }
    let sig = Signature { name, bytes, mask };
    (sig.fixed_count() >= MIN_FIXED).then_some(sig)
}

/// The (offset, length) of a relative branch's operand within an instruction of the given length:
/// `rel32` is the last four bytes, `rel8` the last one. Other shapes contribute no mask.
fn rel_operand(len: usize) -> (usize, usize) {
    if len >= 5 {
        (len - 4, 4)
    } else if len == 2 {
        (1, 1)
    } else {
        (len, 0)
    }
}

/// Matches every function in `program` against the library, returning the names to apply by
/// address. A function is named only when exactly one signature matches (an ambiguous match is
/// left alone), so identification never guesses.
pub fn identify(program: &Program, library: &Library) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    for &entry in program.functions.keys() {
        let Some(bytes) = program.memory.read(entry, SIG_LEN) else {
            continue;
        };
        let mut hit: Option<&str> = None;
        let mut ambiguous = false;
        for sig in &library.signatures {
            if sig.matches(bytes) {
                match hit {
                    None => hit = Some(&sig.name),
                    Some(prev) if prev != sig.name => {
                        ambiguous = true;
                        break;
                    }
                    Some(_) => {}
                }
            }
        }
        if let Some(name) = hit
            && !ambiguous
        {
            out.insert(entry, name.to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use orress_loaders::{BinaryInfo, Format, Kind, NamedAddress, Perms, Section};

    use super::*;

    const BASE: u64 = 0x40_1000;

    /// A tiny x86-64 program: two functions, `alpha` (calls the second) and `beta`.
    fn program_with(call_rel: i32, names: &[(u64, &str)]) -> Program {
        // alpha@0: sub rsp,0x18 ; call beta ; add rsp,0x18 ; ret
        let mut code = vec![
            0x48, 0x83, 0xEC, 0x18, // sub rsp,0x18
            0xE8, 0, 0, 0, 0, // call rel32 (filled below)
            0x48, 0x83, 0xC4, 0x18, // add rsp,0x18
            0xC3, // ret
        ];
        code[5..9].copy_from_slice(&call_rel.to_le_bytes());
        // beta@0x40: a handful of fixed-byte instructions (>= MIN_FIXED bytes, no relocations).
        while code.len() < 0x40 {
            code.push(0xCC);
        }
        code.extend([
            0x31, 0xC0, // xor eax,eax
            0xFF, 0xC0, // inc eax
            0x83, 0xC0, 0x05, // add eax,5
            0x89, 0xC1, // mov ecx,eax
            0x01, 0xC8, // add eax,ecx
            0xC3, // ret
        ]);
        let mut file = vec![0u8; 0x200];
        file.extend(&code); // code at file offset 0x200 -> BASE

        let info = BinaryInfo {
            format: Format::Elf,
            kind: Kind::Executable,
            arch: "x86-64".into(),
            bits: Some(64),
            entry: Some(BASE),
            image_base: 0x40_0000,
            sections: vec![Section {
                name: ".text".into(),
                offset: 0x200,
                file_size: code.len() as u64,
                address: BASE,
                virtual_size: code.len() as u64,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                entropy: None,
            }],
            function_symbols: names
                .iter()
                .map(|(a, n)| NamedAddress {
                    address: *a,
                    name: (*n).into(),
                })
                .collect(),
            ..BinaryInfo::default()
        };
        Program::analyze(&info, Arc::new(file), &[]).expect("x86-64")
    }

    #[test]
    fn generate_then_identify_recovers_names() {
        let p = program_with(0x37, &[(BASE, "alpha"), (BASE + 0x40, "beta")]);
        let lib = generate(&p);
        assert_eq!(lib.signatures.len(), 2);
        let found = identify(&p, &lib);
        assert_eq!(found.get(&BASE).map(String::as_str), Some("alpha"));
        assert_eq!(found.get(&(BASE + 0x40)).map(String::as_str), Some("beta"));
    }

    #[test]
    fn masked_call_target_still_matches() {
        // `alpha` generated with one call offset must identify a copy whose call targets a
        // different address (the rel32 bytes differ) — that is the whole point of masking.
        let a = program_with(0x37, &[(BASE, "alpha"), (BASE + 0x40, "beta")]);
        let lib = generate(&a);
        let b = program_with(0x11, &[(BASE, "alpha"), (BASE + 0x40, "beta")]);
        // Identify `b` (different call bytes) against the library built from `a`.
        let found = identify(&b, &lib);
        assert_eq!(found.get(&BASE).map(String::as_str), Some("alpha"));
        // The `alpha` signature masks exactly the four rel32 bytes of its `call`.
        let alpha = lib.signatures.iter().find(|s| s.name == "alpha").unwrap();
        assert_eq!(&alpha.mask[5..9], &[true, true, true, true]);
        assert!(!alpha.mask[0] && !alpha.mask[4]); // prologue + the E8 opcode are fixed
    }

    #[test]
    fn library_json_round_trip() {
        let p = program_with(0x37, &[(BASE, "alpha"), (BASE + 0x40, "beta")]);
        let lib = generate(&p);
        let back = Library::from_json(&lib.to_json()).unwrap();
        assert_eq!(lib, back);
    }

    #[test]
    fn unnamed_functions_are_skipped() {
        // No symbols: analysis names everything `sub_*`, so nothing is signatured.
        let p = program_with(0x37, &[]);
        assert!(generate(&p).signatures.is_empty());
    }
}
