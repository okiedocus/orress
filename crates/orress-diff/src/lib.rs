//! Binary diffing (M14): BinDiff-style function matching between two analyzed programs — for patch
//! diffing ("what changed between these two builds?") and malware-variant comparison.
//!
//! Each function is reduced to a **position-independent signature**: CFG shape (instruction / basic
//! block / edge / call counts) plus an *opcode hash* (the sequence of decoded mnemonics with their
//! registers and small immediates, but not addresses or branch targets — so it survives relocation
//! and address shifts, while a `jz` -> `jnz` patch still changes it). Functions are
//! then matched one-to-one in order of confidence — by name, then identical opcode hash, then CFG
//! shape, then a greedy best-similarity pass — and each pair is classed **identical** or
//! **changed**; unmatched functions are **added** (only in B) or **removed** (only in A).

use std::collections::HashMap;

use orress_analysis::{Program, TokenKind};

const FNV_OFFSET: u64 = 1469598103934665603;
const FNV_PRIME: u64 = 1099511628211;
/// A greedy match is only accepted above this similarity, so unrelated functions stay unmatched.
const GREEDY_THRESHOLD: f32 = 0.5;
/// The greedy pass compares each function with at most this many unmatched candidates (those with
/// the nearest instruction counts), so it stays near-linear on large binaries.
const GREEDY_CANDIDATES: usize = 256;
/// Immediates at or above this are treated as (relocatable) addresses and left out of the hash —
/// the same cut-off the disassembler uses for data references.
const ADDRESS_LIKE: u64 = 0x1_0000;

/// A function reduced to features that do not depend on its address.
#[derive(Clone, Debug, PartialEq)]
pub struct FuncSig {
    pub entry: u64,
    /// A reliable name (symbol/import/detected — never an auto `sub_xxx`), used as the strongest
    /// matching key.
    pub name: Option<String>,
    pub insns: u32,
    pub blocks: u32,
    pub edges: u32,
    pub calls: u32,
    /// Hash of the instruction sequence (mnemonics, registers, small immediates), in address order.
    pub opcode_hash: u64,
}

impl FuncSig {
    fn fingerprint(&self) -> (u32, u32, u32, u32) {
        (self.insns, self.blocks, self.edges, self.calls)
    }

    fn reference(&self) -> FuncRef {
        FuncRef {
            entry: self.entry,
            name: self.name.clone(),
        }
    }
}

/// How a matched pair of functions relates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// Same code (identical opcode hash and instruction count).
    Identical,
    /// Matched, but the code differs.
    Changed,
}

/// A reference to a function in one program (for the added/removed lists and match endpoints).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncRef {
    pub entry: u64,
    pub name: Option<String>,
}

/// A matched pair of functions across the two programs.
#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    pub a: FuncRef,
    pub b: FuncRef,
    pub kind: MatchKind,
    /// 0.0–1.0 (1.0 when identical).
    pub similarity: f32,
}

/// The result of diffing two programs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Diff {
    pub matches: Vec<Match>,
    /// Functions only in B.
    pub added: Vec<FuncRef>,
    /// Functions only in A.
    pub removed: Vec<FuncRef>,
}

impl Diff {
    /// (identical, changed, added, removed) counts.
    pub fn summary(&self) -> (usize, usize, usize, usize) {
        let identical = self
            .matches
            .iter()
            .filter(|m| m.kind == MatchKind::Identical)
            .count();
        (
            identical,
            self.matches.len() - identical,
            self.added.len(),
            self.removed.len(),
        )
    }
}

/// Extracts a position-independent signature for every function in `program`.
pub fn signatures(program: &Program) -> Vec<FuncSig> {
    program
        .functions
        .values()
        .map(|f| {
            let edges = f.blocks.iter().map(|b| b.succs.len()).sum::<usize>() as u32;
            let mut hash = FNV_OFFSET;
            for block in &f.blocks {
                for &insn_addr in &block.insns {
                    hash_insn(program, insn_addr, &mut hash);
                }
            }
            FuncSig {
                entry: f.entry,
                name: reliable_name(program, f.entry),
                insns: f.insn_count() as u32,
                blocks: f.blocks.len() as u32,
                edges,
                calls: f.calls.len() as u32,
                opcode_hash: hash,
            }
        })
        .collect()
}

fn fnv(hash: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *hash ^= u64::from(b);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

/// Folds one instruction into `hash`: its mnemonic and operands, with addresses (branch targets,
/// RIP-relative/absolute data references, address-sized immediates) replaced by a placeholder so
/// the hash does not depend on where the code or its data was placed.
fn hash_insn(program: &Program, addr: u64, hash: &mut u64) {
    let len = program
        .insns
        .get(&addr)
        .map_or(program.isa.max_len(), |&l| usize::from(l));
    let Some(bytes) = program.memory.read(addr, len) else {
        return;
    };
    let Some(insn) = orress_arch::decode(program.isa, bytes, addr) else {
        // Undecodable: fall back to the first byte.
        fnv(hash, &bytes[..bytes.len().min(1)]);
        return;
    };
    fnv(hash, insn.mnemonic.as_bytes());
    for t in &insn.operands {
        match t.kind {
            TokenKind::Address(_) => fnv(hash, b"\x01"),
            TokenKind::Number if number(&t.text).is_some_and(|v| v >= ADDRESS_LIKE) => {
                fnv(hash, b"\x01")
            }
            _ => fnv(hash, t.text.as_bytes()),
        }
    }
    fnv(hash, b"\x00");
}

/// The value of a numeric operand token (`0x10`, `#0x10]`, `-8`, `16`), ignoring sign.
fn number(text: &str) -> Option<u64> {
    let t = text.trim_matches(|c: char| matches!(c, '#' | '[' | ']' | '!' | ' '));
    let t = t.trim_start_matches('-');
    match t.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse().ok(),
    }
}

/// A name usable as a matching key — present and not an auto-generated `sub_xxx`.
fn reliable_name(program: &Program, entry: u64) -> Option<String> {
    use orress_analysis::NameKind;
    program.names.get(&entry).and_then(|n| match n.kind {
        NameKind::Auto => None,
        _ => Some(n.text.clone()),
    })
}

/// Diffs two analyzed programs.
pub fn diff_programs(a: &Program, b: &Program) -> Diff {
    diff(&signatures(a), &signatures(b))
}

/// The core matcher over extracted signatures (pure; the engine's tested surface).
pub fn diff(a: &[FuncSig], b: &[FuncSig]) -> Diff {
    let mut a_used = vec![false; a.len()];
    let mut b_used = vec![false; b.len()];
    let mut matches = Vec::new();

    // Passes in decreasing confidence; each matches only one-to-one *unique* keys.
    match_unique(a, b, &mut a_used, &mut b_used, &mut matches, |s| {
        s.name.clone()
    });
    match_unique(a, b, &mut a_used, &mut b_used, &mut matches, |s| {
        Some(s.opcode_hash)
    });
    match_unique(a, b, &mut a_used, &mut b_used, &mut matches, |s| {
        Some(s.fingerprint())
    });
    greedy(a, b, &mut a_used, &mut b_used, &mut matches);

    let removed = a
        .iter()
        .zip(&a_used)
        .filter(|(_, u)| !**u)
        .map(|(s, _)| s.reference())
        .collect();
    let added = b
        .iter()
        .zip(&b_used)
        .filter(|(_, u)| !**u)
        .map(|(s, _)| s.reference())
        .collect();
    matches.sort_by_key(|m| m.a.entry); // stable order by A's entry
    Diff {
        matches,
        added,
        removed,
    }
}

/// Pairs functions whose `key` is present exactly once on each side (so a match is unambiguous).
fn match_unique<K: Eq + std::hash::Hash>(
    a: &[FuncSig],
    b: &[FuncSig],
    a_used: &mut [bool],
    b_used: &mut [bool],
    matches: &mut Vec<Match>,
    key: impl Fn(&FuncSig) -> Option<K>,
) {
    let index = |sigs: &[FuncSig], used: &[bool]| {
        let mut map: HashMap<K, Vec<usize>> = HashMap::new();
        for (i, s) in sigs.iter().enumerate() {
            if !used[i]
                && let Some(k) = key(s)
            {
                map.entry(k).or_default().push(i);
            }
        }
        map
    };
    let a_map = index(a, a_used);
    let b_map = index(b, b_used);
    for (k, ais) in &a_map {
        if ais.len() != 1 {
            continue;
        }
        if let Some(bjs) = b_map.get(k)
            && bjs.len() == 1
        {
            let (i, j) = (ais[0], bjs[0]);
            a_used[i] = true;
            b_used[j] = true;
            matches.push(make_match(&a[i], &b[j]));
        }
    }
}

/// Matches leftovers by best similarity above the threshold (one-to-one). Each A function is
/// compared with at most [`GREEDY_CANDIDATES`] unmatched B functions — those nearest in instruction
/// count — so this is not quadratic on large binaries. Ties go to the lowest B index.
fn greedy(
    a: &[FuncSig],
    b: &[FuncSig],
    a_used: &mut [bool],
    b_used: &mut [bool],
    matches: &mut Vec<Match>,
) {
    // Unmatched B functions sorted by instruction count (then index, for determinism).
    let mut order: Vec<usize> = (0..b.len()).filter(|&j| !b_used[j]).collect();
    order.sort_by_key(|&j| (b[j].insns, j));
    for i in 0..a.len() {
        if a_used[i] {
            continue;
        }
        let mut best: Option<usize> = None;
        let mut best_sim = GREEDY_THRESHOLD;
        let mut consider = |j: usize| {
            let s = similarity(&a[i], &b[j]);
            if s > best_sim || (s == best_sim && best.is_some_and(|k| j < k)) {
                best_sim = s;
                best = Some(j);
            }
        };
        // Walk outwards from A's instruction count, nearest first, over unmatched candidates.
        let pos = order.partition_point(|&j| b[j].insns < a[i].insns);
        let (mut lo, mut hi) = (pos, pos);
        let mut seen = 0;
        while seen < GREEDY_CANDIDATES && (lo > 0 || hi < order.len()) {
            let take_hi = match (lo > 0, hi < order.len()) {
                (true, true) => {
                    b[order[hi]].insns - a[i].insns.min(b[order[hi]].insns)
                        <= a[i].insns - b[order[lo - 1]].insns.min(a[i].insns)
                }
                (false, _) => true,
                (true, false) => false,
            };
            let j = if take_hi {
                hi += 1;
                order[hi - 1]
            } else {
                lo -= 1;
                order[lo]
            };
            if !b_used[j] {
                consider(j);
                seen += 1;
            }
        }
        if let Some(j) = best {
            a_used[i] = true;
            b_used[j] = true;
            matches.push(make_match(&a[i], &b[j]));
        }
    }
}

fn make_match(a: &FuncSig, b: &FuncSig) -> Match {
    let identical = a.opcode_hash == b.opcode_hash && a.insns == b.insns;
    Match {
        a: a.reference(),
        b: b.reference(),
        kind: if identical {
            MatchKind::Identical
        } else {
            MatchKind::Changed
        },
        similarity: if identical { 1.0 } else { similarity(a, b) },
    }
}

/// Feature-weighted similarity in 0.0–1.0 (1.0 when the opcode hashes match).
fn similarity(a: &FuncSig, b: &FuncSig) -> f32 {
    if a.opcode_hash == b.opcode_hash {
        return 1.0;
    }
    let ratio = |x: u32, y: u32| {
        if x == 0 && y == 0 {
            1.0
        } else {
            1.0 - (f64::from(x) - f64::from(y)).abs() as f32 / x.max(y) as f32
        }
    };
    0.4 * ratio(a.insns, b.insns)
        + 0.3 * ratio(a.blocks, b.blocks)
        + 0.2 * ratio(a.edges, b.edges)
        + 0.1 * ratio(a.calls, b.calls)
}

#[cfg(test)]
mod tests;
