//! Code analysis: finds functions, splits them into basic blocks, builds control-flow
//! graphs and cross-references, names things, and lays out the linear listing.
//!
//! The approach is recursive descent: start at known function entries (entry point,
//! symbols, exports, exception tables), follow every jump and call, and treat each call
//! target as a new function. Code that is never reached this way is shown as data.

mod dataflow;
mod listing;
mod main_finder;
mod memory;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

pub use listing::{Line, LineKind};
pub use memory::Memory;
pub use orress_arch::{Flow, Insn, Isa, Token, TokenKind};
use orress_bytes::strings::FoundString;
use orress_loaders::BinaryInfo;

/// Stop exploring a single function after this many instructions (obfuscated or
/// misidentified code can otherwise run away).
const MAX_FUNCTION_INSNS: usize = 200_000;
/// Overall cap on discovered functions.
const MAX_FUNCTIONS: usize = 200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Unconditional jump.
    Jump,
    /// Conditional jump, taken (condition true).
    Taken,
    /// Conditional jump not taken: execution falls through to the next block.
    NotTaken,
    /// Plain fall-through into a block that starts because something jumps there.
    FallThrough,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub target: u64,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    /// Address after the last instruction.
    pub end: u64,
    pub insns: Vec<u64>,
    pub succs: Vec<Edge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionKind {
    Normal,
    /// A stub that only jumps to an imported function (PLT entry, import thunk).
    Thunk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub entry: u64,
    pub kind: FunctionKind,
    /// Blocks in address order; the entry block is the one starting at `entry`.
    pub blocks: Vec<Block>,
    /// Direct call targets.
    pub calls: Vec<u64>,
}

impl Function {
    pub fn size(&self) -> u64 {
        self.blocks.iter().map(|b| b.end - b.start).sum()
    }

    pub fn insn_count(&self) -> usize {
        self.blocks.iter().map(|b| b.insns.len()).sum()
    }

    pub fn block_at(&self, addr: u64) -> Option<&Block> {
        self.blocks.iter().find(|b| addr >= b.start && addr < b.end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XrefKind {
    Call,
    Jump,
    /// Reads or takes the address of data (strings, globals, import slots).
    Data,
}

impl XrefKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::Data => "data",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Xref {
    /// Address of the referring instruction.
    pub from: u64,
    pub kind: XrefKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    /// From the file's symbol table or exports.
    Symbol,
    /// An imported function (its import slot or a thunk to it).
    Import,
    /// Found by ORRESS (entry point, main).
    Detected,
    /// Generated: sub_401000.
    Auto,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub text: String,
    pub kind: NameKind,
}

/// The analyzed program.
pub struct Program {
    pub isa: Isa,
    pub memory: Memory,
    pub functions: BTreeMap<u64, Function>,
    /// Every decoded instruction: address -> length.
    pub insns: BTreeMap<u64, u8>,
    /// Block starts that are jump targets (for `loc_` labels).
    pub labels: BTreeSet<u64>,
    pub xrefs_to: HashMap<u64, Vec<Xref>>,
    /// Every address referenced as data by any instruction, program-wide. Sorted, so a jump-table
    /// read can find the next referenced datum after a table's base and stop before it — even when
    /// that datum (e.g. an adjacent table) belongs to a different function.
    data_refs: BTreeSet<u64>,
    pub names: HashMap<u64, Name>,
    /// Recovered `switch` jump tables: the address of the indirect `jmp` -> its case targets in
    /// slot (index) order, duplicates kept. The CFG edges are de-duplicated, so this is the source
    /// of truth for a decompiler that needs the exact index-to-case mapping.
    pub switch_tables: HashMap<u64, Vec<u64>>,
    /// Text of strings referenced by code, by address, for inline comments.
    pub string_refs: HashMap<u64, String>,
    pub main: Option<u64>,
    pub lines: Vec<Line>,
}

impl Program {
    /// Analyzes the code of a triaged binary. Returns `None` for architectures ORRESS
    /// cannot disassemble yet.
    pub fn analyze(info: &BinaryInfo, data: Arc<Vec<u8>>, strings: &[FoundString]) -> Option<Self> {
        let isa = Isa::from_arch_name(&info.arch, info.endian == orress_bytes::Endian::Little)?;
        let memory = Memory::new(info, data);
        let mut p = Self {
            isa,
            memory,
            functions: BTreeMap::new(),
            insns: BTreeMap::new(),
            labels: BTreeSet::new(),
            xrefs_to: HashMap::new(),
            data_refs: BTreeSet::new(),
            switch_tables: HashMap::new(),
            names: HashMap::new(),
            string_refs: HashMap::new(),
            main: None,
            lines: Vec::new(),
        };
        p.seed_names(info);
        let imports: HashMap<u64, String> = info
            .import_slots
            .iter()
            .map(|s| (s.address, s.name.clone()))
            .collect();

        // Function entries, most trustworthy first.
        let mut seeds: Vec<u64> = Vec::new();
        seeds.extend(info.entry);
        seeds.extend(info.function_symbols.iter().map(|s| s.address));
        seeds.extend(info.exports.iter().map(|e| e.address).filter(|&a| a != 0));
        seeds.extend(info.function_starts.iter().copied());
        let known_entries: HashSet<u64> = seeds.iter().copied().collect();

        p.explore(seeds.clone(), &known_entries, &imports);
        if let Some(main) = main_finder::find_main(&p, info) {
            p.main = Some(main);
            if !p.functions.contains_key(&main) {
                p.explore(vec![main], &known_entries, &imports);
            }
            let named = p
                .names
                .get(&main)
                .is_some_and(|n| n.kind == NameKind::Symbol);
            if !named {
                p.names.insert(
                    main,
                    Name {
                        text: main_finder::main_name(&p).into(),
                        kind: NameKind::Detected,
                    },
                );
            }
            // Rust: the C-level main only hands the real `main` to the runtime.
            if let Some(user_main) = main_finder::rust_user_main(&p, info, main) {
                if !p.functions.contains_key(&user_main) {
                    p.explore(vec![user_main], &known_entries, &imports);
                }
                if p.names
                    .get(&main)
                    .is_some_and(|n| n.kind != NameKind::Symbol)
                {
                    p.names.insert(
                        main,
                        Name {
                            text: "rust_runtime_main".into(),
                            kind: NameKind::Detected,
                        },
                    );
                }
                if p.names
                    .get(&user_main)
                    .is_none_or(|n| n.kind != NameKind::Symbol)
                {
                    p.names.insert(
                        user_main,
                        Name {
                            text: "main".into(),
                            kind: NameKind::Detected,
                        },
                    );
                }
                p.main = Some(user_main);
            }
        }
        p.name_functions();
        p.collect_string_refs(info, strings);
        p.lines = listing::build(&p, info);
        Some(p)
    }

    fn seed_names(&mut self, info: &BinaryInfo) {
        for slot in &info.import_slots {
            self.names.insert(
                slot.address,
                Name {
                    text: slot.name.clone(),
                    kind: NameKind::Import,
                },
            );
        }
        for sym in &info.function_symbols {
            self.names.insert(
                sym.address,
                Name {
                    text: sym.name.clone(),
                    kind: NameKind::Symbol,
                },
            );
        }
        for export in info.exports.iter().filter(|e| e.address != 0) {
            self.names.entry(export.address).or_insert(Name {
                text: export.name.clone(),
                kind: NameKind::Symbol,
            });
        }
        if let Some(entry) = info.entry {
            self.names.entry(entry).or_insert(Name {
                text: "entry".into(),
                kind: NameKind::Detected,
            });
        }
    }

    fn add_xref(&mut self, to: u64, from: u64, kind: XrefKind) {
        let list = self.xrefs_to.entry(to).or_default();
        let xref = Xref { from, kind };
        if !list.contains(&xref) {
            list.push(xref);
        }
    }

    fn explore(
        &mut self,
        seeds: Vec<u64>,
        known_entries: &HashSet<u64>,
        imports: &HashMap<u64, String>,
    ) {
        let mut queue: Vec<u64> = seeds;
        queue.reverse();
        while let Some(entry) = queue.pop() {
            if self.functions.len() >= MAX_FUNCTIONS {
                break;
            }
            if self.functions.contains_key(&entry) || !self.memory.is_code(entry) {
                continue;
            }
            if let Some(function) = self.explore_function(entry, known_entries, imports) {
                for &target in function.calls.iter().rev() {
                    if !self.functions.contains_key(&target) {
                        queue.push(target);
                    }
                }
                // Tail calls: jumps out of this function to other function entries.
                self.functions.insert(entry, function);
            }
        }
    }

    /// Reads a jump table's target addresses, in slot order, stopping at the first entry that
    /// is not a valid code address (a heuristic bound for a dense `switch` table).
    fn read_jump_table(&self, base: u64, entry: u8) -> Vec<u64> {
        const MAX_SWITCH_CASES: usize = 1024;
        let mut targets = Vec::new();
        let mut slot = base;
        for _ in 0..MAX_SWITCH_CASES {
            let Some(bytes) = self.memory.read(slot, entry as usize) else {
                break;
            };
            // A slot cut short by the end of its region is not a table entry.
            let target = match (entry, bytes.len()) {
                (8, 8) => u64::from_le_bytes(bytes.try_into().expect("8 bytes")),
                (4, 4) => u64::from(u32::from_le_bytes(bytes.try_into().expect("4 bytes"))),
                _ => break,
            };
            if !self.memory.is_code(target) {
                break;
            }
            targets.push(target);
            let Some(next) = slot.checked_add(u64::from(entry)) else {
                break;
            };
            slot = next;
        }
        targets
    }

    /// Reads up to `max_cases` entries of an *offset-based* jump table — the form 64-bit compilers
    /// (LLVM, MSVC) emit for a position-independent `switch`: each 4-byte entry is a signed offset
    /// added to the table's own base (`.long case - table`). Stops early at the first entry that is
    /// not a code address. The cap is essential: unlike an absolute table, a random offset near the
    /// base often lands in `.text`, so without a bound the read runs away.
    fn read_offset_jump_table(&self, base: u64, max_cases: usize) -> Vec<u64> {
        let mut targets = Vec::new();
        let mut slot = base;
        for _ in 0..max_cases {
            let Some(bytes) = self.memory.read(slot, 4) else {
                break;
            };
            let Ok(bytes) = <[u8; 4]>::try_from(bytes) else {
                break; // cut short by the end of the region
            };
            let offset = i64::from(i32::from_le_bytes(bytes));
            let target = base.wrapping_add(offset as u64);
            if !self.memory.is_code(target) {
                break;
            }
            targets.push(target);
            let Some(next) = slot.checked_add(4) else {
                break;
            };
            slot = next;
        }
        targets
    }

    /// Recovers the targets of a register-indirect `jmp` that implements a `switch` through an
    /// offset table: `cmp idx, N; ja default; … lea base, [rip+table]; …; jmp reg`.
    ///
    /// The safe bound is the key. The **case count** comes from the range check in the contiguous
    /// run just before the jump: either `cmp idx, N` (`N + 1` cases) or a `and idx, MASK` that masks
    /// the index to a power-of-two range (`MASK + 1` cases). The **table base** is a `lea [rip+table]`
    /// somewhere in the function — often hoisted out of the loop, so we look across the whole decoded
    /// function, not just the run. A base is accepted only when reading exactly `N + 1` entries
    /// yields that many code targets, which both bounds the read and validates the base: a random
    /// `lea` almost never produces exactly the predicted number of consecutive code offsets. If the
    /// range check or a matching table is not found, nothing is recovered (never an unbounded read).
    fn offset_table_targets(&self, decoded: &BTreeMap<u64, Insn>, jmp_addr: u64) -> Vec<u64> {
        /// A switch's case count is small; a larger `cmp` immediate is not a range check.
        const MAX_CASES: usize = 512;
        const WINDOW: usize = 32;

        // The range check: the nearest `cmp idx, N` with a small immediate, in the run before the
        // jump (crossing block boundaries by address, since the check sits just above the dispatch).
        let mut cases = None;
        let mut cursor = jmp_addr;
        for _ in 0..WINDOW {
            let Some((&prev, insn)) = decoded.range(..cursor).next_back() else {
                break;
            };
            if prev + u64::from(insn.len) != cursor {
                break;
            }
            // `cmp idx, N; ja` guards the jump (valid 0..=N, so N + 1 cases). `and idx, MASK` masks
            // the index into a power-of-two range (valid 0..=MASK, so MASK + 1 cases).
            if insn.mnemonic == "cmp"
                && let Some(n) = last_number(&insn.operands)
                && n as usize <= MAX_CASES
            {
                cases = Some(n as usize + 1);
                break;
            }
            if insn.mnemonic == "and"
                && let Some(mask) = last_number(&insn.operands)
                && mask as usize <= MAX_CASES
                && (mask + 1).is_power_of_two()
            {
                cases = Some(mask as usize + 1);
                break;
            }
            cursor = prev;
        }
        // Candidate table bases: `lea [rip+table]` into read-only data, anywhere in the function
        // (the base is often hoisted out of the dispatch loop).
        let mut bases: Vec<u64> = decoded
            .values()
            .filter(|i| i.mnemonic == "lea")
            .flat_map(|i| i.data_refs.iter().copied())
            .filter(|&b| !self.memory.is_code(b))
            .collect();
        bases.sort_unstable();
        bases.dedup();

        if let Some(cases) = cases.filter(|&c| c >= 2) {
            // With a range check, accept a base only when reading exactly `cases` entries yields
            // that many code targets — this both bounds the read and validates the base.
            for &base in &bases {
                let targets = self.read_offset_jump_table(base, cases);
                if targets.len() == cases {
                    return targets;
                }
            }
            return Vec::new();
        }

        // No range check (an exhaustive `switch`, where the compiler proved the index in range). We
        // have no case count, so bound the table by the next referenced data address after its base
        // — an adjacent table's base is itself referenced, so this stops before it — and by the
        // first non-code entry. A real base yields a run of code offsets; unrelated data almost never
        // does, so we require several before trusting it.
        const NO_CHECK_CAP: usize = 256;
        const MIN_NO_CHECK: usize = 3;
        for &base in &bases {
            // Stop at the next referenced datum after the base — program-wide, so an adjacent table
            // owned by *any* function bounds this one; also include this function's own refs for the
            // parts not yet added to the program-wide set.
            let next = self
                .data_refs
                .range(base.saturating_add(1)..)
                .next()
                .copied()
                .into_iter()
                .chain(
                    decoded
                        .values()
                        .flat_map(|i| i.data_refs.iter().copied())
                        .filter(|&d| d > base),
                )
                .min();
            let cap = next
                .map(|n| ((n - base) / 4) as usize)
                .unwrap_or(NO_CHECK_CAP)
                .min(NO_CHECK_CAP);
            if cap < MIN_NO_CHECK {
                continue;
            }
            let targets = self.read_offset_jump_table(base, cap);
            if targets.len() >= MIN_NO_CHECK {
                return targets;
            }
        }
        Vec::new()
    }

    fn explore_function(
        &mut self,
        entry: u64,
        known_entries: &HashSet<u64>,
        imports: &HashMap<u64, String>,
    ) -> Option<Function> {
        // Pass 1: find every instruction reachable inside the function, and the leaders
        // (addresses that start a basic block).
        let mut leaders: BTreeSet<u64> = BTreeSet::from([entry]);
        let mut decoded: BTreeMap<u64, Insn> = BTreeMap::new();
        let mut work = vec![entry];
        let mut calls = Vec::new();
        while let Some(mut addr) = work.pop() {
            loop {
                if decoded.contains_key(&addr) || decoded.len() >= MAX_FUNCTION_INSNS {
                    break;
                }
                let Some(insn) = self.decode(addr) else {
                    break;
                };
                let next = insn.end();
                let flow = insn.flow;
                for &r in &insn.data_refs {
                    if self.memory.contains(r) || imports.contains_key(&r) {
                        self.add_xref(r, addr, XrefKind::Data);
                    }
                    if self.memory.contains(r) {
                        self.data_refs.insert(r);
                    }
                }
                match flow {
                    Flow::Call(t) => {
                        self.add_xref(t, addr, XrefKind::Call);
                        if self.memory.is_code(t) {
                            calls.push(t);
                        }
                    }
                    Flow::IndirectCall { slot: Some(s) }
                    | Flow::IndirectJump { slot: Some(s), .. } => {
                        let kind = if matches!(flow, Flow::IndirectCall { .. }) {
                            XrefKind::Call
                        } else {
                            XrefKind::Jump
                        };
                        self.add_xref(s, addr, kind);
                    }
                    // A `switch` jump table: read its targets so their blocks are discovered.
                    Flow::IndirectJump { table: Some(t), .. } => {
                        let targets = self.read_jump_table(t.base, t.entry);
                        if !targets.is_empty() {
                            self.switch_tables.insert(addr, targets.clone());
                        }
                        for tg in targets {
                            self.add_xref(tg, addr, XrefKind::Jump);
                            if self.memory.is_code(tg) {
                                leaders.insert(tg);
                                work.push(tg);
                            }
                        }
                    }
                    // A register-indirect `jmp` may be a bounded `switch` through an offset table
                    // (`cmp idx,N; ja default; lea base,[rip+table]; jmp reg`): recover its targets.
                    Flow::IndirectJump {
                        slot: None,
                        table: None,
                    } => {
                        let targets = self.offset_table_targets(&decoded, addr);
                        if !targets.is_empty() {
                            self.switch_tables.insert(addr, targets.clone());
                        }
                        for tg in targets {
                            self.add_xref(tg, addr, XrefKind::Jump);
                            leaders.insert(tg);
                            work.push(tg);
                        }
                    }
                    Flow::Jump(t) | Flow::CondJump(t) => {
                        self.add_xref(t, addr, XrefKind::Jump);
                        // A jump to another function's entry is a tail call, not part of
                        // this function.
                        let tail_call = t != entry
                            && (known_entries.contains(&t) || self.functions.contains_key(&t));
                        if self.memory.is_code(t) && !tail_call {
                            leaders.insert(t);
                            work.push(t);
                        } else if tail_call && !calls.contains(&t) {
                            calls.push(t);
                        }
                    }
                    _ => {}
                }
                decoded.insert(addr, insn);
                if flow.ends_block() && flow.falls_through() {
                    leaders.insert(next);
                }
                if !flow.falls_through() {
                    break;
                }
                addr = next;
            }
        }
        if decoded.is_empty() {
            return None;
        }

        // Pass 2: cut the instructions into blocks at the leaders.
        // Edges only go to leaders that decoded into a block: a leader whose bytes failed to decode
        // (or lie outside the image) would otherwise leave a dangling edge.
        let is_block = |a: u64| leaders.contains(&a) && decoded.contains_key(&a);
        let mut blocks = Vec::new();
        for &leader in &leaders {
            if !decoded.contains_key(&leader) {
                continue;
            }
            let mut block = Block {
                start: leader,
                end: leader,
                insns: Vec::new(),
                succs: Vec::new(),
            };
            let mut addr = leader;
            while let Some(insn) = decoded.get(&addr) {
                block.insns.push(addr);
                block.end = insn.end();
                let next = insn.end();
                match insn.flow {
                    Flow::Jump(t) => {
                        if is_block(t) {
                            block.succs.push(Edge {
                                target: t,
                                kind: EdgeKind::Jump,
                            });
                        }
                        break;
                    }
                    Flow::CondJump(t) => {
                        if is_block(t) {
                            block.succs.push(Edge {
                                target: t,
                                kind: EdgeKind::Taken,
                            });
                        }
                        if decoded.contains_key(&next) {
                            block.succs.push(Edge {
                                target: next,
                                kind: EdgeKind::NotTaken,
                            });
                        }
                        break;
                    }
                    Flow::IndirectJump { table: Some(t), .. } => {
                        let mut seen = std::collections::HashSet::new();
                        for tg in self.read_jump_table(t.base, t.entry) {
                            if is_block(tg) && seen.insert(tg) {
                                block.succs.push(Edge {
                                    target: tg,
                                    kind: EdgeKind::Jump,
                                });
                            }
                        }
                        break;
                    }
                    Flow::IndirectJump {
                        slot: None,
                        table: None,
                    } => {
                        let mut seen = std::collections::HashSet::new();
                        for tg in self.offset_table_targets(&decoded, addr) {
                            if is_block(tg) && seen.insert(tg) {
                                block.succs.push(Edge {
                                    target: tg,
                                    kind: EdgeKind::Jump,
                                });
                            }
                        }
                        break;
                    }
                    f if !f.falls_through() => break,
                    _ => {}
                }
                if is_block(next) {
                    block.succs.push(Edge {
                        target: next,
                        kind: EdgeKind::FallThrough,
                    });
                    break;
                }
                addr = next;
            }
            blocks.push(block);
        }

        for block in &blocks {
            if block.start != entry {
                self.labels.insert(block.start);
            }
        }
        for (addr, insn) in &decoded {
            self.insns.insert(*addr, insn.len);
        }

        // A function that is a single indirect jump through an import slot is a thunk.
        let first = decoded.get(&entry)?;
        let kind = match first.flow {
            Flow::IndirectJump { slot: Some(s), .. }
                if imports.contains_key(&s) && decoded.len() <= 2 =>
            {
                let name = &imports[&s];
                let text = if self.memory.is_elf {
                    format!("{name}@plt")
                } else {
                    name.clone()
                };
                self.names.entry(entry).or_insert(Name {
                    text,
                    kind: NameKind::Import,
                });
                FunctionKind::Thunk
            }
            _ => FunctionKind::Normal,
        };

        calls.sort_unstable();
        calls.dedup();
        Some(Function {
            entry,
            kind,
            blocks,
            calls,
        })
    }

    fn name_functions(&mut self) {
        for &entry in self.functions.keys() {
            self.names.entry(entry).or_insert_with(|| Name {
                text: format!("sub_{entry:x}"),
                kind: NameKind::Auto,
            });
        }
    }

    fn collect_string_refs(&mut self, info: &BinaryInfo, strings: &[FoundString]) {
        // (address, string), sorted, to also find references into the middle of a
        // string: Rust stores string literals back to back without zero bytes, so
        // "Password: Wrong password" can be two strings.
        let mut by_address: Vec<(u64, &FoundString)> = strings
            .iter()
            .filter(|s| s.encoding == orress_bytes::strings::Encoding::Ascii)
            .filter_map(|s| Some((info.offset_to_address(s.offset as u64)?, s)))
            .collect();
        by_address.sort_by_key(|(a, _)| *a);
        for &target in self.xrefs_to.keys() {
            let i = by_address.partition_point(|(a, _)| *a <= target);
            let Some(&(start, s)) = i.checked_sub(1).and_then(|i| by_address.get(i)) else {
                continue;
            };
            let skip = (target - start) as usize;
            if skip < s.byte_len {
                self.string_refs.insert(target, s.text[skip..].to_owned());
            }
        }
    }

    /// Decodes the instruction at `addr` from the file's bytes.
    pub fn decode(&self, addr: u64) -> Option<Insn> {
        let bytes = self.memory.read(addr, self.isa.max_len())?;
        orress_arch::decode(self.isa, bytes, addr)
    }

    pub fn name(&self, addr: u64) -> Option<&Name> {
        self.names.get(&addr)
    }

    /// The function whose blocks contain `addr` (the innermost by entry if several).
    pub fn function_containing(&self, addr: u64) -> Option<&Function> {
        if let Some(f) = self.functions.get(&addr) {
            return Some(f);
        }
        self.functions
            .range(..=addr)
            .rev()
            .take(64)
            .map(|(_, f)| f)
            .find(|f| f.block_at(addr).is_some())
            .or_else(|| self.functions.values().find(|f| f.block_at(addr).is_some()))
    }

    /// Start of the instruction containing `addr`, if `addr` is inside decoded code.
    pub fn insn_start(&self, addr: u64) -> Option<u64> {
        let (&start, &len) = self.insns.range(..=addr).next_back()?;
        (addr < start.saturating_add(u64::from(len))).then_some(start)
    }

    pub fn xrefs(&self, addr: u64) -> &[Xref] {
        self.xrefs_to.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// Index of the listing line for `addr` (the instruction line if there is one).
    pub fn line_index(&self, addr: u64) -> Option<usize> {
        listing::find(&self.lines, addr)
    }
}

/// The last numeric-literal operand of an instruction (e.g. the immediate of `cmp idx, N`).
/// Numbers are formatted in hex, like the rest of the disassembly.
fn last_number(operands: &[Token]) -> Option<u64> {
    operands
        .iter()
        .rev()
        .find(|t| t.kind == TokenKind::Number)
        .and_then(|t| u64::from_str_radix(t.text.trim_start_matches("0x"), 16).ok())
}

#[cfg(test)]
mod tests;
