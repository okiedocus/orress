//! WebAssembly loading for ORRESS: turn a `.wasm` module into a structured overview (types,
//! imports, functions with resolved signatures, exports, memories, globals, data segments) and a
//! readable **WAT** disassembly. Pure Rust, built on the `wasm-tools` parser/printer. It never
//! runs the module and tolerates truncated/hostile input — parse errors are recorded, not fatal,
//! so the overview is always populated with whatever was read before the failure.
//!
//! WASM shows up in CTF (browser/crypto challenges, custom VMs compiled to wasm) and increasingly
//! in malware; this is the first managed/bytecode format in ORRESS's M10 "managed & exotic" track.

use wasmparser::{CompositeInnerType, ExternalKind, Operator, Parser, Payload, TypeRef};

/// A function type (signature): parameter and result value types, as WAT type names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FuncType {
    pub params: Vec<String>,
    pub results: Vec<String>,
}

impl FuncType {
    /// A compact `(i32, i32) -> i32` rendering.
    pub fn signature(&self) -> String {
        let params = self.params.join(", ");
        let results = match self.results.len() {
            0 => "()".to_string(),
            1 => self.results[0].clone(),
            _ => format!("({})", self.results.join(", ")),
        };
        format!("({params}) -> {results}")
    }
}

/// What an import brings in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    /// A function, with its type-section index.
    Func(u32),
    Table,
    Memory,
    Global,
    Tag,
}

impl ImportKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Func(_) => "func",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Tag => "tag",
        }
    }
}

/// An imported entity (`module.name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub kind: ImportKind,
}

/// An exported entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    /// `func` / `table` / `memory` / `global` / `tag`.
    pub kind: &'static str,
    pub index: u32,
}

/// A linear memory declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memory {
    pub min_pages: u64,
    pub max_pages: Option<u64>,
    pub memory64: bool,
    pub shared: bool,
}

/// A global declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    pub ty: String,
    pub mutable: bool,
}

/// A defined (code-section) function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// Absolute function index (imported functions come first).
    pub index: u32,
    /// Name from the `name` custom section or an export, if any.
    pub name: Option<String>,
    pub type_index: u32,
    pub sig: Option<FuncType>,
    /// Number of declared local slots (beyond parameters).
    pub locals: u32,
    /// Number of operators in the body.
    pub ops: u32,
    /// Size of the function body in bytes.
    pub size: u32,
}

/// A parsed WebAssembly module overview.
#[derive(Debug, Clone, Default)]
pub struct WasmModule {
    pub version: u16,
    /// Function types from the type section (index-aligned; non-function types are empty).
    pub types: Vec<FuncType>,
    pub imports: Vec<Import>,
    pub imported_func_count: u32,
    pub functions: Vec<Function>,
    pub exports: Vec<Export>,
    pub memories: Vec<Memory>,
    pub globals: Vec<Global>,
    pub table_count: u32,
    pub data_segments: u32,
    pub start_func: Option<u32>,
    /// Custom sections as `(name, byte length)`.
    pub custom_sections: Vec<(String, usize)>,
    /// Whether a `name` custom section was present (debug names available).
    pub has_names: bool,
    /// Set if this is a component rather than a core module (overview will be sparse).
    pub is_component: bool,
    /// A parse error that stopped the walk early; the overview holds what was read before it.
    pub parse_error: Option<String>,
}

impl WasmModule {
    /// Total function count (imported + defined).
    pub fn total_funcs(&self) -> u32 {
        self.imported_func_count + self.functions.len() as u32
    }

    /// A short one-line summary for a header.
    pub fn summary(&self) -> String {
        format!(
            "{} function(s) ({} imported, {} defined) · {} export(s) · {} memor{} · {} global(s)",
            self.total_funcs(),
            self.imported_func_count,
            self.functions.len(),
            self.exports.len(),
            self.memories.len(),
            if self.memories.len() == 1 { "y" } else { "ies" },
            self.globals.len(),
        )
    }
}

/// Returns true if `data` starts with the WebAssembly magic (`\0asm`).
pub fn is_wasm(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0x00, 0x61, 0x73, 0x6d]
}

fn valtype_name(t: &wasmparser::ValType) -> String {
    t.to_string()
}

/// Parses a WebAssembly module into an overview. Never panics on bad input; a parse failure is
/// recorded in [`WasmModule::parse_error`] and the partial overview is returned.
pub fn parse(data: &[u8]) -> WasmModule {
    let mut m = WasmModule::default();
    // Type indices for each defined function, in code order.
    let mut func_type_indices: Vec<u32> = Vec::new();
    // Function names by absolute index (from the name section).
    let mut names: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();

    for payload in Parser::new(0).parse_all(data) {
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                m.parse_error = Some(e.to_string());
                break;
            }
        };
        match payload {
            Payload::Version { num, encoding, .. } => {
                m.version = num;
                m.is_component = matches!(encoding, wasmparser::Encoding::Component);
            }
            Payload::TypeSection(reader) => {
                for group in reader {
                    let Ok(group) = group else { continue };
                    for sub in group.types() {
                        let ft = match &sub.composite_type.inner {
                            CompositeInnerType::Func(f) => FuncType {
                                params: f.params().iter().map(valtype_name).collect(),
                                results: f.results().iter().map(valtype_name).collect(),
                            },
                            // Array/struct/cont types (GC proposal): keep the index aligned.
                            _ => FuncType::default(),
                        };
                        m.types.push(ft);
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for imp in reader {
                    let Ok(imp) = imp else { continue };
                    let kind = match imp.ty {
                        TypeRef::Func(i) => {
                            m.imported_func_count += 1;
                            ImportKind::Func(i)
                        }
                        TypeRef::Table(_) => ImportKind::Table,
                        TypeRef::Memory(_) => ImportKind::Memory,
                        TypeRef::Global(_) => ImportKind::Global,
                        TypeRef::Tag(_) => ImportKind::Tag,
                    };
                    m.imports.push(Import {
                        module: imp.module.to_string(),
                        name: imp.name.to_string(),
                        kind,
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                for ti in reader.into_iter().flatten() {
                    func_type_indices.push(ti);
                }
            }
            Payload::TableSection(reader) => {
                m.table_count = reader.count();
            }
            Payload::MemorySection(reader) => {
                for mem in reader.into_iter().flatten() {
                    m.memories.push(Memory {
                        min_pages: mem.initial,
                        max_pages: mem.maximum,
                        memory64: mem.memory64,
                        shared: mem.shared,
                    });
                }
            }
            Payload::GlobalSection(reader) => {
                for g in reader.into_iter().flatten() {
                    m.globals.push(Global {
                        ty: valtype_name(&g.ty.content_type),
                        mutable: g.ty.mutable,
                    });
                }
            }
            Payload::ExportSection(reader) => {
                for e in reader {
                    let Ok(e) = e else { continue };
                    let kind = match e.kind {
                        ExternalKind::Func => "func",
                        ExternalKind::Table => "table",
                        ExternalKind::Memory => "memory",
                        ExternalKind::Global => "global",
                        ExternalKind::Tag => "tag",
                    };
                    m.exports.push(Export {
                        name: e.name.to_string(),
                        kind,
                        index: e.index,
                    });
                }
            }
            Payload::StartSection { func, .. } => m.start_func = Some(func),
            Payload::DataSection(reader) => m.data_segments = reader.count(),
            Payload::CodeSectionEntry(body) => {
                let code_idx = m.functions.len();
                let index = m.imported_func_count + code_idx as u32;
                let type_index = func_type_indices.get(code_idx).copied().unwrap_or(0);
                let mut locals = 0u32;
                if let Ok(lr) = body.get_locals_reader() {
                    for (count, _) in lr.into_iter().flatten() {
                        locals = locals.saturating_add(count);
                    }
                }
                let mut ops = 0u32;
                if let Ok(or) = body.get_operators_reader() {
                    for op in or.into_iter() {
                        match op {
                            Ok(_) => ops = ops.saturating_add(1),
                            Err(_) => break,
                        }
                    }
                }
                let range = body.range();
                let sig = m.types.get(type_index as usize).cloned();
                m.functions.push(Function {
                    index,
                    name: None,
                    type_index,
                    sig,
                    locals,
                    ops,
                    size: (range.end - range.start) as u32,
                });
            }
            Payload::CustomSection(c) => {
                m.custom_sections
                    .push((c.name().to_string(), c.data().len()));
                if c.name() == "name" {
                    m.has_names = true;
                    parse_function_names(c.data(), c.data_offset(), &mut names);
                }
            }
            _ => {}
        }
    }

    // Attach names: prefer the name section, fall back to exported function names.
    for f in &mut m.functions {
        if let Some(n) = names.get(&f.index) {
            f.name = Some(n.clone());
        }
    }
    if m.functions.iter().any(|f| f.name.is_none()) {
        for e in &m.exports {
            if e.kind == "func"
                && let Some(f) = m.functions.iter_mut().find(|f| f.index == e.index)
                && f.name.is_none()
            {
                f.name = Some(e.name.clone());
            }
        }
    }
    m
}

/// Parses the function-name subsection of the `name` custom section (best-effort).
fn parse_function_names(
    data: &[u8],
    offset: usize,
    out: &mut std::collections::BTreeMap<u32, String>,
) {
    use wasmparser::{BinaryReader, Name, NameSectionReader};
    let reader = NameSectionReader::new(BinaryReader::new(data, offset));
    for sub in reader {
        let Ok(sub) = sub else { break };
        if let Name::Function(map) = sub {
            for n in map.into_iter().flatten() {
                out.insert(n.index, n.name.to_string());
            }
        }
    }
}

/// Disassembles the whole module to WAT text, with byte-offset comments (so matches in the hex
/// view line up with instructions). Returns an error message if the module can't be printed.
pub fn disassemble(data: &[u8]) -> Result<String, String> {
    let mut out = String::new();
    let mut cfg = wasmprinter::Config::new();
    cfg.print_offsets(true);
    cfg.print(data, &mut wasmprinter::PrintFmtWrite(&mut out))
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Disassembles a single defined function to a list of `(offset, text)` operator lines. `index`
/// is the absolute function index. Returns an error if the index isn't a defined function or the
/// body can't be read.
pub fn disassemble_function(data: &[u8], index: u32) -> Result<Vec<(usize, String)>, String> {
    let mut imported_funcs = 0u32;
    let mut code_idx = 0u32;
    for payload in Parser::new(0).parse_all(data) {
        let payload = payload.map_err(|e| e.to_string())?;
        match payload {
            Payload::ImportSection(reader) => {
                for imp in reader.into_iter().flatten() {
                    if matches!(imp.ty, TypeRef::Func(_)) {
                        imported_funcs += 1;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let abs = imported_funcs + code_idx;
                code_idx += 1;
                if abs != index {
                    continue;
                }
                let reader = body.get_operators_reader().map_err(|e| e.to_string())?;
                let mut lines = Vec::new();
                let mut depth = 0i32;
                for item in reader.into_iter_with_offsets() {
                    let (op, off) = item.map_err(|e| e.to_string())?;
                    if matches!(op, Operator::End | Operator::Else) {
                        depth = (depth - 1).max(0);
                    }
                    let indent = "  ".repeat(depth as usize);
                    lines.push((off, format!("{indent}{}", mnemonic(&op))));
                    if matches!(
                        op,
                        Operator::Block { .. }
                            | Operator::Loop { .. }
                            | Operator::If { .. }
                            | Operator::Else
                    ) {
                        depth += 1;
                    }
                }
                return Ok(lines);
            }
            _ => {}
        }
    }
    Err(format!("no defined function at index {index}"))
}

/// Renders an operator as a WAT-like mnemonic (`local.get 0`, `i32.const 42`, `call 3`, …).
fn mnemonic(op: &Operator) -> String {
    use Operator::*;
    match op {
        LocalGet { local_index } => format!("local.get {local_index}"),
        LocalSet { local_index } => format!("local.set {local_index}"),
        LocalTee { local_index } => format!("local.tee {local_index}"),
        GlobalGet { global_index } => format!("global.get {global_index}"),
        GlobalSet { global_index } => format!("global.set {global_index}"),
        I32Const { value } => format!("i32.const {value}"),
        I64Const { value } => format!("i64.const {value}"),
        F32Const { value } => format!("f32.const {:#x}", value.bits()),
        F64Const { value } => format!("f64.const {:#x}", value.bits()),
        Call { function_index } => format!("call {function_index}"),
        CallIndirect { type_index, .. } => format!("call_indirect (type {type_index})"),
        Br { relative_depth } => format!("br {relative_depth}"),
        BrIf { relative_depth } => format!("br_if {relative_depth}"),
        _ => {
            // Fall back to the debug form, turned into a wasm-ish mnemonic:
            // `I32Add` -> `i32.add`, `MemoryGrow { .. }` -> `memory.grow ...`.
            let dbg = format!("{op:?}");
            debug_to_mnemonic(&dbg)
        }
    }
}

/// Turns an `Operator` debug string into a lowercase, dotted WAT-ish mnemonic.
fn debug_to_mnemonic(dbg: &str) -> String {
    // Split off any `{ fields }` payload.
    let (head, tail) = match dbg.split_once(" {") {
        Some((h, t)) => (h, Some(t.trim_end_matches('}').trim())),
        None => (dbg, None),
    };
    let mnem = split_camel(head);
    match tail {
        Some(t) if !t.is_empty() => format!("{mnem} ({t})"),
        _ => mnem,
    }
}

/// `I32TruncF64S` -> `i32.trunc_f64_s` (heuristic: dot after a leading type prefix, else snake).
fn split_camel(s: &str) -> String {
    let mut out = String::new();
    let mut first_boundary_done = false;
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            // First boundary becomes a dot (type.op), later boundaries become underscores.
            if !first_boundary_done {
                out.push('.');
                first_boundary_done = true;
            } else {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
mod tests;
