//! The analysis tools the MCP server exposes, each reusing an ORRESS engine crate. Every tool
//! takes a file path, reads it, and returns a text result (or an error string). Output is capped so
//! a huge binary can't flood the agent.

use std::fmt::Write as _;

/// Largest text result returned to the agent.
const MAX_OUT: usize = 60_000;

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

pub(crate) fn cap(mut s: String) -> String {
    if s.len() > MAX_OUT {
        // Cut at a char boundary at or below the limit (`truncate` panics mid-character).
        let mut end = MAX_OUT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("\n… (truncated)");
    }
    s
}

/// Extracts printable ASCII runs of at least `min` characters.
pub fn extract_strings(data: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= min {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min {
        out.push(cur);
    }
    out
}

/// A static triage report (format, hashes, protections, behaviours, IOCs) as Markdown.
pub fn triage(path: &str) -> Result<String, String> {
    let data = read(path)?;
    let info = orress_loaders::triage(&data);
    let strings = extract_strings(&data, 5);
    let sref: Vec<&str> = strings.iter().map(String::as_str).collect();
    let report = orress_triage::build(&info, &sref, &data);
    Ok(cap(report.markdown))
}

/// Printable strings in the file.
pub fn strings(path: &str, min: usize) -> Result<String, String> {
    let data = read(path)?;
    let min = min.clamp(3, 200);
    let s = extract_strings(&data, min);
    Ok(cap(s.join("\n")))
}

/// Deobfuscates a JavaScript file and lists its strings.
pub fn deobfuscate_js(path: &str) -> Result<String, String> {
    let data = read(path)?;
    let src = String::from_utf8_lossy(&data);
    let deob = orress_js::beautify(&orress_js::deobfuscate(&src));
    let mut out = String::from("=== deobfuscated ===\n");
    out.push_str(&deob);
    out.push_str("\n\n=== strings ===\n");
    for s in orress_js::extract_strings(&orress_js::deobfuscate(&src)) {
        let _ = writeln!(out, "{s:?}");
    }
    Ok(cap(out))
}

/// Lists a ZIP/JAR/APK's entries and (for a JAR) its Main-Class.
pub fn archive_list(path: &str) -> Result<String, String> {
    let data = read(path)?;
    let ar = orress_archive::Archive::open(&data)?;
    let mut out = format!("{} entries\n", ar.entries.len());
    for e in &ar.entries {
        if e.is_dir() {
            let _ = writeln!(out, "  {}/", e.name.trim_end_matches('/'));
        } else {
            let _ = writeln!(
                out,
                "  {:<48} {:>9} bytes  ({})",
                e.name,
                e.uncompressed_size,
                e.method_name()
            );
        }
    }
    if let Some(entry) = ar.by_name("META-INF/MANIFEST.MF")
        && let Ok(mf) = ar.read(entry)
    {
        for (k, v) in orress_archive::parse_manifest(&mf) {
            if k == "Main-Class" {
                let _ = writeln!(out, "\nMain-Class: {v}");
            }
        }
    }
    Ok(cap(out))
}

/// Analyzes a native binary into a `Program` (loaders + analysis + disassembly).
fn analyze_program(path: &str) -> Result<orress_analysis::Program, String> {
    let data = std::sync::Arc::new(read(path)?);
    let analysis = orress_project::Analysis::run(&data);
    orress_analysis::Program::analyze(
        &analysis.info,
        std::sync::Arc::clone(&data),
        &analysis.strings,
    )
    .ok_or_else(|| format!("{path}: no native code to diff (architecture not supported)"))
}

/// BinDiff-style comparison of two native binaries: identical/changed/added/removed functions.
pub fn binary_diff(path_a: &str, path_b: &str) -> Result<String, String> {
    let (a, b) = (analyze_program(path_a)?, analyze_program(path_b)?);
    let diff = orress_diff::diff_programs(&a, &b);
    let (identical, changed, added, removed) = diff.summary();
    let name = |r: &orress_diff::FuncRef| {
        r.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", r.entry))
    };

    let mut out = String::new();
    let _ = writeln!(out, "A: {path_a} ({} functions)", a.functions.len());
    let _ = writeln!(out, "B: {path_b} ({} functions)", b.functions.len());
    let _ = writeln!(
        out,
        "identical {identical}  changed {changed}  added {added}  removed {removed}\n"
    );
    if changed > 0 {
        out.push_str("Changed:\n");
        for m in diff
            .matches
            .iter()
            .filter(|m| m.kind == orress_diff::MatchKind::Changed)
        {
            let _ = writeln!(
                out,
                "  {} -> {}  ~{:.0}%",
                name(&m.a),
                name(&m.b),
                m.similarity * 100.0
            );
        }
    }
    if added > 0 {
        out.push_str("Added (only in B):\n");
        for r in &diff.added {
            let _ = writeln!(out, "  {}", name(r));
        }
    }
    if removed > 0 {
        out.push_str("Removed (only in A):\n");
        for r in &diff.removed {
            let _ = writeln!(out, "  {}", name(r));
        }
    }
    Ok(cap(out))
}

/// Flags functions that look like a VM interpreter (bytecode dispatch loop) — the signature of
/// VM-based obfuscation (VMProtect/Themida/custom CTF VMs).
pub fn detect_vm(path: &str) -> Result<String, String> {
    let program = analyze_program(path)?;
    let reports = orress_vm::scan(&program);
    if reports.is_empty() {
        return Ok("No VM-based obfuscation detected (no interpreter dispatch loop found).".into());
    }
    let mut out = format!("{} likely VM interpreter(s):\n", reports.len());
    for r in &reports {
        let _ = writeln!(
            out,
            "  fn {:#x}: dispatcher {:#x}, {} handlers / {} blocks (fan-in {}), confidence {:.0}%",
            r.entry,
            r.dispatcher,
            r.handlers,
            r.blocks,
            r.max_fan_in,
            r.confidence * 100.0
        );
    }
    Ok(cap(out))
}

/// Auto-detects a managed/bytecode format and disassembles it.
pub fn disassemble(path: &str) -> Result<String, String> {
    let data = read(path)?;
    if orress_wasm::is_wasm(&data) {
        return orress_wasm::disassemble(&data).map(cap);
    }
    if orress_pyc::looks_like_pyc(&data) {
        return dis_pyc(&data);
    }
    if orress_java::is_class(&data) {
        return dis_java(&data);
    }
    if orress_dotnet::is_dotnet(&data) {
        return dis_dotnet(&data);
    }
    if orress_dex::is_dex(&data) {
        return dis_dex(&data);
    }
    Err("no bytecode disassembler for this format (try the `triage` tool)".into())
}

fn dis_pyc(data: &[u8]) -> Result<String, String> {
    let pyc = orress_pyc::parse(data)?;
    let mut out = format!("{}\n", pyc.version_label());
    fn walk(c: &orress_pyc::CodeObject, depth: usize, v: Option<(u8, u8)>, out: &mut String) {
        let pad = "  ".repeat(depth);
        let _ = writeln!(out, "{pad}{}", c.signature());
        if let Some(insns) = orress_pyc::disassemble(c, v) {
            for i in insns.iter().take(60) {
                let arg = i
                    .argval
                    .clone()
                    .or_else(|| i.arg.map(|a| a.to_string()))
                    .unwrap_or_default();
                let _ = writeln!(out, "{pad}  {:>4} {:<20} {arg}", i.offset, i.opname);
            }
        }
        for n in c.nested() {
            walk(n, depth + 1, v, out);
        }
    }
    walk(&pyc.top, 0, pyc.version, &mut out);
    Ok(cap(out))
}

fn dis_java(data: &[u8]) -> Result<String, String> {
    let cf = orress_java::parse(data)?;
    let mut out = format!("class {} ({})\n", cf.this_class, cf.java_version());
    for m in &cf.methods {
        let Some(code) = &m.code else { continue };
        let _ = writeln!(out, "\n  {}{}", m.name, m.descriptor);
        for ins in orress_java::disassemble(code, &cf.cp) {
            let _ = writeln!(
                out,
                "    {:>4}: {:<16} {}",
                ins.offset, ins.mnemonic, ins.operands
            );
        }
    }
    Ok(cap(out))
}

fn dis_dotnet(data: &[u8]) -> Result<String, String> {
    let a = orress_dotnet::parse(data)?;
    let mut out = format!("{} module {}\n", a.runtime_version, a.module_name);
    for t in &a.types {
        for m in &t.methods {
            let _ = writeln!(out, "\n  {}.{}{}", t.full_name(), m.name, m.signature);
            if let Ok(il) = a.disassemble(data, m.rva) {
                for i in il.iter().take(80) {
                    let _ = writeln!(
                        out,
                        "    IL_{:04x}: {:<12} {}",
                        i.offset, i.opcode, i.operand
                    );
                }
            }
        }
    }
    Ok(cap(out))
}

fn dis_dex(data: &[u8]) -> Result<String, String> {
    let dex = orress_dex::parse(data)?;
    let mut out = format!("DEX {} · {} strings\n", dex.version, dex.string_count);
    for c in &dex.classes {
        for m in &c.methods {
            if m.code_off == 0 {
                continue;
            }
            let _ = writeln!(out, "\n  {}", m.name);
            if let Ok(il) = dex.disassemble_method(data, m.code_off) {
                for i in il.iter().take(80) {
                    let _ = writeln!(
                        out,
                        "    {:04x}: {:<22} {}",
                        i.offset, i.mnemonic, i.operand
                    );
                }
            }
        }
    }
    Ok(cap(out))
}
