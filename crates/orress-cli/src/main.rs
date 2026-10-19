//! orress-cli: ORRESS's engines on the command line.
//!
//! Inputs are files, or standard input when the file is omitted or `-`, so commands
//! chain with pipes:
//!
//! ```text
//! orress-cli slice crackme.exe 0x1840 64 | orress-cli xor -k 0x42 | orress-cli hex
//! orress-cli recipe "from_base64 | zlib_inflate" payload.txt
//! ```

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use orress_transforms::{Recipe, Step};

#[derive(Parser)]
#[command(
    name = "orress-cli",
    version,
    about = "ORRESS reverse-engineering tools on the command line"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// What is this file? Format, protections, detections, hashes, tips.
    Info {
        file: PathBuf,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Readable strings in a file.
    Strings {
        file: PathBuf,
        /// Minimum length.
        #[arg(short = 'n', long, default_value_t = 4)]
        min: usize,
        /// Only strings that look like CTF flags.
        #[arg(long)]
        flags: bool,
        /// Print the file offset of each string.
        #[arg(short = 'o', long)]
        offsets: bool,
    },
    /// List the functions ORRESS finds.
    Funcs { file: PathBuf },
    /// Detect VM-based obfuscation: functions whose shape is a bytecode interpreter dispatch loop.
    Vm { file: PathBuf },
    /// Disassemble a function: `main` (default), `entry`, a name or a hex address.
    Disasm {
        file: PathBuf,
        target: Option<String>,
    },
    /// Decompile a function to Rust-style pseudocode: `main` (default), `entry`, a name
    /// or a hex address.
    Decompile {
        file: PathBuf,
        target: Option<String>,
    },
    /// Run a Rhai script against a binary's analysis (functions, strings, bytes, disassembly).
    Script {
        file: PathBuf,
        /// Path to a `.rhai` script, or `-e CODE` to run inline code.
        script: PathBuf,
        /// Treat `script` as inline code rather than a file path.
        #[arg(short = 'e', long)]
        eval: bool,
    },
    /// Run a pwntools-style exploit script against a binary (tubes, packing, cyclic, ROP).
    Exploit {
        file: PathBuf,
        /// Path to a `.rhai` script, or `-e CODE` to run inline code.
        script: PathBuf,
        /// Treat `script` as inline code rather than a file path.
        #[arg(short = 'e', long)]
        eval: bool,
    },
    /// List the ROP gadgets in a binary (sequences ending in ret/syscall).
    Gadgets {
        file: PathBuf,
        /// Only show gadgets whose text contains this (case-insensitive).
        #[arg(long)]
        filter: Option<String>,
    },
    /// Find one-shot execve("/bin/sh") gadgets in a libc.
    OneGadget { file: PathBuf },
    /// Generate a FLIRT-style signature library from a binary that still has symbols.
    Sign {
        file: PathBuf,
        /// Write the library (JSON) here; default: stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Name library functions in a binary by matching a signature library from `sign`.
    Identify {
        file: PathBuf,
        /// The signature library (JSON).
        #[arg(long)]
        sigs: PathBuf,
    },
    /// Run a Workbench recipe, e.g. "from_base64 | xor key=0x41".
    Recipe {
        recipe: String,
        file: Option<PathBuf>,
    },
    /// Try to find a decoding recipe automatically.
    Magic {
        file: Option<PathBuf>,
        /// Maximum number of steps.
        #[arg(short, long, default_value_t = 3)]
        depth: usize,
    },
    /// List all Workbench operations and their parameters.
    Ops,
    /// XOR with a repeating key (text, 0x41..., or hex:41 42).
    Xor {
        #[arg(short, long)]
        key: String,
        file: Option<PathBuf>,
    },
    /// Base64 encode, or decode with -d.
    B64 {
        #[arg(short, long)]
        decode: bool,
        file: Option<PathBuf>,
    },
    /// Hex encode, or decode with -d.
    Hex {
        #[arg(short, long)]
        decode: bool,
        file: Option<PathBuf>,
    },
    /// URL encode, or decode with -d.
    Url {
        #[arg(short, long)]
        decode: bool,
        file: Option<PathBuf>,
    },
    /// RC4 encrypt/decrypt.
    Rc4 {
        #[arg(short, long)]
        key: String,
        file: Option<PathBuf>,
    },
    /// MD5, SHA-1, SHA-256 and CRC-32 of the input.
    Hash { file: Option<PathBuf> },
    /// Entropy of the input, overall and per block.
    Entropy {
        file: Option<PathBuf>,
        /// Block size for the per-block view (0 = overall only).
        #[arg(short, long, default_value_t = 0)]
        block: usize,
    },
    /// Copy bytes: OFFSET and optional LENGTH (decimal or 0x hex).
    Slice {
        file: PathBuf,
        offset: String,
        length: Option<String>,
    },
    /// Search files for a byte pattern (hex with ?? wildcards) or text (-t).
    Bgrep {
        pattern: String,
        files: Vec<PathBuf>,
        /// Search for text instead of hex bytes.
        #[arg(short, long)]
        text: bool,
    },
    /// Decode a timestamp: Unix seconds or Windows FILETIME.
    Tsdec { value: String },
    /// Write a patched copy: OFFSET HEXBYTES -o OUTPUT.
    Patch {
        file: PathBuf,
        offset: String,
        bytes: String,
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn read_input(file: Option<&PathBuf>) -> Result<Vec<u8>> {
    match file {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))
        }
        _ => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading standard input")?;
            Ok(buf)
        }
    }
}

fn write_out(bytes: &[u8]) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(bytes)?;
    out.flush()?;
    Ok(())
}

fn number(text: &str) -> Result<u64> {
    let t = text.trim().replace('_', "");
    let value = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse(),
    };
    value.with_context(|| format!("`{text}` is not a number"))
}

fn transform(step: Step, file: Option<&PathBuf>) -> Result<()> {
    let input = read_input(file)?;
    let out = step.apply(&input).map_err(anyhow::Error::msg)?;
    write_out(&out)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { file, json } => info(&file, json),
        Command::Strings {
            file,
            min,
            flags,
            offsets,
        } => {
            let data = read_input(Some(&file))?;
            for s in orress_bytes::strings::extract(&data, min, usize::MAX) {
                if flags && !orress_bytes::strings::looks_like_flag(&s.text) {
                    continue;
                }
                if offsets {
                    println!("0x{:08x}  {}", s.offset, s.text);
                } else {
                    println!("{}", s.text);
                }
            }
            Ok(())
        }
        Command::Funcs { file } => funcs(&file),
        Command::Vm { file } => vm(&file),
        Command::Script { file, script, eval } => run_script(&file, &script, eval),
        Command::Exploit { file, script, eval } => run_exploit(&file, &script, eval),
        Command::Gadgets { file, filter } => list_gadgets(&file, filter.as_deref()),
        Command::OneGadget { file } => one_gadget(&file),
        Command::Sign { file, out } => {
            let (_info, p) = analyze(&file)?;
            let lib = orress_sig::generate(&p);
            match out {
                Some(path) => {
                    std::fs::write(&path, lib.to_json())?;
                    eprintln!(
                        "{} signatures written to {}",
                        lib.signatures.len(),
                        path.display()
                    );
                }
                None => println!("{}", lib.to_json()),
            }
            Ok(())
        }
        Command::Identify { file, sigs } => {
            let (_info, p) = analyze(&file)?;
            let lib = orress_sig::Library::from_json(&std::fs::read_to_string(&sigs)?)
                .map_err(|e| anyhow::anyhow!(e))?;
            let found = orress_sig::identify(&p, &lib);
            for (addr, name) in &found {
                println!("0x{addr:x}  {name}");
            }
            eprintln!("{} functions identified", found.len());
            Ok(())
        }
        Command::Disasm { file, target } => disasm(&file, target.as_deref().unwrap_or("main")),
        Command::Decompile { file, target } => {
            let (info, p) = analyze(&file)?;
            let addr = resolve(&info, &p, target.as_deref().unwrap_or("main"))?;
            let conv = orress_decompiler::convention(info.format);
            let out =
                orress_decompiler::decompile(&p, addr, conv).map_err(|e| anyhow::anyhow!("{e}"))?;
            print!("{}", out.text());
            Ok(())
        }
        Command::Recipe { recipe, file } => {
            let recipe = Recipe::parse(&recipe).map_err(anyhow::Error::msg)?;
            let input = read_input(file.as_ref())?;
            let out = recipe.output(&input).map_err(anyhow::Error::msg)?;
            write_out(&out)
        }
        Command::Magic { file, depth } => {
            let input = read_input(file.as_ref())?;
            let suggestions = orress_transforms::magic(&input, depth);
            if suggestions.is_empty() {
                println!("Nothing found that is more readable than the input.");
            }
            for s in suggestions {
                let preview: String = String::from_utf8_lossy(&s.output)
                    .chars()
                    .take(70)
                    .collect();
                println!(
                    "{:<45}  {}  ({})",
                    s.recipe.to_string(),
                    preview.escape_debug(),
                    s.why
                );
            }
            Ok(())
        }
        Command::Ops => {
            for op in orress_transforms::ops() {
                let params: Vec<String> = op
                    .params
                    .iter()
                    .map(|p| format!("{}={}", p.name, p.default))
                    .collect();
                println!("{:<18} {:<12} {}", op.id, op.category.name(), op.explain);
                if !params.is_empty() {
                    let shown: Vec<String> = params
                        .iter()
                        .map(|p| p.chars().take(40).collect())
                        .collect();
                    println!("{:<31} params: {}", "", shown.join(", "));
                }
            }
            Ok(())
        }
        Command::Xor { key, file } => transform(Step::new("xor").with("key", &key), file.as_ref()),
        Command::B64 { decode, file } => transform(
            Step::new(if decode { "from_base64" } else { "to_base64" }),
            file.as_ref(),
        ),
        Command::Hex { decode, file } => transform(
            if decode {
                Step::new("from_hex")
            } else {
                Step::new("to_hex").with("separator", "")
            },
            file.as_ref(),
        ),
        Command::Url { decode, file } => transform(
            Step::new(if decode { "from_url" } else { "to_url" }),
            file.as_ref(),
        ),
        Command::Rc4 { key, file } => transform(Step::new("rc4").with("key", &key), file.as_ref()),
        Command::Hash { file } => {
            let input = read_input(file.as_ref())?;
            for op in ["md5", "sha1", "sha256", "crc32"] {
                let out = Step::new(op).apply(&input).map_err(anyhow::Error::msg)?;
                println!("{op:<7} {}", String::from_utf8_lossy(&out));
            }
            Ok(())
        }
        Command::Entropy { file, block } => {
            let input = read_input(file.as_ref())?;
            let e = orress_bytes::entropy::shannon(&input);
            println!(
                "{e:.3} bits per byte: {}",
                orress_bytes::entropy::describe(e)
            );
            if block > 0 {
                for (i, e) in orress_bytes::entropy::blocks(&input, block)
                    .iter()
                    .enumerate()
                {
                    let bar = "#".repeat((e * 4.0).round() as usize);
                    println!("0x{:08x}  {e:5.2}  {bar}", i * block);
                }
            }
            Ok(())
        }
        Command::Slice {
            file,
            offset,
            length,
        } => {
            let data = read_input(Some(&file))?;
            let start = number(&offset)? as usize;
            if start > data.len() {
                bail!(
                    "offset 0x{start:x} is past the end of the file (0x{:x} bytes)",
                    data.len()
                );
            }
            let end = match length {
                // A length past the end (even one that would overflow) is clamped to EOF.
                Some(l) => start.saturating_add(number(&l)? as usize).min(data.len()),
                None => data.len(),
            };
            write_out(&data[start..end])
        }
        Command::Bgrep {
            pattern,
            files,
            text,
        } => {
            let p = if text {
                orress_bytes::search::Pattern::text(&pattern, false)
            } else {
                orress_bytes::search::Pattern::parse_hex(&pattern)
            }
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut found = false;
            for file in &files {
                let data = read_input(Some(file))?;
                let mut pos = 0;
                while let Some(at) = p.find_from(&data, pos) {
                    println!("{}: 0x{at:08x}", file.display());
                    found = true;
                    pos = at + 1;
                }
            }
            if !found {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::Tsdec { value } => {
            let v = number(&value)?;
            println!(
                "as Unix time (seconds): {}",
                orress_bytes::inspect::format_unix(v as i64)
            );
            if v > 11_644_473_600 * 10_000_000 {
                let secs = (v / 10_000_000) as i64 - 11_644_473_600;
                println!(
                    "as Windows FILETIME:    {}",
                    orress_bytes::inspect::format_unix(secs)
                );
            }
            Ok(())
        }
        Command::Patch {
            file,
            offset,
            bytes,
            output,
        } => {
            if output == file {
                bail!("refusing to overwrite the input; choose another --output");
            }
            let mut data = read_input(Some(&file))?;
            let start = number(&offset)? as usize;
            let new = orress_transforms::parse_key(&format!("hex:{bytes}"))
                .map_err(anyhow::Error::msg)?;
            let end = start
                .checked_add(new.len())
                .context("the patch offset is out of range")?;
            if end > data.len() {
                bail!("the patch goes past the end of the file");
            }
            data[start..end].copy_from_slice(&new);
            std::fs::write(&output, &data)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "patched {} byte(s) at 0x{start:x}, wrote {}",
                new.len(),
                output.display()
            );
            Ok(())
        }
    }
}

fn info(file: &PathBuf, json: bool) -> Result<()> {
    let data = read_input(Some(file))?;
    let i = orress_loaders::triage(&data);
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "size": i.size,
            "format": i.format.name(),
            "kind": i.kind.name(),
            "arch": i.arch,
            "entry": i.entry,
            "image_base": i.image_base,
            "entropy": i.entropy,
            "hashes": { "md5": i.hashes.md5, "sha1": i.hashes.sha1, "sha256": i.hashes.sha256, "imphash": i.hashes.imphash },
            "sections": i.sections.iter().map(|s| serde_json::json!({
                "name": s.name, "offset": s.offset, "size": s.file_size, "address": s.address,
                "perms": s.perms.label(), "entropy": s.entropy,
            })).collect::<Vec<_>>(),
            "imports": i.imports.iter().map(|x| format!("{}!{}", x.library, x.name)).collect::<Vec<_>>(),
            "protections": i.protections.iter().map(|p| serde_json::json!({
                "name": p.name, "state": format!("{:?}", p.state), "detail": p.detail,
            })).collect::<Vec<_>>(),
            "detections": i.detections.iter().map(|d| serde_json::json!({
                "category": d.category.name(), "name": d.name, "evidence": d.evidence,
            })).collect::<Vec<_>>(),
            "insights": i.insights.iter().map(|x| serde_json::json!({
                "level": format!("{:?}", x.level), "title": x.title, "body": x.body,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!("{}", file.display());
    println!("  {} · {} · {}", i.format.name(), i.kind.name(), i.arch);
    println!(
        "  size {} bytes, entropy {:.2} ({})",
        i.size,
        i.entropy,
        orress_bytes::entropy::describe(i.entropy)
    );
    if let Some(e) = i.entry {
        println!("  entry point 0x{e:x}");
    }
    println!("  sha256 {}", i.hashes.sha256);
    for s in &i.sections {
        println!(
            "  section {:<10} {} offset 0x{:<8x} size 0x{:<8x} entropy {:.2}",
            s.name,
            s.perms.label(),
            s.offset,
            s.file_size,
            s.entropy.unwrap_or(0.0)
        );
    }
    for p in &i.protections {
        println!("  {:<26} {:?} ({})", p.name, p.state, p.detail);
    }
    for d in &i.detections {
        println!(
            "  detected {}: {} [{}]",
            d.category.name(),
            d.name,
            d.evidence
        );
    }
    for x in &i.insights {
        println!("  {:?}: {}", x.level, x.title);
    }
    Ok(())
}

fn analyze(file: &PathBuf) -> Result<(orress_loaders::BinaryInfo, orress_analysis::Program)> {
    let data = Arc::new(read_input(Some(file))?);
    let info = orress_loaders::triage(&data);
    let strings = orress_bytes::strings::extract(&data, 4, 500_000);
    let program = orress_analysis::Program::analyze(&info, Arc::clone(&data), &strings)
        .with_context(|| format!("cannot disassemble {} ({})", info.arch, file.display()))?;
    Ok((info, program))
}

fn run_script(file: &PathBuf, script: &PathBuf, eval: bool) -> Result<()> {
    let src = if eval {
        script.to_string_lossy().into_owned()
    } else {
        std::fs::read_to_string(script)
            .with_context(|| format!("cannot read script {}", script.display()))?
    };
    let data = Arc::new(read_input(Some(file))?);
    let info = orress_loaders::triage(&data);
    let strings = orress_bytes::strings::extract(&data, 4, 500_000);
    let program = orress_analysis::Program::analyze(&info, Arc::clone(&data), &strings)
        .with_context(|| format!("cannot analyze {}", file.display()))?;
    let strs: Vec<&str> = strings.iter().map(|s| s.text.as_str()).collect();
    match orress_script::run(&src, &program, &strs) {
        Ok(out) => {
            print!("{out}");
            if !out.ends_with('\n') {
                println!();
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("script error: {e}"),
    }
}

fn run_exploit(file: &PathBuf, script: &PathBuf, eval: bool) -> Result<()> {
    let src = if eval {
        script.to_string_lossy().into_owned()
    } else {
        std::fs::read_to_string(script)
            .with_context(|| format!("cannot read script {}", script.display()))?
    };
    let data = Arc::new(read_input(Some(file))?);
    let info = orress_loaders::triage(&data);
    let strings = orress_bytes::strings::extract(&data, 4, 500_000);
    let program = orress_analysis::Program::analyze(&info, Arc::clone(&data), &strings)
        .with_context(|| format!("cannot analyze {}", file.display()))?;
    let ctx = exploit_ctx(&info, &program, &data);

    // Stream the script's output to stdout as it runs.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let printer = std::thread::spawn(move || {
        for line in rx {
            print!("{line}");
        }
    });
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = orress_script::run_exploit(&src, ctx, tx, cancel);
    let _ = printer.join();
    match result {
        Ok(()) => Ok(()),
        Err(e) => anyhow::bail!("exploit error: {e}"),
    }
}

/// Builds the scripting context (symbols/GOT/PLT/exec sections) from a binary's analysis.
fn exploit_ctx(
    info: &orress_loaders::BinaryInfo,
    program: &orress_analysis::Program,
    data: &[u8],
) -> orress_script::ExploitCtx {
    use std::collections::HashMap;
    let mut symbols: HashMap<String, u64> = HashMap::new();
    for s in &info.function_symbols {
        symbols.entry(s.name.clone()).or_insert(s.address);
    }
    for e in &info.exports {
        if e.address != 0 {
            symbols.entry(e.name.clone()).or_insert(e.address);
        }
    }
    let got = info
        .import_slots
        .iter()
        .map(|s| (s.name.clone(), s.address))
        .collect();
    let mut plt: HashMap<String, u64> = HashMap::new();
    for f in program.functions.values() {
        if f.kind == orress_analysis::FunctionKind::Thunk
            && let Some(name) = program.name(f.entry)
            && let Some(base_name) = name.text.strip_suffix("@plt")
        {
            plt.entry(base_name.to_string()).or_insert(f.entry);
        }
    }
    let exec = info
        .sections
        .iter()
        .filter(|s| s.perms.execute)
        .filter_map(|s| Some((s.address, data.get(s.file_range()?)?.to_vec())))
        .collect();
    let binsh = orress_bytes::search::Pattern::text("/bin/sh", false)
        .ok()
        .and_then(|p| p.find_from(data, 0))
        .and_then(|off| info.offset_to_address(off as u64));
    let sections = info
        .sections
        .iter()
        .map(|s| (s.name.clone(), s.address))
        .collect();
    orress_script::ExploitCtx {
        base: info.image_base,
        isa: program.isa,
        symbols,
        got,
        plt,
        exec,
        binsh,
        sections,
    }
}

fn one_gadget(file: &PathBuf) -> Result<()> {
    let data = Arc::new(read_input(Some(file))?);
    let info = orress_loaders::triage(&data);
    let strings = orress_bytes::strings::extract(&data, 4, 500_000);
    let program = orress_analysis::Program::analyze(&info, Arc::clone(&data), &strings)
        .with_context(|| format!("cannot analyze {}", file.display()))?;
    let ctx = exploit_ctx(&info, &program, &data);
    let Some(binsh) = ctx.binsh else {
        anyhow::bail!("no \"/bin/sh\" string found in {}", file.display());
    };
    let execve: Vec<u64> = ["execve", "system"]
        .iter()
        .filter_map(|n| ctx.symbols.get(*n).copied())
        .collect();
    let sections: Vec<(u64, &[u8])> = ctx.exec.iter().map(|(a, b)| (*a, b.as_slice())).collect();
    let gadgets = orress_pwn::find_one_gadgets(&sections, binsh, &execve, ctx.isa);
    if gadgets.is_empty() {
        println!("no one_gadgets found");
    }
    for g in gadgets {
        let cons = if g.constraints.is_empty() {
            "(no outstanding constraints)".to_string()
        } else {
            g.constraints.join(", ")
        };
        println!("{:#x}  {cons}", g.addr);
    }
    Ok(())
}

fn list_gadgets(file: &PathBuf, filter: Option<&str>) -> Result<()> {
    let data = read_input(Some(file))?;
    let info = orress_loaders::triage(&data);
    let isa =
        orress_arch::Isa::from_arch_name(&info.arch, info.endian == orress_loaders::Endian::Little)
            .unwrap_or(orress_arch::Isa::X64);
    let sections: Vec<(u64, &[u8])> = info
        .sections
        .iter()
        .filter(|s| s.perms.execute)
        .filter_map(|s| Some((s.address, data.get(s.file_range()?)?)))
        .collect();
    let needle = filter.map(str::to_lowercase);
    for g in orress_pwn::find_gadgets(&sections, isa, 6) {
        if needle
            .as_deref()
            .is_none_or(|n| g.text.to_lowercase().contains(n))
        {
            println!("{:#x}  {}", g.addr, g.text);
        }
    }
    Ok(())
}

fn vm(file: &PathBuf) -> Result<()> {
    let (_, p) = analyze(file)?;
    let reports = orress_vm::scan(&p);
    if reports.is_empty() {
        println!("No VM-based obfuscation detected (no interpreter dispatch loop found).");
        return Ok(());
    }
    println!("{} likely VM interpreter(s):", reports.len());
    for r in &reports {
        let name = p
            .name(r.entry)
            .map_or_else(|| format!("sub_{:x}", r.entry), |n| n.text.clone());
        println!(
            "  {name} @ {:#x}: dispatcher {:#x}, {} handlers / {} blocks (fan-in {}), {:.0}% confidence",
            r.entry,
            r.dispatcher,
            r.handlers,
            r.blocks,
            r.max_fan_in,
            r.confidence * 100.0
        );
        let dis = orress_vm::disassemble(&p, r);
        if let Some(bc) = orress_vm::bytecode(&p, r) {
            // The program's true length is where its disassembly ends (at a halt), not the raw blob
            // extent (which can run into trailing data).
            let prog_len = dis
                .as_ref()
                .and_then(|d| d.last())
                .map_or(bc.len.unwrap_or(0) as usize, |i| {
                    i.offset + 1 + i.operands.len()
                });
            println!("    bytecode blob at {:#x} ({prog_len} bytes):", bc.base);
            if let Some(bytes) = p.memory.read(bc.base, prog_len) {
                for (i, chunk) in bytes.chunks(16).enumerate() {
                    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    println!("      {:04x}: {}", i * 16, hex.join(" "));
                }
            }
        }
        if let Some(dis) = &dis {
            println!("    bytecode disassembly ({} instructions):", dis.len());
            for ins in dis {
                let ops: Vec<String> = ins.operands.iter().map(|b| format!("{b:#04x}")).collect();
                println!(
                    "      {:04x}: op{:<3} {:<13} {}",
                    ins.offset,
                    ins.opcode,
                    ins.op,
                    ops.join(", ")
                );
            }
        }
        // The opcode table: the first step of devirtualization.
        let table = orress_vm::handlers(&p, r);
        if !table.is_empty() {
            println!("    opcode table ({} entries):", table.len());
            for h in &table {
                let ops = if h.ops.is_empty() {
                    "-".to_string()
                } else {
                    h.ops.join(", ")
                };
                println!(
                    "      op {:>3}: {:<13} handler {:#x} ({} insns)  [{ops}]",
                    h.opcode,
                    orress_vm::operation(h),
                    h.address,
                    h.insns
                );
            }
        }
        // The devirtualization payoff: concolically solve for the key that passes the interpreter.
        if let Some(sol) = orress_vm::solve(&p, r) {
            let shown = String::from_utf8_lossy(&sol.key);
            let status = if sol.complete { "verified" } else { "partial" };
            println!(
                "    recovered key ({status}, {} constraints): {:?}",
                sol.constraints, shown
            );
            if !sol.checks.is_empty() {
                println!("    lifted checks:");
                for c in &sol.checks {
                    println!("      {c}");
                }
            }
        }
    }
    Ok(())
}

fn funcs(file: &PathBuf) -> Result<()> {
    let (_, p) = analyze(file)?;
    for (entry, f) in &p.functions {
        let name = p
            .name(*entry)
            .map_or_else(|| format!("sub_{entry:x}"), |n| n.text.clone());
        println!(
            "0x{entry:x}  {name:<40} {:>6} bytes  {:>4} blocks  {:>4} callers",
            f.size(),
            f.blocks.len(),
            p.xrefs(*entry).len()
        );
    }
    Ok(())
}

fn resolve(
    info: &orress_loaders::BinaryInfo,
    p: &orress_analysis::Program,
    target: &str,
) -> Result<u64> {
    Ok(match target {
        "main" => p.main.context("no main function found; try `entry`")?,
        "entry" => info.entry.context("the file has no entry point")?,
        t => match p.names.iter().find(|(_, n)| n.text == t) {
            Some((&a, _)) => a,
            None => number(t)?,
        },
    })
}

fn disasm(file: &PathBuf, target: &str) -> Result<()> {
    let (info, p) = analyze(file)?;
    let addr = resolve(&info, &p, target)?;
    let f = p
        .function_containing(addr)
        .with_context(|| format!("no function at 0x{addr:x}"))?;
    let name = p
        .name(f.entry)
        .map_or_else(|| format!("sub_{:x}", f.entry), |n| n.text.clone());
    println!("{name}:  ; {} blocks", f.blocks.len());
    for block in &f.blocks {
        if block.start != f.entry {
            println!("loc_{:x}:", block.start);
        }
        for &a in &block.insns {
            let insn = p.decode(a).context("decode")?;
            let ops: String = insn
                .operands
                .iter()
                .map(|t| match t.kind {
                    orress_analysis::TokenKind::Address(x) => p.name(x).map_or_else(
                        || {
                            if p.labels.contains(&x) {
                                format!("loc_{x:x}")
                            } else {
                                t.text.clone()
                            }
                        },
                        |n| n.text.clone(),
                    ),
                    _ => t.text.clone(),
                })
                .collect();
            let comment = insn
                .data_refs
                .iter()
                .find_map(|r| p.string_refs.get(r))
                .map(|s| {
                    format!(
                        "  ; \"{}\"",
                        s.chars().take(50).collect::<String>().escape_debug()
                    )
                })
                .unwrap_or_default();
            println!("  {a:x}  {:<8} {ops}{comment}", insn.mnemonic);
        }
    }
    Ok(())
}
