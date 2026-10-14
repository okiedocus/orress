//! Prints a `.pyc` file's version, code-object tree and (for supported versions) a disassembly.
//!
//! Run with: `cargo run -p orress-pyc --example pyc_info -- path/to/module.pyc`

use orress_pyc::CodeObject;

fn main() {
    let path = std::env::args().nth(1).expect("usage: pyc_info <file.pyc>");
    let data = std::fs::read(&path).expect("read file");
    let pyc = match orress_pyc::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    println!("{} — {}", path, pyc.version_label());

    fn walk(c: &CodeObject, depth: usize, version: Option<(u8, u8)>) {
        let pad = "  ".repeat(depth);
        println!(
            "{pad}{} (args {}, {} consts, {} names, {} bytes)",
            c.qualname,
            c.argcount,
            c.consts.len(),
            c.names.len(),
            c.code.len()
        );
        if let Some(insns) = orress_pyc::disassemble(c, version) {
            for ins in insns.iter().take(12) {
                let arg = ins
                    .argval
                    .clone()
                    .or_else(|| ins.arg.map(|a| a.to_string()))
                    .unwrap_or_default();
                println!("{pad}    {:>4}  {:<24} {arg}", ins.offset, ins.opname);
            }
            if insns.len() > 12 {
                println!("{pad}    … {} more", insns.len() - 12);
            }
        }
        for n in c.nested() {
            walk(n, depth + 1, version);
        }
    }
    walk(&pyc.top, 0, pyc.version);
}
