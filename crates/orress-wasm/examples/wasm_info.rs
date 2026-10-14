//! Prints a WebAssembly module's overview and the head of its WAT disassembly.
//!
//! Run with: `cargo run -p orress-wasm --example wasm_info -- path/to/module.wasm`

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: wasm_info <file.wasm>");
    let data = std::fs::read(&path).expect("read file");
    if !orress_wasm::is_wasm(&data) {
        eprintln!("{path}: not a WebAssembly module");
        std::process::exit(1);
    }
    let m = orress_wasm::parse(&data);
    println!("{} — {}", path, m.summary());
    if let Some(e) = &m.parse_error {
        println!("parse error: {e}");
    }
    println!("\nimports:");
    for i in m.imports.iter().take(10) {
        println!("  {} {}.{}", i.kind.label(), i.module, i.name);
    }
    println!("\nexports:");
    for e in m.exports.iter().take(10) {
        println!("  {} {} [{}]", e.kind, e.name, e.index);
    }
    println!("\nfirst functions:");
    for f in m.functions.iter().take(8) {
        println!(
            "  #{} {} {} ({} locals, {} ops, {} bytes)",
            f.index,
            f.name.as_deref().unwrap_or("—"),
            f.sig.as_ref().map(|s| s.signature()).unwrap_or_default(),
            f.locals,
            f.ops,
            f.size
        );
    }

    match orress_wasm::disassemble(&data) {
        Ok(wat) => {
            println!("\nWAT (first 20 lines):");
            for line in wat.lines().take(20) {
                println!("  {line}");
            }
        }
        Err(e) => println!("disassemble failed: {e}"),
    }
}
