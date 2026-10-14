//! Prints the analysis summary and one function of a file:
//! `cargo run -p orress-analysis --example disasm -- FILE [ADDRESS]`

use std::sync::Arc;

use orress_analysis::{Program, TokenKind};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: disasm FILE [ADDRESS]");
    let data = Arc::new(std::fs::read(&path).expect("readable file"));
    let info = orress_loaders::triage(&data);
    let strings = orress_bytes::strings::extract(&data, 4, 500_000);
    let start = std::time::Instant::now();
    let p = Program::analyze(&info, Arc::clone(&data), &strings).expect("supported architecture");
    println!(
        "{}: {} functions, {} instructions, {} lines, main={:x?} ({:?})",
        path,
        p.functions.len(),
        p.insns.len(),
        p.lines.len(),
        p.main,
        start.elapsed()
    );
    let addr = args
        .next()
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("hex address"))
        .or(p.main)
        .or(info.entry)
        .expect("an address");
    let f = p
        .function_containing(addr)
        .expect("a function at that address");
    println!(
        "\n{} ({} blocks)",
        p.name(f.entry).unwrap().text,
        f.blocks.len()
    );
    for block in &f.blocks {
        println!("  -- block {:x} -> {:x?}", block.start, block.succs);
        for &a in &block.insns {
            let insn = p.decode(a).unwrap();
            let ops: String = insn
                .operands
                .iter()
                .map(|t| match t.kind {
                    TokenKind::Address(x) => p.name(x).map_or(t.text.clone(), |n| n.text.clone()),
                    _ => t.text.clone(),
                })
                .collect();
            let comment = insn
                .data_refs
                .iter()
                .find_map(|r| p.string_refs.get(r))
                .map(|s| format!("  ; \"{s}\""))
                .unwrap_or_default();
            println!("  {a:x}  {:<8} {ops}{comment}", insn.mnemonic);
        }
    }
}
