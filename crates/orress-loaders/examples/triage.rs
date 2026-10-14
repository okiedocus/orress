//! Prints the triage summary of a file: `cargo run -p orress-loaders --example triage -- FILE`

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: triage FILE");
        std::process::exit(2);
    };
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let info = orress_loaders::triage(&data);
    println!("{path}");
    println!(
        "  format   {} / {} / {}",
        info.format.name(),
        info.kind.name(),
        info.arch
    );
    println!(
        "  entry    {:x?} (file offset {:x?})",
        info.entry,
        info.entry_offset()
    );
    println!("  sha256   {}", info.hashes.sha256);
    if let Some(imphash) = &info.hashes.imphash {
        println!("  imphash  {imphash}");
    }
    println!("  entropy  {:.2}", info.entropy);
    for s in &info.sections {
        println!(
            "  section  {:<10} off {:>8x} size {:>8x} va {:>12x} {} H={:.2}",
            s.name,
            s.offset,
            s.file_size,
            s.address,
            s.perms.label(),
            s.entropy.unwrap_or(0.0)
        );
    }
    println!(
        "  imports  {} / exports {}",
        info.imports.len(),
        info.exports.len()
    );
    for p in &info.protections {
        println!("  protect  {:<26} {:?} ({})", p.name, p.state, p.detail);
    }
    for d in &info.detections {
        println!(
            "  detect   {}: {} [{}]",
            d.category.name(),
            d.name,
            d.evidence
        );
    }
    for i in &info.insights {
        println!("  insight  {:?}: {}", i.level, i.title);
    }
    if let Some(e) = &info.parse_error {
        println!("  error    {e}");
    }
}
