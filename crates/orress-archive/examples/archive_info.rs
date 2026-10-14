//! Lists a ZIP/JAR's entries and prints the JAR manifest, if present.
//!
//! Run with: `cargo run -p orress-archive --example archive_info -- path/to/app.jar`

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: archive_info <file.zip|.jar>");
    let data = std::fs::read(&path).expect("read file");
    let ar = match orress_archive::Archive::open(&data) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    println!("{path} — {} entries", ar.entries.len());
    for e in &ar.entries {
        if e.is_dir() {
            println!("  {}/", e.name.trim_end_matches('/'));
        } else {
            println!(
                "  {:<40} {:>8} bytes  ({} -> {})",
                e.name,
                e.uncompressed_size,
                e.method_name(),
                e.compressed_size
            );
        }
    }
    if let Some(entry) = ar.by_name("META-INF/MANIFEST.MF")
        && let Ok(mf) = ar.read(entry)
    {
        println!("\nManifest:");
        for (k, v) in orress_archive::parse_manifest(&mf) {
            println!("  {k}: {v}");
        }
    }
}
