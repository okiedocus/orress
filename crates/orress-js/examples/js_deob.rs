//! Deobfuscates a JavaScript file and lists its strings.
//!
//! Run with: `cargo run -p orress-js --example js_deob -- path/to/script.js`

fn main() {
    let path = std::env::args().nth(1).expect("usage: js_deob <script.js>");
    let src = std::fs::read_to_string(&path).expect("read file");
    println!("=== deobfuscated ===");
    println!("{}", orress_js::beautify(&orress_js::deobfuscate(&src)));
    println!("\n=== strings ===");
    for s in orress_js::extract_strings(&orress_js::deobfuscate(&src)) {
        println!("  {s:?}");
    }
}
