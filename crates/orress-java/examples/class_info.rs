//! Prints a `.class` file's header, fields and methods with a JVM disassembly.
//!
//! Run with: `cargo run -p orress-java --example class_info -- path/to/File.class`

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: class_info <File.class>");
    let data = std::fs::read(&path).expect("read file");
    let cf = match orress_java::parse(&data) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    let flags = orress_java::access_flag_names(cf.access & !0x0020).join(" ");
    println!("{flags} class {} ({})", cf.this_class, cf.java_version());
    if let Some(s) = &cf.super_class {
        println!("  extends {s}");
    }
    for f in &cf.fields {
        let fl = orress_java::access_flag_names(f.access).join(" ");
        let cv = f
            .constant_value
            .map(|i| format!(" = {}", cf.cp.resolve(i)))
            .unwrap_or_default();
        println!("  field: {fl} {}: {}{cv}", f.name, f.descriptor);
    }
    for m in &cf.methods {
        let fl = orress_java::access_flag_names(m.access).join(" ");
        println!("\n  method: {fl} {}{}", m.name, m.descriptor);
        if let Some(code) = &m.code {
            for ins in orress_java::disassemble(code, &cf.cp) {
                let mark = if ins.is_branch_target { ">>" } else { "  " };
                println!(
                    "    {mark} {:>4}: {:<16} {}",
                    ins.offset, ins.mnemonic, ins.operands
                );
            }
        }
    }
}
