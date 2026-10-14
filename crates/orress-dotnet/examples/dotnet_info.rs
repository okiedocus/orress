//! Prints a .NET assembly's metadata and the IL of each method.
//! Run: cargo run -p orress-dotnet --example dotnet_info -- File.dll
fn main() {
    let p = std::env::args()
        .nth(1)
        .expect("usage: dotnet_info <File.dll>");
    let d = std::fs::read(&p).unwrap();
    let a = orress_dotnet::parse(&d).expect("parse");
    println!(
        "{} module={} asm={:?} · {} types · {} user strings",
        a.runtime_version,
        a.module_name,
        a.assembly_name,
        a.types.len(),
        a.user_strings.len()
    );
    for t in &a.types {
        if t.methods.is_empty() {
            continue;
        }
        println!("\ntype {}", t.full_name());
        for m in &t.methods {
            println!("  {} (rva {:#x})", m.name, m.rva);
            if let Ok(il) = a.disassemble(&d, m.rva) {
                for i in il.iter().take(40) {
                    let mark = if i.is_branch_target { ">>" } else { "  " };
                    println!(
                        "    {mark} IL_{:04x}: {:<12} {}",
                        i.offset, i.opcode, i.operand
                    );
                }
            }
        }
    }
}
