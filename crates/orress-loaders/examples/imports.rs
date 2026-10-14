//! Lists the imports of a file: `cargo run -p orress-loaders --example imports -- FILE`

fn main() {
    let path = std::env::args().nth(1).expect("usage: imports FILE");
    let info = orress_loaders::triage(&std::fs::read(&path).expect("readable file"));
    for i in &info.imports {
        println!("{}!{}", i.library, i.name);
    }
}
