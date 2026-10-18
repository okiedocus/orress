//! Embeds every lesson (`academy/lessons/*.toml`) and glossary file
//! (`academy/glossary/*.toml`) so adding one needs no code change.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn toml_files(dir: &Path) -> Vec<PathBuf> {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    files
}

fn table(name: &str, files: &[PathBuf]) -> String {
    let mut out = format!("pub(crate) const {name}: &[(&str, &str)] = &[\n");
    for file in files {
        let file_name = file.file_name().unwrap().to_string_lossy();
        let path = file.display().to_string().replace('\\', "/");
        writeln!(out, "    ({file_name:?}, include_str!({path:?})),").unwrap();
    }
    out.push_str("];\n");
    out
}

fn main() {
    // Not canonicalized: on Windows that adds a `\\?\` prefix `include_str!` can't take.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../academy");
    let mut out = table("BUILT_IN", &toml_files(&root.join("lessons")));
    out.push_str(&table(
        "GLOSSARY_FILES",
        &toml_files(&root.join("glossary")),
    ));
    let out_dir = Path::new(&std::env::var("OUT_DIR").unwrap()).to_path_buf();
    std::fs::write(out_dir.join("academy_files.rs"), out).unwrap();
    std::fs::write(
        out_dir.join("crackme_files.rs"),
        crackmes(&root.join("crackmes")),
    )
    .unwrap();
}

/// `CRACKMES`: every `crackmes/<name>.rs` that has a built `crackmes/bin/<name>.exe`.
fn crackmes(dir: &Path) -> String {
    println!("cargo:rerun-if-changed={}", dir.display());
    println!("cargo:rerun-if-changed={}", dir.join("bin").display());
    let mut sources: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    sources.sort();
    let mut out = String::from("pub const CRACKMES: &[Crackme] = &[\n");
    for source in sources {
        let name = source.file_stem().unwrap().to_string_lossy().into_owned();
        let exe = dir.join("bin").join(format!("{name}.exe"));
        if !exe.exists() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", source.display());
        println!("cargo:rerun-if-changed={}", exe.display());
        let slash = |p: &Path| p.display().to_string().replace('\\', "/");
        writeln!(
            out,
            "    Crackme {{ name: {name:?}, file_name: \"{name}.exe\", \
             bytes: include_bytes!({:?}), source: include_str!({:?}) }},",
            slash(&exe),
            slash(&source)
        )
        .unwrap();
    }
    out.push_str("];\n");
    out
}
