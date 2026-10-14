//! Runs the real orress-cli binary.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &[u8]) -> (bool, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_orress-cli"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary runs");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), out.stdout)
}

fn crackme(name: &str) -> String {
    format!(
        "{}/../../academy/crackmes/bin/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn recipe_and_shortcuts() {
    let (ok, out) = run(&["recipe", "to_base64 | from_base64 | rot13"], b"Hello");
    assert!(ok);
    assert_eq!(out, b"Uryyb");
    let (_, out) = run(&["xor", "-k", "0x01"], b"AB");
    assert_eq!(out, b"@C");
    let (_, out) = run(&["hex", "-d"], b"48 69");
    assert_eq!(out, b"Hi");
    let (ok, _) = run(&["recipe", "no_such_op"], b"");
    assert!(!ok, "bad recipes fail");
}

#[test]
fn magic_finds_the_flag() {
    let (_, encoded) = run(
        &["recipe", "xor key=0x33 | to_base64"],
        b"flag{piped_through_the_cli}",
    );
    let (ok, out) = run(&["magic"], &encoded);
    assert!(ok);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("flag{piped_through_the_cli}"), "{text}");
}

#[test]
fn analysis_commands_on_a_crackme() {
    let file = crackme("crackme02.exe");
    let (ok, out) = run(&["disasm", &file, "main"], b"");
    assert!(ok);
    assert!(String::from_utf8_lossy(&out).starts_with("main:"));
    let (ok, out) = run(&["info", &file, "--json"], b"");
    assert!(ok);
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["arch"], "x86-64");
    let (found, _) = run(&["bgrep", "4D 5A", &file], b"");
    assert!(found);
    let (found, _) = run(&["bgrep", "-t", "definitely not inside", &file], b"");
    assert!(!found, "bgrep exits with failure when nothing matches");
}

#[test]
fn patch_writes_a_copy() {
    let dir = std::env::temp_dir().join(format!("orress-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.bin");
    let output = dir.join("out.bin");
    std::fs::write(&input, b"\x74\x05AAAA").unwrap();
    let (ok, _) = run(
        &[
            "patch",
            input.to_str().unwrap(),
            "0",
            "75",
            "-o",
            output.to_str().unwrap(),
        ],
        b"",
    );
    assert!(ok);
    assert_eq!(std::fs::read(&output).unwrap(), b"\x75\x05AAAA");
    let (ok, _) = run(
        &[
            "patch",
            input.to_str().unwrap(),
            "0",
            "75",
            "-o",
            input.to_str().unwrap(),
        ],
        b"",
    );
    assert!(!ok, "never overwrites the input");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn huge_offsets_and_lengths_error_or_clamp_instead_of_panicking() {
    let dir = std::env::temp_dir().join(format!("orress-cli-ovf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.bin");
    std::fs::write(&input, b"ABCDEF").unwrap();
    let file = input.to_str().unwrap();

    // A length that would overflow `start + length` is clamped to the end of the file.
    let (ok, out) = run(&["slice", file, "2", "0xffffffffffffffff"], b"");
    assert!(ok);
    assert_eq!(out, b"CDEF");

    // A patch offset that would overflow is a clean error, not a panic.
    let out = Command::new(env!("CARGO_BIN_EXE_orress-cli"))
        .args([
            "patch",
            file,
            "0xffffffffffffffff",
            "7575",
            "-o",
            dir.join("out.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn decompile_prints_rust() {
    let file = crackme("crackme01.exe");
    let (ok, out) = run(&["decompile", &file], b"");
    assert!(ok);
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("fn main()"), "{text}");
    assert!(text.contains("\"open_sesame_101\""), "{text}");
}
