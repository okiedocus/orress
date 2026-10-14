use std::path::PathBuf;
use std::sync::Arc;

use orress_analysis::Program;
use orress_loaders::{BinaryInfo, Format, Kind, NamedAddress, Perms, Section};

use crate::*;

const BASE: u64 = 0x40_1000;

/// A tiny ELF-like program with one function per `(name, code)` at 0x40 byte steps.
fn program(funcs: &[(&str, &[u8])]) -> Program {
    let mut code = vec![0xccu8; 0x1000];
    let mut symbols = Vec::new();
    for (i, (name, bytes)) in funcs.iter().enumerate() {
        let at = i * 0x40;
        code[at..at + bytes.len()].copy_from_slice(bytes);
        symbols.push(NamedAddress {
            address: BASE + at as u64,
            name: (*name).into(),
        });
    }
    let mut file = vec![0u8; 0x200];
    file.extend(&code);
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "x86-64".into(),
        bits: Some(64),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![Section {
            name: ".text".into(),
            offset: 0x200,
            file_size: 0x1000,
            address: BASE,
            virtual_size: 0x1000,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            entropy: None,
        }],
        function_symbols: symbols,
        ..BinaryInfo::default()
    };
    let data = Arc::new(file);
    Program::analyze(&info, data, &[]).expect("x86-64")
}

fn decompiled(funcs: &[(&str, &[u8])], index: usize) -> String {
    let p = program(funcs);
    let out = decompile(&p, BASE + index as u64 * 0x40, Convention::SysV).expect("decompiles");
    out.text()
}

fn ported(funcs: &[(&str, &[u8])], index: usize) -> String {
    let p = program(funcs);
    port(&p, BASE + index as u64 * 0x40, Convention::SysV).expect("ports")
}

/// Compiles `src` as a library with `rustc`. Returns `true` if it compiles (or rustc is absent).
/// Ports keep unlifted x86-64 instructions as `asm!`, which only an x86-64 host rustc accepts,
/// so on other hosts (e.g. Apple Silicon) such sources are skipped.
fn rustc_compiles(src: &str) -> bool {
    if !cfg!(target_arch = "x86_64") && src.contains("asm!") {
        eprintln!("skipping rustc check: x86-64 inline asm on a non-x86-64 host");
        return true;
    }
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let uniq = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("orress_port_{}_{uniq}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let f = dir.join("port.rs");
    std::fs::write(&f, src).unwrap();
    let out = std::process::Command::new("rustc")
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--emit=metadata",
            "-A",
            "warnings",
            "-o",
        ])
        .arg(dir.join("port.meta"))
        .arg(&f)
        .output();
    let ok = match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!(
                    "rustc rejected the port:\n{}\n{src}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            o.status.success()
        }
        Err(_) => true, // rustc not available in this environment → don't fail the test
    };
    let _ = std::fs::remove_dir_all(&dir);
    ok
}

#[test]
fn port_emits_a_compilable_scaffold() {
    // check(s: &[u8]) -> bool { s.len() == 7 && s[0] == b'R' }
    let code: &[u8] = &[
        0x48, 0x83, 0xfe, 0x07, // cmp rsi, 7
        0x75, 0x0b, // jne fail
        0x80, 0x3f, 0x52, // cmp byte [rdi], 'R'
        0x75, 0x06, // jne fail
        0xb8, 1, 0, 0, 0,    // mov eax, 1
        0xc3, // ret
        0x31, 0xc0, // fail: xor eax, eax
        0xc3, // ret
    ];
    let src = ported(&[("check", code)], 0);
    assert!(src.contains("mod orress_rt"), "{src}");
    assert!(src.contains("pub fn read<T"), "{src}");
    assert!(src.contains("fn check"), "{src}");
    assert!(rustc_compiles(&src));
}

#[test]
fn oversized_functions_are_refused() {
    let n = MAX_INSNS + 1;
    let mut code = vec![0x90u8; n]; // nop x (MAX_INSNS + 1)
    code.push(0xc3); // ret
    let mut file = vec![0u8; 0x200];
    file.extend(&code);
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "x86-64".into(),
        bits: Some(64),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![Section {
            name: ".text".into(),
            offset: 0x200,
            file_size: code.len() as u64,
            address: BASE,
            virtual_size: code.len() as u64,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            entropy: None,
        }],
        function_symbols: vec![NamedAddress {
            address: BASE,
            name: "huge".into(),
        }],
        ..BinaryInfo::default()
    };
    let p = Program::analyze(&info, Arc::new(file), &[]).expect("x86-64");
    let err = decompile(&p, BASE, Convention::SysV).unwrap_err();
    assert_eq!(
        err,
        Error::TooLarge {
            insns: n + 1,
            blocks: 1
        }
    );
    assert!(err.to_string().contains("too large"));
}

#[test]
fn port_mode_gotos_fail_loudly_instead_of_falling_through() {
    // An irreducible loop (entered at both L1 and L2), which the structurer can only express
    // with a goto.
    let code: &[u8] = &[
        0x89, 0xf8, // mov eax, edi
        0x85, 0xff, // test edi, edi
        0x74, 0x02, // jz L2
        0xff, 0xc0, // L1: inc eax
        0x83, 0xc0, 0x02, // L2: add eax, 2
        0x83, 0xf8, 0x0a, // cmp eax, 10
        0x72, 0xf6, // jb L1
        0xc3, // ret
    ];
    let text = decompiled(&[("irr", code)], 0);
    let src = ported(&[("irr", code)], 0);
    // Readable mode keeps the goto as a comment; port mode makes it a loud failure.
    assert!(text.contains("// goto label_"), "{text}");
    assert!(src.contains("unimplemented!(\"goto label_"), "{src}");
    assert!(!src.contains("// goto"), "{src}");
    assert!(rustc_compiles(&src), "{src}");
}

#[test]
fn lifts_rotate_bswap_popcnt_to_rust_methods() {
    // mov eax, edi ; rol eax, 7 ; ret
    let rol: &[u8] = &[0x89, 0xf8, 0xc1, 0xc0, 0x07, 0xc3];
    let s = decompiled(&[("rol", rol)], 0);
    assert!(s.contains("rotate_left"), "{s}");
    assert!(!s.contains("asm!"), "{s}");

    // mov eax, edi ; bswap eax ; ret
    let bswap: &[u8] = &[0x89, 0xf8, 0x0f, 0xc8, 0xc3];
    assert!(decompiled(&[("bs", bswap)], 0).contains("swap_bytes"));

    // popcnt eax, edi ; ret
    let popcnt: &[u8] = &[0xf3, 0x0f, 0xb8, 0xc7, 0xc3];
    assert!(decompiled(&[("pc", popcnt)], 0).contains("count_ones"));

    // The rotate case ports to compilable Rust (rotate_left is std).
    assert!(rustc_compiles(&ported(&[("rol", rol)], 0)));
}

#[test]
fn lifts_bit_test_with_carry_flag() {
    // bt edi, 3 ; setc al ; movzx eax, al ; ret   → returns (a1 >> 3) & 1 != 0
    let code: &[u8] = &[
        0x0f, 0xba, 0xe7, 0x03, // bt edi, 3
        0x0f, 0x92, 0xc0, // setb al  (setc)
        0x0f, 0xb6, 0xc0, // movzx eax, al
        0xc3, // ret
    ];
    let s = decompiled(&[("bit", code)], 0);
    assert!(s.contains(">> 3") && s.contains("& 1"), "{s}");
    assert!(!s.contains("asm!") && !s.contains("flags_"), "{s}");
    assert!(rustc_compiles(&ported(&[("bit", code)], 0)));
}

#[test]
fn port_stubs_external_calls_so_the_scaffold_compiles() {
    // caller: mov edi, 5; call callee; add eax, 1; ret    callee: lea eax, [rdi+rdi]; ret
    let caller: &[u8] = &[
        0xbf, 5, 0, 0, 0, // mov edi, 5
        0xe8, 0x36, 0, 0, 0, // call callee
        0x83, 0xc0, 0x01, // add eax, 1
        0xc3,
    ];
    let callee: &[u8] = &[0x8d, 0x04, 0x3f, 0xc3];
    // Porting just the caller leaves `callee` undefined, so it must be stubbed.
    let src = ported(&[("caller", caller), ("callee", callee)], 0);
    assert!(src.contains("fn callee<"), "{src}");
    assert!(src.contains("orress_rt::unknown(\"callee\")"), "{src}");
    // The stub makes the scaffold self-contained and compilable.
    assert!(rustc_compiles(&src));
    // Porting the callee itself defines it, so no self-stub is emitted.
    let callee_src = ported(&[("caller", caller), ("callee", callee)], 1);
    assert!(!callee_src.contains("fn callee<"), "{callee_src}");
}

#[test]
fn lifts_rep_movs_and_stos_to_memcpy_and_memset() {
    // copy(dst, src, n): mov rcx, rdx; rep movsb; ret   (SysV: rdi=dst, rsi=src, rdx=n)
    let movs: &[u8] = &[
        0x48, 0x89, 0xd1, // mov rcx, rdx
        0xf3, 0xa4, // rep movsb
        0xc3, // ret
    ];
    let s = decompiled(&[("copy", movs)], 0);
    assert!(s.contains("memcpy(a1, a2, a3)"), "{s}");
    assert!(!s.contains("asm!"), "{s}");
    assert!(rustc_compiles(&ported(&[("copy", movs)], 0)));

    // zero(dst, n): xor eax, eax; mov rcx, rsi; rep stosb; ret   (rdi=dst, rsi=n)
    let stos: &[u8] = &[
        0x31, 0xc0, // xor eax, eax
        0x48, 0x89, 0xf1, // mov rcx, rsi
        0xf3, 0xaa, // rep stosb
        0xc3, // ret
    ];
    let z = decompiled(&[("zero", stos)], 0);
    assert!(z.contains("memset(a1, 0, a2)"), "{z}");
    assert!(!z.contains("asm!"), "{z}");
    assert!(rustc_compiles(&ported(&[("zero", stos)], 0)));
}

#[test]
fn lifts_rep_cmps_to_memcmp() {
    // eq(a, b): mov rcx, rdx; repe cmpsb; sete al; movzx eax, al; ret
    //   (rdi=a, rsi=b, rdx=n) → returns memcmp(b, a, n) == 0
    let code: &[u8] = &[
        0x48, 0x89, 0xd1, // mov rcx, rdx
        0xf3, 0xa6, // repe cmpsb
        0x0f, 0x94, 0xc0, // sete al
        0x0f, 0xb6, 0xc0, // movzx eax, al
        0xc3, // ret
    ];
    let s = decompiled(&[("eq", code)], 0);
    assert!(s.contains("memcmp(") && s.contains("== 0"), "{s}");
    assert!(!s.contains("asm!"), "{s}");
    assert!(rustc_compiles(&ported(&[("eq", code)], 0)));
}

#[test]
fn lifts_repne_scasb_idiom_to_strlen() {
    // mystrlen(s): or rcx,-1; xor al,al; repne scasb; not rcx; dec rcx; mov rax,rcx; ret
    let code: &[u8] = &[
        0x48, 0x83, 0xc9, 0xff, // or rcx, -1
        0x30, 0xc0, // xor al, al
        0xf2, 0xae, // repne scasb
        0x48, 0xf7, 0xd1, // not rcx
        0x48, 0xff, 0xc9, // dec rcx
        0x48, 0x89, 0xc8, // mov rax, rcx
        0xc3, // ret
    ];
    let s = decompiled(&[("mystrlen", code)], 0);
    assert!(s.contains("strlen(a1)"), "{s}");
    assert!(!s.contains("__scasb") && !s.contains("asm!"), "{s}");
    assert!(rustc_compiles(&ported(&[("mystrlen", code)], 0)));
}

#[test]
fn lifts_shld_to_a_shift_or_expression() {
    // mov eax, edi ; mov edx, esi ; shld eax, edx, 4 ; ret
    let shld: &[u8] = &[0x89, 0xf8, 0x89, 0xf2, 0x0f, 0xa4, 0xd0, 0x04, 0xc3];
    let s = decompiled(&[("dsh", shld)], 0);
    assert!(
        s.contains("<<") && s.contains(">>") && s.contains('|'),
        "{s}"
    );
    assert!(!s.contains("asm!"), "{s}");
}

#[test]
fn port_keeps_unlifted_instructions_as_inline_asm() {
    // cpuid ; ret — cpuid isn't modelled, so it must survive as a faithful inline-asm block.
    let code: &[u8] = &[0x0f, 0xa2, 0xc3];
    let src = ported(&[("probe", code)], 0);
    assert!(src.contains("core::arch::asm!"), "{src}");
    assert!(src.contains("unsafe"), "{src}");
    assert!(src.contains("cpuid"), "{src}");
    // The registers cpuid writes are captured as outputs (rbx is excluded — LLVM reserves it —
    // so the block still compiles).
    assert!(
        src.contains("out(\"rax\") rax") && src.contains("out(\"rdx\") rdx"),
        "{src}"
    );
    assert!(!src.contains("\"rbx\""), "{src}");
    assert!(rustc_compiles(&src));
}

#[test]
fn slice_parameter_and_byte_compare() {
    // check(s: &[u8]) -> bool { s.len() == 7 && s[0] == b'R' }
    let code: &[u8] = &[
        0x48, 0x83, 0xfe, 0x07, // cmp rsi, 7
        0x75, 0x0b, // jne fail
        0x80, 0x3f, 0x52, // cmp byte [rdi], 'R'
        0x75, 0x06, // jne fail
        0xb8, 1, 0, 0, 0,    // mov eax, 1
        0xc3, // ret
        0x31, 0xc0, // fail: xor eax, eax
        0xc3, // ret
    ];
    let text = decompiled(&[("check", code)], 0);
    assert!(text.contains("fn check(a1: &[u8]) -> bool"), "{text}");
    assert!(text.contains("a1.len() != 7"), "{text}");
    assert!(text.contains("a1[0] != b'R'"), "{text}");
    assert!(
        text.contains("return true;") && text.contains("return false;"),
        "{text}"
    );
}

#[test]
fn sum_loop_collapses_to_iter_sum() {
    // sum(s: &[u8]) -> u32 { let mut t = 0; for i in 0..s.len() { t += s[i] } t }
    let code: &[u8] = &[
        0x31, 0xc0, // xor eax, eax
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0b, // jae done
        0x0f, 0xb6, 0x14, 0x0f, // movzx edx, byte [rdi+rcx]
        0x01, 0xd0, // add eax, edx
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xf0, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("sum", code)], 0);
    assert!(text.contains("fn sum(a1: &[u8]) -> u32"), "{text}");
    // The counted accumulation collapses to an iterator chain — no loop remains.
    assert!(
        text.contains("a1.iter().map(|&rcx| rcx as u32).sum()"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains("while"), "{text}");
    assert!(rustc_compiles(&ported(&[("sum", code)], 0)));
}

#[test]
fn non_sum_accumulation_collapses_to_fold() {
    // xor_all(s: &[u8]) -> u32 { let mut t = 0; for i in 0..s.len() { t ^= s[i] } t }
    // XOR isn't a sum/product, so it becomes a general `fold`.
    let code: &[u8] = &[
        0x31, 0xc0, // xor eax, eax
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0b, // jae done
        0x0f, 0xb6, 0x14, 0x0f, // movzx edx, byte [rdi+rcx]
        0x31, 0xd0, // xor eax, edx
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xf0, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("xor_all", code)], 0);
    assert!(
        text.contains("a1.iter().fold(0, |acc, &rcx| acc ^ rcx as u32)"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains(".sum()"), "{text}");
    assert!(rustc_compiles(&ported(&[("xor_all", code)], 0)));
}

#[test]
fn product_loop_collapses_to_iter_product() {
    // prod(s: &[u8]) -> u32 { let mut t = 1; for i in 0..s.len() { t *= s[i] } t }
    let code: &[u8] = &[
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0c, // jae done
        0x0f, 0xb6, 0x14, 0x0f, // movzx edx, byte [rdi+rcx]
        0x0f, 0xaf, 0xc2, // imul eax, edx
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xef, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("prod", code)], 0);
    assert!(
        text.contains("a1.iter().map(|&rcx| rcx as u32).product()"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains("while"), "{text}");
    assert!(rustc_compiles(&ported(&[("prod", code)], 0)));
}

#[cfg(feature = "compile-check")]
#[test]
fn compile_check_accepts_leaf_ports_and_flags_broken_code() {
    use crate::compile::{CompileStatus, check_port, check_source};

    // A leaf function's scaffold should compile (or rustc is absent).
    let check: &[u8] = &[
        0x48, 0x83, 0xfe, 0x07, 0x75, 0x0b, 0x80, 0x3f, 0x52, 0x75, 0x06, 0xb8, 1, 0, 0, 0, 0xc3,
        0x31, 0xc0, 0xc3,
    ];
    let p = program(&[("check", check)]);
    let (_src, report) = check_port(&p, BASE, Convention::SysV).expect("ports");
    assert!(
        matches!(
            report.status,
            CompileStatus::Compiles | CompileStatus::ToolMissing
        ),
        "{report:?}"
    );

    // Obviously broken Rust is reported as errors (unless rustc is missing).
    let bad = check_source("fn broken() -> u32 { \"not a number\" }");
    assert!(
        matches!(
            bad.status,
            CompileStatus::Errors | CompileStatus::ToolMissing
        ),
        "{bad:?}"
    );
    if bad.status == CompileStatus::Errors {
        assert!(!bad.diagnostics.is_empty());
    }
}

#[test]
fn for_loop_over_a_mut_slice_ports() {
    // fill(s: &mut [u8]) { for i in 0..s.len() { s[i] = 0 } }   (rdi=s, rsi=len)
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // cmp rcx, rsi
        0x73, 0x09, // jae done
        0xc6, 0x04, 0x0f, 0x00, // mov byte [rdi+rcx], 0
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xf2, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("fill", code)], 0);
    // A constant-store element loop collapses all the way to `s.fill(0)`.
    assert!(text.contains("a1.fill(0);"), "{text}");
    assert!(
        !text.contains("while") && !text.contains("a1[rcx]") && !text.contains("for "),
        "{text}"
    );
    assert!(rustc_compiles(&ported(&[("fill", code)], 0)));
}

#[test]
fn iter_mut_read_modify_write() {
    // inc(s: &mut [u8]) { for i in 0..s.len() { s[i] += 1 } }  (rdi=s, rsi=len)
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // cmp rcx, rsi
        0x73, 0x09, // jae done
        0x80, 0x04, 0x0f, 0x01, // add byte [rdi+rcx], 1
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xf2, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("inc", code)], 0);
    assert!(text.contains("for rcx in a1.iter_mut()"), "{text}");
    // The read-modify-write of s[i] through the element binding folds to `*rcx += 1`.
    assert!(text.contains("*rcx += 1;"), "{text}");
    assert!(
        !text.contains("a1[rcx]") && !text.contains("while"),
        "{text}"
    );
    assert!(rustc_compiles(&ported(&[("inc", code)], 0)));
}

#[test]
fn if_else() {
    let code: &[u8] = &[
        0x85, 0xff, // test edi, edi
        0x7e, 0x07, // jle neg
        0xb8, 1, 0, 0, 0, // mov eax, 1
        0xeb, 0x05, // jmp end
        0xb8, 2, 0, 0, 0,    // neg: mov eax, 2
        0xc3, // end: ret
    ];
    let text = decompiled(&[("sign", code)], 0);
    assert!(text.contains("fn sign(a1: i32) -> u32"), "{text}");
    assert!(text.contains("} else {"), "{text}");
    assert!(!text.contains("goto"), "{text}");
}

#[test]
fn calls_get_arguments() {
    // caller: mov edi, 5; call callee; add eax, 1; ret      callee: lea eax, [rdi+rdi]; ret
    let caller: &[u8] = &[
        0xbf, 5, 0, 0, 0, // mov edi, 5
        0xe8, 0x36, 0, 0, 0, // call callee (0x40 - 0x0a)
        0x83, 0xc0, 0x01, // add eax, 1
        0xc3,
    ];
    let callee: &[u8] = &[0x8d, 0x04, 0x3f, 0xc3];
    let text = decompiled(&[("caller", caller), ("callee", callee)], 0);
    assert!(text.contains("callee(5) + 1"), "{text}");
    let text = decompiled(&[("caller", caller), ("callee", callee)], 1);
    assert!(text.contains("fn callee(a1: u32) -> u32"), "{text}");
    assert!(text.contains("return a1 + a1;"), "{text}");
}

fn crackme(name: &str) -> Option<(BinaryInfo, Program)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../academy/crackmes/bin")
        .join(name);
    let data = Arc::new(std::fs::read(path).ok()?);
    let info = orress_loaders::triage(&data);
    let strings = orress_bytes::strings::extract(&data, 4, 500_000);
    let p = Program::analyze(&info, data, &strings)?;
    Some((info, p))
}

/// The password check is one of main's callees; find it by its decompiled shape.
fn decompiled_callees(info: &BinaryInfo, p: &Program) -> Vec<String> {
    let main = p.main.expect("main");
    p.functions[&main]
        .calls
        .iter()
        .filter_map(|&c| decompile(p, c, convention(info.format)).ok())
        .map(|o| o.text())
        .collect()
}

#[test]
fn crackme02_reads_like_the_source() {
    let Some((info, p)) = crackme("crackme02.exe") else {
        return; // built by academy/crackmes/build.ps1 (Windows only)
    };
    let callees = decompiled_callees(&info, &p);
    let check = callees
        .iter()
        .find(|t| t.contains("-> bool"))
        .expect("check_password decompiles to a bool function");
    assert!(check.contains("(a1: &[u8]) -> bool"), "{check}");
    assert!(check.contains("a1.len() != 7"), "{check}");
    for (i, c) in "R3v3rs3".chars().enumerate() {
        assert!(
            check.contains(&format!(
                "a1[{i}] {} b'{c}'",
                if i == 6 { "==" } else { "!=" }
            )),
            "{check}"
        );
    }
    assert!(!check.contains("goto"), "{check}");

    let main = decompile(&p, p.main.unwrap(), convention(info.format))
        .unwrap()
        .text();
    assert!(main.contains("fn main()"), "{main}");
    assert!(main.contains("\"Password: \""), "{main}");
    assert!(main.contains("\"Wrong password. Try again!\\n\""), "{main}");
    assert!(!main.contains("goto"), "{main}");
}

#[test]
fn crackme05_vm_dispatch_decompiles_to_a_switch() {
    // crackme05's check_password is a bytecode VM: a dispatch loop whose register-indirect `jmp`
    // goes through a recovered offset jump table. It must decompile to a structured `match` over
    // its cases, not an opaque indirect tail call.
    let Some((info, p)) = crackme("crackme05.exe") else {
        return; // built by academy/crackmes/build.ps1 (Windows only)
    };
    let (&jmp, cases) = p
        .switch_tables
        .iter()
        .find(|(_, c)| c.len() == 10)
        .expect("the 10-opcode VM dispatch table is recovered");
    let func = p
        .function_containing(jmp)
        .expect("dispatch belongs to a function");
    let text = decompile(&p, func.entry, convention(info.format))
        .unwrap()
        .text();
    assert!(
        text.contains("match "),
        "VM dispatch should decompile to a match:\n{text}"
    );
    // One arm per case, and the fetch loop around it.
    assert!(
        text.matches("=>").count() >= cases.len(),
        "a match arm per case:\n{text}"
    );
    assert!(text.contains("loop {"), "the dispatch is a loop:\n{text}");
    // The scrutinee is the opcode/index, not the clobbered jump-target load expression.
    assert!(
        !text.contains("match read::"),
        "switch scrutinee should be the opcode, not the table-load expression:\n{text}"
    );
    // The opcode is fetched once: the range check reuses the same variable the match switches on,
    // rather than reloading it (value numbering collapsed the black_box store/reload duplicate).
    let scrut = text
        .split("match ")
        .nth(1)
        .and_then(|s| s.split([' ', '\n', '{']).next())
        .expect("match scrutinee");
    assert!(
        text.contains(&format!("if {scrut} >")),
        "range check should reuse the fetched opcode `{scrut}`, not reload it:\n{text}"
    );
}

#[test]
fn crackme01_shows_the_password() {
    let Some((info, p)) = crackme("crackme01.exe") else {
        return;
    };
    let main = decompile(&p, p.main.unwrap(), convention(info.format))
        .unwrap()
        .text();
    assert!(main.contains("\"open_sesame_101\""), "{main}");
    assert!(main.contains("memcmp("), "{main}");
    assert!(!main.contains("goto"), "{main}");
}

#[test]
fn every_function_decompiles() {
    // No panics and no runaway output on real compiler output.
    for name in ["crackme01.exe", "crackme02.exe"] {
        let Some((info, p)) = crackme(name) else {
            return;
        };
        for &f in p.functions.keys() {
            if let Ok(out) = decompile(&p, f, convention(info.format)) {
                assert!(out.lines.len() < 20_000);
            }
        }
    }
}

#[test]
fn two_slice_map_becomes_zip() {
    // map1(dst: &mut [u8], src: &[u8]) { for i in 0..dst.len() { dst[i] = src[i] + 1 } }
    //   SysV: rdi=dst.ptr, rsi=dst.len, rdx=src.ptr; rcx is the counter.
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0f, // jae done
        0x0f, 0xb6, 0x04, 0x0a, // movzx eax, byte [rdx+rcx]
        0x83, 0xc0, 0x01, // add eax, 1
        0x88, 0x04, 0x0f, // mov byte [rdi+rcx], al
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xec, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("map1", code)], 0);
    // Two slices indexed in lock-step become a zipped `iter_mut` map.
    assert!(
        text.contains("for (rcx, &s) in a1.iter_mut().zip(a3)"),
        "{text}"
    );
    assert!(text.contains("*rcx = ") && text.contains("s "), "{text}");
    assert!(!text.contains("a1[") && !text.contains("a3["), "{text}");
    // The function is correctly void (the src-load temp is not mistaken for a return), so
    // there is no dead `rax = …` line and the port compiles.
    assert!(!text.contains("-> ") && !text.contains("return "), "{text}");
    assert!(rustc_compiles(&ported(&[("map1", code)], 0)));
}

#[test]
fn max_loop_collapses_to_fold_max() {
    // max_of(s: &[u8]) -> u32 { let mut m = 0; for i.. { if s[i] > m { m = s[i] } } m }
    //   via cmov: movzx edx,[rdi+rcx]; cmp eax,edx; cmovb eax,edx  (eax = max unsigned)
    let code: &[u8] = &[
        0x31, 0xc0, // xor eax, eax
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0e, // jae done
        0x0f, 0xb6, 0x14, 0x0f, // movzx edx, byte [rdi+rcx]
        0x39, 0xd0, // cmp eax, edx
        0x0f, 0x42, 0xc2, // cmovb eax, edx
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xed, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("max_of", code)], 0);
    // The cmov becomes `.max`, then the accumulation collapses to a fold.
    assert!(
        text.contains("a1.iter().fold(0, |acc, &rcx| acc.max(rcx as u32))"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains("if "), "{text}");
    assert!(rustc_compiles(&ported(&[("max_of", code)], 0)));
}

#[test]
fn index_and_element_use_becomes_enumerate() {
    // wsum(s: &[u8]) -> u64 { let mut acc=0; for i in 0..s.len() { acc += i * s[i] } acc }
    let code: &[u8] = &[
        0x31, 0xc0, // xor eax, eax
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x10, // jae done
        0x0f, 0xb6, 0x14, 0x0f, // movzx edx, byte [rdi+rcx]
        0x48, 0x0f, 0xaf, 0xd1, // imul rdx, rcx
        0x48, 0x01, 0xd0, // add rax, rdx
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xeb, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("wsum", code)], 0);
    // Using the counter both to index and as a value yields `enumerate`.
    assert!(
        text.contains("for (rcx, &x) in a1.iter().enumerate()"),
        "{text}"
    );
    assert!(text.contains("rax += ") && text.contains("rcx"), "{text}");
    assert!(!text.contains("a1[rcx]"), "{text}");
    // (`enumerate` binds the index as `usize`; where the recovered arithmetic is a fixed
    // width the port needs index casts before it compiles — a readability win for now.)
}

#[test]
fn search_loop_becomes_any() {
    // has_r(s: &[u8]) -> bool { for i in 0..s.len() { if s[i] == b'R' { return true } } false }
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x11, // jae notfound
        0x80, 0x3c, 0x0f, 0x52, // cmp byte [rdi+rcx], 'R'
        0x75, 0x06, // jne cont
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xc3, // ret
        0x48, 0xff, 0xc1, // cont: inc rcx
        0xeb, 0xea, // jmp top
        0x31, 0xc0, // notfound: xor eax, eax
        0xc3, // ret
    ];
    let text = decompiled(&[("has_r", code)], 0);
    assert!(
        text.contains("return a1.iter().any(|&rcx| rcx == b'R');"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains("while"), "{text}");
    assert!(rustc_compiles(&ported(&[("has_r", code)], 0)));
}

#[test]
fn search_loop_becomes_all() {
    // all_r(s: &[u8]) -> bool { for i in 0..s.len() { if s[i] != b'R' { return false } } true }
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0e, // jae alltrue
        0x80, 0x3c, 0x0f, 0x52, // cmp byte [rdi+rcx], 'R'
        0x74, 0x03, // je cont
        0x31, 0xc0, // xor eax, eax  (return false)
        0xc3, // ret
        0x48, 0xff, 0xc1, // cont: inc rcx
        0xeb, 0xed, // jmp top
        0xb8, 0x01, 0x00, 0x00, 0x00, // alltrue: mov eax, 1
        0xc3, // ret
    ];
    let text = decompiled(&[("all_r", code)], 0);
    assert!(
        text.contains("return a1.iter().all(|&rcx| rcx == b'R');"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains("while"), "{text}");
    assert!(rustc_compiles(&ported(&[("all_r", code)], 0)));
}

#[test]
fn search_loop_becomes_find() {
    // first_ge(s: &[u8]) -> u8 { for i in 0..s.len() { if s[i] >= 10 { return s[i] } } 0 }
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x0d, // jae none
        0x8a, 0x04, 0x0f, // mov al, [rdi+rcx]
        0x3c, 0x0a, // cmp al, 10
        0x72, 0x01, // jb cont
        0xc3, // ret  (return al)
        0x48, 0xff, 0xc1, // cont: inc rcx
        0xeb, 0xee, // jmp top
        0x31, 0xc0, // none: xor eax, eax
        0xc3, // ret
    ];
    let text = decompiled(&[("first_ge", code)], 0);
    assert!(text.contains("fn first_ge(a1: &[u8]) -> u8"), "{text}");
    assert!(
        text.contains("return a1.iter().copied().find(|&rcx| rcx >= 10).unwrap_or(0);"),
        "{text}"
    );
    assert!(!text.contains("for ") && !text.contains("while"), "{text}");
    // The byte return type is no longer inflated by the wider register, so the port compiles.
    assert!(rustc_compiles(&ported(&[("first_ge", code)], 0)));
}

#[test]
fn keyed_max_loop_becomes_select_fold() {
    // maxk(s: &[u8]) { let mut best=0; for x in s { if (x&0xf) > (best&0xf) { best=x } } best }
    let code: &[u8] = &[
        0x31, 0xc0, // xor eax, eax
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // top: cmp rcx, rsi
        0x73, 0x1d, // jae done
        0x0f, 0xb6, 0x14, 0x0f, // movzx edx, byte [rdi+rcx]
        0x44, 0x8b, 0xc2, // mov r8d, edx
        0x41, 0x83, 0xe0, 0x0f, // and r8d, 0xf
        0x41, 0x89, 0xc1, // mov r9d, eax
        0x41, 0x83, 0xe1, 0x0f, // and r9d, 0xf
        0x45, 0x39, 0xc8, // cmp r8d, r9d
        0x0f, 0x47, 0xc2, // cmova eax, edx
        0x48, 0xff, 0xc1, // inc rcx
        0xeb, 0xde, // jmp top
        0xc3, // done: ret
    ];
    let text = decompiled(&[("maxk", code)], 0);
    // A keyed comparison (max_by) folds with an `if/else` picking the better element.
    assert!(text.contains("a1.iter().fold(0, |acc, &rcx| if "), "{text}");
    assert!(text.contains("{ rcx as u32 } else { acc }"), "{text}");
    assert!(!text.contains("for ") && !text.contains("while"), "{text}");
    assert!(rustc_compiles(&ported(&[("maxk", code)], 0)));
}

#[test]
fn byte_return_is_not_widened_to_the_register() {
    // head(s) -> u8 { *s }   mov al, [rdi]; ret  — returns a byte, not a u64.
    let code: &[u8] = &[0x8a, 0x07, 0xc3];
    let text = decompiled(&[("head", code)], 0);
    assert!(text.contains("-> u8"), "{text}");
    assert!(rustc_compiles(&ported(&[("head", code)], 0)));
}

#[test]
fn signed_accumulator_is_signed() {
    // ssum(s: &[u8]) -> i32 { let mut t=0; for i { t += s[i] as i8 as i32 } t }  (movsx)
    let code: &[u8] = &[
        0x31, 0xc0, 0x31, 0xc9, 0x48, 0x39, 0xf1, 0x73, 0x0b, //
        0x0f, 0xbe, 0x14, 0x0f, // movsx edx, byte [rdi+rcx]
        0x01, 0xd0, 0x48, 0xff, 0xc1, 0xeb, 0xf0, 0xc3,
    ];
    let text = decompiled(&[("ssum", code)], 0);
    // The sign-extending load makes the accumulator and return signed, so the port compiles
    // (a `u32` would reject `Sum<i32>`).
    assert!(text.contains("fn ssum(a1: &[i8]) -> i32"), "{text}");
    assert!(
        text.contains("a1.iter().map(|&rcx| rcx as i32).sum()"),
        "{text}"
    );
    assert!(rustc_compiles(&ported(&[("ssum", code)], 0)));
}

#[test]
fn signed_vs_unsigned_division() {
    // divs(a, b) { a / b } signed:   mov eax,edi; cdq; idiv esi; ret
    let s: &[u8] = &[0x89, 0xf8, 0x99, 0xf7, 0xfe, 0xc3];
    let ts = decompiled(&[("divs", s)], 0);
    // The idiv operands make the parameters signed, so it reads as a plain signed divide.
    assert!(ts.contains("fn divs(a1: i32, a2: i32) -> i32"), "{ts}");
    assert!(ts.contains("return a1 / a2;"), "{ts}");
    assert!(rustc_compiles(&ported(&[("divs", s)], 0)));

    // divu(a, b) { a / b } unsigned:   mov eax,edi; xor edx,edx; div esi; ret
    let u: &[u8] = &[0x89, 0xf8, 0x31, 0xd2, 0xf7, 0xf6, 0xc3];
    let tu = decompiled(&[("divu", u)], 0);
    assert!(tu.contains("fn divu(a1: u32, a2: u32) -> u32"), "{tu}");
    assert!(tu.contains("return a1 / a2;"), "{tu}");
    assert!(rustc_compiles(&ported(&[("divu", u)], 0)));
}

#[test]
fn nested_loops_probe() {
    // fill2(s: &mut [u8]) { for i in 0..s.len() { for j in 0..s.len() { s[j] = 0 } } }
    let code: &[u8] = &[
        0x31, 0xc9, // xor ecx, ecx
        0x48, 0x39, 0xf1, // outer: cmp rcx, rsi
        0x73, 0x15, // jae done
        0x31, 0xd2, // xor edx, edx
        0x48, 0x39, 0xf2, // inner: cmp rdx, rsi
        0x73, 0x09, // jae inner_done
        0xc6, 0x04, 0x17, 0x00, // mov byte [rdi+rdx], 0
        0x48, 0xff, 0xc2, // inc rdx
        0xeb, 0xf2, // jmp inner
        0x48, 0xff, 0xc1, // inner_done: inc rcx
        0xeb, 0xe6, // jmp outer
        0xc3, // done: ret
    ];
    let text = decompiled(&[("fill2", code)], 0);
    // Both levels recover: an outer repeat loop (counter unused → `_`) around an inner constant
    // fill, which collapses to `a1.fill(0)`.
    assert!(text.contains("for _ in 0..a1.len()"), "{text}");
    assert!(text.contains("a1.fill(0);"), "{text}");
    assert!(rustc_compiles(&ported(&[("fill2", code)], 0)));
}

#[test]
fn flattened_2d_probe() {
    // at(m, cols, i, j) -> u8 { m[i*cols + j] }
    //   rdi=m.ptr, rsi=m.len, rdx=cols, rcx=i, r8=j
    let code: &[u8] = &[
        0x48, 0x89, 0xc8, // mov rax, rcx       (i)
        0x48, 0x0f, 0xaf, 0xc2, // imul rax, rdx (i*cols)
        0x4c, 0x01, 0xc0, // add rax, r8         (+ j)
        0x0f, 0xb6, 0x04, 0x07, // movzx eax, byte [rdi+rax]
        0xc3, // ret
    ];
    let text = decompiled(&[("at", code)], 0);
    // A flattened 2D access reads as the row-major index; the readable view stays clean.
    assert!(text.contains("a1[a4 * a3 + a5]"), "{text}");
    // The port casts the index to usize so slice indexing type-checks.
    let port = ported(&[("at", code)], 0);
    assert!(port.contains("a1[(a4 * a3 + a5) as usize]"), "{port}");
    assert!(rustc_compiles(&port));
}

#[test]
fn asm_binds_a_known_input_register() {
    // mov eax, 1 ; cpuid ; ret — the leaf (eax = 1) must reach the asm as an input, not be
    // dead-eliminated, and no hardware register cpuid reads should become a parameter.
    let code: &[u8] = &[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc3];
    let port = ported(&[("probe", code)], 0);
    assert!(port.contains("fn probe() -> u64"), "{port}"); // no spurious params
    // The leaf flows in and the result is captured back out.
    assert!(port.contains("inout(\"rax\") 1 as u64 => rax"), "{port}");
    assert!(rustc_compiles(&port));
}

#[test]
fn lifts_bit_scan_and_bmi() {
    // bsf eax, edi ; ret  → trailing_zeros
    let bsf: &[u8] = &[0x0f, 0xbc, 0xc7, 0xc3];
    assert!(
        decompiled(&[("f", bsf)], 0).contains("trailing_zeros"),
        "{}",
        decompiled(&[("f", bsf)], 0)
    );
    // bsr eax, edi ; ret  → leading_zeros expression
    let bsr: &[u8] = &[0x0f, 0xbd, 0xc7, 0xc3];
    let s = decompiled(&[("f", bsr)], 0);
    assert!(s.contains("leading_zeros") && s.contains("- "), "{s}");
    // andn eax, ecx, edx ; ret  → !ecx & edx
    let andn: &[u8] = &[0xc4, 0xe2, 0x70, 0xf2, 0xc2, 0xc3];
    let a = decompiled(&[("f", andn)], 0);
    assert!(a.contains("!a4 & a3") && !a.contains("asm!"), "{a}");
}

#[test]
fn lifts_blsr_movbe() {
    // blsr eax, ecx ; ret  → x & (x - 1)
    let blsr: &[u8] = &[0xc4, 0xe2, 0x78, 0xf3, 0xc9, 0xc3];
    let b = decompiled(&[("f", blsr)], 0);
    assert!(b.contains("a4 & a4 - 1") && !b.contains("asm!"), "{b}");
    // movbe eax, [rdi] ; ret  → (*a1).swap_bytes()
    let movbe: &[u8] = &[0x0f, 0x38, 0xf0, 0x07, 0xc3];
    let m = decompiled(&[("f", movbe)], 0);
    assert!(
        m.contains("(*a1).swap_bytes()") && !m.contains("asm!"),
        "{m}"
    );
    assert!(rustc_compiles(&ported(&[("f", movbe)], 0)));
}

#[test]
fn lea_multiply_idiom() {
    // lea eax, [rdi + rdi*4] ; ret  → x * 5
    let code: &[u8] = &[0x8d, 0x04, 0xbf, 0xc3];
    let s = decompiled(&[("mul5", code)], 0);
    assert!(s.contains("return a1 * 5;"), "{s}");
}

#[test]
fn jump_table_becomes_match() {
    // switch(i): if i > 3 -> default (255); else dispatch via jump table.
    let mut blob = vec![0u8; 0xa0];
    let code: &[u8] = &[
        0x83, 0xff, 0x03, // 00: cmp edi, 3
        0x77, 0x1f, // 03: ja  +0x1f -> 0x24 (default)
        0xff, 0x24, 0xfd, 0x80, 0x10, 0x40, 0x00, // 05: jmp [rdi*8 + 0x401080]
        0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, // 0c: case0 mov eax,10; ret
        0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3, // 12: case1 mov eax,20; ret
        0xb8, 0x1e, 0x00, 0x00, 0x00, 0xc3, // 18: case2 mov eax,30; ret
        0xb8, 0x28, 0x00, 0x00, 0x00, 0xc3, // 1e: case3 mov eax,40; ret
        0xb8, 0xff, 0x00, 0x00, 0x00, 0xc3, // 24: default mov eax,255; ret
    ];
    blob[..code.len()].copy_from_slice(code);
    for (i, &off) in [0x0cu64, 0x12, 0x18, 0x1e].iter().enumerate() {
        let addr = (BASE + off).to_le_bytes();
        blob[0x80 + i * 8..0x88 + i * 8].copy_from_slice(&addr);
    }
    let s = decompiled(&[("switch", &blob)], 0);
    assert!(s.contains("if a1 > 3 {"), "missing bounds guard:\n{s}");
    assert!(s.contains("match a1 {"), "missing match:\n{s}");
    assert!(s.contains("0 => {"), "missing case 0:\n{s}");
    assert!(s.contains("3 => {"), "missing case 3:\n{s}");
    assert!(s.contains("return 20;"), "missing case-1 body:\n{s}");
    assert!(s.contains("_ => {}"), "missing default arm:\n{s}");
}

#[test]
fn float_arithmetic_and_conversions() {
    // addc(x: f64) = x + 2.5, with 2.5 in a rip-relative literal pool.
    let mut addc = vec![0xccu8; 0x18];
    addc[..9].copy_from_slice(&[0xF2, 0x0F, 0x58, 0x05, 0x08, 0x00, 0x00, 0x00, 0xC3]);
    addc[0x10..0x18].copy_from_slice(&2.5f64.to_le_bytes());

    let cases: &[(&str, &[u8])] = &[
        ("scale", &[0xF2, 0x0F, 0x59, 0xC1, 0xC3]), // mulsd xmm0,xmm1; ret
        ("to_f", &[0xF2, 0x0F, 0x2A, 0xC7, 0xC3]),  // cvtsi2sd xmm0,edi; ret
        ("trunc", &[0xF2, 0x0F, 0x2C, 0xC0, 0xC3]), // cvttsd2si eax,xmm0; ret
        ("root", &[0xF2, 0x0F, 0x51, 0xC0, 0xC3]),  // sqrtsd xmm0,xmm0; ret
        ("addc", &addc),
    ];

    let scale = decompiled(cases, 0);
    assert!(
        scale.contains("fn scale(a1: f64, a2: f64) -> f64"),
        "{scale}"
    );
    assert!(scale.contains("return a1 * a2;"), "{scale}");

    let to_f = decompiled(cases, 1);
    assert!(to_f.contains("fn to_f(a1: i32) -> f64"), "{to_f}");
    assert!(to_f.contains("return a1 as f64;"), "{to_f}");

    let trunc = decompiled(cases, 2);
    assert!(trunc.contains("fn trunc(a1: f64) -> i32"), "{trunc}");
    assert!(trunc.contains("return a1 as i32;"), "{trunc}");

    let root = decompiled(cases, 3);
    assert!(root.contains("return a1.sqrt();"), "{root}");

    let addc_s = decompiled(cases, 4);
    assert!(addc_s.contains("return a1 + 2.5;"), "{addc_s}");

    for i in 0..cases.len() {
        assert!(
            rustc_compiles(&ported(cases, i)),
            "case {i} did not compile"
        );
    }
}

#[test]
fn float_compare_and_branch() {
    // maxish(x, y): if x > y { x } else { y }  — comisd sets float flags; jbe reads them.
    let code: &[u8] = &[
        0x66, 0x0F, 0x2F, 0xC1, // comisd xmm0, xmm1
        0x76, 0x01, // jbe else
        0xC3, // ret (return x)
        0xF2, 0x0F, 0x10, 0xC1, // else: movsd xmm0, xmm1
        0xC3, // ret (return y)
    ];
    let text = decompiled(&[("maxish", code)], 0);
    assert!(
        text.contains("fn maxish(a1: f64, a2: f64) -> f64"),
        "{text}"
    );
    assert!(text.contains("if a1 <= a2 {"), "{text}");
    assert!(
        text.contains("return a2;") && text.contains("return a1;"),
        "{text}"
    );
    assert!(!text.contains("xmm0"), "raw xmm register leaked:\n{text}");
    assert!(rustc_compiles(&ported(&[("maxish", code)], 0)));
}

#[test]
fn struct_pointer_recovery() {
    // getter(p): return p->flag (u8 @0) + p->count (u32 @4) — mixed widths => struct.
    let getter: &[u8] = &[0x0F, 0xB6, 0x07, 0x8B, 0x57, 0x04, 0x01, 0xD0, 0xC3];
    let g = decompiled(&[("getter", getter)], 0);
    assert!(g.contains("struct Struct1 {"), "{g}");
    assert!(
        g.contains("field_0: u8,") && g.contains("field_4: u32,"),
        "{g}"
    );
    assert!(g.contains("fn getter(a1: &Struct1) -> u32"), "{g}");
    assert!(g.contains("a1.field_0 as u32 + a1.field_4"), "{g}");
    assert!(
        rustc_compiles(&ported(&[("getter", getter)], 0)),
        "getter port"
    );

    // setter(p): p->flag@0 = 1 (byte); p->x@8 = 2 (qword) — written => &mut Struct.
    let setter: &[u8] = &[
        0xC6, 0x07, 0x01, 0x48, 0xC7, 0x47, 0x08, 0x02, 0x00, 0x00, 0x00, 0xC3,
    ];
    let s = decompiled(&[("setter", setter)], 0);
    assert!(s.contains("fn setter(a1: &mut Struct1)"), "{s}");
    assert!(
        s.contains("a1.field_0 = 1;") && s.contains("a1.field_8 = 2;"),
        "{s}"
    );
    assert!(
        rustc_compiles(&ported(&[("setter", setter)], 0)),
        "setter port"
    );
}

fn program_arm(funcs: &[(&str, &[u8])]) -> Program {
    let mut code = vec![0u8; 0x1000];
    let mut symbols = Vec::new();
    for (i, (name, bytes)) in funcs.iter().enumerate() {
        let at = i * 0x40;
        code[at..at + bytes.len()].copy_from_slice(bytes);
        symbols.push(NamedAddress {
            address: BASE + at as u64,
            name: (*name).into(),
        });
    }
    let mut file = vec![0u8; 0x200];
    file.extend(&code);
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "ARM64 (AArch64)".into(),
        bits: Some(64),
        entry: Some(BASE),
        image_base: 0x40_0000,
        sections: vec![Section {
            name: ".text".into(),
            offset: 0x200,
            file_size: 0x1000,
            address: BASE,
            virtual_size: 0x1000,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            entropy: None,
        }],
        function_symbols: symbols,
        ..BinaryInfo::default()
    };
    Program::analyze(&info, Arc::new(file), &[]).expect("arm64")
}

fn arm_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn decompiled_arm(funcs: &[(&str, &[u8])], index: usize) -> String {
    let p = program_arm(funcs);
    decompile(&p, BASE + index as u64 * 0x40, Convention::SysV)
        .expect("decompiles")
        .text()
}

#[test]
fn arm_arithmetic_and_select() {
    let add2 = arm_words(&[0x8b010000, 0xd65f03c0]); // add x0,x0,x1; ret
    let smul = arm_words(&[0x9b017c00, 0x91000c00, 0xd65f03c0]); // mul; add #3; ret
    let maxi = arm_words(&[0xeb01001f, 0x9a81c000, 0xd65f03c0]); // cmp; csel gt; ret
    let cases: &[(&str, &[u8])] = &[("add2", &add2), ("smul", &smul), ("maxi", &maxi)];

    assert!(
        decompiled_arm(cases, 0).contains("return a1 + a2;"),
        "{}",
        decompiled_arm(cases, 0)
    );
    assert!(
        decompiled_arm(cases, 1).contains("return a1 * a2 + 3;"),
        "{}",
        decompiled_arm(cases, 1)
    );
    assert!(
        decompiled_arm(cases, 2).contains("(a1).max(a2)"),
        "{}",
        decompiled_arm(cases, 2)
    );
}

#[test]
fn arm_pac_returns_and_branches() {
    let add_retab = arm_words(&[0x8b010000, 0xd65f0fff]); // add x0,x0,x1; retab
    let tail_brabz = arm_words(&[0xd61f0c3f]); // brabz x1
    let call_blrabz = arm_words(&[0xd63f0c3f, 0xd65f03c0]); // blrabz x1; ret
    let cases: &[(&str, &[u8])] = &[
        ("add2", &add_retab),
        ("tail", &tail_brabz),
        ("call", &call_blrabz),
    ];
    let a = decompiled_arm(cases, 0);
    assert!(a.contains("return a1 + a2;"), "{a}");
    assert!(!a.contains("asm!"), "{a}");
    for i in 1..3 {
        let t = decompiled_arm(cases, i);
        assert!(!t.contains("brabz") && !t.contains("blrabz"), "{t}");
        assert!(t.contains("(a2)("), "{t}");
    }
}

#[test]
fn arm_pointer_walk_loop_becomes_iterator() {
    // sum(s, n): a counted pointer-walk loop (`p += 4; n -= 1; until n == 0`) summing `*p`.
    // It recovers as `&[u32]` slice iteration, not a raw pointer loop.
    let sum = arm_words(&[
        0x34000121, 0xaa0003e8, 0x2a1f03e0, 0x2a0103e9, 0xb840450a, 0xf1000529, 0x0b000140,
        0x54ffffa1, 0xd65f03c0, 0x2a1f03e0, 0xd65f03c0,
    ]);
    let text = decompiled_arm(&[("sum", &sum)], 0);
    assert!(
        text.contains("fn sum(a1: &[u32]) -> u32"),
        "slice not recovered:\n{text}"
    );
    assert!(
        text.contains("a1.iter().sum()"),
        "not folded to sum:\n{text}"
    );
    assert!(
        text.contains("if a1.len() == 0 {"),
        "length param not recovered:\n{text}"
    );
    // No raw pointer walk survives.
    assert!(
        !text.contains("x8 +=") && !text.contains("+= 4") && !text.contains("read::<"),
        "{text}"
    );
    assert!(
        !text.contains("loop {") && !text.contains("while "),
        "loop not recovered:\n{text}"
    );
}

#[test]
fn struct_field_signedness() {
    // p->sbyte (i8 @0, via movsx) + p->count (u32 @4): the sign-extended load types field_0 i8.
    let code: &[u8] = &[0x0F, 0xBE, 0x07, 0x03, 0x47, 0x04, 0xC3];
    let text = decompiled(&[("getter", code)], 0);
    assert!(
        text.contains("field_0: i8,") && text.contains("field_4: u32,"),
        "{text}"
    );
}

#[test]
fn movq_gpr_xmm_bitcast() {
    // bits(x): f64::from_bits(x)  — movq xmm0, rdi; ret
    let code: &[u8] = &[0x66, 0x48, 0x0F, 0x6E, 0xC7, 0xC3];
    let text = decompiled(&[("bits", code)], 0);
    assert!(text.contains("return f64::from_bits(a1);"), "{text}");
    assert!(
        rustc_compiles(&ported(&[("bits", code)], 0)),
        "port must compile"
    );
}

#[test]
fn float_spill_typed_f64() {
    // A computed double (x+x) spilled to the stack declares as f64, not an integer.
    let code: &[u8] = &[
        0x50, 0x66, 0x0f, 0x28, 0xc8, 0xf2, 0x0f, 0x58, 0xc8, 0xf2, 0x0f, 0x11, 0x0c, 0x24, 0xe8,
        0x00, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x58, 0x04, 0x24, 0x58, 0xc3,
    ];
    let text = decompiled(&[("f", code)], 0);
    assert!(
        text.contains("local_8: f64;") && text.contains("local_8 = a1 + a1;"),
        "{text}"
    );
}

#[test]
fn arm_scalar_float() {
    fn wrds(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|x| x.to_le_bytes()).collect()
    }
    let scale = wrds(&[0x1e610800, 0xd65f03c0]);
    let addc = wrds(&[0x1e609001, 0x1e612800, 0xd65f03c0]);
    let tof = wrds(&[0x1e620000, 0xd65f03c0]);
    let trunc = wrds(&[0x1e780000, 0xd65f03c0]);
    let maxd = wrds(&[0x1e612000, 0x1e61cc00, 0xd65f03c0]);
    let cases: &[(&str, &[u8])] = &[
        ("scale", &scale),
        ("addc", &addc),
        ("tof", &tof),
        ("trunc", &trunc),
        ("maxd", &maxd),
    ];

    assert!(decompiled_arm(cases, 0).contains("fn scale(a1: f64, a2: f64) -> f64"));
    assert!(decompiled_arm(cases, 0).contains("return a1 * a2;"));
    assert!(decompiled_arm(cases, 1).contains("return a1 + 2.5;"));
    assert!(decompiled_arm(cases, 2).contains("fn tof(a1: i32) -> f64"));
    assert!(decompiled_arm(cases, 2).contains("return a1 as f64;"));
    assert!(decompiled_arm(cases, 3).contains("fn trunc(a1: f64) -> i32"));
    assert!(decompiled_arm(cases, 3).contains("return a1 as i32;"));
    assert!(
        decompiled_arm(cases, 4).contains("return a1.max(a2);"),
        "{}",
        decompiled_arm(cases, 4)
    );

    // A float port compiles.
    let p = program_arm(cases);
    let src = port(&p, BASE, Convention::SysV).expect("ports");
    assert!(rustc_compiles(&src), "{src}");
}

#[test]
fn arm_mutable_pointer_walk_becomes_iter_mut() {
    // inc(p, n): while(n--) { *p += 1; p++; }  — a writing pointer walk over the argument reg.
    let inc = arm_words(&[
        0x340000c1, 0xb9400008, 0x71000421, 0x11000508, 0xb8004408, 0x54ffff81, 0xd65f03c0,
    ]);
    let text = decompiled_arm(&[("inc", &inc)], 0);
    assert!(
        text.contains("fn inc(a1: &mut [u32])"),
        "not &mut slice:\n{text}"
    );
    assert!(text.contains(".iter_mut()"), "no iter_mut:\n{text}");
    assert!(
        text.contains("*x0 += 1;"),
        "compound element write not recovered:\n{text}"
    );
    assert!(
        !text.contains("-> u64") && !text.contains("return x0"),
        "spurious return:\n{text}"
    );
    assert!(
        !text.contains("loop {") && !text.contains("+= 4"),
        "pointer walk left raw:\n{text}"
    );
    assert!(
        rustc_compiles(&ported_arm(&[("inc", &inc)], 0)),
        "iter_mut port must compile"
    );
}

fn ported_arm(funcs: &[(&str, &[u8])], index: usize) -> String {
    let p = program_arm(funcs);
    port(&p, BASE + index as u64 * 0x40, Convention::SysV).expect("ports")
}

#[test]
fn arm_fill_loop_becomes_fill() {
    // fill7(p, n): while(n--) *p++ = 7;  — a constant-store pointer walk → `s.fill(7)`.
    let fill7 = arm_words(&[
        0x340000a1, 0x528000e8, 0x71000421, 0xb8004408, 0x54ffffc1, 0xd65f03c0,
    ]);
    let text = decompiled_arm(&[("fill7", &fill7)], 0);
    assert!(text.contains("fn fill7(a1: &mut [u32])"), "{text}");
    assert!(text.contains("a1.fill(7);"), "fill not recovered:\n{text}");
    assert!(
        !text.contains("iter_mut") && !text.contains("for "),
        "loop left:\n{text}"
    );
    assert!(
        rustc_compiles(&ported_arm(&[("fill7", &fill7)], 0)),
        "fill port must compile"
    );
}

#[test]
fn simd_packed_ops_lift_to_vectors() {
    // vadd3(a, b, out): *out = *a + *b  (packed dwords — movdqu/paddd/movdqu).
    let code: &[u8] = &[
        0xF3, 0x0F, 0x6F, 0x07, // movdqu xmm0, [rdi]
        0xF3, 0x0F, 0x6F, 0x0E, // movdqu xmm1, [rsi]
        0x66, 0x0F, 0xFE, 0xC1, // paddd xmm0, xmm1
        0xF3, 0x0F, 0x7F, 0x02, // movdqu [rdx], xmm0
        0xC3,
    ];
    let text = decompiled(&[("vadd3", code)], 0);
    assert!(
        text.contains("fn vadd3(a1: u64, a2: u64, a3: u64)"),
        "{text}"
    );
    assert!(
        text.contains("vstore(a3, vadd(vload::<u32, 4>(a1), vload::<u32, 4>(a2)))"),
        "{text}"
    );
    assert!(!text.contains("asm!") && !text.contains("-> f32"), "{text}");
    // The packed-vector scaffold compiles.
    assert!(
        rustc_compiles(&ported(&[("vadd3", code)], 0)),
        "simd port must compile"
    );
}

#[test]
fn simd_horizontal_sum_recovers() {
    // hsum4(p) = p[0]+p[1]+p[2]+p[3]: a packed load + pshufd/paddd reduce + movd extract.
    let code: &[u8] = &[
        0xF3, 0x0F, 0x6F, 0x07, // movdqu xmm0, [rdi]
        0x66, 0x0F, 0x70, 0xC8, 0xEE, // pshufd xmm1, xmm0, 0xee
        0x66, 0x0F, 0xFE, 0xC8, // paddd xmm1, xmm0
        0x66, 0x0F, 0x70, 0xC1, 0x55, // pshufd xmm0, xmm1, 0x55
        0x66, 0x0F, 0xFE, 0xC1, // paddd xmm0, xmm1
        0x66, 0x0F, 0x7E, 0xC0, // movd eax, xmm0
        0xC3,
    ];
    let text = decompiled(&[("hsum4", code)], 0);
    assert!(
        text.contains("vload::<u32, 4>(a1).iter().sum::<u32>()"),
        "{text}"
    );
    assert!(
        !text.contains("to_bits") && !text.contains("vshuffle") && !text.contains("asm!"),
        "{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("hsum4", code)], 0)),
        "hsum port must compile"
    );
}

#[test]
fn reused_register_splits_into_distinct_vars() {
    // rcx is reused for two disjoint, multiply-used values; each becomes its own variable.
    let code: &[u8] = &[
        0x48, 0x8b, 0x0f, // mov rcx, [rdi]
        0x48, 0x89, 0x0e, // mov [rsi], rcx
        0x48, 0x89, 0x4e, 0x08, // mov [rsi+8], rcx
        0x48, 0x8b, 0x4f, 0x10, // mov rcx, [rdi+16]
        0x48, 0x89, 0x4e, 0x10, // mov [rsi+16], rcx
        0x48, 0x89, 0x4e, 0x18, // mov [rsi+24], rcx
        0xc3,
    ];
    let text = decompiled(&[("f", code)], 0);
    // The two live ranges of rcx become rcx_1 and rcx_2 (not one confusingly-reused `rcx`).
    assert!(
        text.contains("rcx_1") && text.contains("rcx_2"),
        "not split:\n{text}"
    );
    assert!(
        text.contains("rcx_1 = ") && text.contains("rcx_2 = "),
        "{text}"
    );
}

#[test]
fn return_register_splits_from_scratch_reuse() {
    // rax holds a multiply-used scratch (2*p[0], stored twice), then is reused as the return
    // value (p[3]). Splitting keeps the returned value as `rax` and renames the scratch.
    let code: &[u8] = &[
        0x8b, 0x07, // mov eax, [rdi]
        0x01, 0xc0, // add eax, eax
        0x89, 0x47, 0x04, // mov [rdi+4], eax
        0x89, 0x47, 0x08, // mov [rdi+8], eax
        0x8b, 0x47, 0x0c, // mov eax, [rdi+12]
        0xc3,
    ];
    let text = decompiled(&[("f", code)], 0);
    // The scratch value gets its own name; the return reads p[3], not the scratch.
    assert!(text.contains("rax_"), "scratch not split:\n{text}");
    assert!(
        text.contains("return a1[3];"),
        "return not separated:\n{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("f", code)], 0)),
        "port must compile"
    );
}

#[test]
fn vectorized_sum_recovers_iter_sum() {
    // The real clang -O2 vectorised reduction: n==0 guard, n<8 dispatch, a packed-SSE2 loop,
    // horizontal reduce, and a scalar remainder loop sharing the tail. The reduction analysis
    // proves the vector prefix s[0..i] plus the scalar remainder s[i..len] cover the whole slice
    // and folds the lot to `s.iter().sum()`.
    let code: &[u8] = &[
        0x85, 0xf6, 0x74, 0x0d, 0x89, 0xf1, 0x83, 0xfe, 0x08, 0x73, 0x09, 0x31, 0xd2, 0x31, 0xc0,
        0xeb, 0x5f, 0x31, 0xc0, 0xc3, 0x89, 0xca, 0x83, 0xe2, 0xf8, 0x48, 0x8d, 0x04, 0x8d, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x83, 0xe0, 0xe0, 0x66, 0x0f, 0xef, 0xc0, 0x31, 0xf6, 0x66, 0x0f,
        0xef, 0xc9, 0x90, 0xf3, 0x0f, 0x6f, 0x14, 0x37, 0x66, 0x0f, 0xfe, 0xca, 0xf3, 0x0f, 0x6f,
        0x54, 0x37, 0x10, 0x66, 0x0f, 0xfe, 0xc2, 0x48, 0x83, 0xc6, 0x20, 0x48, 0x39, 0xf0, 0x75,
        0xe4, 0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0x70, 0xc8, 0xee, 0x66, 0x0f, 0xfe, 0xc8, 0x66,
        0x0f, 0x70, 0xc1, 0x55, 0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0x7e, 0xc0, 0x39, 0xca, 0x74,
        0x11, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x03, 0x04, 0x97, 0x48, 0xff, 0xc2, 0x48, 0x39,
        0xd1, 0x75, 0xf5, 0xc3,
    ];
    let text = decompiled(&[("sum", code)], 0);
    assert!(text.contains("fn sum(a1: &[u32]) -> u32"), "{text}");
    assert!(
        text.contains("return a1.iter().sum();"),
        "not folded to iter().sum():\n{text}"
    );
    // The entire vectorised scaffold is gone — no loop, no vector ops, no goto.
    assert!(
        !text.contains("loop") && !text.contains("vload") && !text.contains("goto"),
        "{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("sum", code)], 0)),
        "folded port must compile"
    );
}

#[test]
fn product_reduction_recovers() {
    // prod(s): t = 1; for x in s { t *= x }  (ARM pointer-walk) → s.iter().product().
    let prod = arm_words(&[
        0x34000121, 0xaa0003e8, 0x2a0103e9, 0x52800020, 0xb840450a, 0xf1000529, 0x1b007d40,
        0x54ffffa1, 0xd65f03c0, 0x52800020, 0xd65f03c0,
    ]);
    let text = decompiled_arm(&[("prod", &prod)], 0);
    assert!(text.contains("fn prod(a1: &[u32]) -> u32"), "{text}");
    assert!(
        text.contains("a1.iter().product();"),
        "product not recovered:\n{text}"
    );
    assert!(
        text.contains("return 1;"),
        "empty-product identity missing:\n{text}"
    );
    assert!(
        !text.contains("loop") && !text.contains("*="),
        "loop not folded:\n{text}"
    );
}

#[test]
fn vectorised_max_blend_folds_to_reduction() {
    // The full integer max pipeline: the SSE2 compare-and-blend (pcmpgtd/pand/pandn/por) lifts to
    // `VecMax`, and the semantic reducer then proves the whole function is a slice max and folds it
    // to `s.iter().copied().reduce(|a, b| a.max(b)).unwrap()` — the vector scaffold is discarded.
    let code: &[u8] = &[
        0x8b, 0x07, 0x83, 0xfe, 0x02, 0x0f, 0x82, 0xe5, 0x00, 0x00, 0x00, 0x89, 0xf1, 0xba, 0x01,
        0x00, 0x00, 0x00, 0x83, 0xfe, 0x09, 0x0f, 0x82, 0xc5, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x71,
        0xff, 0x49, 0x89, 0xf0, 0x49, 0x83, 0xe0, 0xf8, 0x49, 0x8d, 0x50, 0x01, 0x66, 0x0f, 0x6e,
        0xc0, 0x66, 0x0f, 0x70, 0xc0, 0x00, 0x31, 0xc0, 0x66, 0x0f, 0x6f, 0xc8, 0x0f, 0x1f, 0x80,
        0x00, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x6f, 0x54, 0x87, 0x04, 0xf3, 0x0f, 0x6f, 0x5c, 0x87,
        0x14, 0x66, 0x0f, 0x6f, 0xe2, 0x66, 0x0f, 0x66, 0xe0, 0x66, 0x0f, 0xdb, 0xd4, 0x66, 0x0f,
        0xdf, 0xe0, 0x66, 0x0f, 0x6f, 0xc4, 0x66, 0x0f, 0xeb, 0xc2, 0x66, 0x0f, 0x6f, 0xd3, 0x66,
        0x0f, 0x66, 0xd1, 0x66, 0x0f, 0xdb, 0xda, 0x66, 0x0f, 0xdf, 0xd1, 0x66, 0x0f, 0x6f, 0xca,
        0x66, 0x0f, 0xeb, 0xcb, 0x48, 0x83, 0xc0, 0x08, 0x49, 0x39, 0xc0, 0x75, 0xbb, 0x66, 0x0f,
        0x6f, 0xd0, 0x66, 0x0f, 0x66, 0xd1, 0x66, 0x0f, 0xdb, 0xc2, 0x66, 0x0f, 0xdf, 0xd1, 0x66,
        0x0f, 0xeb, 0xd0, 0x66, 0x0f, 0x70, 0xc2, 0xee, 0x66, 0x0f, 0x6f, 0xca, 0x66, 0x0f, 0x66,
        0xc8, 0x66, 0x0f, 0xdb, 0xd1, 0x66, 0x0f, 0xdf, 0xc8, 0x66, 0x0f, 0xeb, 0xca, 0x66, 0x0f,
        0x70, 0xc1, 0x55, 0x66, 0x0f, 0x6f, 0xd1, 0x66, 0x0f, 0x66, 0xd0, 0x66, 0x0f, 0xdb, 0xca,
        0x66, 0x0f, 0xdf, 0xd0, 0x66, 0x0f, 0xeb, 0xd1, 0x66, 0x0f, 0x7e, 0xd0, 0x4c, 0x39, 0xc6,
        0x74, 0x1c, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b,
        0x34, 0x97, 0x39, 0xc6, 0x0f, 0x4f, 0xc6, 0x48, 0xff, 0xc2, 0x48, 0x39, 0xd1, 0x75, 0xf0,
        0xc3,
    ];
    let text = decompiled(&[("maxv", code)], 0);
    // The whole function folds to a slice max reduction (proving blend → VecMax → reduction).
    assert!(
        text.contains("fn maxv(a1: &[i32]) -> i32"),
        "signature wrong:\n{text}"
    );
    assert!(
        text.contains("a1.iter().copied().reduce(|a, b| a.max(b)).unwrap()"),
        "max reduction not recovered:\n{text}"
    );
    // The vector scaffold, blend ops and raw asm are all discarded.
    assert!(
        !text.contains("loop") && !text.contains("vmax(") && !text.contains("vgt("),
        "scaffold not discarded:\n{text}"
    );
    assert!(
        !text.contains("pcmpgtd") && !text.contains("asm!(\"pand"),
        "{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("maxv", code)], 0)),
        "folded max port must compile"
    );
}

#[test]
fn packed_float_elementwise_multiply() {
    // clang -O2 of `void mulv(float* c, const float* a, const float* b, unsigned n)` with
    // `c[i] = a[i] * b[i]`: a packed `mulps` loop (movups/mulps/movups) + a scalar `mulss` tail.
    // The packed body lifts to `vmul` over **f32** lanes (not u32) — the packed-float lifting.
    // (Typing the slice parameters themselves as `&[f32]` so the whole port compiles is the next
    // step: it needs float-aware slice inference and float scalar-tail indexing.)
    let code: &[u8] = &[
        0x85, 0xC9, 0x74, 0x63, 0x89, 0xC8, 0x83, 0xF9, 0x04, 0x73, 0x04, 0x31, 0xC9, 0xEB, 0x41,
        0x89, 0xC1, 0x83, 0xE1, 0xFC, 0x4C, 0x8D, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x49, 0x83,
        0xE0, 0xF0, 0x45, 0x31, 0xC9, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x42, 0x0F, 0x10, 0x04, 0x0E, 0x42, 0x0F, 0x10, 0x0C, 0x0A, 0x0F, 0x59,
        0xC8, 0x42, 0x0F, 0x11, 0x0C, 0x0F, 0x49, 0x83, 0xC1, 0x10, 0x4D, 0x39, 0xC8, 0x75, 0xE5,
        0x39, 0xC1, 0x74, 0x18, 0x90, 0xF3, 0x0F, 0x10, 0x04, 0x8E, 0xF3, 0x0F, 0x59, 0x04, 0x8A,
        0xF3, 0x0F, 0x11, 0x04, 0x8F, 0x48, 0xFF, 0xC1, 0x48, 0x39, 0xC8, 0x75, 0xE9, 0xC3, 0x0F,
        0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let text = decompiled(&[("mulv", code)], 0);
    // The packed float multiply lifts to `vmul` over f32 lanes (vload_slice typed `::<f32, 4>`),
    // not an integer op and not left as inline asm.
    assert!(
        text.contains("vmul("),
        "packed float multiply not lifted:\n{text}"
    );
    assert!(
        text.contains("vload_slice::<f32, 4>"),
        "float vector load not typed f32:\n{text}"
    );
    assert!(!text.contains("asm!(\"mulps"), "mulps left as asm:\n{text}");
    // The slice parameters are typed as float slices from the packed-float access…
    assert!(
        text.contains("&mut [f32]") && text.contains("&[f32]"),
        "slices not typed f32:\n{text}"
    );
    // …and the scalar remainder reads/writes them as float slice elements (`a[i]`), not raw
    // `read::<f32>(ptr + i*4)`.
    assert!(
        text.contains("a2[rcx_1] * a3[rcx_1]")
            || text.contains("a2[rcx_1 as usize] * a3[rcx_1 as usize]"),
        "scalar float tail not slice-indexed:\n{text}"
    );
    assert!(
        !text.contains("read::<f32>"),
        "float element left as a raw pointer read:\n{text}"
    );
    // The function is void — it writes through `a1`, so the leftover register the trailing `ret`
    // reads is not a result: no `-> …` return type and no spurious `return <scratch>`.
    assert!(
        text.contains("fn mulv(a1: &mut [f32], a2: &[f32], a3: &[f32]) {"),
        "not void:\n{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("mulv", code)], 0)),
        "void float port must compile"
    );
}

#[test]
fn float_vectorised_sum_recovers() {
    // clang -O3 -ffast-math of `float sumf(const float* s, unsigned n){ acc=0; for.. acc+=s[i]; }`:
    // an `addps` reduction loop + an `unpckhpd`/`shufps`/`addss` horizontal reduce + a scalar
    // remainder, result returned in xmm0. The semantic reduction analysis proves the whole thing
    // computes the slice sum and folds it to `s.iter().sum()` with an `f32` return — the messy
    // float horizontal-reduce idiom is discarded, not matched.
    let code: &[u8] = &[
        0x85, 0xF6, 0x74, 0x0E, 0x89, 0xF0, 0x83, 0xFE, 0x04, 0x73, 0x0B, 0x0F, 0x57, 0xC0, 0x31,
        0xC9, 0xEB, 0x4E, 0x0F, 0x57, 0xC0, 0xC3, 0x89, 0xC1, 0x83, 0xE1, 0xFC, 0x48, 0x8D, 0x14,
        0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xE2, 0xF0, 0x0F, 0x57, 0xC0, 0x31, 0xF6, 0x0F,
        0x1F, 0x40, 0x00, 0x0F, 0x10, 0x0C, 0x37, 0x0F, 0x58, 0xC1, 0x48, 0x83, 0xC6, 0x10, 0x48,
        0x39, 0xF2, 0x75, 0xF0, 0x0F, 0x28, 0xC8, 0x66, 0x0F, 0x15, 0xC8, 0x0F, 0x58, 0xC8, 0x0F,
        0x28, 0xC1, 0x0F, 0xC6, 0xC1, 0x55, 0xF3, 0x0F, 0x58, 0xC1, 0x39, 0xC1, 0x74, 0x14, 0x0F,
        0x1F, 0x80, 0x00, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x58, 0x04, 0x8F, 0x48, 0xFF, 0xC1, 0x48,
        0x39, 0xC8, 0x75, 0xF3, 0xC3,
    ];
    let text = decompiled(&[("sumf", code)], 0);
    assert!(
        text.contains("fn sumf(a1: &[f32]) -> f32"),
        "float return not recovered:
{text}"
    );
    assert!(
        text.contains("a1.iter().sum()"),
        "float sum not folded:
{text}"
    );
    assert!(
        !text.contains("asm!") && !text.contains("loop") && !text.contains("unpckhpd"),
        "hsum not discarded:
{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("sumf", code)], 0)),
        "folded float-sum port must compile"
    );
}

#[test]
fn float_vectorised_max_recovers() {
    // clang -O3 -ffast-math of a float max loop (`m = s[0]; for i in 1.. if s[i]>m m=s[i]`):
    // a `maxps` reduction loop + an `unpckhpd`/`shufps`/`maxss` horizontal reduce + a scalar
    // remainder, seeded with s[0] (no zero identity). The semantic reducer recognises the whole
    // as a slice max and folds it, discarding the float hsum idiom.
    let code: &[u8] = &[
        0xF3, 0x0F, 0x10, 0x07, 0x83, 0xFE, 0x02, 0x72, 0x64, 0x89, 0xF0, 0xB9, 0x01, 0x00, 0x00,
        0x00, 0x83, 0xFE, 0x05, 0x72, 0x4B, 0x48, 0x8D, 0x50, 0xFF, 0x48, 0x89, 0xD6, 0x48, 0x83,
        0xE6, 0xFC, 0x48, 0x8D, 0x4E, 0x01, 0x0F, 0xC6, 0xC0, 0x00, 0x45, 0x31, 0xC0, 0x0F, 0x1F,
        0x44, 0x00, 0x00, 0x42, 0x0F, 0x10, 0x4C, 0x87, 0x04, 0x0F, 0x5F, 0xC1, 0x49, 0x83, 0xC0,
        0x04, 0x4C, 0x39, 0xC6, 0x75, 0xEE, 0x0F, 0x28, 0xC8, 0x66, 0x0F, 0x15, 0xC8, 0x0F, 0x5F,
        0xC8, 0x0F, 0x28, 0xC1, 0x0F, 0xC6, 0xC1, 0x55, 0xF3, 0x0F, 0x5F, 0xC1, 0x48, 0x39, 0xF2,
        0x74, 0x11, 0x0F, 0x1F, 0x40, 0x00, 0xF3, 0x0F, 0x5F, 0x04, 0x8F, 0x48, 0xFF, 0xC1, 0x48,
        0x39, 0xC8, 0x75, 0xF3, 0xC3,
    ];
    let text = decompiled(&[("maxf", code)], 0);
    assert!(
        text.contains("fn maxf(a1: &[f32]) -> f32"),
        "float max signature wrong:
{text}"
    );
    assert!(
        text.contains("a1.iter().copied().reduce(|a, b| a.max(b)).unwrap()"),
        "max not folded:
{text}"
    );
    assert!(
        !text.contains("asm!") && !text.contains("loop") && !text.contains("maxps"),
        "hsum not discarded:
{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("maxf", code)], 0)),
        "folded float-max port must compile"
    );
}

#[test]
fn vectorised_pmuludq_product_recovers() {
    // clang -O3 of an unsigned product `p=1; for i.. p*=s[i]`. SSE2 has no packed 32-bit multiply,
    // so the packed loop emulates it with the `pmuludq`/`pshufd`/`punpckldq` dance, plus a
    // `pshufd`/`pmuludq` horizontal product and a scalar `imull` remainder. The semantic reducer
    // recognises the whole as a slice product and folds it — the emulation dance is discarded, not
    // matched (so the gnarly `pmuludq` idiom never needs lifting).
    let code: &[u8] = &[
        0x85, 0xF6, 0x74, 0x13, 0x89, 0xF1, 0x83, 0xFE, 0x04, 0x73, 0x12, 0xB8, 0x01, 0x00, 0x00,
        0x00, 0x31, 0xD2, 0xE9, 0x89, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x89,
        0xCA, 0x83, 0xE2, 0xFC, 0x48, 0x8D, 0x04, 0x8D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xE0,
        0xF0, 0x66, 0x0F, 0x6F, 0x05, 0x00, 0x00, 0x00, 0x00, 0x31, 0xF6, 0x0F, 0x1F, 0x84, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x6F, 0x0C, 0x37, 0x66, 0x0F, 0x70, 0xD1, 0xF5, 0x66,
        0x0F, 0xF4, 0xC8, 0x66, 0x0F, 0x70, 0xC0, 0xF5, 0x66, 0x0F, 0x70, 0xC9, 0xE8, 0x66, 0x0F,
        0xF4, 0xC2, 0x66, 0x0F, 0x70, 0xD0, 0xE8, 0x66, 0x0F, 0x6F, 0xC1, 0x66, 0x0F, 0x62, 0xC2,
        0x48, 0x83, 0xC6, 0x10, 0x48, 0x39, 0xF0, 0x75, 0xCE, 0x66, 0x0F, 0x70, 0xC8, 0xEE, 0x66,
        0x0F, 0x70, 0xD0, 0xFF, 0x66, 0x0F, 0x70, 0xD8, 0xF5, 0x66, 0x0F, 0xF4, 0xDA, 0x66, 0x0F,
        0xF4, 0xC8, 0x66, 0x0F, 0xF4, 0xCB, 0x66, 0x0F, 0x7E, 0xC8, 0x39, 0xCA, 0x74, 0x17, 0x66,
        0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xAF, 0x04, 0x97, 0x48,
        0xFF, 0xC2, 0x48, 0x39, 0xD1, 0x75, 0xF4, 0xC3,
    ];
    let text = decompiled(&[("prod", code)], 0);
    assert!(
        text.contains("fn prod(a1: &[u32]) -> u32"),
        "signature wrong:
{text}"
    );
    assert!(
        text.contains("a1.iter().product()"),
        "product not recovered:
{text}"
    );
    assert!(
        !text.contains("asm!") && !text.contains("loop") && !text.contains("pmuludq"),
        "dance not discarded:
{text}"
    );
    assert!(
        rustc_compiles(&ported(&[("prod", code)], 0)),
        "folded product port must compile"
    );
}

#[test]
fn opaque_predicate_branch_is_removed() {
    // An opaque guard: `if ((x & 1) == 2) { return 0xdead } return 1`. `x & 1` is 0 or 1, never 2,
    // so the branch is dead. The known-bits deobfuscation pass folds the comparison and the dead
    // arm (returning 0xdead) disappears; the function reduces to `return 1`.
    //   89 F8            mov eax, edi
    //   83 E0 01         and eax, 1
    //   83 F8 02         cmp eax, 2
    //   75 06            jne +6 (-> real)
    //   B8 AD DE 00 00   mov eax, 0xdead   ; dead
    //   C3               ret
    //   B8 01 00 00 00   mov eax, 1        ; real
    //   C3               ret
    let code: &[u8] = &[
        0x89, 0xF8, 0x83, 0xE0, 0x01, 0x83, 0xF8, 0x02, 0x75, 0x06, 0xB8, 0xAD, 0xDE, 0x00, 0x00,
        0xC3, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
    ];
    let text = decompiled(&[("guard", code)], 0);
    assert!(
        !text.contains("0xdead") && !text.to_lowercase().contains("57005"),
        "dead opaque-predicate arm was not removed:\n{text}"
    );
}

// --- QA regression tests (transform + print fixes) ------------------------

#[test]
fn nested_signed_then_unsigned_cast_keeps_inner_sign() {
    // Cast(Cast(x:B8, B32, signed), B16, unsigned): the outer narrow is a truncation, so the
    // result bits are the INNER signed extension — the collapse must keep signed=true.
    use crate::ir::{Expr, Width};
    let e = Expr::Cast(
        Box::new(Expr::Cast(
            Box::new(Expr::Param(0, Width::B8)),
            Width::B32,
            true,
        )),
        Width::B16,
        false,
    );
    let f = crate::simplify::fold(e);
    assert!(
        matches!(f, Expr::Cast(_, Width::B16, true)),
        "inner sign-extension must survive the collapse: {f:?}"
    );
}

#[test]
fn lea_multiply_fold_does_not_overflow() {
    // x + x*0xFFFF_FFFF_FFFF_FFFF  ->  x * (k+1); k+1 wraps to 0 and must not panic.
    use crate::ir::{BinOp, Expr, Width};
    let x = Expr::Param(0, Width::B64);
    let e = Expr::bin(
        BinOp::Add,
        x.clone(),
        Expr::bin(BinOp::Mul, x, Expr::konst(u64::MAX, Width::B64), Width::B64),
        Width::B64,
    );
    let _ = crate::simplify::fold(e); // must not panic in a debug build
}

#[test]
fn sar_prints_as_arithmetic_shift() {
    // mov eax, edi ; sar eax, 31 ; ret  — an arithmetic shift-right of a signed value.
    let code: &[u8] = &[0x89, 0xF8, 0xC1, 0xF8, 0x1F, 0xC3];
    let s = decompiled(&[("sar", code)], 0);
    assert!(s.contains("as i32"), "SAR operand must be cast signed: {s}");
    assert!(s.contains(">>"), "{s}");
    assert!(
        rustc_compiles(&ported(&[("sar", code)], 0)),
        "the SAR port must compile"
    );
}

#[test]
fn allones_constant_respects_signedness() {
    // Unsigned compare against all-ones must print the true value (0xffffffff), not -1
    // (which is the wrong value for a u32 and won't compile in port mode).
    let unsigned: &[u8] = &[
        0x89, 0xF8, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x92, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3,
    ]; // mov eax,edi; cmp eax,0xffffffff; setb al; movzx eax,al; ret
    let u = decompiled(&[("u", unsigned)], 0);
    assert!(u.contains("0xffffffff") && !u.contains("-1"), "{u}");
    assert!(rustc_compiles(&ported(&[("u", unsigned)], 0)), "{u}");
    // A signed compare still renders the negative literal.
    let signed: &[u8] = &[
        0x89, 0xF8, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x9C, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3,
    ]; // ...; setl al
    let s = decompiled(&[("s", signed)], 0);
    assert!(s.contains("-1"), "signed compare should keep -1: {s}");
}

#[test]
fn signed_compare_of_load_is_signed_and_compiles() {
    // cmp dword [rdi], 5 ; setl al ; movzx eax,al ; ret  — a SIGNED `< 5` of a memory load.
    // The load operand must be cast signed, and the cast must be parenthesized or Rust parses
    // `*a1 as i32 < 5` as generic arguments to i32 and rejects it.
    let code: &[u8] = &[0x83, 0x3F, 0x05, 0x0F, 0x9C, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3];
    let s = decompiled(&[("f", code)], 0);
    assert!(s.contains("as i32") && s.contains("< 5"), "{s}");
    assert!(
        rustc_compiles(&ported(&[("f", code)], 0)),
        "signed load compare must compile: {s}"
    );
}

#[test]
fn loop_instruction_keeps_its_back_edge() {
    // mov rcx,rdi; xor eax,eax; top: inc rax; loop top; ret
    // The `loop` must model the rcx decrement and the conditional back-edge — previously it fell
    // through to `asm!` with no terminator and the loop structure was lost.
    let code: &[u8] = &[
        0x48, 0x89, 0xF9, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xE2, 0xFB, 0xC3,
    ];
    let s = decompiled(&[("f", code)], 0);
    assert!(
        s.contains("loop {") || s.contains("while"),
        "expected a loop: {s}"
    );
    assert!(
        s.contains("rcx -= 1") || s.contains("rcx - 1"),
        "expected the decrement: {s}"
    );
    assert!(!s.contains("asm!"), "loop should be modelled, not asm: {s}");
    assert!(rustc_compiles(&ported(&[("f", code)], 0)), "{s}");
}

#[test]
fn inner_loop_break_of_outer_uses_a_label() {
    // Nested loops; the inner body's `je end` jumps clear out of BOTH loops — a break of the
    // OUTER loop. It must become a labeled `break 'l..`, not a dropped `// goto`.
    //   acc=0; for i in 0..n { for j in 0..m { acc++; if acc==100 { break outer } } }
    let code: &[u8] = &[
        0x31, 0xC0, 0x31, 0xC9, 0x48, 0x39, 0xF9, 0x73, 0x1D, 0x31, 0xD2, 0x48, 0x39, 0xF2, 0x73,
        0x11, 0x48, 0x83, 0xC0, 0x01, 0x48, 0x3D, 0x64, 0x00, 0x00, 0x00, 0x74, 0x0A, 0x48, 0xFF,
        0xC2, 0xEB, 0xEA, 0x48, 0xFF, 0xC1, 0xEB, 0xDE, 0xC3,
    ];
    let s = decompiled(&[("f", code)], 0);
    assert!(s.contains("break 'l"), "expected a labeled break: {s}");
    assert!(
        !s.contains("goto"),
        "the outer break must not degrade to a goto: {s}"
    );
    assert!(
        rustc_compiles(&ported(&[("f", code)], 0)),
        "labeled-break port must compile: {s}"
    );
}

#[test]
fn self_loop_structures_cleanly() {
    // mov rax,rdi; self: dec rax; jnz self; ret  — a block that branches to itself must become a
    // clean loop with no dangling goto.
    let code: &[u8] = &[0x48, 0x89, 0xF8, 0x48, 0xFF, 0xC8, 0x75, 0xFB, 0xC3];
    let s = decompiled(&[("f", code)], 0);
    assert!(s.contains("loop {") || s.contains("while"), "{s}");
    assert!(
        !s.contains("goto"),
        "self-loop should not leave a goto: {s}"
    );
    assert!(rustc_compiles(&ported(&[("f", code)], 0)), "{s}");
}

#[test]
fn multi_exit_loop_is_correct_and_has_no_dead_code() {
    // A loop with two distinct exits that merge afterwards. The merge tail is duplicated into
    // each exit path (allowed: never drop), and there must be no unreachable statement after an
    // unconditional `continue`/`break`.
    // i=0; loop { if i>=n {rax=1; goto merge} if i==5 {rax=2; fall} i++ } merge: rax+=i; ret
    let code: &[u8] = &[
        0x31, 0xC9, 0x48, 0x39, 0xF9, 0x73, 0x0B, 0x48, 0x83, 0xF9, 0x05, 0x74, 0x0E, 0x48, 0xFF,
        0xC1, 0xEB, 0xF0, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x07, 0x48, 0xC7, 0xC0,
        0x02, 0x00, 0x00, 0x00, 0x48, 0x01, 0xC8, 0xC3,
    ];
    let s = decompiled(&[("f", code)], 0);
    // No dead `break;` immediately after a `continue;`.
    let dense: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !dense.contains("continue; break;"),
        "dead code after continue: {s}"
    );
    assert!(rustc_compiles(&ported(&[("f", code)], 0)), "{s}");
}

#[test]
fn one_operand_mul_keeps_the_high_half() {
    // mov rax,rdi; mul rsi; mov rax,rdx; ret  — returns the HIGH 64 bits of the product. The
    // one-operand mul previously dropped rdx, leaving it stale.
    let umul: &[u8] = &[0x48, 0x89, 0xF8, 0x48, 0xF7, 0xE6, 0x48, 0x89, 0xD0, 0xC3];
    let u = decompiled(&[("f", umul)], 0);
    assert!(u.contains("as u128") && u.contains(">> 0x40"), "{u}");
    assert!(rustc_compiles(&ported(&[("f", umul)], 0)), "{u}");
    // Signed imul: high half via i128 (arithmetic shift), params typed signed.
    let imul: &[u8] = &[0x48, 0x89, 0xF8, 0x48, 0xF7, 0xEE, 0x48, 0x89, 0xD0, 0xC3];
    let i = decompiled(&[("f", imul)], 0);
    assert!(
        i.contains("as i128"),
        "signed imul high half should widen to i128: {i}"
    );
    assert!(rustc_compiles(&ported(&[("f", imul)], 0)), "{i}");
}

#[test]
fn probe_crackme02() {
    let Some((info, p)) = crackme("crackme02.exe") else {
        eprintln!("NO BINARY");
        return;
    };
    for (i, c) in decompiled_callees(&info, &p).iter().enumerate() {
        if c.contains("a1[") || c.contains("-> bool") || c.contains("& 0xff") || c.contains("| ") {
            eprintln!("=== callee {i} ===\n{c}\n");
        }
    }
}

#[test]
fn partial_register_write_preserves_upper_bits() {
    // mov eax,0x1122 ; mov al,5 ; add eax,0x10000 ; ret
    // `mov al,5` must preserve eax's upper bits (eax -> 0x1105), so the add gives 0x11105.
    // (The clean-replace model would clobber eax to 5 and give 0x10005.)
    let code: &[u8] = &[
        0xB8, 0x22, 0x11, 0x00, 0x00, 0xB0, 0x05, 0x05, 0x00, 0x00, 0x01, 0x00, 0xC3,
    ];
    let s = decompiled(&[("f", code)], 0);
    assert!(
        s.contains("0x11105"),
        "upper bits must survive the al write: {s}"
    );
    assert!(rustc_compiles(&ported(&[("f", code)], 0)), "{s}");
    // A byte return must NOT be wrapped in a read-modify-write (upper bits are dead).
    let br: &[u8] = &[0xB0, 0x07, 0xC3]; // mov al,7; ret
    let b = decompiled(&[("g", br)], 0);
    assert!(!b.contains("& 0xff"), "byte return should stay clean: {b}");
}

#[test]
fn max_min_preserves_comparison_signedness() {
    // mov rax,rdi; cmp rax,rsi; cmovl rax,rsi; ret  — a SIGNED max (cmovl) -> i64 types.
    let smax: &[u8] = &[
        0x48, 0x89, 0xF8, 0x48, 0x39, 0xF0, 0x48, 0x0F, 0x4C, 0xC6, 0xC3,
    ];
    let s = decompiled(&[("f", smax)], 0);
    assert!(
        s.contains("i64") && s.contains(".max(a2)"),
        "signed max must be i64: {s}"
    );
    assert!(rustc_compiles(&ported(&[("f", smax)], 0)), "{s}");
    // Same shape with cmovb is an UNSIGNED max -> u64.
    let umax: &[u8] = &[
        0x48, 0x89, 0xF8, 0x48, 0x39, 0xF0, 0x48, 0x0F, 0x42, 0xC6, 0xC3,
    ];
    let u = decompiled(&[("g", umax)], 0);
    assert!(
        u.contains("u64") && !u.contains("i64"),
        "unsigned max must stay u64: {u}"
    );
    assert!(rustc_compiles(&ported(&[("g", umax)], 0)), "{u}");
}
