//! Robustness ("fuzz-style") tests: every loader/parser must handle hostile input — truncated,
//! bit-flipped and random bytes — without panicking, hanging or over-allocating. True coverage-
//! guided fuzzing (cargo-fuzz/libFuzzer) needs a nightly toolchain that isn't available in this
//! dev environment, so this is a deterministic stand-in (seeded PRNG, committed and cross-platform)
//! that exercises the same hostile-input paths. A panic in any parser fails the owning test with a
//! reproducible input; a hang or OOM points at an unbounded read/allocation to cap.

use std::sync::Arc;

/// A tiny deterministic xorshift PRNG — no `rand` dependency, reproducible across runs/platforms.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

/// Real samples plus bare format magics, as mutation seeds.
fn seeds() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = Vec::new();
    for name in ["crackme01", "crackme05", "crackme08"] {
        let p = format!(
            "{}/../../academy/crackmes/bin/{name}.exe",
            env!("CARGO_MANIFEST_DIR")
        );
        if let Ok(b) = std::fs::read(&p) {
            v.push(b);
        }
    }
    v.extend([
        b"\x00asm\x01\x00\x00\x00".to_vec(),          // wasm
        b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34".to_vec(), // java class
        b"PK\x03\x04\x14\x00\x00\x00".to_vec(),       // zip local header
        b"dex\n035\x00".to_vec(),                     // dex
        b"MZ\x90\x00\x03\x00\x00\x00".to_vec(),       // PE/DOS
        b"\x7fELF\x02\x01\x01\x00".to_vec(),          // ELF64
        b"\xa7\x0d\x0d\x0a".to_vec(),                 // pyc-ish magic
    ]);
    v
}

/// A hostile corpus: the empty input, every truncation of each seed (sampled), several bit-flip
/// mutations per seed, and pure-random blobs. `per` scales the mutation/random counts.
fn corpus(per: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut out: Vec<Vec<u8>> = vec![Vec::new()];
    for seed in seeds() {
        let step = (seed.len() / 256).max(1);
        let mut i = 0;
        while i <= seed.len() {
            out.push(seed[..i].to_vec());
            i += step;
        }
        for _ in 0..per {
            let mut m = seed.clone();
            if m.is_empty() {
                continue;
            }
            for _ in 0..1 + rng.below(8) {
                let p = rng.below(m.len());
                m[p] ^= 1 << (rng.next() % 8);
            }
            out.push(m);
        }
    }
    for _ in 0..per {
        let len = 1 + rng.below(512);
        out.push((0..len).map(|_| rng.byte()).collect());
    }
    out
}

#[test]
fn loaders_triage_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_loaders::triage(&d);
    }
}

#[test]
fn wasm_parser_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_wasm::is_wasm(&d);
        let _ = orress_wasm::parse(&d);
        let _ = orress_wasm::disassemble(&d);
    }
}

#[test]
fn pyc_parser_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_pyc::looks_like_pyc(&d);
        let _ = orress_pyc::parse(&d);
    }
}

#[test]
fn java_parser_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_java::is_class(&d);
        if let Ok(cf) = orress_java::parse(&d) {
            for m in cf.methods.iter().take(32) {
                if let Some(code) = &m.code {
                    let _ = orress_java::disassemble(code, &cf.cp);
                }
            }
        }
    }
}

#[test]
fn dotnet_parser_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_dotnet::is_dotnet(&d);
        let _ = orress_dotnet::parse(&d);
    }
}

#[test]
fn dex_parser_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_dex::is_dex(&d);
        let _ = orress_dex::parse(&d);
    }
}

#[test]
fn archive_parser_handles_hostile_input() {
    for d in corpus(150) {
        let _ = orress_archive::looks_like_zip(&d);
        let _ = orress_archive::parse_manifest(&d);
        if let Ok(a) = orress_archive::Archive::open(&d) {
            for e in a.entries.iter().take(32) {
                let _ = a.read(e);
            }
        }
    }
}

#[test]
fn js_deobfuscator_handles_hostile_input() {
    for d in corpus(150) {
        let s = String::from_utf8_lossy(&d);
        let _ = orress_js::deobfuscate(&s);
        let _ = orress_js::extract_strings(&s);
        let _ = orress_js::beautify(&s);
    }
}

#[test]
fn full_analysis_handles_hostile_input() {
    // The disassembly pipeline on hostile/truncated images (heavier, so a smaller corpus).
    for d in corpus(40) {
        let info = orress_loaders::triage(&d);
        let _ = orress_analysis::Program::analyze(&info, Arc::new(d.clone()), &[]);
    }
}
