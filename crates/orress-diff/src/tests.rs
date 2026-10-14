use super::*;

fn sig(
    entry: u64,
    name: Option<&str>,
    insns: u32,
    blocks: u32,
    edges: u32,
    calls: u32,
    hash: u64,
) -> FuncSig {
    FuncSig {
        entry,
        name: name.map(str::to_string),
        insns,
        blocks,
        edges,
        calls,
        opcode_hash: hash,
    }
}

#[test]
fn identical_program_matches_everything() {
    let a = vec![
        sig(0x1000, Some("main"), 20, 4, 5, 2, 0xaa),
        sig(0x1100, Some("helper"), 8, 1, 0, 1, 0xbb),
    ];
    // Same code at shifted addresses (a rebuild): matched by name/opcode-hash, all identical.
    let b = vec![
        sig(0x2000, Some("main"), 20, 4, 5, 2, 0xaa),
        sig(0x2100, Some("helper"), 8, 1, 0, 1, 0xbb),
    ];
    let d = diff(&a, &b);
    assert_eq!(d.summary(), (2, 0, 0, 0));
    assert!(
        d.matches
            .iter()
            .all(|m| m.kind == MatchKind::Identical && m.similarity == 1.0)
    );
}

#[test]
fn a_changed_function_is_matched_by_name_and_marked_changed() {
    let a = vec![sig(0x1000, Some("check"), 20, 4, 5, 2, 0xaa)];
    // Same name, different code/shape -> Changed (not identical).
    let b = vec![sig(0x2000, Some("check"), 24, 5, 7, 3, 0xcc)];
    let d = diff(&a, &b);
    assert_eq!(d.summary(), (0, 1, 0, 0));
    assert_eq!(d.matches[0].kind, MatchKind::Changed);
    assert!(d.matches[0].similarity > 0.0 && d.matches[0].similarity < 1.0);
}

#[test]
fn added_and_removed_functions_are_reported() {
    let a = vec![
        sig(0x1000, Some("main"), 20, 4, 5, 2, 0xaa),
        sig(0x1100, Some("gone"), 8, 1, 0, 1, 0xbb),
    ];
    let b = vec![
        sig(0x2000, Some("main"), 20, 4, 5, 2, 0xaa),
        sig(0x2100, Some("fresh"), 30, 6, 9, 4, 0xdd),
    ];
    let d = diff(&a, &b);
    assert_eq!(d.summary(), (1, 0, 1, 1));
    assert_eq!(d.removed[0].name.as_deref(), Some("gone"));
    assert_eq!(d.added[0].name.as_deref(), Some("fresh"));
}

#[test]
fn identical_code_matches_even_when_renamed() {
    // No reliable names (both auto): matched by opcode hash -> identical, despite moving.
    let a = vec![sig(0x1000, None, 12, 2, 2, 0, 0x55)];
    let b = vec![sig(0x9000, None, 12, 2, 2, 0, 0x55)];
    let d = diff(&a, &b);
    assert_eq!(d.summary(), (1, 0, 0, 0));
    assert_eq!(d.matches[0].a.entry, 0x1000);
    assert_eq!(d.matches[0].b.entry, 0x9000);
}

#[test]
fn greedy_matches_a_moved_tweaked_function_but_not_unrelated_ones() {
    // Nameless, different hash, but near-identical CFG shape -> greedy Changed match.
    let a = vec![sig(0x1000, None, 100, 10, 14, 5, 0x1)];
    let b = vec![sig(0x2000, None, 101, 10, 14, 5, 0x2)];
    let d = diff(&a, &b);
    assert_eq!(d.summary().1, 1); // one changed match
    assert!(d.added.is_empty() && d.removed.is_empty());

    // Wildly different shapes stay unmatched (below threshold).
    let a2 = vec![sig(0x1000, None, 100, 20, 40, 10, 0x1)];
    let b2 = vec![sig(0x2000, None, 3, 1, 0, 0, 0x2)];
    let d2 = diff(&a2, &b2);
    assert_eq!(d2.summary(), (0, 0, 1, 1)); // added + removed, no match
}

#[test]
fn name_match_wins_over_an_ambiguous_shape() {
    // Two B functions share the fingerprint; the name pass disambiguates `main` first.
    let a = vec![sig(0x1000, Some("main"), 10, 2, 2, 1, 0xaa)];
    let b = vec![
        sig(0x2000, Some("other"), 10, 2, 2, 1, 0xff),
        sig(0x2100, Some("main"), 10, 2, 2, 1, 0xaa),
    ];
    let d = diff(&a, &b);
    assert_eq!(d.matches.len(), 1);
    assert_eq!(d.matches[0].b.name.as_deref(), Some("main"));
    assert_eq!(d.matches[0].kind, MatchKind::Identical);
    assert_eq!(d.added.len(), 1); // "other" is B-only
}

/// An ELF-like x86-64 program with `code` at `base` and a `check` symbol at its start.
fn program(code: &[u8], base: u64) -> orress_analysis::Program {
    use orress_loaders::{BinaryInfo, Format, Kind, NamedAddress, Perms, Section};
    let mut text = vec![0xccu8; 0x100];
    text[..code.len()].copy_from_slice(code);
    let mut file = vec![0u8; 0x200];
    file.extend(&text);
    let info = BinaryInfo {
        format: Format::Elf,
        kind: Kind::Executable,
        arch: "x86-64".into(),
        bits: Some(64),
        entry: Some(base),
        image_base: base & !0xfff,
        sections: vec![Section {
            name: ".text".into(),
            offset: 0x200,
            file_size: 0x100,
            address: base,
            virtual_size: 0x100,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            entropy: None,
        }],
        function_symbols: vec![NamedAddress {
            address: base,
            name: "check".into(),
        }],
        ..BinaryInfo::default()
    };
    orress_analysis::Program::analyze(&info, std::sync::Arc::new(file), &[]).expect("x86-64")
}

#[test]
fn a_patched_condition_is_reported_changed() {
    // test eax,eax; jz (near, 0f 84) +6; mov eax,1; ret; xor eax,eax; ret — vs. the same with
    // jnz (0f 85): only the second opcode byte differs, and the CFG shape is identical.
    let original = [
        0x85, 0xc0, 0x0f, 0x84, 0x06, 0, 0, 0, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
    ];
    let mut patched = original;
    patched[3] = 0x85;
    let a = program(&original, 0x40_1000);
    let b = program(&patched, 0x40_1000);
    let d = diff_programs(&a, &b);
    assert_eq!(d.summary(), (0, 1, 0, 0), "{d:?}");

    // The same code moved to another address is still identical.
    let moved = program(&original, 0x50_2000);
    assert_eq!(diff_programs(&a, &moved).summary(), (1, 0, 0, 0));
}

#[test]
fn greedy_scales_and_still_matches_the_closest_shape() {
    // Many unrelated nameless functions on both sides; the tweaked one still pairs up.
    let mut a: Vec<FuncSig> = (0..2000)
        .map(|i| sig(0x1000 + i * 0x10, None, 5 + i as u32, 1, 0, 0, 0x1_0000 + i))
        .collect();
    let mut b: Vec<FuncSig> = (0..2000)
        .map(|i| sig(0x9000 + i * 0x10, None, 5 + i as u32, 1, 0, 0, 0x9_0000 + i))
        .collect();
    a.push(sig(0x80_0000, None, 100_000, 50, 70, 9, 0x77));
    b.push(sig(0x90_0000, None, 100_010, 50, 70, 9, 0x78));
    let d = diff(&a, &b);
    let m = d
        .matches
        .iter()
        .find(|m| m.a.entry == 0x80_0000)
        .expect("matched");
    assert_eq!(m.b.entry, 0x90_0000);
}
