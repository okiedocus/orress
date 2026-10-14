use std::path::Path;

use crate::*;

#[test]
fn detects_languages() {
    assert_eq!(
        Language::from_path(Path::new("a/b/solve.rs")),
        Language::Rust
    );
    assert_eq!(Language::from_path(Path::new("x.py")), Language::Python);
    assert_eq!(Language::from_path(Path::new("boot.asm")), Language::Asm);
    assert_eq!(Language::from_path(Path::new("Cargo.toml")), Language::Toml);
    assert_eq!(Language::from_path(Path::new("notes")), Language::PlainText);
    assert_eq!(Language::from_path(Path::new("main.c")), Language::C);
    assert_eq!(Language::from_path(Path::new("api.h")), Language::C);
    assert_eq!(Language::from_path(Path::new("app.cpp")), Language::Cpp);
    assert_eq!(Language::from_path(Path::new("v.hpp")), Language::Cpp);
}

#[test]
fn highlights_c_with_tree_sitter() {
    assert!(has_grammar(Language::C));
    let src = "// sum\nint add(int a, int b) {\n    return a + b; /* ok */\n}\n";
    let toks = highlight(src, Language::C);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(kinds.contains(&("// sum", Tok::Comment)), "{kinds:?}");
    assert!(
        kinds.iter().any(|(t, k)| *k == Tok::Type && *t == "int"),
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::Keyword && *t == "return"),
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::Comment && t.contains("ok")),
        "{kinds:?}"
    );
}

#[test]
fn highlights_cpp_with_tree_sitter() {
    assert!(has_grammar(Language::Cpp));
    let src = "class Foo {\n  int bar() { return 42; }\n};\n";
    let toks = highlight(src, Language::Cpp);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::Keyword && *t == "class"),
        "{kinds:?}"
    );
    assert!(
        kinds.iter().any(|(t, k)| *k == Tok::Number && *t == "42"),
        "{kinds:?}"
    );
}

#[test]
fn imported_highlight_query_is_applied() {
    // A minimal "Zed" highlights.scm that colours only `return` as a keyword and strings. Using it
    // over the bundled C grammar proves imported queries drive the highlighting (the query half of
    // Zed grammar compatibility). A capture the query omits (e.g. `int` as a type) is not coloured.
    let query = "(return_statement) @keyword\n(string_literal) @string\n";
    let src = "int f() { return \"hi\"; }";
    let toks = highlight_with_query(src, Language::C, query);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(
        kinds.iter().any(|(_, k)| *k == Tok::String),
        "string not from imported query: {kinds:?}"
    );
    // The imported query does not capture `int` as a type, so it is not coloured as one.
    assert!(
        !kinds.iter().any(|(t, k)| *k == Tok::Type && *t == "int"),
        "{kinds:?}"
    );
    // A query that does not compile falls back to the built-in highlighting (so `int` is a type).
    let fallback = highlight_with_query(src, Language::C, "(this_node_does_not_exist) @keyword");
    let fk: Vec<_> = fallback
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(
        fk.iter().any(|(t, k)| *k == Tok::Type && *t == "int"),
        "no fallback: {fk:?}"
    );
}

#[test]
fn buffer_dirty_tracking() {
    let mut b = Buffer::untitled();
    assert!(!b.is_dirty());
    b.text.insert(b.text.len_chars(), "fn main() {}");
    assert!(b.is_dirty());
    assert_eq!(b.title(), "untitled *");
}

#[test]
fn scratch_buffer_is_named_typed_and_unsaved() {
    let b = Buffer::scratch("maxv.rs", "fn maxv() {}");
    assert_eq!(b.language, Language::Rust);
    assert_eq!(b.as_string(), "fn maxv() {}");
    // No file on disk yet, so it is dirty and the tab shows the name with `*`.
    assert!(b.is_dirty());
    assert_eq!(b.title(), "maxv.rs *");
}

#[test]
fn highlights_rust() {
    let src = "// a comment\nfn main() {\n    let x: u32 = 0x1F;\n    println!(\"hi {}\", x);\n}\n";
    let toks = crate::highlight::tokenizer(src, Language::Rust);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(kinds.contains(&("// a comment", Tok::Comment)), "{kinds:?}");
    assert!(kinds.contains(&("fn", Tok::Keyword)), "{kinds:?}");
    assert!(kinds.contains(&("let", Tok::Keyword)), "{kinds:?}");
    assert!(kinds.contains(&("u32", Tok::Type)), "{kinds:?}");
    assert!(kinds.contains(&("0x1F", Tok::Number)), "{kinds:?}");
    assert!(kinds.contains(&("println!", Tok::Macro)), "{kinds:?}");
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::String && t.contains("hi")),
        "{kinds:?}"
    );
    // Tokens are ordered and non-overlapping.
    for w in toks.windows(2) {
        assert!(w[0].end <= w[1].start, "overlap: {:?}", w);
    }
}

#[test]
fn highlights_python() {
    let src = "import os\n@deco\ndef f(x):\n    s = \"text\"  # note\n    return x\n";
    let toks = crate::highlight::tokenizer(src, Language::Python);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(kinds.contains(&("import", Tok::Keyword)), "{kinds:?}");
    assert!(kinds.contains(&("def", Tok::Keyword)), "{kinds:?}");
    assert!(kinds.contains(&("@deco", Tok::Attribute)), "{kinds:?}");
    assert!(kinds.iter().any(|(_, k)| *k == Tok::Comment), "{kinds:?}");
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::String && t.contains("text")),
        "{kinds:?}"
    );
}

#[test]
fn escaped_multibyte_char_in_a_string_does_not_panic() {
    // `\é`: the escaped character is two bytes; skipping a fixed 2 bytes used to land mid-char.
    for (src, lang) in [
        ("s = \"\\é\"\nx = 1\n", Language::Python),
        ("let s = \"a\\é\\😀b\"; let t = 2;", Language::Rust),
        ("x = \"\\é", Language::Python), // unterminated, backslash-escape at EOF
        ("x = \"\\", Language::Python),
    ] {
        let toks = crate::highlight::tokenizer(src, lang);
        for t in &toks {
            assert!(src.is_char_boundary(t.start) && src.is_char_boundary(t.end));
        }
        assert!(toks.iter().any(|t| t.kind == Tok::String), "{src:?}");
    }
}

#[test]
fn char_literal_vs_lifetime() {
    let src = "let c = 'z'; fn f<'a>(x: &'a str) {}";
    let toks = crate::highlight::tokenizer(src, Language::Rust);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(kinds.contains(&("'z'", Tok::Char)), "{kinds:?}");
    assert!(kinds.contains(&("'a", Tok::Lifetime)), "{kinds:?}");
}

#[test]
fn unicode_in_strings_is_safe() {
    // Byte offsets must land on char boundaries even with multi-byte content.
    let src = "let s = \"héllo → world\"; // café\n";
    let toks = highlight(src, Language::Rust);
    for t in &toks {
        assert!(
            src.is_char_boundary(t.start) && src.is_char_boundary(t.end),
            "bad boundary {t:?}"
        );
        let _ = &src[t.start..t.end]; // must not panic
    }
}

#[test]
fn tasks_for_standalone_rust_compiles_then_runs() {
    let t = tasks_for(Path::new("/tmp/solve.rs"), Language::Rust);
    assert_eq!(t[0].label, "rustc & run");
    assert_eq!(t[0].steps.len(), 2);
    assert_eq!(t[0].steps[0].program, "rustc");
    assert!(t[0].steps[1].program.contains("solve"));
}

#[test]
fn tasks_for_python() {
    let t = tasks_for(Path::new("x.py"), Language::Python);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].steps[0].program, "python");
}

#[test]
fn no_tasks_for_plain_text() {
    assert!(tasks_for(Path::new("notes.txt"), Language::PlainText).is_empty());
}

#[test]
fn tree_sitter_highlights_rust() {
    // The public highlight() uses tree-sitter for Rust.
    let src = "fn main() {
    let x: u32 = 0x1F; // hi
    let s = \"text\";
}
";
    let toks = highlight(src, Language::Rust);
    let kinds: Vec<_> = toks
        .iter()
        .map(|t| (&src[t.start..t.end], t.kind))
        .collect();
    assert!(
        kinds.iter().any(|(t, k)| *t == "fn" && *k == Tok::Keyword),
        "{kinds:?}"
    );
    assert!(
        kinds.iter().any(|(t, k)| *t == "u32" && *k == Tok::Type),
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::Number && t.contains("0x1F")),
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::Comment && t.contains("hi")),
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|(t, k)| *k == Tok::String && t.contains("text")),
        "{kinds:?}"
    );
    // ordered, non-overlapping, char-boundary-safe.
    for w in toks.windows(2) {
        assert!(w[0].end <= w[1].start, "overlap {w:?}");
    }
    for t in &toks {
        assert!(src.is_char_boundary(t.start) && src.is_char_boundary(t.end));
    }
}

#[test]
fn tree_sitter_available() {
    // The Rust and Python grammars must load in this build.
    assert!(
        crate::highlight("fn x(){}", Language::Rust)
            .iter()
            .any(|t| t.kind == Tok::Keyword)
    );
    assert!(
        crate::highlight("def x(): pass", Language::Python)
            .iter()
            .any(|t| t.kind == Tok::Keyword)
    );
}

#[test]
fn imported_query_configs_are_cached() {
    let query = "(return_statement) @keyword
(string_literal) @string
";
    let src = "int f() { return \"hi\"; }";
    // The second lookup reuses the first compiled configuration rather than recompiling.
    let first = crate::ts::cached_config(Language::C, query).expect("compiles");
    let second = crate::ts::cached_config(Language::C, query).expect("cached");
    assert!(std::sync::Arc::ptr_eq(&first, &second));
    // A different query (or language) gets its own entry.
    let other = crate::ts::cached_config(
        Language::C,
        "(string_literal) @string
",
    )
    .unwrap();
    assert!(!std::sync::Arc::ptr_eq(&first, &other));
    // Cached output is identical to compiling the query afresh.
    let fresh = crate::ts::build_config_with(Language::C, query).unwrap();
    let uncached = crate::ts::run(src, &fresh).unwrap();
    assert_eq!(highlight_with_query(src, Language::C, query), uncached);
    assert_eq!(highlight_with_query(src, Language::C, query), uncached);
    // A query that does not compile is cached as a miss (and highlighting falls back).
    assert!(crate::ts::cached_config(Language::C, "(no_such_node) @keyword").is_none());
    assert!(crate::ts::cached_config(Language::C, "(no_such_node) @keyword").is_none());
}

#[test]
fn languages_resolve_by_name() {
    assert_eq!(Language::from_name("c++"), Some(Language::Cpp));
    assert_eq!(Language::from_name("Rust"), Some(Language::Rust));
    assert_eq!(Language::from_name("Nim"), None);
}
