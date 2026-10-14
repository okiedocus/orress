use super::*;

#[test]
fn tokenizes_strings_regex_and_division() {
    // `/` after `=` is a regex; after `)` it is division.
    let raw = tokenize("var x = /ab\\/c/g; y = (a)/b");
    let toks: Vec<(Tok, &str)> = raw
        .iter()
        .filter(|t| t.kind != Tok::Space)
        .map(|t| (t.kind, t.text.as_str()))
        .collect();
    assert!(toks.contains(&(Tok::Regex, "/ab\\/c/g")));
    // The second slash is division (Punct), not a regex.
    assert_eq!(toks.iter().filter(|(k, _)| *k == Tok::Regex).count(), 1);
    assert!(toks.contains(&(Tok::Punct, "/")));
}

#[test]
fn decodes_hex_unicode_and_octal_escapes() {
    assert_eq!(decode_escapes("\\x66\\x6c\\x61\\x67"), "flag");
    assert_eq!(decode_escapes("\\u0041\\u{1F600}"), "A\u{1F600}");
    assert_eq!(decode_escapes("\\110\\151"), "Hi"); // octal H, i
    assert_eq!(decode_escapes("a\\tb\\nc"), "a\tb\nc");
}

#[test]
fn decodes_string_literals_in_place() {
    let src = "var u = \"\\x68\\x74\\x74\\x70://evil\"; call(u)";
    let out = decode_string_literals(src);
    assert!(out.contains("\"http://evil\""), "{out}");
    // Non-string text is preserved verbatim.
    assert!(out.contains("var u = "));
    assert!(out.contains("; call(u)"));
}

#[test]
fn folds_fromcharcode() {
    assert_eq!(
        fold_fromcharcode("var s=String.fromCharCode(102,108,97,103);"),
        "var s=\"flag\";"
    );
    // Hex args work too.
    assert_eq!(
        fold_fromcharcode("x=String.fromCharCode(0x41,0x42)"),
        "x=\"AB\""
    );
    // Non-integer args are left untouched.
    let keep = "String.fromCharCode(a,b)";
    assert_eq!(fold_fromcharcode(keep), keep);
}

#[test]
fn folds_string_concatenation() {
    assert_eq!(
        fold_concat("x = \"ab\" + \"cd\" + \"ef\";"),
        "x = \"abcdef\";"
    );
    // A non-string operand stops the fold.
    assert_eq!(fold_concat("\"a\" + b + \"c\""), "\"a\" + b + \"c\"");
}

#[test]
fn deobfuscate_unwinds_layered_obfuscation() {
    // fromCharCode builds "ev", concatenated with an escaped "al(1)".
    let src = "var f = String.fromCharCode(101,118) + \"\\x61\\x6c(1)\";";
    let out = deobfuscate(src);
    assert!(out.contains("\"eval(1)\""), "{out}");
}

#[test]
fn folds_atob_base64() {
    // atob("ZXZpbC5jb20=") == "evil.com"
    assert_eq!(
        fold_atob("var h=atob(\"ZXZpbC5jb20=\");"),
        "var h=\"evil.com\";"
    );
    // window.atob receiver is replaced too.
    assert_eq!(fold_atob("x=window.atob(\"QUI=\")"), "x=\"AB\"");
    // Non-base64 / binary result is left alone.
    let keep = "atob(someVar)";
    assert_eq!(fold_atob(keep), keep);
}

#[test]
fn folds_unescape_percent() {
    assert_eq!(fold_unescape("unescape(\"%41%42%43\")"), "\"ABC\"");
    assert_eq!(fold_unescape("decodeURIComponent(\"a%20b\")"), "\"a b\"");
    assert_eq!(fold_unescape("unescape(\"%u0041!\")"), "\"A!\"");
}

#[test]
fn dereferences_literal_string_array() {
    let src = "var _a=['ht','tp','://x'];var u=_a[0]+_a[1]+_a[2];";
    let out = fold_string_array(src);
    assert_eq!(
        out,
        "var _a=['ht','tp','://x'];var u=\"ht\"+\"tp\"+\"://x\";"
    );
    // And the full pipeline collapses it to one URL string.
    assert!(deobfuscate(src).contains("\"http://x\""));
}

#[test]
fn reassigned_array_is_left_alone() {
    // _a is reassigned, so indexing must not be substituted (unsound otherwise).
    let src = "var _a=['x','y'];_a=getArray();f(_a[0]);";
    assert_eq!(fold_string_array(src), src);
}

#[test]
fn deobfuscate_combines_array_atob_and_escapes() {
    let src = "var s=['ZXZhbA==','\\x28\\x31\\x29'];var r=atob(s[0])+s[1];";
    let out = deobfuscate(src);
    assert!(out.contains("\"eval(1)\""), "{out}");
}

#[test]
fn extracts_decoded_strings() {
    let src = "a(\"\\x66\\x6c\\x61\\x67{js}\"); b('plain'); c(\"\")";
    let strings = extract_strings(src);
    assert!(strings.contains(&"flag{js}".to_string()));
    assert!(strings.contains(&"plain".to_string()));
    // Empty strings are dropped.
    assert!(!strings.iter().any(|s| s.is_empty()));
}

#[test]
fn beautify_indents_and_preserves_tokens() {
    let src = "function f(a){if(a){return a+1;}return 0;}";
    let pretty = beautify(src);
    // It added structure.
    assert!(pretty.contains('\n'));
    assert!(pretty.contains("  return")); // indented body

    // Crucially, beautifying must not change the significant token stream.
    let sig = |s: &str| -> Vec<(Tok, String)> {
        tokenize(s)
            .into_iter()
            .filter(|t| t.kind != Tok::Space)
            .map(|t| (t.kind, t.text))
            .collect()
    };
    assert_eq!(sig(src), sig(&pretty));
}

#[test]
fn template_literals_stay_valid_and_stable() {
    // `\`` , `\\` and `\${` must stay escaped; real interpolations stay live.
    let src = r"x = `a\`b \\ c \${no} ${yes} \x41`;";
    let once = decode_string_literals(src);
    assert_eq!(once, r"x = `a\`b \\ c \${no} ${yes} A`;");
    // Repeated passes don't decay the escapes.
    assert_eq!(decode_string_literals(&once), once);
    assert_eq!(deobfuscate(src), once);
}

#[test]
fn fold_calls_ignores_strings_comments_and_computed_receivers() {
    // Inside a string or a comment nothing is rewritten.
    let s = r#"a = "String.fromCharCode(72)"; // atob("QUI=")"#;
    assert_eq!(fold_fromcharcode(s), s);
    assert_eq!(fold_atob(s), s);
    // A computed receiver can't be dropped (it would leave `window[...]"H"`).
    let c = r#"x = window["String"].fromCharCode(72); y = f().atob("QUI=");"#;
    assert_eq!(fold_fromcharcode(c), c);
    assert_eq!(fold_atob(c), c);
    // A longer identifier is not a match.
    assert_eq!(fold_atob(r#"myatob("QUI=")"#), r#"myatob("QUI=")"#);
    // Nested calls: the inner one folds, the outer one on a later pass.
    assert_eq!(fold_atob(r#"atob(atob("VVVrOQ=="))"#), r#"atob("UUk9")"#);
}

#[test]
fn fromcharcode_and_uri_decoding_follow_js() {
    // Values are truncated to 16 bits; surrogate pairs combine.
    assert_eq!(fold_fromcharcode("String.fromCharCode(65601)"), "\"A\"");
    assert_eq!(
        fold_fromcharcode("String.fromCharCode(0xD83D, 0xDE00)"),
        "\"\u{1F600}\""
    );
    // decodeURIComponent decodes UTF-8 byte sequences …
    assert_eq!(
        fold_unescape(r#"decodeURIComponent("%C3%A9t%C3%A9")"#),
        "\"été\""
    );
    // … and leaves calls JS would reject alone.
    let bad = r#"decodeURIComponent("%E9")"#;
    assert_eq!(fold_unescape(bad), bad);
    // unescape keeps its Latin-1 / UTF-16 semantics.
    assert_eq!(
        fold_unescape(r#"unescape("%E9%uD83D%uDE00")"#),
        "\"é\u{1F600}\""
    );
}

#[test]
fn string_array_poisoning() {
    for src in [
        // Element write.
        "var _a=['x','y'];_a[0]='z';f(_a[0]);",
        // Compound element write and update.
        "var _a=['x','y'];_a[1]+='z';f(_a[0]);",
        "var _a=['x','y'];delete _a[0];f(_a[0]);",
        // Mutating methods (the rotate-the-table trick).
        "var _a=['x','y'];_a.push(_a.shift());f(_a[0]);",
        "var _a=['x','y'];_a.reverse();f(_a[0]);",
        // Shadowing by a parameter or a re-declaration.
        "var _a=['x','y'];function g(_a){return _a[0];}",
        "var _a=['x','y'];var h=(_a)=>_a[0];",
        "var _a=['x','y'];var h=_a=>_a[0];",
        "var _a=['x','y'];{let _a;f(_a[0]);}",
        // Compound assignment of the name itself.
        "var _a=['x','y'];_a+='';f(_a[0]);",
    ] {
        assert_eq!(fold_string_array(src), src, "{src}");
    }
    // Comparisons are reads, not writes.
    let src = "var _a=['x','y'];if(_a[0]==_a[1]){f(_a[1])}";
    assert_eq!(
        fold_string_array(src),
        "var _a=['x','y'];if(\"x\"==\"y\"){f(\"y\")}"
    );
    // A property of another object is never substituted.
    let src = "var _a=['x'];o._a[0];";
    assert_eq!(fold_string_array(src), src);
}

#[test]
fn beautify_keeps_operators_apart_and_asi_line_breaks() {
    let pretty = beautify("x = a - -b; y = c + +d; z = e+ ++f;");
    assert!(pretty.contains("- -b"), "{pretty}");
    assert!(pretty.contains("+ +d"), "{pretty}");
    assert!(!pretty.contains("+++"), "{pretty}");
    // `return\nvalue` returns undefined; joining the lines would change that.
    let pretty = beautify("function f(){return\n42}");
    assert!(pretty.contains("return\n"), "{pretty}");
    assert!(!pretty.contains("return 42"), "{pretty}");
    // `1 .toString()` must not become `1.toString()`.
    let pretty = beautify("x = 1 .toString()");
    assert!(pretty.contains("1 ."), "{pretty}");
}
