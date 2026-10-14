//! JavaScript deobfuscation and beautifying for ORRESS.
//!
//! Obfuscated JavaScript is a staple of CTF and of malware droppers (droppers hide URLs, commands
//! and payloads behind `\xNN` escapes, `String.fromCharCode(...)` and string concatenation). This
//! crate, built on a tokenizer (not a full parser), offers string-level transforms that reveal the
//! hidden text, a string extractor, and a beautifier that re-indents minified code. Pure `std`,
//! never panics, always produces output.
//!
//! The transforms are deliberately conservative: they only rewrite what they can decode certainly
//! (string literals, numeric `fromCharCode`, literal concatenation), leaving everything else
//! verbatim — so the result stays valid and nothing is silently lost.

mod token;

pub use token::{Tok, Token, tokenize};

/// Decodes the escape sequences inside a string's content (without the surrounding quotes):
/// `\xNN`, `\uNNNN`, `\u{…}`, octal `\NNN`, the named escapes and line continuations.
pub fn decode_escapes(inner: &str) -> String {
    let c: Vec<char> = inner.chars().collect();
    let mut out = String::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        if c[i] != '\\' {
            out.push(c[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= c.len() {
            out.push('\\');
            break;
        }
        let e = c[i];
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'b' => out.push('\u{08}'),
            'f' => out.push('\u{0C}'),
            'v' => out.push('\u{0B}'),
            'x' => {
                if let Some(ch) = take_hex(&c, i + 1, 2) {
                    out.push(ch);
                    i += 2;
                } else {
                    out.push('x');
                }
            }
            'u' => {
                if c.get(i + 1) == Some(&'{') {
                    // \u{H+}
                    let mut j = i + 2;
                    let mut v: u32 = 0;
                    let mut any = false;
                    while j < c.len() && c[j] != '}' {
                        match c[j].to_digit(16) {
                            Some(d) => {
                                v = v.saturating_mul(16) + d;
                                any = true;
                            }
                            None => break,
                        }
                        j += 1;
                    }
                    if any && c.get(j) == Some(&'}') {
                        out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
                        i = j;
                    } else {
                        out.push('u');
                    }
                } else if let Some(ch) = take_hex(&c, i + 1, 4) {
                    out.push(ch);
                    i += 4;
                } else {
                    out.push('u');
                }
            }
            '0'..='7' => {
                // Octal escape \NNN (1–3 octal digits); `\0` alone decodes to NUL.
                let mut v = e.to_digit(8).unwrap();
                let mut taken = 0;
                while taken < 2 && c.get(i + 1).and_then(|d| d.to_digit(8)).is_some() {
                    v = v * 8 + c[i + 1].to_digit(8).unwrap();
                    i += 1;
                    taken += 1;
                }
                out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
            }
            '\n' => {} // line continuation
            other => out.push(other),
        }
        i += 1;
    }
    out
}

fn take_hex(c: &[char], start: usize, len: usize) -> Option<char> {
    if start + len > c.len() {
        return None;
    }
    let mut v: u32 = 0;
    for &ch in &c[start..start + len] {
        v = v * 16 + ch.to_digit(16)?;
    }
    char::from_u32(v)
}

/// Re-quotes decoded text as a double-quoted JS string literal, re-escaping what must be escaped.
fn requote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Strips a string/template token's surrounding quotes, returning the inner content.
fn inner_of(text: &str) -> &str {
    let b = text.as_bytes();
    if b.len() >= 2 && (b[b.len() - 1] == b[0]) {
        &text[1..text.len() - 1]
    } else {
        &text[1..] // unterminated
    }
}

/// Rewrites every string literal to its escape-decoded form (templates keep their backticks).
pub fn decode_string_literals(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for t in tokenize(src) {
        match t.kind {
            Tok::Str => out.push_str(&requote(&decode_escapes(inner_of(&t.text)))),
            Tok::Template => out.push_str(&decode_template(&t.text)),
            _ => out.push_str(&t.text),
        }
    }
    out
}

/// Escape-decodes a template literal's literal text while keeping it a valid template: `${…}`
/// interpolations are copied verbatim, and in the decoded text the characters that would end or
/// interpolate the template (`` ` ``, `\`, `${`) are re-escaped, so repeated passes are stable.
fn decode_template(text: &str) -> String {
    let c: Vec<char> = inner_of(text).chars().collect();
    let mut out = String::with_capacity(text.len());
    out.push('`');
    let mut lit = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\\' {
            lit.push(c[i]);
            if let Some(&n) = c.get(i + 1) {
                lit.push(n);
            }
            i += 2;
            continue;
        }
        if c[i] == '$' && c.get(i + 1) == Some(&'{') {
            out.push_str(&escape_template(&decode_escapes(&lit)));
            lit.clear();
            // Copy the interpolation through its matching `}` (nested braces counted).
            let mut depth = 0usize;
            while i < c.len() {
                out.push(c[i]);
                match c[i] {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            continue;
        }
        lit.push(c[i]);
        i += 1;
    }
    out.push_str(&escape_template(&decode_escapes(&lit)));
    out.push('`');
    out
}

/// Escapes decoded text for the literal part of a template.
fn escape_template(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        match ch {
            '`' => out.push_str("\\`"),
            '\\' => out.push_str("\\\\"),
            '$' if it.peek() == Some(&'{') => out.push_str("\\$"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

fn is_trivia(t: &Token) -> bool {
    matches!(t.kind, Tok::Space | Tok::LineComment | Tok::BlockComment)
}

/// Folds every call `[recv.]name(args)` whose arguments `f` can decode into a string literal
/// (a plain identifier receiver chain such as `window.String.` is replaced too). Works on tokens,
/// so text inside strings, comments and regexes is never touched. Calls `f` returns `None` for —
/// and calls on a computed receiver (`x["String"].fromCharCode(…)`, `f().atob(…)`) — are left
/// verbatim.
fn fold_calls(src: &str, name: &str, f: impl Fn(&str) -> Option<String>) -> String {
    let toks = tokenize(src);
    let prev_sig = |from: usize| (0..from).rev().find(|&i| !is_trivia(&toks[i]));
    let next_sig = |from: usize| (from..toks.len()).find(|&i| !is_trivia(&toks[i]));
    let is_punct = |i: usize, p: &str| toks[i].kind == Tok::Punct && toks[i].text == p;

    let mut out = String::with_capacity(src.len());
    // `marks[i]` = length of `out` before token `i` was emitted, so a receiver chain that was
    // already emitted can be taken back.
    let mut marks = Vec::with_capacity(toks.len());
    let mut ti = 0;
    while ti < toks.len() {
        marks.push(out.len());
        let t = &toks[ti];
        if t.kind == Tok::Ident
            && t.text == name
            && let Some(open) = next_sig(ti + 1)
            && is_punct(open, "(")
        {
            // Walk the receiver chain back: `a.b.name` → start at `a`.
            let mut start = ti;
            let mut computed = false;
            while let Some(dot) = prev_sig(start)
                && is_punct(dot, ".")
            {
                match prev_sig(dot) {
                    Some(r) if toks[r].kind == Tok::Ident => start = r,
                    _ => {
                        computed = true; // `]`, `)`, `?.`, … — not a plain name chain
                        break;
                    }
                }
            }
            if !computed && let Some(close) = matching_paren_tok(&toks, open) {
                let args: String = toks[open + 1..close]
                    .iter()
                    .map(|t| t.text.as_str())
                    .collect();
                if let Some(decoded) = f(&args) {
                    out.truncate(marks[start]);
                    out.push_str(&requote(&decoded));
                    // Keep `marks` aligned for the tokens being skipped.
                    marks.resize(close + 1, out.len());
                    ti = close + 1;
                    continue;
                }
            }
        }
        out.push_str(&t.text);
        ti += 1;
    }
    out
}

/// Index of the token closing the bracket opened at `open` (counting nested brackets).
fn matching_paren_tok(toks: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        if t.kind != Tok::Punct {
            continue;
        }
        match t.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Folds `X.fromCharCode(n, n, …)` with integer arguments into the decoded string literal.
pub fn fold_fromcharcode(src: &str) -> String {
    fold_calls(src, "fromCharCode", decode_char_codes)
}

/// Folds `atob("…")` (base64 decode) into the decoded string, when the result is valid UTF-8.
pub fn fold_atob(src: &str) -> String {
    fold_calls(src, "atob", |inner| {
        let bytes = base64_decode(&single_string_arg(inner)?)?;
        String::from_utf8(bytes).ok()
    })
}

/// Folds `unescape("…")` / `decodeURIComponent("…")` (percent-decode) into the decoded string.
pub fn fold_unescape(src: &str) -> String {
    let unescape = |inner: &str| single_string_arg(inner).map(|s| unescape_decode(&s));
    let uri = |inner: &str| single_string_arg(inner).and_then(|s| uri_decode(&s));
    fold_calls(
        &fold_calls(src, "unescape", unescape),
        "decodeURIComponent",
        uri,
    )
}

/// If `inner` is exactly one string literal, returns its escape-decoded content.
fn single_string_arg(inner: &str) -> Option<String> {
    let sig: Vec<Token> = tokenize(inner)
        .into_iter()
        .filter(|t| t.kind != Tok::Space)
        .collect();
    match sig.as_slice() {
        [t] if t.kind == Tok::Str => Some(decode_escapes(inner_of(&t.text))),
        _ => None,
    }
}

/// Decodes standard base64 (padding optional; whitespace ignored). `None` on invalid input.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut acc = 0u32;
    let mut bits = 0;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// `hex` digits starting at `start` as a number (exactly `len` of them), or `None`.
fn hex_value(c: &[char], start: usize, len: usize) -> Option<u32> {
    let digits = c.get(start..start + len)?;
    digits
        .iter()
        .try_fold(0u32, |v, ch| Some(v * 16 + ch.to_digit(16)?))
}

/// JS `unescape`: `%xx` is a Latin-1 code unit and `%uXXXX` a UTF-16 code unit (so surrogate
/// pairs combine); malformed sequences and other characters pass through.
fn unescape_decode(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut units: Vec<u16> = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        if c[i] == '%' {
            if c.get(i + 1) == Some(&'u')
                && let Some(v) = hex_value(&c, i + 2, 4)
            {
                units.push(v as u16);
                i += 6;
                continue;
            }
            if let Some(v) = hex_value(&c, i + 1, 2) {
                units.push(v as u16);
                i += 3;
                continue;
            }
        }
        let mut buf = [0u16; 2];
        units.extend_from_slice(c[i].encode_utf16(&mut buf));
        i += 1;
    }
    decode_utf16_lossy(&units)
}

/// JS `decodeURIComponent`: `%xx` sequences are UTF-8 bytes. `None` where JS would throw a
/// `URIError` (malformed `%`, invalid UTF-8), so the call is left as written.
fn uri_decode(s: &str) -> Option<String> {
    let c: Vec<char> = s.chars().collect();
    let mut bytes: Vec<u8> = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        if c[i] == '%' {
            bytes.push(hex_value(&c, i + 1, 2)? as u8);
            i += 3;
            continue;
        }
        let mut buf = [0u8; 4];
        bytes.extend_from_slice(c[i].encode_utf8(&mut buf).as_bytes());
        i += 1;
    }
    String::from_utf8(bytes).ok()
}

/// UTF-16 code units to a string; lone surrogates become U+FFFD.
fn decode_utf16_lossy(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decodes a comma-separated list of integer literals to a string, or `None` if any arg isn't a
/// plain integer (so a `fromCharCode` with computed arguments is left untouched). Like JS, each
/// value is truncated to a UTF-16 code unit (`v & 0xFFFF`) and surrogate pairs combine.
fn decode_char_codes(args: &str) -> Option<String> {
    let args = args.trim();
    if args.is_empty() {
        return None;
    }
    let mut units = Vec::new();
    for part in args.split(',') {
        let p = part.trim();
        let v = if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()?
        } else {
            p.parse::<u64>().ok()?
        };
        units.push((v & 0xFFFF) as u16);
    }
    Some(decode_utf16_lossy(&units))
}

/// Folds adjacent string-literal concatenations (`"a" + "b"` → `"ab"`) at the token level.
pub fn fold_concat(src: &str) -> String {
    let toks = tokenize(src);
    // Build a list of significant-token indices for easy lookahead.
    let mut out: Vec<Token> = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        if toks[i].kind == Tok::Str {
            // Look ahead for ( Space* '+' Space* Str )+ chains.
            let mut combined = decode_escapes(inner_of(&toks[i].text));
            let mut j = i + 1;
            let mut matched_any = false;
            loop {
                let plus = skip_space(&toks, j);
                if toks.get(plus).map(|t| (t.kind, t.text.as_str())) != Some((Tok::Punct, "+")) {
                    break;
                }
                let next = skip_space(&toks, plus + 1);
                match toks.get(next) {
                    Some(t) if t.kind == Tok::Str => {
                        combined.push_str(&decode_escapes(inner_of(&t.text)));
                        j = next + 1;
                        matched_any = true;
                    }
                    _ => break,
                }
            }
            if matched_any {
                out.push(Token {
                    kind: Tok::Str,
                    text: requote(&combined),
                });
                i = j;
                continue;
            }
        }
        out.push(toks[i].clone());
        i += 1;
    }
    out.iter().map(|t| t.text.as_str()).collect()
}

fn skip_space(toks: &[Token], mut i: usize) -> usize {
    while toks.get(i).map(|t| t.kind) == Some(Tok::Space) {
        i += 1;
    }
    i
}

/// Methods that mutate an array in place; calling one on the table makes it unsafe to inline.
const ARRAY_MUTATORS: &[&str] = &[
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "reverse",
    "sort",
    "fill",
    "copyWithin",
];

/// Replaces `NAME[i]` with the literal from a single top-level literal string array
/// (`var NAME = ['a','b',…];`). This is the common string-table obfuscation (the non-rotated
/// form). Any sign that the table might not hold its initial contents at a use site poisons the
/// name and leaves every use alone: a reassignment (`NAME = …`, `NAME += …`, `++NAME`), an element
/// write (`NAME[…] = …`, `delete NAME[…]`), a mutating method call (`NAME.push(…)`, `.shift()`,
/// `.splice()`, …), a second declaration, the name appearing as a function/arrow/catch parameter
/// (shadowing), or appearing as a property (`obj.NAME`).
pub fn fold_string_array(src: &str) -> String {
    use std::collections::{HashMap, HashSet};
    let toks = tokenize(src);
    let sig: Vec<usize> = (0..toks.len()).filter(|&i| !is_trivia(&toks[i])).collect();
    let at = |k: usize| sig.get(k).map(|&i| &toks[i]);
    let kv = |k: usize| at(k).map(|t| (t.kind, t.text.as_str()));
    let punct = |k: usize, p: &str| kv(k) == Some((Tok::Punct, p));
    let ident = |k: usize| {
        at(k)
            .filter(|t| t.kind == Tok::Ident)
            .map(|t| t.text.as_str())
    };
    let prev_punct = |k: usize, p: &str| k > 0 && punct(k - 1, p);
    // Sig index of the bracket closing the one opened at sig index `open`.
    let close_of = |open: usize| {
        let mut depth = 0usize;
        for j in open..sig.len() {
            match kv(j) {
                Some((Tok::Punct, "(" | "[" | "{")) => depth += 1,
                Some((Tok::Punct, ")" | "]" | "}")) => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(j);
                    }
                }
                _ => {}
            }
        }
        None
    };
    // Sig index of the bracket opening the one closed at sig index `close`.
    let open_of = |close: usize| {
        let mut depth = 0usize;
        for j in (0..=close).rev() {
            match kv(j) {
                Some((Tok::Punct, ")" | "]" | "}")) => depth += 1,
                Some((Tok::Punct, "(" | "[" | "{")) => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(j);
                    }
                }
                _ => {}
            }
        }
        None
    };
    // Whether an assignment / update operator starts at sig index `j` (`=`, `+=`, `>>>=`, `??=`,
    // `++`, `--`, … but not `==`, `!=`, `<=`, `=>`).
    let assigns = |j: usize| {
        let mut op = String::new();
        let mut j = j;
        while let Some((Tok::Punct, p)) = kv(j) {
            if !"+-*/%<>&|^?!=".contains(p) || op.len() >= 4 {
                break;
            }
            op.push_str(p);
            j += 1;
            if p == "=" {
                break;
            }
        }
        if op.starts_with("++") || op.starts_with("--") {
            return true;
        }
        let Some(prefix) = op.strip_suffix('=') else {
            return false;
        };
        !punct(j, "=")
            && !punct(j, ">")
            && matches!(
                prefix,
                "" | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "**"
                    | "<<"
                    | ">>"
                    | ">>>"
                    | "&"
                    | "|"
                    | "^"
                    | "&&"
                    | "||"
                    | "??"
            )
    };

    // Pass A: collect literal arrays by name; `None` marks a second definition.
    let mut arrays: HashMap<String, Option<Vec<String>>> = HashMap::new();
    let mut poisoned: HashSet<String> = HashSet::new();
    let mut declarations: HashMap<String, usize> = HashMap::new();
    let poison_idents = |from: usize, to: usize, poisoned: &mut HashSet<String>| {
        for j in from..=to {
            if let Some(n) = ident(j) {
                poisoned.insert(n.to_string());
            }
        }
    };
    let mut k = 0;
    while k < sig.len() {
        // Parameters shadow outer names: `function f(a, b)`, `catch (e)`, `(a, b) =>`, `a =>`.
        if punct(k, "=") && punct(k + 1, ">") && k > 0 {
            if ident(k - 1).is_some() {
                poison_idents(k - 1, k - 1, &mut poisoned);
            } else if punct(k - 1, ")")
                && let Some(open) = open_of(k - 1)
            {
                poison_idents(open, k - 1, &mut poisoned);
            }
        }
        let Some(name) = ident(k) else {
            k += 1;
            continue;
        };
        if matches!(name, "function" | "catch") {
            let open = if punct(k + 1, "(") { k + 1 } else { k + 2 };
            if punct(open, "(")
                && let Some(close) = close_of(open)
            {
                poison_idents(k + 1, close, &mut poisoned); // name + params
            }
            k += 1;
            continue;
        }
        let name = name.to_string();
        if prev_punct(k, ".") {
            // `obj.NAME` is some other object's property; don't guess, poison.
            poisoned.insert(name);
            k += 1;
            continue;
        }
        if k > 0 && matches!(ident(k - 1), Some("var" | "let" | "const")) {
            *declarations.entry(name.clone()).or_default() += 1;
        }
        if k >= 2
            && ((punct(k - 1, "+") && punct(k - 2, "+"))
                || (punct(k - 1, "-") && punct(k - 2, "-")))
        {
            poisoned.insert(name.clone()); // ++NAME / --NAME
        }
        if punct(k + 1, ".") && ident(k + 2).is_some_and(|m| ARRAY_MUTATORS.contains(&m)) {
            poisoned.insert(name.clone());
        }
        if punct(k + 1, "[") {
            // Element write: `NAME[…] = …`, `NAME[…]++`, `delete NAME[…]`.
            let writes = close_of(k + 1).is_some_and(|close| assigns(close + 1))
                || (k > 0 && ident(k - 1) == Some("delete"));
            if writes {
                poisoned.insert(name.clone());
            }
        }
        if punct(k + 1, "=") && punct(k + 2, "[") {
            let mut vals = Vec::new();
            let mut j = k + 3;
            let mut expect_str = true;
            let mut ok = true;
            loop {
                match kv(j) {
                    Some((Tok::Punct, "]")) => break,
                    Some((Tok::Str, _)) if expect_str => {
                        vals.push(decode_escapes(inner_of(&at(j).unwrap().text)));
                        expect_str = false;
                        j += 1;
                    }
                    Some((Tok::Punct, ",")) if !expect_str => {
                        expect_str = true;
                        j += 1;
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                arrays
                    .entry(name)
                    .and_modify(|e| *e = None) // second definition → poison
                    .or_insert(Some(vals));
                k = j + 1;
                continue;
            }
            poisoned.insert(name);
        } else if assigns(k + 1) {
            // Any other assignment to (or update of) the name poisons it.
            poisoned.insert(name);
        }
        k += 1;
    }
    for (name, n) in declarations {
        if n > 1 {
            poisoned.insert(name);
        }
    }
    let clean: HashMap<String, Vec<String>> = arrays
        .into_iter()
        .filter(|(k, _)| !poisoned.contains(k))
        .filter_map(|(k, v)| v.map(|vv| (k, vv)))
        .collect();
    if clean.is_empty() {
        return src.to_string();
    }

    // Pass B: replace `NAME[int]` (read positions only) with the literal.
    let mut sig_of = vec![usize::MAX; toks.len()];
    for (s, &ti) in sig.iter().enumerate() {
        sig_of[ti] = s;
    }
    let mut out = String::with_capacity(src.len());
    let mut ti = 0;
    while ti < toks.len() {
        let t = &toks[ti];
        let s = sig_of[ti];
        if t.kind == Tok::Ident
            && let Some(arr) = clean.get(&t.text)
            && !prev_punct(s, ".")
            && punct(s + 1, "[")
            && kv(s + 2).map(|(k, _)| k) == Some(Tok::Number)
            && punct(s + 3, "]")
            && !assigns(s + 4)
            && let Ok(idx) = at(s + 2).unwrap().text.parse::<usize>()
            && let Some(val) = arr.get(idx)
        {
            out.push_str(&requote(val));
            ti = sig[s + 3] + 1;
            continue;
        }
        out.push_str(&t.text);
        ti += 1;
    }
    out
}

/// Applies the deobfuscation transforms repeatedly until the source stops changing (bounded), so
/// layered obfuscation (array lookups → fromCharCode → escapes → concatenation) is unwound.
pub fn deobfuscate(src: &str) -> String {
    let mut cur = src.to_string();
    for _ in 0..6 {
        let step = fold_string_array(&cur);
        let step = fold_fromcharcode(&step);
        let step = fold_atob(&step);
        let step = fold_unescape(&step);
        let step = fold_concat(&step);
        let next = decode_string_literals(&step);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Every string literal's decoded text, in source order (deduplicated, blanks dropped).
pub fn extract_strings(src: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for t in tokenize(src) {
        if matches!(t.kind, Tok::Str | Tok::Template) {
            let d = decode_escapes(inner_of(&t.text));
            if !d.trim().is_empty() && seen.insert(d.clone()) {
                out.push(d);
            }
        }
    }
    out
}

/// Re-indents minified JavaScript. Not a pretty-printer — it adds newlines around `{}` and after
/// `;`, indents blocks, and spaces word boundaries, enough to read the structure. The token stream
/// is preserved (only whitespace changes).
pub fn beautify(src: &str) -> String {
    // Drop whitespace, but remember what separated each token from the previous one: a space
    // (so `a - -b` doesn't fuse into `a--b`) or a newline (so ASI after `return` is kept).
    let mut toks: Vec<Token> = Vec::new();
    let mut gap: Vec<Gap> = Vec::new();
    let mut pending = Gap::None;
    for t in tokenize(src) {
        if t.kind == Tok::Space {
            pending = if t.text.contains('\n') || pending == Gap::Newline {
                Gap::Newline
            } else {
                Gap::Space
            };
            continue;
        }
        toks.push(t);
        gap.push(std::mem::replace(&mut pending, Gap::None));
    }
    let mut out = String::new();
    let mut indent: usize = 0;
    let nl = |out: &mut String, indent: usize| {
        out.push('\n');
        out.push_str(&"  ".repeat(indent));
    };
    for idx in 0..toks.len() {
        let t = &toks[idx];
        let prev = idx.checked_sub(1).map(|i| &toks[i]);
        let next = toks.get(idx + 1);
        match (t.kind, t.text.as_str()) {
            (Tok::Punct, "{") => {
                if needs_space_before_brace(prev) {
                    out.push(' ');
                }
                out.push('{');
                indent += 1;
                nl(&mut out, indent);
            }
            (Tok::Punct, "}") => {
                indent = indent.saturating_sub(1);
                trim_trailing_ws(&mut out);
                nl(&mut out, indent);
                out.push('}');
                // Start a new line after a block, unless a continuation follows it.
                let continues = matches!(
                    next.map(|n| (n.kind, n.text.as_str())),
                    Some((Tok::Punct, ";" | "," | ")" | "]" | "."))
                        | Some((Tok::Ident, "else" | "catch" | "finally" | "while"))
                );
                if next.is_some() && !continues {
                    nl(&mut out, indent);
                }
            }
            (Tok::Punct, ";") => {
                out.push(';');
                if next.map(|n| n.text.as_str()) != Some("}") {
                    nl(&mut out, indent);
                }
            }
            (Tok::Punct, ",") => out.push_str(", "),
            (Tok::LineComment, _) => {
                out.push_str(&t.text);
                nl(&mut out, indent);
            }
            _ => {
                if keeps_line_break(prev, t, next, gap[idx]) {
                    trim_trailing_ws(&mut out);
                    nl(&mut out, indent);
                } else if needs_space(prev, t, gap[idx]) {
                    out.push(' ');
                }
                out.push_str(&t.text);
            }
        }
    }
    out.trim().to_string()
}

/// What separated a token from the previous one in the source.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gap {
    None,
    Space,
    Newline,
}

/// A source line break that automatic semicolon insertion depends on: after `return`, `break`,
/// `continue`, `throw` or `yield` (a newline there ends the statement), and before a prefix
/// `++`/`--`.
fn keeps_line_break(prev: Option<&Token>, cur: &Token, next: Option<&Token>, gap: Gap) -> bool {
    if gap != Gap::Newline {
        return false;
    }
    let Some(p) = prev else { return false };
    let restricted = p.kind == Tok::Ident
        && matches!(
            p.text.as_str(),
            "return" | "break" | "continue" | "throw" | "yield"
        );
    let prefix_update = cur.kind == Tok::Punct
        && matches!(cur.text.as_str(), "+" | "-")
        && next.is_some_and(|n| n.kind == Tok::Punct && n.text == cur.text);
    restricted || prefix_update
}

fn trim_trailing_ws(out: &mut String) {
    while out.ends_with(' ') || out.ends_with('\n') {
        out.pop();
    }
}

fn needs_space_before_brace(prev: Option<&Token>) -> bool {
    matches!(prev, Some(t) if t.kind == Tok::Ident || matches!(t.text.as_str(), ")" | "="))
}

fn is_word(t: &Token) -> bool {
    matches!(
        t.kind,
        Tok::Ident | Tok::Number | Tok::Str | Tok::Template | Tok::Regex
    )
}

fn needs_space(prev: Option<&Token>, cur: &Token, gap: Gap) -> bool {
    let Some(p) = prev else { return false };
    // Keep word tokens apart, and put a space after control keywords before `(`.
    if is_word(p) && is_word(cur) {
        return true;
    }
    if gap != Gap::None {
        // Operators are single-character tokens; ones that were apart in the source must stay
        // apart (`a - -b`, `a + +b`, `x = /re/` after `/`), or they would fuse into another.
        const OPS: &str = "+-*/%<>=!&|^?.";
        if p.kind == Tok::Punct
            && cur.kind == Tok::Punct
            && OPS.contains(p.text.as_str())
            && OPS.contains(cur.text.as_str())
        {
            return true;
        }
        // Anything else that would re-lex differently when joined (`1 .x` → `1.x`, `a / /re/`).
        let joined = format!("{}{}", p.text, cur.text);
        let relexed = tokenize(&joined);
        if relexed.len() != 2 || relexed[0] != *p || relexed[1] != *cur {
            return true;
        }
    }
    if p.kind == Tok::Ident
        && cur.kind == Tok::Punct
        && cur.text == "("
        && matches!(
            p.text.as_str(),
            "if" | "for" | "while" | "switch" | "catch" | "return" | "function" | "do"
        )
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests;
