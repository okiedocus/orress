//! A JavaScript tokenizer good enough for beautifying and string-level deobfuscation. It is not a
//! full parser: it splits source into strings, template literals, regex literals, comments,
//! numbers, identifiers and single-character punctuation, which is what the transforms need. It
//! never panics and always consumes the whole input (an unterminated string/comment runs to EOF).

/// The kind of a lexical token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tok {
    /// A `'…'` or `"…"` string literal (text includes the quotes).
    Str,
    /// A `` `…` `` template literal (text includes the backticks).
    Template,
    /// A `/…/flags` regular-expression literal.
    Regex,
    Number,
    Ident,
    /// One punctuation character (operators are emitted char-by-char).
    Punct,
    LineComment,
    BlockComment,
    /// A run of whitespace (kept so transforms can reproduce the original source verbatim).
    Space,
}

/// A lexical token: its kind and exact source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: Tok,
    pub text: String,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$' || (c as u32) > 127
}
fn is_ident_part(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

/// The last token that isn't whitespace or a comment.
fn last_significant(out: &[Token]) -> Option<&Token> {
    out.iter()
        .rev()
        .find(|t| !matches!(t.kind, Tok::Space | Tok::LineComment | Tok::BlockComment))
}

/// Whether a `/` after the previous significant token begins a regex (vs. division). A regex can't
/// follow a value: an identifier, number, string, `)`, `]`, or `}` (close of a block/value).
fn regex_allowed(prev: Option<&Token>) -> bool {
    match prev {
        None => true,
        Some(t) => match t.kind {
            Tok::Ident => matches!(
                t.text.as_str(),
                "return"
                    | "typeof"
                    | "instanceof"
                    | "in"
                    | "of"
                    | "new"
                    | "delete"
                    | "void"
                    | "do"
                    | "else"
                    | "yield"
                    | "await"
                    | "case"
            ),
            Tok::Number | Tok::Str | Tok::Template | Tok::Regex => false,
            Tok::Punct => !matches!(t.text.as_str(), ")" | "]" | "}"),
            _ => true,
        },
    }
}

/// Tokenizes JavaScript source. Every character lands in exactly one token: whitespace runs
/// become [`Tok::Space`] tokens and comments are kept, so concatenating the token texts
/// reproduces the input exactly.
pub fn tokenize(src: &str) -> Vec<Token> {
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let n = chars.len();
    let mut out: Vec<Token> = Vec::new();

    let push = |out: &mut Vec<Token>, kind: Tok, s: String| out.push(Token { kind, text: s });

    while i < n {
        let c = chars[i];
        if c.is_whitespace() {
            let start = i;
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            push(&mut out, Tok::Space, chars[start..i].iter().collect());
            continue;
        }
        // Comments.
        if c == '/' && i + 1 < n && chars[i + 1] == '/' {
            let start = i;
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            push(&mut out, Tok::LineComment, chars[start..i].iter().collect());
            continue;
        }
        if c == '/' && i + 1 < n && chars[i + 1] == '*' {
            let start = i;
            i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(n);
            push(
                &mut out,
                Tok::BlockComment,
                chars[start..i].iter().collect(),
            );
            continue;
        }
        // Strings.
        if c == '"' || c == '\'' {
            let start = i;
            i += 1;
            while i < n && chars[i] != c {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(n);
            push(&mut out, Tok::Str, chars[start..i].iter().collect());
            continue;
        }
        // Template literals (interpolation boundaries are not tracked).
        if c == '`' {
            let start = i;
            i += 1;
            while i < n && chars[i] != '`' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(n);
            push(&mut out, Tok::Template, chars[start..i].iter().collect());
            continue;
        }
        // Regex vs. division.
        if c == '/' && regex_allowed(last_significant(&out)) {
            let start = i;
            i += 1;
            let mut in_class = false;
            while i < n {
                let d = chars[i];
                if d == '\\' {
                    i += 2;
                    continue;
                }
                if d == '[' {
                    in_class = true;
                } else if d == ']' {
                    in_class = false;
                } else if d == '/' && !in_class {
                    break;
                } else if d == '\n' {
                    break; // unterminated; bail
                }
                i += 1;
            }
            i = (i + 1).min(n); // consume closing '/'
            while i < n && chars[i].is_ascii_alphabetic() {
                i += 1; // flags
            }
            push(&mut out, Tok::Regex, chars[start..i].iter().collect());
            continue;
        }
        // Numbers.
        if c.is_ascii_digit() || (c == '.' && i + 1 < n && chars[i + 1].is_ascii_digit()) {
            let start = i;
            i += 1;
            while i < n {
                let d = chars[i];
                let exponent_sign = (d == '+' || d == '-') && matches!(chars[i - 1], 'e' | 'E');
                if d.is_ascii_alphanumeric() || d == '.' || d == '_' || exponent_sign {
                    i += 1;
                } else {
                    break;
                }
            }
            push(&mut out, Tok::Number, chars[start..i].iter().collect());
            continue;
        }
        // Identifiers / keywords.
        if is_ident_start(c) {
            let start = i;
            i += 1;
            while i < n && is_ident_part(chars[i]) {
                i += 1;
            }
            push(&mut out, Tok::Ident, chars[start..i].iter().collect());
            continue;
        }
        // Everything else: one punctuation character.
        push(&mut out, Tok::Punct, c.to_string());
        i += 1;
    }
    out
}
