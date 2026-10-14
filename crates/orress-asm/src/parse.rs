//! A small Intel-syntax parser, independent of any target. It splits source into lines, pulls off
//! an optional `label:`, a mnemonic and comma-separated operands, and classifies each operand as an
//! immediate, a memory reference `[base + index*scale + disp]`, or a bare *name* (a register or a
//! symbol — the encoder decides which, so this parser needs no per-architecture register table).

use crate::Diagnostic;

/// One source line, parsed. Produced for **every** physical line (including blank/comment lines,
/// which have no `stmt`) so the listing and diagnostics line up 1:1 with the editor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Line {
    /// 1-based line number.
    pub line: usize,
    /// The trimmed source text, for the listing display.
    pub source: String,
    /// A label defined on this line (`name:`), if any.
    pub label: Option<String>,
    /// The instruction on this line, if any.
    pub stmt: Option<Stmt>,
}

/// A mnemonic and its operands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Stmt {
    /// Lower-cased mnemonic, e.g. `mov`.
    pub mnemonic: String,
    pub operands: Vec<Operand>,
}

/// A single operand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operand {
    /// A bare identifier: either a register or a symbol/label reference. Lower-cased.
    Name(String),
    /// An immediate value.
    Imm(i64),
    /// A memory reference.
    Mem(Mem),
    /// A shift or extend modifier operand (A64), e.g. `lsl #4`, `asr #2`, `sxtw`.
    Shift { op: ShiftOp, amount: i64 },
}

/// A shift or register-extend operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShiftOp {
    Lsl,
    Lsr,
    Asr,
    Ror,
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

impl ShiftOp {
    fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "lsl" => Self::Lsl,
            "lsr" => Self::Lsr,
            "asr" => Self::Asr,
            "ror" => Self::Ror,
            "uxtb" => Self::Uxtb,
            "uxth" => Self::Uxth,
            "uxtw" => Self::Uxtw,
            "uxtx" => Self::Uxtx,
            "sxtb" => Self::Sxtb,
            "sxth" => Self::Sxth,
            "sxtw" => Self::Sxtw,
            "sxtx" => Self::Sxtx,
            _ => return None,
        })
    }
}

/// A memory operand: `[base + index*scale + disp]`, optionally with a size prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Mem {
    pub size: Option<MemSize>,
    /// Base register name (lower-cased), if any.
    pub base: Option<String>,
    /// Index register name (lower-cased), if any.
    pub index: Option<String>,
    /// Index scale: 1, 2, 4 or 8.
    pub scale: u8,
    /// Signed displacement.
    pub disp: i64,
}

/// An explicit operand size prefix (`byte ptr [...]`, `qword [...]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemSize {
    Byte,
    Word,
    Dword,
    Qword,
}

/// Parse the whole source into lines. Returns the parsed lines on success, or every line-anchored
/// diagnostic found.
pub(crate) fn parse(source: &str) -> Result<Vec<Line>, Vec<Diagnostic>> {
    let mut lines = Vec::new();
    let mut errors = Vec::new();
    for (i, raw) in source.lines().enumerate() {
        let line = i + 1;
        match parse_line(line, raw) {
            Ok(l) => lines.push(l),
            Err(d) => errors.push(d),
        }
    }
    if errors.is_empty() {
        Ok(lines)
    } else {
        Err(errors)
    }
}

fn parse_line(line: usize, raw: &str) -> Result<Line, Diagnostic> {
    let no_comment = strip_comment(raw);
    let text = no_comment.trim();
    let source = text.to_string();
    if text.is_empty() {
        return Ok(Line {
            line,
            source,
            label: None,
            stmt: None,
        });
    }

    // Optional leading `label:`.
    let (label, rest) = split_label(text);
    let rest = rest.trim();
    if rest.is_empty() {
        return Ok(Line {
            line,
            source,
            label,
            stmt: None,
        });
    }

    // mnemonic + operands
    let (mnemonic, operand_text) = match rest.split_once(char::is_whitespace) {
        Some((m, ops)) => (m, ops.trim()),
        None => (rest, ""),
    };
    let mnemonic = mnemonic.to_ascii_lowercase();
    let mut operands = Vec::new();
    for piece in split_operands(operand_text, line)? {
        operands.push(parse_operand(&piece, line)?);
    }

    Ok(Line {
        line,
        source,
        label,
        stmt: Some(Stmt { mnemonic, operands }),
    })
}

/// Remove a trailing `;` comment, ignoring a `;` inside a `'...'` char literal.
fn strip_comment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_char = false;
    let mut escaped = false;
    for c in raw.chars() {
        if in_char {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '\'' {
                in_char = false;
            }
            continue;
        }
        match c {
            ';' => break,
            '\'' => {
                in_char = true;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// If `text` begins with `ident:`, return the label and the remainder.
fn split_label(text: &str) -> (Option<String>, &str) {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !is_ident_start(bytes[0] as char) {
        return (None, text);
    }
    let mut i = 0;
    while i < bytes.len() && is_ident_part(bytes[i] as char) {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b':' {
        let label = text[..i].to_ascii_lowercase();
        (Some(label), &text[i + 1..])
    } else {
        (None, text)
    }
}

/// Split operand text on commas that are not inside `[...]`.
fn split_operands(text: &str, line: usize) -> Result<Vec<String>, Diagnostic> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err(Diagnostic::new(line, "unbalanced `]` in operands"));
                }
            }
            ',' if depth == 0 => {
                parts.push(text[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(Diagnostic::new(line, "unclosed `[` in operands"));
    }
    parts.push(text[start..].trim().to_string());
    if parts.iter().any(|p| p.is_empty()) {
        return Err(Diagnostic::new(line, "empty operand"));
    }
    Ok(parts)
}

fn parse_operand(text: &str, line: usize) -> Result<Operand, Diagnostic> {
    // Size-prefixed or bare memory operand.
    let lower = text.to_ascii_lowercase();
    if let Some(mem) = try_parse_mem(&lower, line)? {
        return Ok(Operand::Mem(mem));
    }
    // Immediate?
    if let Some(v) = parse_imm(text) {
        return Ok(Operand::Imm(v));
    }
    // A shift/extend modifier: `lsl #4`, `asr #2`, `sxtw` ...
    if let Some((op, amount)) = parse_shift(&lower) {
        return Ok(Operand::Shift { op, amount });
    }
    // Otherwise a bare name (register or symbol).
    if lower.chars().all(is_ident_part) && lower.chars().next().is_some_and(is_ident_start) {
        return Ok(Operand::Name(lower));
    }
    Err(Diagnostic::new(
        line,
        format!("cannot parse operand `{text}`"),
    ))
}

/// Parse a `[...]` memory operand, with an optional `byte|word|dword|qword [ptr]` size prefix.
/// Returns `Ok(None)` if `text` is not a memory operand.
fn try_parse_mem(lower: &str, line: usize) -> Result<Option<Mem>, Diagnostic> {
    let mut rest = lower.trim();
    let mut size = None;
    for (kw, s) in [
        ("byte", MemSize::Byte),
        ("word", MemSize::Word),
        ("dword", MemSize::Dword),
        ("qword", MemSize::Qword),
    ] {
        if let Some(after) = rest.strip_prefix(kw)
            && (after.starts_with(char::is_whitespace) || after.starts_with('['))
        {
            size = Some(s);
            rest = after.trim_start();
            rest = rest.strip_prefix("ptr").unwrap_or(rest).trim_start();
            break;
        }
    }
    let inner = match (rest.strip_prefix('['), rest.strip_suffix(']')) {
        (Some(_), Some(_)) if rest.ends_with(']') => &rest[1..rest.len() - 1],
        _ => {
            if size.is_some() {
                return Err(Diagnostic::new(
                    line,
                    "size prefix must be followed by `[...]`",
                ));
            }
            return Ok(None);
        }
    };
    let mem = parse_mem_inner(inner.trim(), size, line)?;
    Ok(Some(mem))
}

/// Parse the inside of `[...]`: terms joined by `+`/`-`, each a register, `reg*scale`,
/// `scale*reg`, or a displacement number.
fn parse_mem_inner(inner: &str, size: Option<MemSize>, line: usize) -> Result<Mem, Diagnostic> {
    let mut mem = Mem {
        size,
        scale: 1,
        ..Mem::default()
    };
    if inner.is_empty() {
        return Err(Diagnostic::new(line, "empty `[]` memory operand"));
    }
    for (term, neg) in split_terms(inner) {
        let term = term.trim();
        if term.is_empty() {
            return Err(Diagnostic::new(line, "empty term in memory operand"));
        }
        if let Some((a, b)) = term.split_once('*') {
            // reg*scale or scale*reg
            let (reg, scale) = match (parse_u8_scale(a.trim()), parse_u8_scale(b.trim())) {
                (Some(s), None) => (b.trim(), s),
                (None, Some(s)) => (a.trim(), s),
                _ => return Err(Diagnostic::new(line, format!("bad scaled term `{term}`"))),
            };
            if neg {
                return Err(Diagnostic::new(line, "a scaled index cannot be subtracted"));
            }
            if mem.index.is_some() {
                return Err(Diagnostic::new(line, "more than one index register"));
            }
            if !is_ident(reg) {
                return Err(Diagnostic::new(line, format!("`{reg}` is not a register")));
            }
            mem.index = Some(reg.to_string());
            mem.scale = scale;
        } else if let Some(v) = parse_imm(term) {
            mem.disp = mem
                .disp
                .checked_add(if neg { v.wrapping_neg() } else { v })
                .ok_or_else(|| Diagnostic::new(line, "displacement overflow"))?;
        } else if is_ident(term) {
            if neg {
                return Err(Diagnostic::new(line, "a register cannot be subtracted"));
            }
            if mem.base.is_none() {
                mem.base = Some(term.to_string());
            } else if mem.index.is_none() {
                mem.index = Some(term.to_string());
            } else {
                return Err(Diagnostic::new(
                    line,
                    "too many registers in memory operand",
                ));
            }
        } else if let Some((op, amount)) = parse_shift(term) {
            // A64 scaled index: `[xn, xm, lsl #s]` → scale 1<<s.
            if op != ShiftOp::Lsl {
                return Err(Diagnostic::new(line, "only `lsl` may scale a memory index"));
            }
            if mem.index.is_none() {
                return Err(Diagnostic::new(
                    line,
                    "`lsl` has no index register to scale",
                ));
            }
            mem.scale = match amount {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => {
                    return Err(Diagnostic::new(
                        line,
                        "memory index shift must be lsl #0..3",
                    ));
                }
            };
        } else {
            return Err(Diagnostic::new(
                line,
                format!("cannot parse `{term}` in `[]`"),
            ));
        }
    }
    Ok(mem)
}

/// Split a memory operand's inner text into signed terms. x86 uses `+`/`-` between terms; A64 uses
/// commas and `#`-prefixed immediates (whose own `-` sign must stay attached). We detect A64 by the
/// presence of `#` and then split on commas only, leaving `#-8` intact.
fn split_terms(inner: &str) -> Vec<(String, bool)> {
    let arm = inner.contains('#');
    let mut terms = Vec::new();
    let mut cur = String::new();
    let mut neg = false;
    for c in inner.chars() {
        match c {
            ',' => {
                terms.push((std::mem::take(&mut cur), neg));
                neg = false;
            }
            '+' if !arm => {
                terms.push((std::mem::take(&mut cur), neg));
                neg = false;
            }
            '-' if !arm => {
                terms.push((std::mem::take(&mut cur), neg));
                neg = true;
            }
            _ => cur.push(c),
        }
    }
    terms.push((cur, neg));
    // The first push with an empty `cur` (leading sign) is dropped by the empty-term check.
    terms
        .into_iter()
        .filter(|(t, _)| !t.trim().is_empty())
        .collect()
}

fn parse_u8_scale(s: &str) -> Option<u8> {
    match s {
        "1" => Some(1),
        "2" => Some(2),
        "4" => Some(4),
        "8" => Some(8),
        _ => None,
    }
}

/// Parse an immediate: decimal, `0x` hex, `0b` binary, `0o` octal, or a `'c'` char literal.
/// A leading `-` negates.
fn parse_imm(text: &str) -> Option<i64> {
    let t = text.trim();
    if let Some(ch) = parse_char_literal(t) {
        return Some(ch as i64);
    }
    // ARM-style immediates are written with a leading `#` (e.g. `#8`, `#0x10`, `#-1`).
    let t = t.strip_prefix('#').map_or(t, str::trim_start);
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b.trim_start()),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let body = body.replace('_', "");
    let value: i64 = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()? as i64
    } else if let Some(b) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
        u64::from_str_radix(b, 2).ok()? as i64
    } else if let Some(o) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
        u64::from_str_radix(o, 8).ok()? as i64
    } else if body.chars().all(|c| c.is_ascii_digit()) && !body.is_empty() {
        body.parse::<u64>().ok()? as i64
    } else {
        return None;
    };
    Some(if neg { value.wrapping_neg() } else { value })
}

/// Parse a shift/extend modifier: `lsl #4`, `asr 2`, or a bare `sxtw` (amount 0).
fn parse_shift(text: &str) -> Option<(ShiftOp, i64)> {
    let mut it = text.split_whitespace();
    let op = ShiftOp::from_name(it.next()?)?;
    let amount = match it.next() {
        Some(a) => parse_imm(a)?,
        None => 0,
    };
    if it.next().is_some() {
        return None;
    }
    Some((op, amount))
}

fn parse_char_literal(t: &str) -> Option<char> {
    let inner = t.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = inner.chars();
    let c = chars.next()?;
    if c == '\\' {
        let esc = chars.next()?;
        if chars.next().is_some() {
            return None;
        }
        return Some(match esc {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '0' => '\0',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            _ => return None,
        });
    }
    if chars.next().is_some() {
        return None;
    }
    Some(c)
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().next().is_some_and(is_ident_start) && s.chars().all(is_ident_part)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '.'
}

fn is_ident_part(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmt(src: &str) -> Stmt {
        let lines = parse(src).expect("parses");
        lines
            .into_iter()
            .find_map(|l| l.stmt)
            .expect("has a statement")
    }

    #[test]
    fn blank_and_comment_lines_have_no_stmt() {
        let lines = parse("\n  ; just a comment\n\t\n").expect("parses");
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.stmt.is_none() && l.label.is_none()));
    }

    #[test]
    fn mnemonic_and_register_operands() {
        let s = stmt("  MOV rax, rbx ; copy");
        assert_eq!(s.mnemonic, "mov");
        assert_eq!(
            s.operands,
            vec![Operand::Name("rax".into()), Operand::Name("rbx".into())]
        );
    }

    #[test]
    fn immediates_in_several_bases() {
        assert_eq!(parse_imm("42"), Some(42));
        assert_eq!(parse_imm("0x2a"), Some(42));
        assert_eq!(parse_imm("0b101010"), Some(42));
        assert_eq!(parse_imm("0o52"), Some(42));
        assert_eq!(parse_imm("-7"), Some(-7));
        assert_eq!(parse_imm("'A'"), Some(65));
        assert_eq!(parse_imm("'\\n'"), Some(10));
        assert_eq!(parse_imm("rax"), None);
    }

    #[test]
    fn immediates_with_the_top_bit_set() {
        // Full 64-bit patterns parse as their two's-complement bits.
        assert_eq!(parse_imm("0x8000000000000000"), Some(i64::MIN));
        assert_eq!(parse_imm("0xffffffffffffffff"), Some(-1));
        assert_eq!(parse_imm("18446744073709551615"), Some(-1));
        assert_eq!(parse_imm("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_imm("#-0x10"), Some(-16));
        // Too wide for 64 bits.
        assert_eq!(parse_imm("0x1_0000_0000_0000_0000"), None);
    }

    #[test]
    fn label_then_instruction() {
        let lines = parse("loop: dec rcx").expect("parses");
        assert_eq!(lines[0].label.as_deref(), Some("loop"));
        let s = lines[0].stmt.clone().expect("stmt");
        assert_eq!(s.mnemonic, "dec");
        assert_eq!(s.operands, vec![Operand::Name("rcx".into())]);
    }

    #[test]
    fn bare_label_line() {
        let lines = parse("done:").expect("parses");
        assert_eq!(lines[0].label.as_deref(), Some("done"));
        assert!(lines[0].stmt.is_none());
    }

    #[test]
    fn memory_operand_full_form() {
        let s = stmt("mov rax, qword ptr [rbx + rcx*4 - 8]");
        let Operand::Mem(m) = &s.operands[1] else {
            panic!("expected memory operand, got {:?}", s.operands[1]);
        };
        assert_eq!(m.size, Some(MemSize::Qword));
        assert_eq!(m.base.as_deref(), Some("rbx"));
        assert_eq!(m.index.as_deref(), Some("rcx"));
        assert_eq!(m.scale, 4);
        assert_eq!(m.disp, -8);
    }

    #[test]
    fn memory_operand_bare_and_scale_first() {
        let s = stmt("mov al, [8*rsi + rbp]");
        let Operand::Mem(m) = &s.operands[1] else {
            panic!("expected memory operand");
        };
        assert_eq!(m.size, None);
        assert_eq!(m.base.as_deref(), Some("rbp"));
        assert_eq!(m.index.as_deref(), Some("rsi"));
        assert_eq!(m.scale, 8);
        assert_eq!(m.disp, 0);
    }

    #[test]
    fn no_operand_instruction() {
        let s = stmt("ret");
        assert_eq!(s.mnemonic, "ret");
        assert!(s.operands.is_empty());
    }

    #[test]
    fn unbalanced_bracket_is_an_error() {
        assert!(parse("mov rax, [rbx").is_err());
    }
}
