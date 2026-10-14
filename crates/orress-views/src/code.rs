//! Rendering code lines as colored, clickable text, shared by the disassembly and graph
//! views. Text is monospace, so a token's position is its character column.

use std::collections::BTreeSet;
use std::ops::Range;

use egui::text::LayoutJob;
use egui::{Color32, Context, FontId, Id, TextFormat};
use orress_analysis::{Insn, Line, LineKind, Program, TokenKind};
use orress_editor::{Language, Tok};
use orress_project::Document;
use orress_theme::SyntaxColors;

/// Colour for one source token kind, mirroring the code editor's own mapping.
fn source_color(kind: Tok, c: &SyntaxColors, default: Color32) -> Color32 {
    match kind {
        Tok::Keyword => c.keyword.0,
        Tok::Type => c.type_name.0,
        Tok::Function | Tok::Macro => c.function.0,
        Tok::Attribute | Tok::Lifetime => c.label.0,
        Tok::String | Tok::Char => c.string.0,
        Tok::Number => c.immediate.0,
        Tok::Comment => c.comment.0,
        #[allow(unreachable_patterns)]
        _ => default,
    }
}

/// A syntax-highlighted layout job for `text` as `lang` source, using the same tree-sitter
/// highlighter and theme colours as the code editor. Used for read-only colored views such as
/// the decompiler's Rust-port tab, so it reads like the IDE editor. Does not wrap (the view
/// scrolls horizontally).
pub fn highlight_job(
    text: &str,
    lang: Language,
    colors: &SyntaxColors,
    font: FontId,
    default: Color32,
) -> LayoutJob {
    let tokens = orress_editor::highlight(text, lang);
    let mut job = LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    let len = text.len();
    // A boundary at every token edge, so each emitted run has one uniform colour.
    let mut points: BTreeSet<usize> = BTreeSet::from([0, len]);
    for t in &tokens {
        points.insert(t.start.min(len));
        points.insert(t.end.min(len));
    }
    let points: Vec<usize> = points
        .into_iter()
        .filter(|p| text.is_char_boundary(*p))
        .collect();
    for w in points.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b {
            continue;
        }
        let col = tokens
            .iter()
            .find(|t| t.start <= a && a < t.end)
            .map_or(default, |t| source_color(t.kind, colors, default));
        job.append(&text[a..b], 0.0, TextFormat::simple(font.clone(), col));
    }
    job
}

/// What a span of text refers to, for clicks and explanations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Address(u64),
    Number(u64),
    Mnemonic(String),
    Register(String),
}

#[derive(Clone, Debug)]
pub struct Span {
    pub chars: Range<usize>,
    pub target: Target,
}

pub struct Rendered {
    pub job: LayoutJob,
    pub spans: Vec<Span>,
    pub chars: usize,
}

fn syntax_id() -> Id {
    Id::new("orress::syntax_colors")
}

/// The app stores the current theme's syntax colors here.
pub fn set_syntax(ctx: &Context, colors: SyntaxColors) {
    ctx.data_mut(|d| d.insert_temp(syntax_id(), colors));
}

pub fn syntax(ctx: &Context) -> SyntaxColors {
    ctx.data(|d| d.get_temp::<SyntaxColors>(syntax_id()))
        .unwrap_or_else(|| orress_theme::Theme::rusty_dark().syntax)
}

pub struct Style {
    pub font: FontId,
    pub colors: SyntaxColors,
    pub text: Color32,
    pub muted: Color32,
    pub wide: bool,
    pub show_address: bool,
    pub show_bytes: bool,
}

struct Builder<'a> {
    job: LayoutJob,
    spans: Vec<Span>,
    chars: usize,
    style: &'a Style,
}

impl Builder<'_> {
    fn push(&mut self, text: &str, color: Color32, target: Option<Target>) {
        let n = text.chars().count();
        if let Some(target) = target {
            self.spans.push(Span {
                chars: self.chars..self.chars + n,
                target,
            });
        }
        self.job.append(
            text,
            0.0,
            TextFormat::simple(self.style.font.clone(), color),
        );
        self.chars += n;
    }

    fn pad_to(&mut self, column: usize) {
        if self.chars < column {
            let pad = " ".repeat(column - self.chars);
            self.push(&pad, self.style.text, None);
        }
    }

    fn finish(self) -> Rendered {
        Rendered {
            job: self.job,
            spans: self.spans,
            chars: self.chars,
        }
    }
}

fn hex_color(c: &orress_theme::Hex) -> Color32 {
    c.0
}

pub fn address_text(addr: u64, wide: bool) -> String {
    if wide {
        format!("{addr:016x}")
    } else {
        format!("{addr:08x}")
    }
}

/// Name for an address, with an offset into a function if it is inside one:
/// `main`, `main+0x1a`, or the plain hex address.
pub fn describe_address(doc: &Document, program: &Program, addr: u64) -> String {
    if let Some(name) = doc.name_of(addr) {
        return name;
    }
    if let Some(f) = program.function_containing(addr)
        && let Some(name) = doc.name_of(f.entry)
    {
        return format!("{name}+0x{:x}", addr - f.entry);
    }
    format!("0x{addr:x}")
}

fn parse_number(text: &str) -> Option<u64> {
    let t = text.trim_start_matches('#');
    match t.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse::<i64>().ok().map(|v| v as u64),
    }
}

/// Text hidden in a number: compilers store short strings as immediates, e.g.
/// `mov rcx,0x7365735f6e65706f` is "open_ses" (bytes in little-endian order).
pub fn text_in_number(value: u64) -> Option<String> {
    let bytes = value.to_le_bytes();
    let len = 8 - bytes.iter().rev().take_while(|&&b| b == 0).count();
    let text = &bytes[..len];
    (len >= 3 && text.iter().all(|b| (0x20..=0x7e).contains(b)))
        .then(|| String::from_utf8_lossy(text).into_owned())
}

/// Plain-language reading of a number: hex, decimal, signed, character.
pub fn describe_number(value: u64) -> String {
    let mut s = format!("0x{value:x} = {value}");
    if (value as i64) < 0 {
        s += &format!(" = {} (signed)", value as i64);
    }
    if value <= 0xff {
        let ch = match value as u8 {
            0x20..=0x7e => format!("'{}'", value as u8 as char),
            0 => "NUL".into(),
            0x0a => "'\\n' (newline)".into(),
            0x0d => "'\\r' (carriage return)".into(),
            0x09 => "'\\t' (tab)".into(),
            _ => "not a printable character".into(),
        };
        s += &format!("\nas a character: {ch}");
    } else if let Some(text) = text_in_number(value) {
        s += &format!("\nas text (little-endian bytes): \"{text}\"");
    }
    s
}

/// Comment for an instruction: yours, a string it refers to, or text hidden in an
/// immediate number.
pub fn auto_comment(doc: &Document, program: &Program, insn: &Insn) -> Option<String> {
    if let Some(c) = doc.annotations.comments.get(&insn.address) {
        return Some(c.clone());
    }
    let string = insn.data_refs.iter().find_map(|r| {
        program.string_refs.get(r).map(|s| {
            // Rust passes strings as (pointer, length): if the next instruction loads a
            // small number, that is likely the length, so cut the text there.
            let len = following_length(program, insn)
                .filter(|&n| n > 0 && n <= s.len() && s.is_char_boundary(n));
            let s = len.map_or(s.as_str(), |n| &s[..n]);
            let mut text: String = s.chars().take(60).collect();
            if s.chars().count() > 60 {
                text.push('…');
            }
            format!("\"{text}\"")
        })
    });
    string.or_else(|| {
        insn.operands.iter().find_map(|t| match t.kind {
            TokenKind::Number => parse_number(&t.text)
                .filter(|&v| v > 0xffff)
                .and_then(text_in_number)
                .map(|text| format!("\"{text}\" (text stored in a number)")),
            _ => None,
        })
    })
}

/// Length loaded right after a string address, if any (`mov edx,0x15`). Newer Rust
/// versions store literal lengths as `len * 2 + 1`; both forms are accepted.
fn following_length(program: &Program, insn: &Insn) -> Option<usize> {
    let next = program.decode(insn.end())?;
    if next.mnemonic != "mov" {
        return None;
    }
    let value = next.operands.iter().rev().find_map(|t| match t.kind {
        TokenKind::Number => parse_number(&t.text),
        _ => None,
    })?;
    let value = if value % 2 == 1 { value >> 1 } else { value };
    usize::try_from(value).ok()
}

pub fn render_insn(doc: &Document, program: &Program, insn: &Insn, style: &Style) -> Rendered {
    let c = &style.colors;
    let mut b = Builder {
        job: LayoutJob::default(),
        spans: Vec::new(),
        chars: 0,
        style,
    };
    if style.show_address {
        b.push(
            &address_text(insn.address, style.wide),
            hex_color(&c.address),
            None,
        );
        b.push("  ", style.text, None);
    }
    if style.show_bytes {
        let bytes = program
            .memory
            .read(insn.address, insn.len.into())
            .unwrap_or(&[]);
        let mut hex: String = bytes.iter().take(8).map(|x| format!("{x:02x} ")).collect();
        if bytes.len() > 8 {
            hex.push('…');
        }
        b.push(&format!("{hex:<25}"), hex_color(&c.bytes), None);
    }
    let start = b.chars;
    b.push(
        &insn.mnemonic,
        hex_color(&c.mnemonic),
        Some(Target::Mnemonic(insn.mnemonic.clone())),
    );
    b.pad_to(start + 8);
    for token in &insn.operands {
        match token.kind {
            TokenKind::Address(addr) => {
                let (text, color) = match doc.name_of(addr) {
                    Some(name) => {
                        let color = if program.functions.contains_key(&addr)
                            || program
                                .name(addr)
                                .is_some_and(|n| n.kind == orress_analysis::NameKind::Import)
                        {
                            hex_color(&c.function)
                        } else {
                            hex_color(&c.label)
                        };
                        (name, color)
                    }
                    // Jump targets inside a function are labels, shown as in the listing.
                    None if program.labels.contains(&addr) => {
                        (format!("loc_{addr:x}"), hex_color(&c.label))
                    }
                    None => (token.text.clone(), hex_color(&c.immediate)),
                };
                b.push(&text, color, Some(Target::Address(addr)));
            }
            TokenKind::Register => b.push(
                &token.text,
                hex_color(&c.register),
                Some(Target::Register(token.text.clone())),
            ),
            TokenKind::Number => {
                let target = parse_number(&token.text).map(Target::Number);
                b.push(&token.text, hex_color(&c.immediate), target);
            }
            TokenKind::Keyword => b.push(&token.text, hex_color(&c.keyword), None),
            TokenKind::Mnemonic => b.push(&token.text, hex_color(&c.mnemonic), None),
            TokenKind::Punct | TokenKind::Text => b.push(&token.text, style.text, None),
        }
    }
    if let Some(comment) = auto_comment(doc, program, insn) {
        b.pad_to(start + 40);
        b.push(&format!("  ; {comment}"), hex_color(&c.comment), None);
    }
    b.finish()
}

/// Renders one listing line (instruction, label, function header, data or region).
pub fn render_line(doc: &Document, program: &Program, line: &Line, style: &Style) -> Rendered {
    let c = &style.colors;
    let mut b = Builder {
        job: LayoutJob::default(),
        spans: Vec::new(),
        chars: 0,
        style,
    };
    match line.kind {
        LineKind::Insn => {
            return match program.decode(line.addr) {
                Some(insn) => render_insn(doc, program, &insn, style),
                None => {
                    b.push(
                        &address_text(line.addr, style.wide),
                        hex_color(&c.address),
                        None,
                    );
                    b.push("  ??", style.muted, None);
                    b.finish()
                }
            };
        }
        LineKind::Region => {
            let name = program
                .memory
                .region(line.addr)
                .map_or_else(String::new, |r| r.name.clone());
            b.push(
                &address_text(line.addr, style.wide),
                hex_color(&c.address),
                None,
            );
            b.push(
                &format!("  ; ===== section {name} ====="),
                hex_color(&c.comment),
                None,
            );
        }
        LineKind::Function => {
            b.push(
                &address_text(line.addr, style.wide),
                hex_color(&c.address),
                None,
            );
            b.push("  ", style.text, None);
            let name = doc
                .name_of(line.addr)
                .unwrap_or_else(|| format!("sub_{:x}", line.addr));
            b.push(
                &format!("{name}:"),
                hex_color(&c.function),
                Some(Target::Address(line.addr)),
            );
            let refs = program.xrefs(line.addr).len();
            let blocks = program
                .functions
                .get(&line.addr)
                .map_or(0, |f| f.blocks.len());
            let mut info = format!(
                "   ; function · {blocks} block{}",
                if blocks == 1 { "" } else { "s" }
            );
            if refs > 0 {
                info += &format!(" · {refs} reference{}", if refs == 1 { "" } else { "s" });
            }
            if program.main == Some(line.addr) {
                info += " · program entry (main)";
            }
            if let Some(comment) = doc.annotations.comments.get(&line.addr) {
                info += &format!(" · {comment}");
            }
            b.push(&info, hex_color(&c.comment), None);
        }
        LineKind::Label => {
            b.push(
                &address_text(line.addr, style.wide),
                hex_color(&c.address),
                None,
            );
            b.push("  ", style.text, None);
            let name = doc
                .name_of(line.addr)
                .unwrap_or_else(|| format!("loc_{:x}", line.addr));
            b.push(
                &format!("{name}:"),
                hex_color(&c.label),
                Some(Target::Address(line.addr)),
            );
        }
        LineKind::Data(n) => {
            b.push(
                &address_text(line.addr, style.wide),
                hex_color(&c.address),
                None,
            );
            b.push("  ", style.text, None);
            let start = b.chars;
            b.push("db", style.muted, None);
            b.pad_to(start + 8);
            let bytes = program.memory.read(line.addr, n.into()).unwrap_or(&[]);
            let text: Vec<String> = bytes.iter().map(|x| format!("0x{x:02x}")).collect();
            b.push(&text.join(","), style.muted, None);
        }
    }
    b.finish()
}

/// Span under a character column.
pub fn span_at(spans: &[Span], column: usize) -> Option<&Span> {
    spans.iter().find(|s| s.chars.contains(&column))
}

/// The largest index `<= max` that is a char boundary of `s`, so `&s[..i]` never panics.
pub(crate) fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    (0..=max)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0)
}
