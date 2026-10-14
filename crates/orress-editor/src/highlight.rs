//! A small, dependency-free syntax highlighter: a generic lexer driven by a per-language
//! spec. It colours comments, strings, numbers, keywords, types, functions and (for Rust)
//! macros, attributes and lifetimes. Good enough to read and write solver scripts and
//! crackmes; a tree-sitter backend is the planned richer upgrade (same `Token` output).

use crate::Language;

/// What a highlighted span represents. Punctuation and plain identifiers are left out
/// (rendered in the default text colour), so the output is sparse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    Keyword,
    Type,
    Function,
    Macro,
    Attribute,
    String,
    Char,
    Number,
    Comment,
    Lifetime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub start: usize,
    pub end: usize,
    pub kind: Tok,
}

struct Spec {
    line_comments: &'static [&'static str],
    block_comment: Option<(&'static str, &'static str)>,
    /// String delimiters as (open, close). Longer delimiters must come first.
    strings: &'static [(&'static str, &'static str)],
    char_lit: bool,
    keywords: &'static [&'static str],
    types: &'static [&'static str],
    /// Rust-style extras: `name!` macros, `#[attr]`, `'lifetime`, CamelCase as a type.
    rust_like: bool,
    /// A leading decorator character (`@` in Python).
    decorator: Option<char>,
}

fn spec(lang: Language) -> Option<Spec> {
    Some(match lang {
        Language::Rust => Spec {
            line_comments: &["//"],
            block_comment: Some(("/*", "*/")),
            strings: &[("\"", "\"")],
            char_lit: true,
            keywords: RUST_KEYWORDS,
            types: RUST_TYPES,
            rust_like: true,
            decorator: None,
        },
        Language::Python => Spec {
            line_comments: &["#"],
            block_comment: None,
            strings: &[
                ("\"\"\"", "\"\"\""),
                ("'''", "'''"),
                ("\"", "\""),
                ("'", "'"),
            ],
            char_lit: false,
            keywords: PYTHON_KEYWORDS,
            types: PYTHON_TYPES,
            rust_like: false,
            decorator: Some('@'),
        },
        // C and C++ are highlighted by tree-sitter; this spec is only the fallback if that fails.
        Language::C => Spec {
            line_comments: &["//"],
            block_comment: Some(("/*", "*/")),
            strings: &[("\"", "\"")],
            char_lit: true,
            keywords: C_KEYWORDS,
            types: C_TYPES,
            rust_like: false,
            decorator: Some('#'),
        },
        Language::Cpp => Spec {
            line_comments: &["//"],
            block_comment: Some(("/*", "*/")),
            strings: &[("\"", "\"")],
            char_lit: true,
            keywords: CPP_KEYWORDS,
            types: C_TYPES,
            rust_like: false,
            decorator: Some('#'),
        },
        Language::Asm => Spec {
            line_comments: &[";", "#"],
            block_comment: None,
            strings: &[("\"", "\""), ("'", "'")],
            char_lit: false,
            keywords: ASM_MNEMONICS,
            types: ASM_REGISTERS,
            rust_like: false,
            decorator: None,
        },
        Language::Toml => Spec {
            line_comments: &["#"],
            block_comment: None,
            strings: &[
                ("\"\"\"", "\"\"\""),
                ("'''", "'''"),
                ("\"", "\""),
                ("'", "'"),
            ],
            char_lit: false,
            keywords: &["true", "false"],
            types: &[],
            rust_like: false,
            decorator: None,
        },
        Language::Json => Spec {
            line_comments: &[],
            block_comment: None,
            strings: &[("\"", "\"")],
            char_lit: false,
            keywords: &["true", "false", "null"],
            types: &[],
            rust_like: false,
            decorator: None,
        },
        Language::Markdown | Language::PlainText => return None,
    })
}

/// x86 / x86-64 mnemonics (a broad common set), plus operand-size words and a few assembler
/// directives (their leading `.` is punctuation, so the bare word is matched). Coloured as keywords.
const ASM_MNEMONICS: &[&str] = &[
    // data movement
    "mov",
    "movabs",
    "movzx",
    "movsx",
    "movsxd",
    "lea",
    "push",
    "pop",
    "xchg",
    "cmpxchg",
    "xadd",
    "bswap",
    // arithmetic / logic
    "add",
    "sub",
    "adc",
    "sbb",
    "and",
    "or",
    "xor",
    "not",
    "neg",
    "inc",
    "dec",
    "cmp",
    "test",
    "mul",
    "imul",
    "div",
    "idiv",
    "shl",
    "shr",
    "sal",
    "sar",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "bt",
    "bts",
    "btr",
    "btc",
    "bsf",
    "bsr",
    "popcnt",
    "lzcnt",
    "tzcnt",
    // control flow
    "jmp",
    "call",
    "ret",
    "retn",
    "retf",
    "leave",
    "enter",
    "nop",
    "ud2",
    "int",
    "int3",
    "into",
    "syscall",
    "sysret",
    "sysenter",
    "sysexit",
    "cpuid",
    "rdtsc",
    "rdtscp",
    "endbr64",
    "endbr32",
    "je",
    "jne",
    "jz",
    "jnz",
    "jl",
    "jle",
    "jg",
    "jge",
    "jb",
    "jbe",
    "ja",
    "jae",
    "jc",
    "jnc",
    "js",
    "jns",
    "jo",
    "jno",
    "jp",
    "jnp",
    "jpe",
    "jpo",
    "jcxz",
    "jecxz",
    "jrcxz",
    "loop",
    "loope",
    "loopne",
    // set / cmov
    "sete",
    "setne",
    "setl",
    "setle",
    "setg",
    "setge",
    "setb",
    "setbe",
    "seta",
    "setae",
    "sets",
    "setns",
    "setz",
    "setnz",
    "cmove",
    "cmovne",
    "cmovl",
    "cmovle",
    "cmovg",
    "cmovge",
    "cmovb",
    "cmovbe",
    "cmova",
    "cmovae",
    "cmovs",
    "cmovns",
    "cmovz",
    "cmovnz",
    // sign extend / string ops
    "cdq",
    "cqo",
    "cwd",
    "cdqe",
    "cwde",
    "cbw",
    "movs",
    "movsb",
    "movsw",
    "movsq",
    "stos",
    "stosb",
    "stosw",
    "stosd",
    "stosq",
    "lods",
    "lodsb",
    "scas",
    "scasb",
    "cmps",
    "cmpsb",
    "rep",
    "repe",
    "repz",
    "repne",
    "repnz",
    // flags / misc
    "pushf",
    "pushfq",
    "popf",
    "popfq",
    "lahf",
    "sahf",
    "clc",
    "stc",
    "cmc",
    "cld",
    "std",
    "cli",
    "sti",
    "hlt",
    "pause",
    "lfence",
    "sfence",
    "mfence",
    "prefetcht0",
    "prefetchnta",
    // x87 / SSE (common)
    "fld",
    "fst",
    "fstp",
    "fadd",
    "fsub",
    "fmul",
    "fdiv",
    "fild",
    "fistp",
    "movss",
    "movaps",
    "movups",
    "movapd",
    "movupd",
    "movdqa",
    "movdqu",
    "movd",
    "movq",
    "addss",
    "subss",
    "mulss",
    "divss",
    "addsd",
    "subsd",
    "mulsd",
    "divsd",
    "xorps",
    "xorpd",
    "pxor",
    "cvtsi2sd",
    "cvtsi2ss",
    "cvttsd2si",
    "cvttss2si",
    "comiss",
    "comisd",
    "ucomiss",
    "ucomisd",
    // operand-size and address keywords
    "byte",
    "word",
    "dword",
    "qword",
    "tbyte",
    "xmmword",
    "ymmword",
    "ptr",
    "short",
    "near",
    "far",
    "offset",
    "rel",
    // common directives (the leading '.' is punctuation and skipped)
    "section",
    "global",
    "globl",
    "extern",
    "align",
    "db",
    "dw",
    "dd",
    "dq",
    "resb",
    "resw",
    "resd",
    "resq",
    "equ",
    "times",
    "org",
    "bits",
    "default",
    "text",
    "data",
    "bss",
    // AArch64 (A64) mnemonics not already covered above
    "movz",
    "movk",
    "movn",
    "orr",
    "eor",
    "orn",
    "eon",
    "bic",
    "bics",
    "ands",
    "mvn",
    "madd",
    "msub",
    "mneg",
    "smull",
    "umull",
    "smulh",
    "umulh",
    "sdiv",
    "udiv",
    "bl",
    "br",
    "blr",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
    "adr",
    "adrp",
    "ldr",
    "str",
    "ldp",
    "stp",
    "ldrb",
    "strb",
    "ldrh",
    "strh",
    "ldur",
    "stur",
    "ldrsw",
    "sxtw",
    "uxtw",
    "sxtb",
    "uxtb",
    "sxth",
    "uxth",
    "lsl",
    "lsr",
    "asr",
    "csel",
    "cset",
    "csetm",
    "csinc",
    "csinv",
    "csneg",
    "ccmp",
    "ccmn",
    "cmn",
    "fmov",
    "fcmp",
    "scvtf",
    "ucvtf",
    "fcvtzs",
    "fcvtzu",
    "dmb",
    "dsb",
    "isb",
    "yield",
    "wfe",
    "wfi",
    "sev",
    "svc",
    "hvc",
    "smc",
    "brk",
    "eret",
    "mrs",
    "msr",
    "stlr",
    "ldar",
    "ldxr",
    "stxr",
    "ldaxr",
    "stlxr",
    "cas",
    "swp",
    "rev",
    "rev16",
    "rev32",
    "clz",
    "cls",
    "rbit",
    "ubfx",
    "sbfx",
    "bfi",
    "bfxil",
    "extr",
    "ngc",
    "negs",
];

/// x86-64 and AArch64 register names, coloured as types so they stand apart from mnemonics.
const ASM_REGISTERS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d", "r10d",
    "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w",
    "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "al", "bl", "cl", "dl", "sil", "dil",
    "bpl", "spl", "ah", "bh", "ch", "dh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b",
    "r15b", "rip", "eip", "ip", "rflags", "eflags", "flags", "cs", "ds", "es", "fs", "gs", "ss",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
    "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5",
    "ymm6", "ymm7", "cr0", "cr2", "cr3", "cr4", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
    // AArch64 general-purpose and special registers
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11",
    "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24",
    "w25", "w26", "w27", "w28", "w29", "w30", "wsp", "xzr", "wzr", "lr", "fp", "pc",
];

/// Highlights `text` of the given language into sparse, non-overlapping tokens in order.
pub(crate) fn tokenizer(text: &str, lang: Language) -> Vec<Token> {
    let Some(spec) = spec(lang) else {
        return Vec::new();
    };
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let n = text.len();
    // Byte offsets of the start of the current line, to spot line-leading constructs.
    let mut at_line_start = true;

    while i < n {
        let rest = &text[i..];
        let c = bytes[i];

        if c == b'\n' {
            i += 1;
            at_line_start = true;
            continue;
        }
        if c == b' ' || c == b'\t' || c == b'\r' {
            i += 1;
            continue;
        }

        // Comments.
        if let Some((open, close)) = spec.block_comment
            && rest.starts_with(open)
        {
            let end = text[i + open.len()..]
                .find(close)
                .map_or(n, |p| i + open.len() + p + close.len());
            out.push(Token {
                start: i,
                end,
                kind: Tok::Comment,
            });
            i = end;
            at_line_start = false;
            continue;
        }
        if spec.line_comments.iter().any(|p| rest.starts_with(p)) {
            let end = rest.find('\n').map_or(n, |p| i + p);
            out.push(Token {
                start: i,
                end,
                kind: Tok::Comment,
            });
            i = end;
            continue;
        }

        // Rust attributes: `#[ ... ]` or `#![ ... ]` to the end of the line.
        if spec.rust_like && c == b'#' && (rest.starts_with("#[") || rest.starts_with("#![")) {
            let end = rest.find('\n').map_or(n, |p| i + p);
            out.push(Token {
                start: i,
                end,
                kind: Tok::Attribute,
            });
            i = end;
            continue;
        }

        // Python decorators at the start of a line: `@name`.
        if let Some(dec) = spec.decorator
            && at_line_start
            && c == dec as u8
        {
            let mut j = i + 1;
            while j < n
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'.')
            {
                j += 1;
            }
            out.push(Token {
                start: i,
                end: j,
                kind: Tok::Attribute,
            });
            i = j;
            at_line_start = false;
            continue;
        }

        // Strings (including Rust raw/byte string prefixes handled loosely).
        if let Some(tok) = string_at(text, i, &spec) {
            out.push(tok);
            i = tok.end;
            at_line_start = false;
            continue;
        }

        // Char literal vs. Rust lifetime.
        if spec.char_lit && c == b'\'' {
            if let Some(end) = char_literal_end(text, i) {
                out.push(Token {
                    start: i,
                    end,
                    kind: Tok::Char,
                });
                i = end;
            } else if spec.rust_like {
                // `'ident` lifetime.
                let mut j = i + 1;
                while j < n && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                out.push(Token {
                    start: i,
                    end: j,
                    kind: Tok::Lifetime,
                });
                i = j.max(i + 1);
            } else {
                i += 1;
            }
            at_line_start = false;
            continue;
        }

        // Numbers.
        if c.is_ascii_digit() || (c == b'.' && i + 1 < n && bytes[i + 1].is_ascii_digit()) {
            let end = number_end(text, i);
            out.push(Token {
                start: i,
                end,
                kind: Tok::Number,
            });
            i = end;
            at_line_start = false;
            continue;
        }

        // Identifiers / keywords / types / functions / macros.
        if c.is_ascii_alphabetic() || c == b'_' {
            let mut j = i + 1;
            while j < n && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let word = &text[i..j];
            // Look past spaces for a following `(` (function) or `!` (macro).
            let mut k = j;
            while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            let next = bytes.get(k).copied();

            let kind = if spec.keywords.contains(&word) {
                Some(Tok::Keyword)
            } else if spec.types.contains(&word) || (spec.rust_like && starts_upper(word)) {
                Some(Tok::Type)
            } else if spec.rust_like && bytes.get(j) == Some(&b'!') {
                // macro: include the `!`.
                out.push(Token {
                    start: i,
                    end: j + 1,
                    kind: Tok::Macro,
                });
                i = j + 1;
                at_line_start = false;
                continue;
            } else if next == Some(b'(') {
                Some(Tok::Function)
            } else {
                None
            };
            if let Some(kind) = kind {
                out.push(Token {
                    start: i,
                    end: j,
                    kind,
                });
            }
            i = j;
            at_line_start = false;
            continue;
        }

        // Anything else (punctuation/operators): default colour.
        i += next_char_len(rest);
        at_line_start = false;
    }
    out
}

fn next_char_len(rest: &str) -> usize {
    rest.chars().next().map_or(1, char::len_utf8)
}

fn starts_upper(word: &str) -> bool {
    word.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

/// Matches a string starting at `i`, honouring the spec's delimiters and backslash
/// escapes (for single-char delimiters).
fn string_at(text: &str, i: usize, spec: &Spec) -> Option<Token> {
    let rest = &text[i..];
    // Rust raw/byte-string prefixes: r"...", b"...", br"...", r#"..."#.
    let prefix = if spec.rust_like {
        ["br#\"", "b r", "br\"", "r#\"", "b\"", "r\""]
            .iter()
            .find(|p| rest.starts_with(**p) && p.ends_with('"'))
            .map_or(0, |p| p.len() - 1) // length up to the opening quote
    } else {
        0
    };
    let body = &text[i + prefix..];
    for (open, close) in spec.strings {
        if body.starts_with(open) {
            let start_search = i + prefix + open.len();
            let mut j = start_search;
            let bytes = text.as_bytes();
            while j < text.len() {
                if open.len() == 1 && bytes[j] == b'\\' {
                    // Skip the backslash and the whole escaped character (which may be
                    // multi-byte, e.g. `\é`), so `j` stays on a char boundary.
                    j += 1;
                    if j < text.len() {
                        j += next_char_len(&text[j..]);
                    }
                    continue;
                }
                if text[j..].starts_with(close) {
                    return Some(Token {
                        start: i,
                        end: j + close.len(),
                        kind: Tok::String,
                    });
                }
                j += next_char_len(&text[j..]);
            }
            // Unterminated string runs to EOF (or end of line for 1-char quotes).
            let end = if open.len() == 1 {
                text[start_search..]
                    .find('\n')
                    .map_or(text.len(), |p| start_search + p)
            } else {
                text.len()
            };
            return Some(Token {
                start: i,
                end,
                kind: Tok::String,
            });
        }
    }
    None
}

/// If `text[i..]` is a char literal `'x'` or `'\n'`, returns its end.
fn char_literal_end(text: &str, i: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let n = text.len();
    debug_assert_eq!(bytes[i], b'\'');
    let mut j = i + 1;
    if j >= n {
        return None;
    }
    if bytes[j] == b'\\' {
        j += 2; // escape: \n, \t, \', \\, \xNN (loose)
        while j < n && bytes[j] != b'\'' && bytes[j] != b'\n' {
            j += 1;
        }
    } else {
        j += next_char_len(&text[j..]);
    }
    (j < n && bytes[j] == b'\'').then_some(j + 1)
}

fn number_end(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    let n = text.len();
    let mut j = i;
    // 0x / 0b / 0o prefixes, then hex/alnum digits, underscores, a dot and an exponent.
    if bytes[j] == b'0'
        && j + 1 < n
        && matches!(bytes[j + 1], b'x' | b'X' | b'b' | b'B' | b'o' | b'O')
    {
        j += 2;
    }
    while j < n {
        let c = bytes[j];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
            // Stop at a `..` range operator.
            if c == b'.' && j + 1 < n && bytes[j + 1] == b'.' {
                break;
            }
            j += 1;
        } else {
            break;
        }
    }
    j.max(i + 1)
}

const C_KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "const",
    "continue",
    "default",
    "do",
    "else",
    "enum",
    "extern",
    "for",
    "goto",
    "if",
    "inline",
    "register",
    "restrict",
    "return",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "volatile",
    "while",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Generic",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
];
const CPP_KEYWORDS: &[&str] = &[
    "alignas",
    "alignof",
    "auto",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "constexpr",
    "consteval",
    "const_cast",
    "continue",
    "co_await",
    "co_return",
    "co_yield",
    "decltype",
    "default",
    "delete",
    "do",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "nullptr",
    "operator",
    "override",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "return",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "using",
    "virtual",
    "volatile",
    "while",
];
const C_TYPES: &[&str] = &[
    "void",
    "bool",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "wchar_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "intptr_t",
    "uintptr_t",
    "uintmax_t",
    "FILE",
];
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "union",
    "unsafe", "use", "where", "while",
];
const RUST_TYPES: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64", "bool", "char", "str", "String", "Vec", "Option", "Result", "Box", "Rc", "Arc",
    "HashMap", "HashSet", "BTreeMap",
];
const PYTHON_KEYWORDS: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
    "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield", "True",
    "False", "None", "self",
];
const PYTHON_TYPES: &[&str] = &[
    "int",
    "float",
    "str",
    "bytes",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "bytearray",
    "frozenset",
    "complex",
];
