//! A small C-declaration parser: paste C and get [`UserType`]s for the catalog, as a second
//! input alongside the Types view's form. Pure Rust, hand-written tokenizer + recursive
//! descent — no external crate. It understands `struct`/`union`/`enum`/`typedef`, member
//! lists with pointers and arrays, `<stdint.h>` fixed-width types, and `//` / `/* */`
//! comments. Widths follow the LP64 model (`long` = 64-bit), which matches the 64-bit
//! targets ORRESS usually analyses.

use crate::types::{FieldDef, Prim, TypeRef, UserType};

/// Parses one or more C type declarations into catalog types, in source order. Returns a
/// readable error (with no byte offsets — this is paste-and-fix, not a compiler) on the first
/// problem.
pub fn parse_c_decls(src: &str) -> Result<Vec<UserType>, String> {
    let tokens = tokenize(src)?;
    let mut p = Parser { tokens, pos: 0 };
    let mut out = Vec::new();
    while p.peek().is_some() {
        p.declaration(&mut out)?;
    }
    if out.is_empty() {
        return Err("no type declarations found".into());
    }
    Ok(out)
}

/// Best-effort parse of a whole C header: preprocessor directives, `__attribute__`/`__declspec`
/// and comments are stripped, then each top-level declaration is parsed; anything the model does
/// not represent (function prototypes, typedef'd function pointers, bitfields, anonymous members)
/// is skipped rather than failing the import. Returns the recovered types and how many
/// declarations were skipped.
pub fn parse_header(src: &str) -> Result<(Vec<UserType>, usize), String> {
    let cleaned = preprocess(src);
    let tokens = tokenize(&cleaned)?;
    let mut p = Parser { tokens, pos: 0 };
    let mut out = Vec::new();
    let mut skipped = 0;
    while p.peek().is_some() {
        let before = p.pos;
        if p.declaration(&mut out).is_err() {
            skipped += 1;
            // Resync to the next top-level `;` so one bad declaration does not stop the import.
            p.skip_declaration();
            // Guarantee forward progress even if nothing was consumed.
            if p.pos == before {
                p.pos += 1;
            }
        }
    }
    Ok((out, skipped))
}

// ---------------------------------------------------------------------------- tokenizer

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Num(i64),
    /// One of `{ } ( ) [ ] ; , * =`.
    Punct(char),
}

fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            if i >= b.len() {
                return Err("unterminated /* */ comment".into());
            }
            i += 2;
        } else if c == b'_' || c.is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_owned()));
        } else if c.is_ascii_digit() {
            let start = i;
            let (radix, skip) = if c == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X')) {
                (16, 2)
            } else {
                (10, 0)
            };
            i += skip;
            while i < b.len() && (b[i].is_ascii_hexdigit() || b[i] == b'_') {
                i += 1;
            }
            let digits: String = src[start + skip..i].chars().filter(|&c| c != '_').collect();
            let n = i64::from_str_radix(&digits, radix)
                .map_err(|_| format!("bad number `{}`", &src[start..i]))?;
            out.push(Tok::Num(n));
        } else if matches!(
            c,
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b';' | b',' | b'*' | b'='
        ) {
            out.push(Tok::Punct(c as char));
            i += 1;
        } else if c.is_ascii_punctuation() {
            // Any other ASCII punctuation (`-`, `:`, `<`, `&`, …) becomes a generic token. The
            // parser only acts on the ones it expects; the rest let header import skip a
            // declaration it does not model (a bitfield `:`, an operator in a macro, …) rather
            // than failing to tokenize.
            out.push(Tok::Punct(c as char));
            i += 1;
        } else {
            return Err(format!("unexpected character `{}`", c as char));
        }
    }
    Ok(out)
}

// ----------------------------------------------------------------------------- parser

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat_punct(&mut self, c: char) -> Result<(), String> {
        match self.next() {
            Some(Tok::Punct(p)) if p == c => Ok(()),
            other => Err(format!(
                "expected `{c}`, found {}",
                describe(other.as_ref())
            )),
        }
    }

    fn is_punct(&self, c: char) -> bool {
        matches!(self.peek(), Some(Tok::Punct(p)) if *p == c)
    }

    fn ident(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!(
                "expected a name, found {}",
                describe(other.as_ref())
            )),
        }
    }

    /// Parses one top-level declaration and appends the type(s) it defines.
    fn declaration(&mut self, out: &mut Vec<UserType>) -> Result<(), String> {
        match self.peek() {
            Some(Tok::Ident(kw)) if kw == "typedef" => {
                self.next();
                self.typedef(out)
            }
            Some(Tok::Ident(kw)) if kw == "struct" || kw == "union" => {
                let is_union = kw == "union";
                self.next();
                let name = self.ident()?;
                self.aggregate(out, &name, is_union)?;
                self.eat_punct(';')
            }
            Some(Tok::Ident(kw)) if kw == "enum" => {
                self.next();
                let name = self.ident()?;
                self.enumeration(out, &name)?;
                self.eat_punct(';')
            }
            other => Err(format!(
                "expected struct/union/enum/typedef, found {}",
                describe(other)
            )),
        }
    }

    /// `struct/union Name { members }` → an aggregate type appended to `out`.
    fn aggregate(
        &mut self,
        out: &mut Vec<UserType>,
        name: &str,
        is_union: bool,
    ) -> Result<(), String> {
        self.eat_punct('{')?;
        let mut fields = Vec::new();
        while !self.is_punct('}') {
            if self.peek().is_none() {
                return Err("unterminated `{` in struct/union".into());
            }
            self.member(&mut fields)?;
        }
        self.eat_punct('}')?;
        let name = name.to_owned();
        out.push(if is_union {
            UserType::Union { name, fields }
        } else {
            UserType::Struct { name, fields }
        });
        Ok(())
    }

    /// One member line: `TYPE decl [, decl]* ;` where each decl is `*`* name `[N]`*.
    fn member(&mut self, fields: &mut Vec<FieldDef>) -> Result<(), String> {
        let base = self.base_type()?;
        loop {
            let mut ty = base.clone();
            while self.is_punct('*') {
                self.next();
                self.skip_qualifiers(); // `char * const p`
                ty = TypeRef::Pointer(Box::new(ty));
            }
            let name = self.ident()?;
            let mut count: u64 = 1;
            while self.is_punct('[') {
                self.next();
                let n = match self.next() {
                    Some(Tok::Num(n)) if n >= 0 => n as u64,
                    other => {
                        return Err(format!(
                            "array length must be a number, found {}",
                            describe(other.as_ref())
                        ));
                    }
                };
                self.eat_punct(']')?;
                count = count.saturating_mul(n.max(1));
            }
            fields.push(FieldDef { name, ty, count });
            if self.is_punct(',') {
                self.next();
                continue;
            }
            break;
        }
        self.eat_punct(';')
    }

    /// `typedef <base> *name;` or `typedef struct/union/enum ... Name;`.
    fn typedef(&mut self, out: &mut Vec<UserType>) -> Result<(), String> {
        // `typedef struct [Tag] { ... } Alias;` — define the aggregate, then alias it.
        if let Some(Tok::Ident(kw)) = self.peek()
            && (kw == "struct" || kw == "union" || kw == "enum")
        {
            let kw = kw.clone();
            self.next();
            // Optional tag; if the body follows, use a tag (given or synthesised from the alias later).
            let tag = if let Some(Tok::Ident(_)) = self.peek() {
                if self.peek_is_punct_after_ident('{') {
                    Some(self.ident()?)
                } else {
                    // `typedef struct Tag Alias;` — a plain alias to an existing aggregate.
                    let tag = self.ident()?;
                    let alias = self.ident()?;
                    self.eat_punct(';')?;
                    out.push(UserType::Typedef {
                        name: alias,
                        target: TypeRef::Named(tag),
                    });
                    return Ok(());
                }
            } else {
                None
            };
            if self.is_punct('{') {
                // Body present: parse it under the tag (or, if anonymous, under the alias name).
                let alias_is_name = tag.is_none();
                let placeholder = tag.clone().unwrap_or_default();
                if kw == "enum" {
                    self.enumeration(out, &placeholder)?;
                } else {
                    self.aggregate(out, &placeholder, kw == "union")?;
                }
                let alias = self.ident()?;
                self.eat_punct(';')?;
                if alias_is_name {
                    // Anonymous aggregate: rename the just-pushed type to the alias.
                    rename_last(out, &alias);
                } else {
                    out.push(UserType::Typedef {
                        name: alias,
                        target: TypeRef::Named(placeholder),
                    });
                }
                return Ok(());
            }
            return Err("expected `{` or an alias name after typedef struct/union/enum".into());
        }
        // `typedef <base> *name;`
        let base = self.base_type()?;
        let mut target = base;
        while self.is_punct('*') {
            self.next();
            target = TypeRef::Pointer(Box::new(target));
        }
        let name = self.ident()?;
        self.eat_punct(';')?;
        out.push(UserType::Typedef { name, target });
        Ok(())
    }

    /// `enum Name { A, B = 5, ... }` → an enum type (underlying `U32`, C's default).
    fn enumeration(&mut self, out: &mut Vec<UserType>, name: &str) -> Result<(), String> {
        self.eat_punct('{')?;
        let mut variants = Vec::new();
        let mut next_val: i64 = 0;
        while !self.is_punct('}') {
            let vname = self.ident()?;
            let value = if self.is_punct('=') {
                self.next();
                let neg = if self.is_punct('-') {
                    self.next();
                    true
                } else {
                    false
                };
                match self.next() {
                    Some(Tok::Num(n)) => {
                        if neg {
                            -n
                        } else {
                            n
                        }
                    }
                    other => {
                        return Err(format!(
                            "enum value must be a number, found {}",
                            describe(other.as_ref())
                        ));
                    }
                }
            } else {
                next_val
            };
            variants.push((vname, value));
            next_val = value.saturating_add(1);
            if self.is_punct(',') {
                self.next();
            } else {
                break;
            }
        }
        self.eat_punct('}')?;
        out.push(UserType::Enum {
            name: name.to_owned(),
            width: Prim::U32,
            variants,
        });
        Ok(())
    }

    /// Parses a base type: a `struct/union/enum Tag` reference, a run of primitive specifier
    /// words, or a bare named type (another user type / typedef).
    /// Advances past the rest of a declaration after an error: to and over the next `;` at
    /// brace depth 0 (skipping any `{ … }` body along the way).
    fn skip_declaration(&mut self) {
        let mut depth = 0i32;
        while let Some(tok) = self.next() {
            match tok {
                Tok::Punct('{') => depth += 1,
                Tok::Punct('}') => depth -= 1,
                Tok::Punct(';') if depth <= 0 => break,
                _ => {}
            }
        }
    }

    /// Skips C qualifier keywords the type model does not represent (`const`, `volatile`, …).
    fn skip_qualifiers(&mut self) {
        while let Some(Tok::Ident(s)) = self.peek() {
            if is_qualifier(s) {
                self.next();
            } else {
                break;
            }
        }
    }

    fn base_type(&mut self) -> Result<TypeRef, String> {
        self.skip_qualifiers();
        if let Some(Tok::Ident(kw)) = self.peek()
            && (kw == "struct" || kw == "union" || kw == "enum")
        {
            self.next();
            let tag = self.ident()?;
            return Ok(TypeRef::Named(tag));
        }
        let mut words: Vec<String> = Vec::new();
        while let Some(Tok::Ident(s)) = self.peek() {
            if is_specifier(s) {
                words.push(s.clone());
                self.next();
            } else {
                break;
            }
        }
        if !words.is_empty() {
            return specifier_to_type(&words)
                .ok_or_else(|| format!("unknown type `{}`", words.join(" ")));
        }
        // A bare name: another user type.
        match self.peek() {
            Some(Tok::Ident(_)) => Ok(TypeRef::Named(self.ident()?)),
            other => Err(format!("expected a type, found {}", describe(other))),
        }
    }

    /// Whether the identifier two tokens ahead (name then this punct) is `c` — used to tell
    /// `typedef struct Tag { … }` from `typedef struct Tag Alias;`.
    fn peek_is_punct_after_ident(&self, c: char) -> bool {
        matches!(self.tokens.get(self.pos + 1), Some(Tok::Punct(p)) if *p == c)
    }
}

/// Renames the most recently pushed type (used for anonymous `typedef struct { … } Name;`).
fn rename_last(out: &mut [UserType], name: &str) {
    if let Some(ty) = out.last_mut() {
        let name = name.to_owned();
        match ty {
            UserType::Struct { name: n, .. }
            | UserType::Union { name: n, .. }
            | UserType::Enum { name: n, .. }
            | UserType::Typedef { name: n, .. } => *n = name,
        }
    }
}

/// Primitive type specifier keywords (plus `<stdint.h>` names), so the parser knows where a
/// base type ends and the declarator begins.
/// C qualifiers and storage/linkage keywords the type model ignores.
fn is_qualifier(w: &str) -> bool {
    matches!(
        w,
        "const"
            | "volatile"
            | "restrict"
            | "__restrict"
            | "__restrict__"
            | "register"
            | "_Atomic"
            | "__extension__"
            | "inline"
            | "__inline"
            | "__inline__"
            | "static"
            | "extern"
            | "auto"
    )
}

/// Strips what the type grammar cannot parse from a C header: preprocessor directives
/// (`#...`, with `\`-continuation), and `__attribute__((…))` / `__declspec(…)` groups. Comments
/// are handled by the tokenizer.
fn preprocess(src: &str) -> String {
    // Drop preprocessor directive lines.
    let mut body = String::new();
    let mut continued = false;
    for line in src.lines() {
        let directive = continued || line.trim_start().starts_with('#');
        continued = directive && line.trim_end().ends_with('\\');
        if directive {
            continue;
        }
        body.push_str(line);
        body.push('\n');
    }
    // Remove `__attribute__((…))` and `__declspec(…)` balanced groups.
    for name in ["__attribute__", "__declspec"] {
        body = strip_balanced(&body, name);
    }
    body
}

/// Removes every `name( … )` (balanced parentheses) occurrence from `s`.
fn strip_balanced(s: &str, name: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(pos) = rest.find(name) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + name.len()..];
        // Skip whitespace, then a balanced parenthesis group if present.
        let trimmed = after.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('(') {
            let mut depth = 1i32;
            let mut end = 0;
            for (i, c) in stripped.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest = &stripped[end..];
        } else {
            // `name` not followed by `(`: keep it as-is to avoid an infinite loop.
            out.push_str(name);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn is_specifier(w: &str) -> bool {
    matches!(
        w,
        "void"
            | "char"
            | "short"
            | "int"
            | "long"
            | "signed"
            | "unsigned"
            | "float"
            | "double"
            | "bool"
            | "_Bool"
    ) || stdint_prim(w).is_some()
}

/// A single-token `<stdint.h>` / common fixed-width name → its primitive.
fn stdint_prim(w: &str) -> Option<Prim> {
    Some(match w {
        "int8_t" => Prim::I8,
        "uint8_t" => Prim::U8,
        "int16_t" => Prim::I16,
        "uint16_t" => Prim::U16,
        "int32_t" => Prim::I32,
        "uint32_t" => Prim::U32,
        "int64_t" => Prim::I64,
        "uint64_t" | "size_t" | "uintptr_t" => Prim::U64,
        "intptr_t" | "ssize_t" => Prim::I64,
        _ => return None,
    })
}

/// Maps a run of C primitive specifier words to a primitive type (LP64 widths).
fn specifier_to_type(words: &[String]) -> Option<TypeRef> {
    // A lone stdint name.
    if words.len() == 1
        && let Some(p) = stdint_prim(&words[0])
    {
        return Some(TypeRef::Prim(p));
    }
    let has = |w: &str| words.iter().any(|x| x == w);
    let longs = words.iter().filter(|w| *w == "long").count();
    let prim = if has("double") {
        Prim::F64
    } else if has("float") {
        Prim::F32
    } else if has("void") {
        Prim::Void
    } else if has("bool") || has("_Bool") {
        Prim::Bool
    } else if has("char") {
        if has("unsigned") {
            Prim::U8
        } else if has("signed") {
            Prim::I8
        } else {
            Prim::Char
        }
    } else {
        // Integer: width from short/long, signedness from unsigned.
        let unsigned = has("unsigned");
        if has("short") {
            if unsigned { Prim::U16 } else { Prim::I16 }
        } else if longs >= 1 {
            if unsigned { Prim::U64 } else { Prim::I64 }
        } else {
            // plain int / signed / unsigned
            if unsigned { Prim::U32 } else { Prim::I32 }
        }
    };
    Some(TypeRef::Prim(prim))
}

fn describe(t: Option<&Tok>) -> String {
    match t {
        None => "end of input".into(),
        Some(Tok::Ident(s)) => format!("`{s}`"),
        Some(Tok::Num(n)) => format!("`{n}`"),
        Some(Tok::Punct(c)) => format!("`{c}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(src: &str) -> UserType {
        let v = parse_c_decls(src).unwrap();
        assert_eq!(v.len(), 1, "expected one type: {v:?}");
        v.into_iter().next().unwrap()
    }

    #[test]
    fn struct_with_array_pointer_and_stdint() {
        let ty = one("struct Packet { uint32_t magic; char body[64]; struct Packet *next; };");
        let UserType::Struct { name, fields } = ty else {
            panic!("{ty:?}");
        };
        assert_eq!(name, "Packet");
        assert_eq!(fields[0].ty, TypeRef::Prim(Prim::U32));
        assert_eq!(fields[0].count, 1);
        assert_eq!(fields[1].ty, TypeRef::Prim(Prim::Char));
        assert_eq!(fields[1].count, 64);
        assert_eq!(
            fields[2].ty,
            TypeRef::Pointer(Box::new(TypeRef::Named("Packet".into())))
        );
    }

    #[test]
    fn primitive_widths_lp64() {
        let ty = one(
            "struct S { int a; unsigned u; long l; unsigned long ul; short s; \
             unsigned char uc; signed char sc; double d; float f; _Bool b; };",
        );
        let UserType::Struct { fields, .. } = ty else {
            panic!()
        };
        let p: Vec<Prim> = fields
            .iter()
            .map(|f| match &f.ty {
                TypeRef::Prim(p) => *p,
                _ => panic!(),
            })
            .collect();
        assert_eq!(
            p,
            vec![
                Prim::I32,
                Prim::U32,
                Prim::I64,
                Prim::U64,
                Prim::I16,
                Prim::U8,
                Prim::I8,
                Prim::F64,
                Prim::F32,
                Prim::Bool,
            ]
        );
    }

    #[test]
    fn multi_declarator_and_comments() {
        // Several names on one line, plus comments.
        let ty = one("struct P /* pt */ { int x, y; }; // 2d point");
        let UserType::Struct { fields, .. } = ty else {
            panic!()
        };
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "x");
        assert_eq!(fields[1].name, "y");
    }

    #[test]
    fn enum_with_values() {
        let ty = one("enum Cmd { READ, WRITE = 5, APPEND, STOP = -1 };");
        let UserType::Enum {
            name,
            width,
            variants,
        } = ty
        else {
            panic!("{ty:?}");
        };
        assert_eq!(name, "Cmd");
        assert_eq!(width, Prim::U32);
        assert_eq!(
            variants,
            vec![
                ("READ".into(), 0),
                ("WRITE".into(), 5),
                ("APPEND".into(), 6),
                ("STOP".into(), -1),
            ]
        );
    }

    #[test]
    fn union_and_typedef_alias() {
        let v = parse_c_decls("union U { int i; float f; }; typedef uint32_t u32;").unwrap();
        assert_eq!(v.len(), 2);
        assert!(matches!(&v[0], UserType::Union { name, .. } if name == "U"));
        assert!(
            matches!(&v[1], UserType::Typedef { name, target } if name == "u32" && *target == TypeRef::Prim(Prim::U32))
        );
    }

    #[test]
    fn typedef_anonymous_struct() {
        let ty = one("typedef struct { int a; int b; } Pair;");
        assert!(matches!(ty, UserType::Struct { ref name, .. } if name == "Pair"));
    }

    #[test]
    fn typedef_tagged_struct_makes_struct_and_alias() {
        let v = parse_c_decls("typedef struct Node { int v; } Node_t;").unwrap();
        assert_eq!(v.len(), 2);
        assert!(matches!(&v[0], UserType::Struct { name, .. } if name == "Node"));
        assert!(
            matches!(&v[1], UserType::Typedef { name, target } if name == "Node_t" && *target == TypeRef::Named("Node".into()))
        );
    }

    #[test]
    fn errors_are_readable() {
        // An unknown bare name is a forward type reference; the catalog validates it later.
        let v = parse_c_decls("struct S { Widget w; };").unwrap();
        assert!(matches!(
            &v[0],
            UserType::Struct { fields, .. } if fields[0].ty == TypeRef::Named("Widget".into())
        ));
        // Genuinely broken input errors with a readable message.
        assert!(
            parse_c_decls("struct S { int x; ")
                .unwrap_err()
                .contains("unterminated")
        );
        assert!(
            parse_c_decls("")
                .unwrap_err()
                .contains("no type declarations")
        );
        assert!(parse_c_decls("int x;").is_err()); // not a type declaration
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn imports_structs_and_skips_noise() {
        let header = r#"
            #ifndef FOO_H
            #define FOO_H 1
            #include <stdint.h>

            /* a packet */
            typedef struct __attribute__((packed)) Packet {
                const uint32_t magic;
                char body[64];
                struct Packet *next;
            } Packet;

            // a function prototype — skipped
            int process(Packet *p, int flags);

            enum Cmd { CMD_READ = 1, CMD_WRITE = 2 };

            struct WithBitfield { unsigned a : 3; unsigned b : 5; };  // skipped (bitfields)
            #endif
        "#;
        let (types, _skipped) = parse_header(header).unwrap();
        let names: Vec<&str> = types.iter().map(UserType::name).collect();
        assert!(names.contains(&"Packet"), "{names:?}");
        assert!(names.contains(&"Cmd"), "{names:?}");
        // The `const` qualifier is ignored; the struct's first field is still a u32.
        let packet = types
            .iter()
            .find(|t| matches!(t, UserType::Struct { name, .. } if name == "Packet"))
            .unwrap();
        if let UserType::Struct { fields, .. } = packet {
            assert_eq!(fields[0].ty, TypeRef::Prim(Prim::U32));
            assert_eq!(fields[1].count, 64);
        }
        // The function prototype and the bitfield struct did not abort the import.
        assert!(!types.is_empty());
    }

    #[test]
    fn empty_header_is_ok() {
        let (types, skipped) = parse_header("#include <stdio.h>\nint main(void);\n").unwrap();
        assert!(types.is_empty());
        assert!(skipped >= 1);
    }
}
