//! String extraction, like the classic `strings` tool: finds runs of readable
//! characters in ASCII and in UTF-16LE (the encoding Windows uses for "wide" strings).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

impl Encoding {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf16Le => "UTF-16",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundString {
    /// File offset of the first byte.
    pub offset: usize,
    /// Length in bytes (twice the character count for UTF-16).
    pub byte_len: usize,
    pub encoding: Encoding,
    pub text: String,
}

/// Printable ASCII plus tab. Newlines end a string, which keeps results one-line.
fn printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t')
}

/// Extracts strings of at least `min_len` characters, sorted by offset.
/// Returns at most `limit` strings so a huge random file cannot exhaust memory: each scan
/// (ASCII, UTF-16 at even offsets, UTF-16 at odd offsets) stops after its own first `limit` hits,
/// and the merged, offset-sorted result is then truncated, so the result is exactly the first
/// `limit` strings of the file regardless of encoding.
pub fn extract(data: &[u8], min_len: usize, limit: usize) -> Vec<FoundString> {
    let min_len = min_len.max(1);
    let mut out = Vec::new();
    ascii(data, min_len, limit, &mut out);
    utf16le(data, min_len, limit, &mut out);
    out.sort_by_key(|s| s.offset);
    out.truncate(limit);
    out
}

fn ascii(data: &[u8], min_len: usize, limit: usize, out: &mut Vec<FoundString>) {
    let base = out.len();
    let mut start = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0)).enumerate() {
        match (printable(b) && i < data.len(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    out.push(FoundString {
                        offset: s,
                        byte_len: i - s,
                        encoding: Encoding::Ascii,
                        text: String::from_utf8_lossy(&data[s..i]).into_owned(),
                    });
                    if out.len() - base >= limit {
                        return;
                    }
                }
                start = None;
            }
            _ => {}
        }
    }
}

fn utf16le(data: &[u8], min_len: usize, limit: usize, out: &mut Vec<FoundString>) {
    // Two passes, for strings starting at even and at odd offsets.
    for phase in 0..2 {
        let base = out.len();
        let mut start: Option<usize> = None;
        let mut text = String::new();
        let mut i = phase;
        loop {
            let unit = data.get(i..i + 2);
            let ch = unit.and_then(|u| (u[1] == 0 && printable(u[0])).then_some(u[0] as char));
            match (ch, start) {
                (Some(c), None) => {
                    start = Some(i);
                    text.clear();
                    text.push(c);
                }
                (Some(c), Some(_)) => text.push(c),
                (None, Some(s)) => {
                    if text.len() >= min_len {
                        out.push(FoundString {
                            offset: s,
                            byte_len: i - s,
                            encoding: Encoding::Utf16Le,
                            text: std::mem::take(&mut text),
                        });
                        if out.len() - base >= limit {
                            break;
                        }
                    }
                    start = None;
                }
                (None, None) => {}
            }
            if unit.is_none() {
                break;
            }
            i += 2;
        }
    }
}

/// Heuristic: does this look like a CTF flag? Matches `xxx{...}` with a short
/// alphanumeric prefix such as `flag{`, `CTF{`, `picoCTF{`, `HTB{`.
pub fn looks_like_flag(text: &str) -> bool {
    let Some(open) = text.find('{') else {
        return false;
    };
    let prefix = &text[..open];
    let prefix = prefix
        .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or("");
    (2..=12).contains(&prefix.len())
        && prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && text[open..].contains('}')
        && {
            let lower = prefix.to_ascii_lowercase();
            lower.contains("flag")
                || lower.contains("ctf")
                || prefix.chars().all(|c| c.is_ascii_uppercase())
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_and_utf16() {
        // 0xff separator: "b\0" would otherwise also read as the UTF-16 letter b.
        let mut data = b"\x00\x01hello world\x00ab\x00\xff".to_vec();
        data.extend("Wide!".encode_utf16().flat_map(u16::to_le_bytes));
        data.push(0xff);
        let found = extract(&data, 4, 100);
        let texts: Vec<_> = found
            .iter()
            .map(|s| (s.text.as_str(), s.encoding))
            .collect();
        assert!(texts.contains(&("hello world", Encoding::Ascii)));
        assert!(texts.contains(&("Wide!", Encoding::Utf16Le)));
        assert!(!texts.iter().any(|(t, _)| *t == "ab"));
        let hello = found.iter().find(|s| s.text == "hello world").unwrap();
        assert_eq!(hello.offset, 2);
        assert_eq!(hello.byte_len, 11);
    }

    #[test]
    fn string_at_end_of_data_is_found() {
        let found = extract(b"\x00\x00tail", 4, 10);
        assert_eq!(found[0].text, "tail");
    }

    #[test]
    fn limit_is_respected() {
        let data = b"aaaa\x00bbbb\x00cccc\x00dddd".repeat(10);
        assert_eq!(extract(&data, 4, 3).len(), 3);
    }

    #[test]
    fn limit_keeps_the_earliest_strings_of_any_encoding() {
        // Two wide strings first, then many ASCII ones: with limit 3 the result must be the
        // first three by offset, not "ASCII until the limit, then whatever UTF-16 fits".
        let mut data = Vec::new();
        for w in ["WideA", "WideB"] {
            data.extend(w.encode_utf16().flat_map(u16::to_le_bytes));
            data.push(0xff);
        }
        data.extend(b"aaaa\xffbbbb\xffcccc\xffdddd\xff");
        let found = extract(&data, 4, 3);
        let texts: Vec<_> = found.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, ["WideA", "WideB", "aaaa"]);
    }

    #[test]
    fn flag_heuristic() {
        assert!(looks_like_flag("flag{s0me_th1ng}"));
        assert!(looks_like_flag("Your flag: picoCTF{abc}"));
        assert!(looks_like_flag("HTB{x}"));
        assert!(!looks_like_flag("if (x) { return; }"));
        assert!(!looks_like_flag("no braces here"));
    }
}
