//! How "readable" or meaningful bytes look, to rank automatic decoding results.

/// Known file signatures: (magic bytes, description).
const SIGNATURES: &[(&[u8], &str)] = &[
    (b"MZ", "a Windows program (PE)"),
    (b"\x7fELF", "a Linux program (ELF)"),
    (b"PK\x03\x04", "a ZIP archive"),
    (b"\x89PNG", "a PNG image"),
    (b"\xff\xd8\xff", "a JPEG image"),
    (b"GIF8", "a GIF image"),
    (b"%PDF", "a PDF document"),
    (b"\x1f\x8b", "gzip data"),
    (b"7z\xbc\xaf", "a 7-Zip archive"),
    (b"Rar!", "a RAR archive"),
    (b"\xca\xfe\xba\xbe", "a Java class or Mach-O file"),
    (b"dex\n", "Android DEX code"),
];

/// Describes the data if it starts with a known file signature.
pub fn file_type(data: &[u8]) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|(magic, _)| data.starts_with(magic) && data.len() > magic.len() + 8)
        .map(|(_, name)| *name)
}

const COMMON_WORDS: &[&str] = &[
    "the", "and", "flag", "password", "http", "key", "you", "this", "that", "with", "for",
    "secret", "user", "admin", "win", "correct", "ctf",
];

/// Readability score, roughly 0..=1, plus bonuses for flags and file signatures.
pub fn score(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    if file_type(data).is_some() {
        return 1.5;
    }
    let len = data.len() as f32;
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count() as f32;
    let letters = data.iter().filter(|b| b.is_ascii_alphabetic()).count() as f32;
    let spaces = data.iter().filter(|&&b| b == b' ').count() as f32;
    let mut s = printable / len * 0.6 + (letters + spaces) / len * 0.3;
    // Natural text has spaces roughly every 5–6 characters.
    if (0.05..0.3).contains(&(spaces / len)) {
        s += 0.1;
    }
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    let words = COMMON_WORDS.iter().filter(|w| text.contains(*w)).count();
    s += (words as f32 * 0.05).min(0.2);
    if orress_bytes::strings::looks_like_flag(&text) {
        s += 1.0;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_beats_noise() {
        let text = score(b"The password is hunter2, keep it secret.");
        let noise = score(&[0x8f, 0x12, 0xa0, 0x33, 0xfe, 0x01, 0x77, 0x90]);
        assert!(text > 0.8 && noise < 0.3, "{text} {noise}");
        assert!(score(b"flag{x0r_is_fun}") > 1.0);
        assert_eq!(
            file_type(b"\x89PNG\r\n\x1a\n0000000000"),
            Some("a PNG image")
        );
    }
}
