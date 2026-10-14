//! Number parsing and formatting for the number-systems lessons and quiz answers.

/// Parses `42`, `0x2a`, `2Ah`, `0b101010`, `-1`, `'A'`. Underscores and spaces are
/// ignored. Returns the value as i128 so both u64 and negative numbers fit.
pub fn parse(text: &str) -> Option<i128> {
    let t: String = text
        .trim()
        .chars()
        .filter(|c| *c != '_' && *c != ' ')
        .collect();
    if t.is_empty() {
        return None;
    }
    if let Some(c) = t.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        let mut chars = c.chars();
        let ch = chars.next()?;
        return chars.next().is_none().then_some(i128::from(u32::from(ch)));
    }
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest.to_owned()),
        None => (false, t),
    };
    let lower = t.to_ascii_lowercase();
    let value = if let Some(hex) = lower.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()?
    } else if let Some(bin) = lower.strip_prefix("0b") {
        i128::from_str_radix(bin, 2).ok()?
    } else if let Some(hex) = lower.strip_suffix('h') {
        i128::from_str_radix(hex, 16).ok()?
    } else {
        lower.parse::<i128>().ok()?
    };
    Some(if neg { -value } else { value })
}

pub fn binary_grouped(value: u64, bits: u32) -> String {
    let mut s = String::new();
    for i in (0..bits).rev() {
        s.push(if value >> i & 1 == 1 { '1' } else { '0' });
        if i % 4 == 0 && i != 0 {
            s.push(' ');
        }
    }
    s
}

/// Two's complement interpretation of the low `bits` bits.
pub fn signed(value: u64, bits: u32) -> i64 {
    if bits >= 64 {
        return value as i64;
    }
    let mask = (1u64 << bits) - 1;
    let v = value & mask;
    if v >> (bits - 1) & 1 == 1 {
        (v as i64) - (1i64 << bits)
    } else {
        v as i64
    }
}

/// Bytes of the low `bits` bits, little-endian order.
pub fn le_bytes(value: u64, bits: u32) -> Vec<u8> {
    value.to_le_bytes()[..(bits / 8) as usize].to_vec()
}

pub fn char_of(value: u64) -> String {
    match value {
        0x20..=0x7e => format!("'{}'", value as u8 as char),
        0 => "NUL".into(),
        0x0a => "newline (\\n)".into(),
        0x0d => "carriage return (\\r)".into(),
        0x09 => "tab (\\t)".into(),
        _ => "not printable".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_forms() {
        assert_eq!(parse("42"), Some(42));
        assert_eq!(parse("0x2A"), Some(42));
        assert_eq!(parse("2ah"), Some(42));
        assert_eq!(parse("0b10_1010"), Some(42));
        assert_eq!(parse("-1"), Some(-1));
        assert_eq!(parse("'A'"), Some(65));
        assert_eq!(parse("0x12345678"), Some(0x1234_5678));
        assert_eq!(parse("nope"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn formatting() {
        assert_eq!(binary_grouped(0x2a, 8), "0010 1010");
        assert_eq!(signed(0xff, 8), -1);
        assert_eq!(signed(0x7f, 8), 127);
        assert_eq!(signed(0x80, 8), -128);
        assert_eq!(le_bytes(0x1234_5678, 32), vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(char_of(0x41), "'A'");
    }
}
