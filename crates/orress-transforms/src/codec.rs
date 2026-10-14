//! Text encodings, implemented here so custom alphabets (a common CTF trick) work.

pub const BASE64_STANDARD: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const BASE64_URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
pub const BASE32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Hex to bytes. Ignores whitespace, commas, `0x` and `\x` prefixes.
pub fn from_hex(input: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8_lossy(input)
        .replace("0x", "")
        .replace("0X", "")
        .replace("\\x", "");
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b',' && *b != b':')
        .collect();
    if let Some(bad) = digits.iter().find(|b| !b.is_ascii_hexdigit()) {
        return Err(format!("`{}` is not a hex digit", *bad as char));
    }
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    Ok(digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("ascii"), 16).expect("hex"))
        .collect())
}

pub fn to_hex(input: &[u8], separator: &str) -> Vec<u8> {
    input
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(separator)
        .into_bytes()
}

fn check_alphabet(alphabet: &str, len: usize) -> Result<Vec<u8>, String> {
    let a = alphabet.as_bytes().to_vec();
    if a.len() != len {
        return Err(format!(
            "the alphabet needs exactly {len} characters, it has {}",
            a.len()
        ));
    }
    let mut seen = [false; 256];
    for &c in &a {
        if std::mem::replace(&mut seen[usize::from(c)], true) {
            return Err(format!("`{}` appears twice in the alphabet", c as char));
        }
    }
    Ok(a)
}

pub fn to_base64(input: &[u8], alphabet: &str, pad: bool) -> Result<Vec<u8>, String> {
    let a = check_alphabet(alphabet, 64)?;
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(a[((n >> (18 - 6 * i)) & 63) as usize]);
            } else if pad {
                out.push(b'=');
            }
        }
    }
    Ok(out)
}

pub fn from_base64(input: &[u8], alphabet: &str) -> Result<Vec<u8>, String> {
    let a = check_alphabet(alphabet, 64)?;
    let mut lookup = [255u8; 256];
    for (i, &c) in a.iter().enumerate() {
        lookup[usize::from(c)] = i as u8;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &c in input {
        // Look the character up first: a custom alphabet may legitimately
        // contain `=` or whitespace.
        let v = lookup[usize::from(c)];
        if v == 255 {
            if c == b'=' {
                // Padding ends a quantum: drop the leftover (zero) bits so a
                // following concatenated block ("QQ==QQ==") starts aligned.
                buffer = 0;
                bits = 0;
                continue;
            }
            if c.is_ascii_whitespace() {
                continue;
            }
            return Err(format!("`{}` is not in the base64 alphabet", c as char));
        }
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

pub fn to_base32(input: &[u8]) -> Vec<u8> {
    let a = BASE32.as_bytes();
    let mut out = Vec::new();
    for chunk in input.chunks(5) {
        let mut block = [0u8; 5];
        block[..chunk.len()].copy_from_slice(chunk);
        let n = block.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < chars {
                out.push(a[((n >> (35 - 5 * i)) & 31) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

pub fn from_base32(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u64, 0u32);
    for &c in input {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        let v = BASE32
            .bytes()
            .position(|x| x == c.to_ascii_uppercase())
            .ok_or_else(|| format!("`{}` is not a base32 character", c as char))?;
        buffer = (buffer << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

pub fn to_base58(input: &[u8]) -> Vec<u8> {
    let a = BASE58.as_bytes();
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-58 digits
    for &byte in &input[zeros..] {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = vec![b'1'; zeros];
    out.extend(digits.iter().rev().map(|&d| a[usize::from(d)]));
    out
}

pub fn from_base58(input: &[u8]) -> Result<Vec<u8>, String> {
    let text: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let zeros = text.iter().take_while(|&&b| b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new(); // little-endian
    for &c in &text[zeros..] {
        let v = BASE58
            .bytes()
            .position(|x| x == c)
            .ok_or_else(|| format!("`{}` is not a base58 character", c as char))?;
        let mut carry = v as u32;
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// Exactly two ASCII hex digits → one byte (no separators, no prefixes).
fn hex_pair(pair: &[u8]) -> Option<u8> {
    if pair.len() != 2 || !pair.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()
}

pub fn from_url(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => {
                let byte = input
                    .get(i + 1..i + 3)
                    .and_then(hex_pair)
                    .ok_or("a `%` must be followed by two hex digits")?;
                out.push(byte);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

pub fn to_url(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in input {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b);
        } else {
            out.extend(format!("%{b:02X}").bytes());
        }
    }
    out
}

/// `\x41\n\t\\` → bytes.
pub fn from_escaped(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let next = *input
            .get(i + 1)
            .ok_or("the text ends with a lone backslash")?;
        i += 2;
        match next {
            b'x' => {
                let byte = input
                    .get(i..i + 2)
                    .and_then(hex_pair)
                    .ok_or("`\\x` needs two hex digits")?;
                out.push(byte);
                i += 2;
            }
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'0' => out.push(0),
            other => out.push(other),
        }
    }
    Ok(out)
}

pub fn to_escaped(input: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    for &b in input {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.into_bytes()
}
