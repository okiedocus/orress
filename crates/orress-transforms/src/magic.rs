//! "Magic": search for a recipe that makes the input readable, like CyberChef's Magic.
//!
//! A small beam search: from the input, try every decoding that plausibly applies
//! (base64 only if the text looks like base64, zlib only if it starts like zlib, ...),
//! keep the best few results, and repeat a few levels deep.

use crate::score::{file_type, score};
use crate::{Recipe, Step};

#[derive(Clone, Debug)]
pub struct Suggestion {
    pub recipe: Recipe,
    pub output: Vec<u8>,
    pub score: f32,
    /// Plain-language reason, e.g. "readable text" or "a PNG image".
    pub why: String,
}

const BEAM: usize = 12;
const MAX_INPUT: usize = 1 << 20;

fn is_text(data: &[u8]) -> bool {
    !data.is_empty()
        && data
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
}

/// Decodings worth trying on `data`.
fn candidates(data: &[u8]) -> Vec<Step> {
    let mut out = Vec::new();
    let text = is_text(data);
    let compact: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if text && compact.len() >= 4 {
        if compact.len().is_multiple_of(2) && compact.iter().all(u8::is_ascii_hexdigit) {
            out.push(Step::new("from_hex"));
        }
        if compact
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b))
        {
            out.push(Step::new("from_base64"));
        }
        if compact
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_=".contains(b))
        {
            out.push(Step::new("from_base64").with("alphabet", crate::codec::BASE64_URL));
        }
        if compact
            .iter()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(b) || *b == b'=')
        {
            out.push(Step::new("from_base32"));
        }
        if compact
            .iter()
            .all(|b| crate::codec::BASE58.as_bytes().contains(b))
        {
            out.push(Step::new("from_base58"));
        }
        if data.contains(&b'%') {
            out.push(Step::new("from_url"));
        }
        if data.windows(2).any(|w| w == b"\\x") {
            out.push(Step::new("from_escaped"));
        }
        if data.iter().filter(|b| b.is_ascii_alphabetic()).count() * 2 > data.len() {
            out.push(Step::new("rot13"));
        }
        out.push(Step::new("reverse"));
    }
    if data.len() >= 2 && data[0] == 0x78 {
        out.push(Step::new("zlib_inflate"));
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        out.push(Step::new("gzip_decompress"));
    }
    if data.len() >= 4
        && data.len().is_multiple_of(2)
        && data.iter().skip(1).step_by(2).all(|&b| b == 0)
    {
        out.push(Step::new("utf16le_to_utf8"));
    }
    // XOR can also turn text into printable gibberish, so try it on anything that does
    // not already contain a flag.
    let has_flag = orress_bytes::strings::looks_like_flag(&String::from_utf8_lossy(data));
    if !has_flag && data.len() >= 4 {
        // Best single-byte XOR key.
        let sample = &data[..data.len().min(2048)];
        if let Some((key, _)) = (1..=255u8)
            .map(|k| (k, score(&sample.iter().map(|b| b ^ k).collect::<Vec<_>>())))
            .max_by(|a, b| a.1.total_cmp(&b.1))
        {
            out.push(Step::new("xor").with("key", &format!("0x{key:02x}")));
        }
        // Known plaintext: maybe it is an XOR-encrypted flag.
        if let Some(key) = crate::ops::recover_xor_key(data, b"flag{", 0)
            && key.len() < 5
        {
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            out.push(Step::new("xor").with("key", &format!("0x{hex}")));
        }
    }
    out
}

fn describe(data: &[u8]) -> String {
    if let Some(kind) = file_type(data) {
        return kind.to_owned();
    }
    if orress_bytes::strings::looks_like_flag(&String::from_utf8_lossy(data)) {
        return "looks like a flag!".to_owned();
    }
    if is_text(data) {
        return "readable text".to_owned();
    }
    "binary data".to_owned()
}

/// Ranked suggestions, best first. `depth` is the maximum recipe length.
pub fn magic(input: &[u8], depth: usize) -> Vec<Suggestion> {
    let input = &input[..input.len().min(MAX_INPUT)];
    let base = score(input);
    let mut frontier: Vec<(Recipe, Vec<u8>)> = vec![(Recipe::default(), input.to_vec())];
    let mut found: Vec<Suggestion> = Vec::new();
    for _ in 0..depth {
        let mut next: Vec<(Recipe, Vec<u8>, f32)> = Vec::new();
        for (recipe, data) in &frontier {
            for step in candidates(data) {
                // Do not undo the previous step (reverse after reverse, rot13 twice).
                if recipe.0.last().is_some_and(|last| {
                    last.op == step.op && matches!(step.op.as_str(), "reverse" | "rot13")
                }) {
                    continue;
                }
                let Ok(out) = step.apply(data) else {
                    continue;
                };
                if out.is_empty() || out == *data {
                    continue;
                }
                let mut r = recipe.clone();
                r.0.push(step);
                let s = score(&out);
                next.push((r, out, s));
            }
        }
        next.sort_by(|a, b| b.2.total_cmp(&a.2));
        next.dedup_by(|a, b| a.1 == b.1);
        next.truncate(BEAM);
        for (recipe, output, s) in &next {
            // Longer recipes must earn their extra steps.
            let adjusted = s - 0.05 * recipe.0.len() as f32;
            if *s > base + 0.1 && !found.iter().any(|f| f.output == *output) {
                found.push(Suggestion {
                    recipe: recipe.clone(),
                    why: describe(output),
                    output: output.clone(),
                    score: adjusted,
                });
            }
        }
        frontier = next.into_iter().map(|(r, o, _)| (r, o)).collect();
        if frontier.is_empty() {
            break;
        }
    }
    found.sort_by(|a, b| b.score.total_cmp(&a.score));
    found.truncate(10);
    found
}
