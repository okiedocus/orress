//! Byte pattern search.
//!
//! Patterns are written as hex with `??` wildcards, like most RE tools:
//! `4D 5A ?? 00`, `e8????????`. Text patterns are converted to bytes (optionally as
//! UTF-16LE, for Windows wide strings).

use memchr::memmem;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    /// `None` is a wildcard that matches any byte.
    bytes: Vec<Option<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    BadHex(String),
    AllWildcards,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("the pattern is empty"),
            Self::BadHex(tok) => write!(f, "`{tok}` is not a hex byte (use 00–FF or ??)"),
            Self::AllWildcards => f.write_str("the pattern needs at least one fixed byte"),
        }
    }
}

impl std::error::Error for PatternError {}

impl Pattern {
    /// Parses `4D 5A ?? 00`, `4d5a??00`, `0x4D 0x5A`, or with `?` as a short wildcard.
    pub fn parse_hex(source: &str) -> Result<Self, PatternError> {
        let cleaned: String = source
            .split_whitespace()
            .map(|t| t.trim_start_matches("0x").trim_start_matches("0X"))
            .map(|t| if t == "?" { "??" } else { t })
            .collect();
        if cleaned.is_empty() {
            return Err(PatternError::Empty);
        }
        if !cleaned.len().is_multiple_of(2) {
            return Err(PatternError::BadHex(source.trim().to_owned()));
        }
        let mut bytes = Vec::with_capacity(cleaned.len() / 2);
        for pair in cleaned.as_bytes().chunks(2) {
            let token = std::str::from_utf8(pair).unwrap_or("");
            if token == "??" {
                bytes.push(None);
            } else {
                let value = u8::from_str_radix(token, 16)
                    .map_err(|_| PatternError::BadHex(token.to_owned()))?;
                bytes.push(Some(value));
            }
        }
        if bytes.iter().all(Option::is_none) {
            return Err(PatternError::AllWildcards);
        }
        Ok(Self { bytes })
    }

    pub fn text(text: &str, utf16: bool) -> Result<Self, PatternError> {
        if text.is_empty() {
            return Err(PatternError::Empty);
        }
        let raw: Vec<u8> = if utf16 {
            text.encode_utf16().flat_map(u16::to_le_bytes).collect()
        } else {
            text.as_bytes().to_vec()
        };
        Ok(Self {
            bytes: raw.into_iter().map(Some).collect(),
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn matches_at(&self, data: &[u8], at: usize) -> bool {
        data.get(at..at + self.len()).is_some_and(|window| {
            window
                .iter()
                .zip(&self.bytes)
                .all(|(b, p)| p.is_none_or(|p| p == *b))
        })
    }

    /// First match at or after `from`.
    pub fn find_from(&self, data: &[u8], from: usize) -> Option<usize> {
        if from >= data.len() {
            return None;
        }
        let hay = &data[from..];
        if self.bytes.iter().all(Option::is_some) {
            let needle: Vec<u8> = self.bytes.iter().flatten().copied().collect();
            return memmem::find(hay, &needle).map(|i| i + from);
        }
        // Anchor on the first fixed byte and verify the rest.
        let (anchor_index, anchor) = self
            .bytes
            .iter()
            .enumerate()
            .find_map(|(i, b)| b.map(|b| (i, b)))?;
        let mut pos = anchor_index;
        while let Some(found) = memchr::memchr(anchor, hay.get(pos..)?) {
            let start = pos + found - anchor_index;
            if self.matches_at(hay, start) {
                return Some(start + from);
            }
            pos += found + 1;
        }
        None
    }

    /// Last match that starts before `before`.
    pub fn find_before(&self, data: &[u8], before: usize) -> Option<usize> {
        let end = before.min(data.len());
        (0..end).rev().find(|&i| self.matches_at(data, i))
    }

    /// Next match after `cursor`, wrapping to the start of the data.
    pub fn find_next_wrapping(&self, data: &[u8], cursor: usize) -> Option<usize> {
        self.find_from(data, cursor + 1)
            .or_else(|| self.find_from(data, 0))
    }

    /// Number of matches, counting at most `limit`.
    pub fn count(&self, data: &[u8], limit: usize) -> usize {
        let mut n = 0;
        let mut pos = 0;
        while n < limit {
            match self.find_from(data, pos) {
                Some(i) => {
                    n += 1;
                    pos = i + 1;
                }
                None => break,
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_forms() {
        let p = Pattern::parse_hex("4D 5A ?? 00").unwrap();
        assert_eq!(p.bytes, vec![Some(0x4d), Some(0x5a), None, Some(0)]);
        assert_eq!(Pattern::parse_hex("4d5a??00").unwrap(), p);
        assert_eq!(Pattern::parse_hex("0x4D 0x5A ? 00").unwrap(), p);
        assert_eq!(Pattern::parse_hex(""), Err(PatternError::Empty));
        assert_eq!(Pattern::parse_hex("?? ??"), Err(PatternError::AllWildcards));
        assert!(matches!(
            Pattern::parse_hex("4G"),
            Err(PatternError::BadHex(_))
        ));
        assert!(matches!(
            Pattern::parse_hex("4D5"),
            Err(PatternError::BadHex(_))
        ));
    }

    #[test]
    fn finds_with_and_without_wildcards() {
        let data = b"xxMZ\x90\x00yyMZ\x00\x00";
        let exact = Pattern::parse_hex("4D 5A").unwrap();
        assert_eq!(exact.find_from(data, 0), Some(2));
        assert_eq!(exact.find_from(data, 3), Some(8));
        let wild = Pattern::parse_hex("4D 5A ?? 00").unwrap();
        assert_eq!(wild.find_from(data, 0), Some(2));
        assert_eq!(wild.find_from(data, 3), Some(8));
        let leading_wild = Pattern::parse_hex("?? 5A").unwrap();
        assert_eq!(leading_wild.find_from(data, 0), Some(2));
        assert_eq!(wild.count(data, 10), 2);
        assert_eq!(wild.find_before(data, 8), Some(2));
        assert_eq!(wild.find_next_wrapping(data, 8), Some(2));
    }

    #[test]
    fn text_patterns() {
        let data = b"..f\x00l\x00a\x00g\x00..flag";
        assert_eq!(
            Pattern::text("flag", false).unwrap().find_from(data, 0),
            Some(12)
        );
        assert_eq!(
            Pattern::text("flag", true).unwrap().find_from(data, 0),
            Some(2)
        );
    }
}
