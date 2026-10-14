//! Data transforms: decode, decrypt, decompress and hash bytes, alone or chained into
//! a [`Recipe`] such as `from_base64 | xor key=0x41 | zlib_inflate`.
//!
//! The same recipes run in ORRESS's Workbench and in `orress-cli`, and [`magic`]
//! searches for a recipe that turns unreadable input into something readable.

mod codec;
mod magic;
mod ops;
pub mod score;

use std::collections::BTreeMap;
use std::fmt;

pub use magic::{Suggestion, magic};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Encoding,
    Text,
    Bitwise,
    Crypto,
    Compression,
    Hash,
    Data,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Self::Encoding => "Encoding",
            Self::Text => "Text",
            Self::Bitwise => "Bitwise",
            Self::Crypto => "Crypto",
            Self::Compression => "Compression",
            Self::Hash => "Hashes",
            Self::Data => "Data",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamKind {
    /// Bytes: `0x4142`, `hex:41 42`, `text:abc` or plain text.
    Key,
    Int,
    Text,
    Choice(&'static [&'static str]),
}

#[derive(Clone, Copy, Debug)]
pub struct Param {
    pub name: &'static str,
    pub kind: ParamKind,
    pub default: &'static str,
    pub explain: &'static str,
}

pub type OpFn = fn(&[u8], &Args<'_>) -> Result<Vec<u8>, String>;

/// A transform operation.
#[derive(Clone, Copy)]
pub struct Op {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub explain: &'static str,
    pub params: &'static [Param],
    pub run: OpFn,
}

/// Parameter values for one step, with typed access.
pub struct Args<'a> {
    values: &'a BTreeMap<String, String>,
    spec: &'static [Param],
}

impl Args<'_> {
    fn raw(&self, name: &str) -> &str {
        self.values
            .get(name)
            .map(String::as_str)
            .or_else(|| self.spec.iter().find(|p| p.name == name).map(|p| p.default))
            .unwrap_or("")
    }

    pub fn key(&self, name: &str) -> Result<Vec<u8>, String> {
        parse_key(self.raw(name)).map_err(|e| format!("{name}: {e}"))
    }

    pub fn int(&self, name: &str) -> Result<i64, String> {
        let raw = self.raw(name).trim();
        let value = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(hex) => i64::from_str_radix(hex, 16).ok(),
            None => raw.parse().ok(),
        };
        value.ok_or_else(|| format!("{name}: `{raw}` is not a number"))
    }

    pub fn text(&self, name: &str) -> String {
        self.raw(name).to_owned()
    }
}

/// Parses a key or other byte parameter:
/// - `0x41424344` or `hex:41 42 43` → hex bytes
/// - `text:hello` → the text's bytes
/// - anything else → the text's bytes as typed
pub fn parse_key(text: &str) -> Result<Vec<u8>, String> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("hex:") {
        return codec::from_hex(hex.as_bytes());
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))
        && !hex.is_empty()
        && hex.chars().all(|c| c.is_ascii_hexdigit() || c == ' ')
    {
        return codec::from_hex(hex.as_bytes());
    }
    if let Some(raw) = t.strip_prefix("text:") {
        return Ok(raw.as_bytes().to_vec());
    }
    Ok(text.as_bytes().to_vec())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub op: String,
    pub params: BTreeMap<String, String>,
    pub enabled: bool,
}

impl Step {
    /// A step with default parameters.
    pub fn new(op: &str) -> Self {
        let params = find(op)
            .map(|o| {
                o.params
                    .iter()
                    .map(|p| (p.name.to_owned(), p.default.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            op: op.to_owned(),
            params,
            enabled: true,
        }
    }

    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.params.insert(name.to_owned(), value.to_owned());
        self
    }

    pub fn apply(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let op = find(&self.op).ok_or_else(|| format!("unknown operation `{}`", self.op))?;
        let args = Args {
            values: &self.params,
            spec: op.params,
        };
        (op.run)(input, &args)
    }
}

/// A chain of steps; each step's output is the next one's input.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recipe(pub Vec<Step>);

impl Recipe {
    /// Runs the recipe, returning every enabled step's output. Stops at the first error.
    pub fn run(&self, input: &[u8]) -> Vec<Result<Vec<u8>, String>> {
        let mut outputs = Vec::new();
        let mut current = input.to_vec();
        for step in self.0.iter().filter(|s| s.enabled) {
            match step.apply(&current) {
                Ok(out) => {
                    outputs.push(Ok(out.clone()));
                    current = out;
                }
                Err(e) => {
                    outputs.push(Err(e));
                    break;
                }
            }
        }
        outputs
    }

    /// The final output, or the first error.
    pub fn output(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        match self.run(input).pop() {
            Some(result) => result,
            None => Ok(input.to_vec()),
        }
    }

    /// Parses `op key=value | op2 key="two words"`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut steps = Vec::new();
        for part in split_outside_quotes(text, '|') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let tokens = split_outside_quotes(part, ' ');
            let mut tokens = tokens.iter().map(|t| t.trim()).filter(|t| !t.is_empty());
            let op = tokens.next().ok_or("empty step")?;
            let spec = find(op).ok_or_else(|| format!("unknown operation `{op}`"))?;
            let mut step = Step::new(op);
            for token in tokens {
                let (name, value) = token
                    .split_once('=')
                    .ok_or_else(|| format!("`{token}`: parameters are written name=value"))?;
                if !spec.params.iter().any(|p| p.name == name) {
                    let known: Vec<&str> = spec.params.iter().map(|p| p.name).collect();
                    return Err(format!(
                        "`{op}` has no parameter `{name}` (it has: {})",
                        if known.is_empty() {
                            "none".to_owned()
                        } else {
                            known.join(", ")
                        }
                    ));
                }
                let value = value.trim_matches('"');
                step.params.insert(name.to_owned(), value.to_owned());
            }
            steps.push(step);
        }
        Ok(Self(steps))
    }
}

impl fmt::Display for Recipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for step in self.0.iter().filter(|s| s.enabled) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str(&step.op)?;
            let defaults = find(&step.op).map_or(&[][..], |o| o.params);
            for (name, value) in &step.params {
                let is_default = defaults
                    .iter()
                    .any(|p| p.name == name && p.default == value);
                if is_default {
                    continue;
                }
                if value.contains([' ', '|']) || value.is_empty() {
                    write!(f, " {name}=\"{value}\"")?;
                } else {
                    write!(f, " {name}={value}")?;
                }
            }
        }
        Ok(())
    }
}

fn split_outside_quotes(text: &str, sep: char) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut quoted = false;
    for c in text.chars() {
        if c == '"' {
            quoted = !quoted;
        }
        if c == sep && !quoted {
            parts.push(String::new());
        } else {
            parts.last_mut().expect("non-empty").push(c);
        }
    }
    parts
}

/// All operations, in display order.
pub fn ops() -> &'static [Op] {
    ops::ALL
}

pub fn find(id: &str) -> Option<&'static Op> {
    ops::ALL.iter().find(|o| o.id == id)
}

#[cfg(test)]
mod tests;
