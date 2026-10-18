//! The Academy glossary: every technical word the lessons use, explained for a
//! beginner. Files are in `academy/glossary/`, one per level, merged at startup:
//!
//! ```toml
//! [[term]]
//! term = "register"
//! aliases = ["registers"]          # other spellings found in lesson text
//! short = "A tiny, very fast storage slot inside the CPU."
//! text = """Longer Markdown explanation, with an example."""
//! see = ["rax", "stack"]           # related terms
//! ```
//!
//! Lesson steps list the glossary terms that appear in their text automatically, so
//! a learner never meets a word that is not explained somewhere.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Term {
    pub term: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One sentence.
    pub short: String,
    /// Optional longer Markdown explanation.
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub see: Vec<String>,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    term: Vec<Term>,
}

pub fn parse(source: &str) -> Result<Vec<Term>, String> {
    toml::from_str::<File>(source)
        .map(|f| f.term)
        .map_err(|e| e.to_string())
}

/// All built-in terms, sorted alphabetically (case-insensitive).
pub fn catalog() -> Vec<Term> {
    let mut terms: Vec<Term> = crate::lesson::GLOSSARY_FILES
        .iter()
        .flat_map(|(file, source)| {
            parse(source).unwrap_or_else(|e| panic!("built-in glossary {file}: {e}"))
        })
        .collect();
    terms.sort_by_key(|t| t.term.to_lowercase());
    terms
}

/// Index of the term named `name` (or with that alias), ignoring case.
pub fn find(terms: &[Term], name: &str) -> Option<usize> {
    terms.iter().position(|t| {
        t.term.eq_ignore_ascii_case(name) || t.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))
    })
}

/// Whether `needle` occurs in `haystack` as a whole word (or words), ignoring ASCII case.
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hay = haystack.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(pos) = hay[from..].find(&needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before = hay[..start].chars().next_back();
        let after = hay[end..].chars().next();
        if !before.is_some_and(is_word) && !after.is_some_and(is_word) {
            return true;
        }
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Indices of the terms mentioned in `text`, in glossary order.
pub fn mentioned(terms: &[Term], text: &str) -> Vec<usize> {
    terms
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            contains_word(text, &t.term) || t.aliases.iter().any(|a| contains_word(text, a))
        })
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_glossary_is_valid() {
        let terms = catalog();
        assert!(!terms.is_empty());
        let mut names: Vec<String> = terms
            .iter()
            .flat_map(|t| std::iter::once(&t.term).chain(&t.aliases))
            .map(|n| n.to_lowercase())
            .collect();
        let count = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), count, "glossary terms and aliases are unique");
        for t in &terms {
            assert!(
                !t.short.trim().is_empty(),
                "`{}` has a short explanation",
                t.term
            );
            for see in &t.see {
                assert!(
                    find(&terms, see).is_some(),
                    "`{}` refers to `{see}`, which is not in the glossary",
                    t.term
                );
            }
        }
    }

    #[test]
    fn finds_whole_words_only() {
        assert!(contains_word("The Stack grows down.", "stack"));
        assert!(contains_word("a call stack frame", "stack frame"));
        assert!(!contains_word("stacked boxes", "stack"));
        assert!(!contains_word("unstack", "stack"));
        assert!(contains_word("use `rax`.", "rax"));
        assert!(!contains_word("anything", ""));
    }
}
