//! Tree-sitter syntax highlighting for Rust, Python, C and C++ — the scalable highlighter that
//! replaces the built-in tokenizer for those languages. It produces the same [`Token`] stream, so
//! nothing downstream changes (the tokenizer stays as the fallback for other languages and if a
//! grammar fails to load).
//!
//! Each language pairs a compiled-in grammar with a highlight query (`.scm`). The grammar set is a
//! table, so adding a language is one arm; and [`highlight_with_query`] highlights a built-in
//! grammar with an *imported* query — e.g. a Zed grammar extension's `highlights.scm` — which is
//! the query half of Zed grammar/query compatibility (the grammar half, loading Zed's WASM
//! parsers, waits for the wasmtime host). Imported queries are compiled once and cached per
//! (language, query), so highlighting with one on every edit costs no more than the built-in query.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

use crate::{Language, Tok, Token};

/// Capture names we ask tree-sitter to recognise, mapped to our token kinds by index.
const NAMES: &[&str] = &[
    "keyword",
    "type",
    "type.builtin",
    "constructor",
    "function",
    "function.method",
    "function.macro",
    "string",
    "string.special",
    "escape",
    "character",
    "number",
    "boolean",
    "constant",
    "constant.builtin",
    "comment",
    "attribute",
    "label",
];

fn tok_for(idx: usize) -> Option<Tok> {
    Some(match *NAMES.get(idx)? {
        "keyword" | "boolean" => Tok::Keyword,
        "constant.builtin" => Tok::Number,
        "type" | "type.builtin" | "constructor" | "constant" => Tok::Type,
        "function" | "function.method" => Tok::Function,
        "function.macro" => Tok::Macro,
        "string" | "string.special" | "escape" => Tok::String,
        "character" => Tok::Char,
        "number" => Tok::Number,
        "comment" => Tok::Comment,
        "attribute" => Tok::Attribute,
        "label" => Tok::Lifetime,
        _ => return None,
    })
}

/// The compiled-in grammar for a language, if ORRESS bundles one.
fn grammar(lang: Language) -> Option<tree_sitter::Language> {
    Some(match lang {
        Language::Rust => tree_sitter::Language::new(tree_sitter_rust::LANGUAGE),
        Language::Python => tree_sitter::Language::new(tree_sitter_python::LANGUAGE),
        Language::C => tree_sitter::Language::new(tree_sitter_c::LANGUAGE),
        Language::Cpp => tree_sitter::Language::new(tree_sitter_cpp::LANGUAGE),
        _ => return None,
    })
}

/// The highlight query shipped with each bundled grammar. C++ inherits C's query (its grammar is a
/// superset), as editors do with `; inherits: c`, then adds the C++-specific captures.
fn default_query(lang: Language) -> Option<&'static str> {
    Some(match lang {
        Language::Rust => tree_sitter_rust::HIGHLIGHTS_QUERY,
        Language::Python => tree_sitter_python::HIGHLIGHTS_QUERY,
        Language::C => tree_sitter_c::HIGHLIGHT_QUERY,
        Language::Cpp => {
            static CPP: OnceLock<String> = OnceLock::new();
            CPP.get_or_init(|| {
                format!(
                    "{}\n{}",
                    tree_sitter_c::HIGHLIGHT_QUERY,
                    tree_sitter_cpp::HIGHLIGHT_QUERY
                )
            })
        }
        _ => return None,
    })
}

/// Builds a highlighter for `lang`'s bundled grammar from a specific query — the bundled one, or a
/// query imported from an extension (e.g. a Zed grammar's `highlights.scm`). Returns `None` if the
/// grammar is unavailable or the query does not compile against it.
pub fn build_config_with(lang: Language, query: &str) -> Option<HighlightConfiguration> {
    let language = grammar(lang)?;
    let mut config = HighlightConfiguration::new(language, lang.name(), query, "", "").ok()?;
    config.configure(NAMES);
    Some(config)
}

fn config(lang: Language) -> Option<&'static HighlightConfiguration> {
    // One default configuration per language, built once.
    static RUST: OnceLock<Option<HighlightConfiguration>> = OnceLock::new();
    static PYTHON: OnceLock<Option<HighlightConfiguration>> = OnceLock::new();
    static C: OnceLock<Option<HighlightConfiguration>> = OnceLock::new();
    static CPP: OnceLock<Option<HighlightConfiguration>> = OnceLock::new();
    let build = || build_config_with(lang, default_query(lang)?);
    match lang {
        Language::Rust => RUST.get_or_init(build).as_ref(),
        Language::Python => PYTHON.get_or_init(build).as_ref(),
        Language::C => C.get_or_init(build).as_ref(),
        Language::Cpp => CPP.get_or_init(build).as_ref(),
        _ => None,
    }
}

/// Whether tree-sitter can highlight this language (ORRESS bundles a grammar for it).
pub fn supported(lang: Language) -> bool {
    grammar(lang).is_some()
}

/// Highlights with an imported highlight query (e.g. a Zed grammar extension's `highlights.scm`)
/// over the bundled grammar for `lang`, instead of the built-in query. Returns `None` if the
/// grammar is unavailable, the query does not compile, or parsing fails — so the caller can fall
/// back to the built-in query or the tokenizer.
pub fn highlight_with_query(text: &str, lang: Language, query: &str) -> Option<Vec<Token>> {
    let config = cached_config(lang, query)?;
    run(text, &config)
}

/// How many compiled imported-query configurations are kept. Each installed grammar extension
/// contributes one per language, so this is generous; on overflow the cache simply starts over.
const QUERY_CACHE_CAP: usize = 32;

/// A compiled imported query, or `None` when it does not compile against the bundled grammar
/// (cached too, so a broken query is not recompiled on every edit).
type CachedConfig = Option<Arc<HighlightConfiguration>>;

/// The compiled highlight configuration for `lang`'s bundled grammar with `query`, compiled on first
/// use and cached per (language, query hash) — compiling a query is far slower than highlighting,
/// so doing it per edit would make typing lag. Thread-safe and bounded ([`QUERY_CACHE_CAP`]).
pub(crate) fn cached_config(lang: Language, query: &str) -> CachedConfig {
    static CACHE: OnceLock<Mutex<HashMap<(Language, u64), CachedConfig>>> = OnceLock::new();
    let key = (lang, query_hash(query));
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().ok()?.get(&key) {
        return hit.clone();
    }
    // Compile outside the lock, so other threads highlighting meanwhile are not held up.
    let built = build_config_with(lang, query).map(Arc::new);
    let mut map = cache.lock().ok()?;
    if map.len() >= QUERY_CACHE_CAP && !map.contains_key(&key) {
        map.clear();
    }
    // If another thread compiled it first, keep (and return) that one.
    map.entry(key).or_insert(built).clone()
}

fn query_hash(query: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    query.hash(&mut h);
    h.finish()
}

/// Highlights with tree-sitter's built-in query for the language. Returns `None` if the grammar is
/// unavailable or parsing fails, so the caller can fall back to the tokenizer.
pub fn highlight(text: &str, lang: Language) -> Option<Vec<Token>> {
    run(text, config(lang)?)
}

/// Runs a prepared highlight configuration over `text`, collecting the [`Token`] spans.
pub(crate) fn run(text: &str, config: &HighlightConfiguration) -> Option<Vec<Token>> {
    let mut highlighter = Highlighter::new();
    let events = highlighter
        .highlight(config, text.as_bytes(), None, |_| None)
        .ok()?;
    let mut out: Vec<Token> = Vec::new();
    let mut stack: Vec<Option<Tok>> = Vec::new();
    for event in events {
        match event.ok()? {
            HighlightEvent::HighlightStart(h) => stack.push(tok_for(h.0)),
            HighlightEvent::HighlightEnd => {
                stack.pop();
            }
            HighlightEvent::Source { start, end } => {
                if let Some(Some(kind)) = stack.last() {
                    // Merge with the previous span if it is the same kind and adjacent.
                    if let Some(last) = out.last_mut()
                        && last.kind == *kind
                        && last.end == start
                    {
                        last.end = end;
                    } else {
                        out.push(Token {
                            start,
                            end,
                            kind: *kind,
                        });
                    }
                }
            }
        }
    }
    Some(out)
}
