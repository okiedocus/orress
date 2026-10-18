//! Turn a mangled linker symbol into a readable name. Tries Rust (legacy `_ZN…E` and v0 `_R…`),
//! MSVC (`?…`) and C++ Itanium (`_Z…`/`__Z…`), in that order. Pure Rust — no C `__cxa_demangle`.
//!
//! [`demangle`] returns `Some(readable)` only when a demangler recognises the name and produces
//! something different; a plain or auto-generated name (`main`, `sub_1400`, `puts`) returns `None`,
//! so callers can keep the original.

/// Demangles `name`, or `None` if it is not a recognised mangled symbol.
pub fn demangle(name: &str) -> Option<String> {
    // Rust: `{:#}` omits the trailing hash (`...::h1a2b3c` -> `...`).
    if let Ok(d) = rustc_demangle::try_demangle(name) {
        let s = format!("{d:#}");
        if s != name {
            return Some(s);
        }
    }
    // MSVC C++ (`?` prefix).
    if name.starts_with('?') {
        let flags = msvc_demangler::DemangleFlags::COMPLETE
            | msvc_demangler::DemangleFlags::NO_MS_KEYWORDS;
        if let Ok(s) = msvc_demangler::demangle(name, flags)
            && s != name
        {
            return Some(s);
        }
    }
    // C++ Itanium (`_Z` / `__Z`).
    if (name.starts_with("_Z") || name.starts_with("__Z"))
        && let Ok(sym) = cpp_demangle::Symbol::new(name)
    {
        let s = sym.to_string();
        if s != name {
            return Some(s);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_legacy_and_v0() {
        // Legacy Rust mangling.
        let d = demangle("_ZN4core3fmt9Formatter3pad17h0123456789abcdefE").unwrap();
        assert_eq!(d, "core::fmt::Formatter::pad");
        // v0 Rust mangling (`_R…`): core::panicking::panic.
        let d = demangle("_RNvNtCs1234_4core9panicking5panic").unwrap();
        assert!(d.contains("panicking") && d.contains("panic"), "{d}");
    }

    #[test]
    fn cpp_itanium() {
        // int foo(int, int)
        assert_eq!(demangle("_Z3fooii").unwrap(), "foo(int, int)");
    }

    #[test]
    fn msvc() {
        // `int __cdecl foo(int)` mangled by MSVC.
        let d = demangle("?foo@@YAHH@Z").unwrap();
        assert!(d.contains("foo"), "{d}");
    }

    #[test]
    fn plain_names_are_left_alone() {
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("sub_140001100"), None);
        assert_eq!(demangle("puts"), None);
        assert_eq!(demangle("check_password"), None);
    }
}
