## What and why

<!-- What does this change, and why is it needed? Link the issue: "Fixes #123". -->

## How it was tested

<!-- New or updated tests, and any manual checks (which file, which view, which OS). -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
      `cargo test --workspace` pass locally
- [ ] Tests added or updated for the change
- [ ] No `unwrap()`/unbounded allocation on data read from a file
- [ ] New dependencies (if any) are pure Rust and pass `cargo deny check`
- [ ] User-visible changes are noted under *Unreleased* in `CHANGELOG.md`
- [ ] Docs updated (README, action explanation, Academy) where behaviour changed

By submitting this pull request I agree that my contribution is dual-licensed under MIT and
Apache-2.0, as described in [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md).
