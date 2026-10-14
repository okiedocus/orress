# Contributing to ORRESS

Thanks for helping! Bug reports, test samples, Academy lessons, documentation and code are all
welcome. This guide covers how to get a change merged.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go
through [SECURITY.md](SECURITY.md), **not** public issues.

## Ways to help

- **Report a bug** — use the *Bug report* issue form. A small reproducer (a file, or the steps
  that produce a wrong disassembly or decompilation) makes a fix far more likely.
- **Suggest a feature** — use the *Feature request* form and describe the problem you are solving,
  not just the feature.
- **Improve the Academy** — lessons are plain TOML in [`academy/lessons/`](academy/lessons).
- **Send code** — see below. For anything larger than a focused fix, open an issue first so we can
  agree on the approach before you spend time on it.

## Setting up

1. Install Rust with [rustup](https://rustup.rs). The repository pins its toolchain in
   [`rust-toolchain.toml`](rust-toolchain.toml); rustup installs it automatically.
2. On Linux, install the GUI libraries:
   `sudo apt install libxkbcommon-dev libgtk-3-dev libwayland-dev`.
3. Build and run:

   ```sh
   cargo run -p orress            # the app (debug build)
   cargo run --release -p orress  # smoother for real binaries
   ```

A full debug build with tests needs several gigabytes of disk space for `target/`.

## Before you open a pull request

CI runs exactly these checks on Windows and Linux; please run them locally first:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

and, if you changed dependencies, [`cargo deny check`](https://github.com/EmbarkStudios/cargo-deny).

A good pull request:

- **does one thing** and explains *why* in its description;
- **adds or updates tests** — parsers get a test with real or hand-built bytes, the decompiler gets
  a case in its test module, bug fixes get a regression test;
- **keeps the project pure Rust** — a new dependency that needs a C/C++ toolchain needs a strong
  reason, and every new dependency must pass `cargo deny` (permissive licenses, crates.io only);
- **handles hostile input** — ORRESS opens malware. Never `unwrap()` on data from a file, bound
  allocations and loops by the input size, and prefer returning an error over panicking;
- **updates the docs** — the README, the action's explanation in
  [`crates/orress/src/actions.rs`](crates/orress/src/actions.rs), or the Academy when behaviour
  changes users can see;
- adds an entry under *Unreleased* in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## Where things live

ORRESS is a workspace of focused crates; the app is a thin shell over reusable engines. The
README's [Architecture](README.md#architecture) section maps every crate. A few conventions:

- **Every user-facing operation is an action** with a plain-language explanation in
  `crates/orress/src/actions.rs`. Menus, the command palette, shortcuts and buttons all dispatch
  through it, so a new feature automatically appears everywhere.
- **Views** live in `crates/orress-views`; long-running work (analysis, emulation, scans) runs on a
  worker thread — never block the UI thread.
- **Engines stay UI-free.** Loaders, analysis, the decompiler, the emulator and friends must not
  depend on `egui`, so the CLI and the MCP server can reuse them.
- `unsafe` is forbidden workspace-wide. The only exceptions are two OS interfaces that cannot be
  written without it — the native debugger (`orress-debug`) and the sandbox's Windows Job Objects
  (`orress-sandbox/src/job.rs`) — each opted in explicitly, with a safety comment on every block.

## Commit messages

Use a short imperative summary, optionally prefixed with the area:

```
decompiler: fold signed max/min idioms
loaders: classify PIE executables as executables, not libraries
```

Keep unrelated changes in separate commits.

## Licensing of contributions

ORRESS is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE). Unless you
explicitly state otherwise, any contribution you intentionally submit for inclusion in ORRESS, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or
conditions.

Only contribute code you wrote or have the right to submit. Do not paste code from IDA, Ghidra,
Binary Ninja, Zed or other projects unless its license is compatible and it is clearly attributed.

## Malware samples

Never commit live malware. Tests use small hand-built binaries or harmless crackmes. If a bug only
reproduces with a real sample, do not attach it to a public issue — follow the instructions in
[SECURITY.md](SECURITY.md) to share it privately.
