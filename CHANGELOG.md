# Changelog

All notable changes to ORRESS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-14

The first public release of ORRESS — the Okiedocus Rusty Reverse Engineering Software Suite.

### Highlights

- **A pure-Rust reverse-engineering IDE** with a Zed-inspired workspace: docks, panes, splits, a
  command palette, and Zed-format keymaps and themes.
- **Loaders and formats**: PE, ELF and Mach-O, plus .NET, Java class/JAR, Android DEX, Python
  `.pyc`, WebAssembly, JavaScript, and ZIP-based containers (ZIP64, JAR, APK).
- **Disassembly and analysis** for x86/x86-64 and ARM64: functions, control-flow graphs, cross
  references, strings, renaming, comments and bookmarks.
- **A decompiler that speaks Rust**, including a *Rust port* mode that turns assembly into
  compilable Rust.
- **Run, debug and solve**: a native debugger (Windows; Linux experimental), an x86-64 emulator
  with time-travel tracing, a symbolic solver, devirtualization, and binary diffing.
- **Malware analysis**: triage with imphash, fuzzy hashes and IOCs, YARA-X scanning, and a sandbox
  that requires a VM, contains the whole process tree and offers a fake network.
- **Built-in tools**: an in-app assembler and patcher, a CyberChef-style transform workbench, a
  code editor with language-server support, a debug-adapter client and an integrated terminal.
- **Extensible**: runs Zed extensions (themes, grammars, language servers, WASM) and Rhai scripts.
- **Learn inside the tool**: the ORRESS Academy — 8 levels, 37 lessons, practice crackmes and a
  CPU simulator.
- **AI, your way**: an assistant on your Claude plan (via the `claude` CLI), the Claude API, any
  OpenAI-compatible or local model, or fully offline; plus an MCP server (`orress-mcp`) that exposes
  ORRESS's engines to AI agents.
- **Team play**: end-to-end-encrypted real-time collaboration through a small relay
  (`orress-relay`), with CTFd and rCTF integration.

### Security

- Extensions run in the wasmtime 36 long-term-support series with path confinement, a filtered
  environment and an execution policy; YARA-X is held on a release built on the same patched
  series.
- Dependencies are checked by `cargo deny` (RustSec advisories, licenses, sources) on every push
  and daily.

[Unreleased]: https://github.com/okiedocus/orress/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/okiedocus/orress/releases/tag/v1.0.0
