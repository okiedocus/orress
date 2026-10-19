# Changelog

All notable changes to ORRESS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **IL view**: a read-only **IL** tab shows the decompiler's lifted intermediate
  representation for the function under the cursor — machine code lifted into simple
  statements and basic blocks, before it is structured into `if`/`while` and printed as
  Rust. A window on how decompilation works; each line keeps its source address and block
  labels are clickable.
- **Linear view covers data sections**: the disassembly (linear) view now lists the
  non-executable regions too (`.rodata`/`.data`/…), not just code — detected ASCII strings
  render as quoted literals and other bytes as `db` runs, so you can scroll the whole image
  in address order like IDA/Binary Ninja.
- **Paste C types**: the Types view has a **Paste C…** button that parses pasted C
  declarations (`struct`/`union`/`enum`/`typedef`, with arrays, pointers and `<stdint.h>`
  types) into catalog types — a fast second input alongside the GUI form. Pure-Rust parser,
  LP64 widths.
- **Close project / fresh start**: a **Close Project** command in the File menu closes the
  open folder, and the open project is now session-only — ORRESS starts fresh with no
  project each launch (open files already started clean). The File menu's "Open Recent" is
  renamed **Open Recent File**, and a new **Open Recent Project** submenu reopens a recent
  folder.

- **User-defined types**: a Types view to declare `struct`/`union`/`enum`/`typedef` with a
  form builder (field name, type, array count, pointer), with a live C-layout preview
  (offsets, sizes, padding). Apply a type to a data address from the hex view's right-click
  menu and the Inspector lays the bytes out as named, typed fields. Types persist per
  binary alongside names and comments. The decompiler uses the catalog too: when a
  recovered struct parameter matches a user struct, its fields print with the user's names
  (`p.magic` instead of `p.field_0`), and applied function prototypes override the
  recovered signature. A **Set prototype** editor in the decompiler header pins a
  function's return type and named, typed parameters (a pointer-to-struct parameter then
  prints as field accesses). A **Save struct** menu in the decompiler header promotes a
  struct the decompiler recovered (its `field_N` layout) into a reusable catalog type to
  name and apply elsewhere.
- **Symbol demangling** (`orress-demangle`): mangled linker names in the imports, exports
  and function-symbol lists are now shown readable — Rust (legacy `_ZN…E` and v0 `_R…`),
  C++ Itanium (`_Z…`) and MSVC (`?…`). Pure Rust, no C `__cxa_demangle`. GOT/PLT slot
  names are kept raw so exploit `got()`/`plt()` lookups still match.

## [1.2.0] - 2026-10-18

The binary-exploitation release: enough that a student of a Linux pwn/RE course (such as
the *nightmare* course) can work end to end inside ORRESS.

### Added

- **Linux native debugging**: the `ptrace` back end (breakpoints, stepping, registers,
  stack and memory) is now offered in the Debugger panel on Linux (x86-64) as well as
  Windows, and ELF executables are debuggable targets.
- **Exploit-development toolkit** (`orress-pwn`): tubes that talk to a local process or a
  remote TCP service (`send`/`recvuntil`/…), integer packing (`p8`–`p64`/`u*`), cyclic
  (de Bruijn) patterns and offset recovery, a ROP gadget finder, and payload builders —
  format-string writes (`fmtstr`), sigreturn frames (SROP), `execve("/bin/sh")` shellcode,
  `one_gadget`, `ret2csu` and `ret2dlresolve`.
- **Exploit console**: a pwntools-style scripting tab (Rhai) exposing all of the above
  plus symbol/GOT/PLT lookups and gadget search, run on a worker thread with live output.
- **Gadgets panel**: list and filter the binary's ROP gadgets and copy their addresses.
- **glibc heap visualizer** (`orress-heap` + Heap panel): while a Linux program is stopped,
  show the malloc chunks, the tcache, and (with `main_arena`, auto-located from the unsorted
  bin) the fastbins and unsorted/small/large bins.
- **CLI**: `exploit` (run a pwn script headless), `gadgets`, and `one-gadget` subcommands.

## [1.1.0] - 2026-10-18

### Added

- **Project folders** (Zed-style): **File > New Project…** and **Open Project…** root the app at a
  folder, restored on startup. A lazy folder tree sits at the top of the left panel (the open-files
  and analysis-views list stays below it); click a file to open it, right-click to reveal it in the
  OS, make a notes file, or extract an executable's resources.
- **Resource extractor** (new `orress-resources` crate and **Resources** tab): pull native Win32
  resources (icons rebuilt as `.ico`, bitmaps as `.bmp`, manifest, version info, string tables,
  RCDATA), embedded files found by magic-byte signature (PNG/JPEG/GIF/BMP/WAV/ZIP/GZIP/PDF/…), every
  PE section, and overlay data out of a binary, saved into the project folder.
- **Disassembly and decompiler search** (Ctrl+F, F3 / Shift+F3) and right-click menus in the code
  views exposing every action and view.
- **ORRESS Academy, rewritten for beginners**: a full course that assumes only basic Rust, with a
  glossary, per-step goals, "do this" instructions and explained multiple-choice. Level 3 (dynamic
  analysis) is complete — the debugger, breakpoints and stepping, reading and changing a running
  program, patching, emulation and beating anti-debugging — and the course now spans 560 steps.

### Changed

- The **emulator** now models the common SSE2 subset (movdqu/movdqa, pxor/xorps, pcmpeqb,
  pmovmskb, movd/movq, …), so the fixed-length byte comparisons Rust compiles to SIMD now emulate.
- The **Challenge Workbench** bundles its own `challenge-kit`, vendored into each scaffolded
  challenge so it builds offline with no external repository; a Built-in / External toggle keeps the
  escape hatch for a custom checkout.
- The **debugger** can be started again after a program ends, and the CPU simulator shows r8–r15
  when a program uses them.

## [1.0.0] - 2026-10-14

The first public release of ORRESS — the Okiedocus Rusty Reverse Engineering Software Suite.

### Highlights

- **Prebuilt for Windows (x86-64), Linux (x86-64, ARM64) and macOS (Apple Silicon, Intel).**
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

### Fixed (since the pre-release builds)

- Mach-O executables now report their real entry point: `LC_MAIN` stores a file offset, which
  is now translated to a virtual address (previously "go to entry" and analysis seeding were off
  on every macOS binary).
- Linux position-independent executables are classified as executables, not libraries.
- Mach-O imports are resolved to their stubs and GOT slots (from the indirect symbol table), so
  calls into system libraries are named in macOS binaries.

### Security

- Extensions run in the wasmtime 36 long-term-support series with path confinement, a filtered
  environment and an execution policy; YARA-X is held on a release built on the same patched
  series.
- Dependencies are checked by `cargo deny` (RustSec advisories, licenses, sources) on every push
  and daily.

[Unreleased]: https://github.com/okiedocus/orress/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/okiedocus/orress/releases/tag/v1.2.0
[1.1.0]: https://github.com/okiedocus/orress/releases/tag/v1.1.0
[1.0.0]: https://github.com/okiedocus/orress/releases/tag/v1.0.0
