# Writing Academy lessons

The Academy is a **complete course**. Its learner knows **basic Rust** (variables, functions,
`if`/`loop`/`match`, `Vec`, `String`, `&str`, structs, `cargo run`) and **nothing else**: not
hexadecimal, not what a register is, not what a debugger does, not how an `.exe` is built.
Everything beyond basic Rust is taught here, in order, before it is used.

Lessons live in `academy/lessons/*.toml`, the glossary in `academy/glossary/*.toml`. Both are
found automatically (see `crates/orress-academy/build.rs`). Run
`cargo test -p orress-academy` after every change: it validates every lesson and glossary file.

## The rules

1. **Never use a word before it is taught.** If a step says "register", either a previous lesson
   taught it, or this step explains it in a sentence and it is in the glossary. When unsure,
   explain again: repetition is cheaper than confusion.
2. **Explain first, then ask.** A step that asks something is preceded by text that teaches
   everything needed to answer it. No step tests knowledge a lesson did not give.
3. **Every task says exactly what to do.** A step whose `check` is anything other than
   `continue` or `choice` must have `instructions`: a numbered list of concrete actions that
   name the exact menu, button, panel, view, key or field. ("In the **Project** panel on the
   left, click **Strings**.", not "Open the strings.") The tests enforce that the list exists;
   you are responsible for it being precise and *true* (check the UI code, see below).
4. **Explain the why.** After each task, `success` says what the learner just saw and why it
   matters. Wrong multiple-choice answers get an `explain` entry saying why they are wrong.
5. **Rust is the anchor.** Show the Rust code first, then what it becomes. The learner can
   read Rust; use it to explain everything else.
6. **Small steps.** One idea per step. A step's `text` is roughly 120-350 words. A lesson has
   about 6-14 steps. Split a lesson that grows past that.
7. **Worked examples before exercises.** Walk through one example completely, then let the
   learner do a similar one.
8. **Hints go from a nudge to almost the answer**, at most three. The last hint should make the
   step solvable for anyone who read the text.
9. **Plain language.** Short sentences. Active voice. Address the learner as "you". No
   "simply", "just", "obviously", "trivially". Not everyone's first language is English.
10. **Characters:** the UI font cannot show `→ ← ✔ ✓ ● ○` (a test rejects them). Write `->`.

## Lesson format

```toml
id = "l1-crackme1"          # stable: progress is saved by id; do not rename existing ids
level = 1                   # 0-7, see LEVELS in src/lesson.rs
order = 11                  # sort order inside the level (unique within the course)
title = "Your first crackme"
summary = "One line shown in the overview."
goals = [                   # "In this lesson you will learn to ..." (3-5 items)
    "find readable text inside a program with the Strings view",
    "jump from a string to the code that uses it",
]
badge = "First Crack"       # optional
reveal_source = "crackme01" # optional: show the crackme's source after the lesson

[[steps]]
title = "Open the strings"
goal = "See every piece of readable text inside the program."   # one line, optional
text = '''
Markdown teaching text. Use **bold** for UI names and `code` for code, values and keys.
'''
deep_dive = '''
Optional: extra depth for the curious, folded under "Learn more". Never needed to continue.
'''
instructions = [
    "In the **Project** panel on the left, click **Strings**.",
    "In the filter box at the top of the Strings view, type `pass`.",
]
spotlight = "tree.Strings"  # optional; must be a known target (see lesson.rs tests)
check = { kind = "view", view = "Strings" }
hints = ["...", "...", "..."]
success = '''Shown once the step is done: what you saw, and why it matters.'''
```

### Checks (`check = { kind = ... }`)

| kind | completes when | fields |
|---|---|---|
| `continue` (default) | the learner presses Next | |
| `choice` | the right option is picked | `options`, `correct` (0-based), `explain` (one per option, recommended) |
| `answer` | the typed answer matches | `answers`, `number` (42 = 0x2a = 0b101010), `case_sensitive` |
| `secret` | typed text has this SHA-256 | `sha256` (hides passwords from people reading the file) |
| `action` | a command runs | `id`, e.g. `view::Decompiler` (ids: `crates/orress/src/actions.rs`) |
| `view` | a file view gets focus | `view`: Disassembly, Graph, Functions, Info, Hex, Sections, Imports, Strings |
| `open_crackme` | a practice program is opened | `name`: crackme01 ... crackme08 (the step shows an Open button) |
| `sim` | the CPU simulator program ends with these registers | `expect = [["rax", 15]]`, `requires = ["add"]`; needs `solution` (+ usually `sim_code`) |
| `cursor_in_main` | the cursor is inside the detected `main` | |
| `renamed` | the learner renamed something | |
| `commented` | the learner added a comment | |

Prefer checks that prove the learner **did and understood** something: an `answer` whose value
they can only get by actually looking (an address, a constant, a byte count, a password) teaches
more than "open view X". Verify such answers against the real crackme (see below).

Widgets (`widget = ...`): `number_converter`, `ascii_table`.

## Glossary format

One file per level: `academy/glossary/<level>-<name>.toml`. Define a term in the **earliest
level that uses it**; later levels reuse it. Every term and alias must be unique across all
files (a test checks), and every `see` entry must exist.

```toml
[[term]]
term = "register"
aliases = ["registers"]    # spellings in lesson text that should match (plural, short forms)
short = "A tiny, very fast storage slot inside the CPU that instructions work on."
text = '''
Longer Markdown explanation for a beginner, ideally with a Rust comparison and an example.
'''
see = ["rax", "CPU"]
```

Each step automatically lists the glossary terms its text mentions ("Words in this step"), so
every technical word a lesson uses should be in the glossary. Avoid terms that are also common
English words in other senses, or give them a specific spelling (`"call (instruction)"` would
never match; prefer `call instruction` and use that phrase in the text).

## Verifying against the real app

Never guess what the UI looks like or what a crackme contains.

- **UI**: views are in `crates/orress-views/src/`, the workspace and project tree in
  `crates/orress-workspace/src/`, menus and commands in `crates/orress/src/app.rs` and
  `crates/orress/src/actions.rs`, default key bindings in `crates/orress-actions/src/keymap.rs`
  and `assets/keymaps/` (if present). Name buttons and menus exactly as they are labelled.
- **Crackmes**: sources in `academy/crackmes/*.rs`, binaries in `academy/crackmes/bin/`.
  Check what ORRESS shows with the CLI, e.g.
  `target/debug/orress-cli.exe strings academy/crackmes/bin/crackme01.exe`,
  `... disasm academy/crackmes/bin/crackme02.exe main`,
  `... decompile academy/crackmes/bin/crackme03.exe <name or 0xaddress>`,
  `... funcs`, `... info`, `... vm`. Run `orress-cli.exe --help` for the rest.

## Adding a practice program

Write `academy/crackmes/crackmeNN.rs` (a small Rust program: start with a `//!` comment that says
which lesson uses it and how it is solved), then run
`powershell -ExecutionPolicy Bypass -File academy\crackmes\build.ps1`. It builds only crackmes that
have no `.exe` yet; `-Only crackmeNN` rebuilds one after its source changed (that changes the file
hash, so learners lose names they saved for it, and addresses quoted in lessons must be rechecked).
Every source with a built
`bin/crackmeNN.exe` is embedded automatically and can be used with `open_crackme`. Keep the
build flags from `build.ps1` (stripped, opt-level=1) so lessons match what learners see.
Programs must be harmless: no network, no file changes outside their own folder, nothing that
persists.

## Testing

`cargo test -p orress-academy` validates everything. The test `every_lesson_file_is_valid`
lists all broken files at once (`file name: lesson id step N: problem`), so you can see your own
files' problems even while other files are being edited.
