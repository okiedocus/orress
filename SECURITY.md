# Security Policy

ORRESS is built to open hostile files: malware, crackmes and deliberately malformed binaries.
Bugs that let such input escape the analysis are taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (latest minor release) | ✅ security fixes |
| < 1.0 | ❌ |

Fixes land on `main` and ship in the next patch release.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Preferred: GitHub's private reporting — the **Security** tab → **Report a vulnerability**.
- Or email **info@okiedocus.nl** with `ORRESS security` in the subject.

Include the ORRESS version (or commit), your OS, what you did, what happened, and ideally a
reproducer. If the reproducer is a malicious or malformed sample, send it as a password-protected
archive (password `infected`) and say so.

What to expect:

- an acknowledgement within **3 working days**;
- an assessment and a planned fix or mitigation within **14 days**;
- credit in the release notes and the advisory, unless you prefer to stay anonymous.

Please give us a reasonable chance to release a fix before you disclose publicly; we aim to
coordinate disclosure within **90 days**.

## What counts as a vulnerability

In scope — for example:

- **Parsing untrusted files.** A crafted PE, ELF, Mach-O, archive, .NET, Java, DEX, `.pyc`,
  WASM or JavaScript file that causes memory corruption, code execution, writes outside expected
  locations, or an unbounded hang or allocation that static analysis should survive.
- **Extensions.** A WASM extension (including Zed extensions) that escapes its sandbox: reading or
  writing files outside the directories it was granted, reading environment secrets, or running
  commands beyond the extension policy.
- **The sandbox and debugger.** A sample that escapes process-tree containment, survives a kill,
  or runs when the "refuse outside a VM" policy should have stopped it.
- **The MCP server** (`orress-mcp`) and the **collaboration relay** (`orress-relay`): crashes or
  resource exhaustion from remote input, data leaking between rooms, or breaking the end-to-end
  encryption of collaboration sessions.
- **AI integration.** Anything that sends file contents, keys or other data to a model provider
  without the user's explicit opt-in.
- Vulnerable dependencies that are reachable in ORRESS.

Out of scope:

- Malware doing what malware does when you deliberately run it in the **Sandbox** outside a VM
  after turning off the VM check, or on a bridged network. See *Malware analysis safely* in the
  README.
- Results that are simply wrong (a bad decompilation or a missed YARA match) — please file those
  as normal bugs.
- Code you choose to run yourself: the terminal, Run/Debug tasks, scripts, or language servers
  you configured.
- Prompt-injection text inside a binary that changes what an AI model *says*, as long as it
  cannot make ORRESS act or leak data.

## Hardening already in place

- Pure-Rust parsers with size and recursion limits; parsers are tested against truncated and
  hostile input.
- Extensions run in wasmtime with path confinement, a filtered environment and an execution
  policy; runaway guests are interrupted.
- The Sandbox requires a detected VM by default, contains the whole process tree (Windows Job
  Objects, Unix process groups), and offers a fake network.
- AI context is opt-in and previewed before sending; API keys are not stored unless you ask.
- CI runs `cargo deny` (RustSec advisories, licenses, crate sources) on every push and pull
  request and again daily, so a newly published advisory turns the build red. Dependabot keeps
  dependencies and CI actions current, and CI actions are pinned to commit SHAs.
