# Extension host test fixtures

`demo-guest.wasm` is a tiny WASM **component** implementing the `orress:extension` WIT world
(`../wit/world.wit`). The host test `runs_a_real_guest_extension_over_the_wit_world` loads it to
verify the component host end to end: host imports, exported functions, records and strings.

It is checked in (≈22 KB) so the test needs no WASM toolchain. To regenerate it after changing the
WIT world or the guest, with the stable Rust toolchain plus the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown`) — no external binaries, cargo only:

```sh
# 1. Build the guest to a core module (wit-bindgen embeds the component type).
cd guest && cargo build --release --target wasm32-unknown-unknown && cd ..
# 2. Wrap the core module into a component and write ../demo-guest.wasm.
cd encode && cargo run --release && cd ..
```

`guest/` and `encode/` are each their own detached workspace, so the main ORRESS build ignores
them; their `target/` directories are git-ignored.

## Zed extension fixture

`zed-guest.wasm` is a *real* Zed extension built with the `zed_extension_api` crate
(`zed-guest/`), used by `runs_a_real_zed_extension_and_resolves_its_language_server` to verify the
clean-room Zed host. Regenerate it with:

```sh
cd zed-guest && cargo build --release --target wasm32-unknown-unknown && cd ..
cd encode && cargo run --release -- \
  ../zed-guest/target/wasm32-unknown-unknown/release/orress_zed_demo_guest.wasm \
  ../zed-guest.wasm && cd ..
```

## Older Zed API version fixture

`zed-guest-old.wasm` is a Zed extension built against the **pre-`dap`** `since_v0.5.0` WIT world
(the last `zed:extension` world before `since_v0.6.0` added the `dap` interface). It is hand-written
with `wit-bindgen` against that vendored WIT (`zed-guest-old/wit/`) rather than `zed_extension_api`,
so it compiles for `wasm32-unknown-unknown` without a WASI runtime — isolating the one property
under test in `runs_an_older_api_version_zed_extension`: that the host (whose linker exposes the
newer `since_v0.6.0` import surface) still instantiates and drives a component that neither imports
`dap` nor exports the five `dap-*` functions. It also implements the context-server and
slash-command exports with real values, so the host's wiring for those
(`runs_context_server_and_slash_command_exports`) is tested against it too. Regenerate it with:

```sh
cd zed-guest-old && cargo build --release --target wasm32-unknown-unknown && cd ..
cd encode && cargo run --release -- \
  ../zed-guest-old/target/wasm32-unknown-unknown/release/orress_zed_old_guest.wasm \
  ../zed-guest-old.wasm && cd ..
```

## WASI extension fixture

`zed-guest-wasi.wasm` is the **same** real extension as `zed-guest/`, but built for
**`wasm32-wasip1`** — the target Zed actually ships extensions in. Its `init-extension` touches
`std::env`/the C runtime cwd, so it only runs if the host provides a WASI runtime (`wasmtime-wasi`)
with `$PWD` set. The test `runs_a_wasi_zed_extension` proves exactly that. The `encode` tool
auto-detects a WASI preview1 core (one importing `wasi_snapshot_preview1`) and splices in the WASI
preview1 **reactor** adapter (from the `wasi-preview1-component-adapter-provider` crate, pinned to
the wasmtime version), producing a component that imports the componentized `wasi:*` interfaces.
Needs the target (`rustup target add wasm32-wasip1`):

```sh
cd zed-guest && cargo build --release --target wasm32-wasip1 && cd ..
cd encode && cargo run --release -- \
  ../zed-guest/target/wasm32-wasip1/release/orress_zed_demo_guest.wasm \
  ../zed-guest-wasi.wasm && cd ..
```
