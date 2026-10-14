//! Wraps a guest core wasm module into a component and writes it. Defaults to the demo guest;
//! pass `<core.wasm> <out.wasm>` to encode another (e.g. the Zed guest). See `../README.md`.
//!
//! A `wasm32-unknown-unknown` core is wrapped directly. A `wasm32-wasip1` core (one that imports
//! the `wasi_snapshot_preview1` module) additionally has the WASI preview1 **reactor** adapter
//! spliced in, so the result is a component importing the componentized `wasi:*` interfaces — the
//! shape real Zed extensions ship in.

use wasi_preview1_component_adapter_provider::{
    WASI_SNAPSHOT_PREVIEW1_ADAPTER_NAME, WASI_SNAPSHOT_PREVIEW1_REACTOR_ADAPTER,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (input, output) = match args.as_slice() {
        [] => (
            "../guest/target/wasm32-unknown-unknown/release/orress_ext_demo_guest.wasm".to_string(),
            "../demo-guest.wasm".to_string(),
        ),
        [i, o] => (i.clone(), o.clone()),
        _ => return Err("usage: encode [<core.wasm> <out.wasm>]".into()),
    };
    let core = std::fs::read(&input)?;
    let mut encoder = wit_component::ComponentEncoder::default().validate(true).module(&core)?;
    // A WASI preview1 core imports the `wasi_snapshot_preview1` module; give it the reactor adapter.
    let targets_wasi = core
        .windows(WASI_SNAPSHOT_PREVIEW1_ADAPTER_NAME.len())
        .any(|w| w == WASI_SNAPSHOT_PREVIEW1_ADAPTER_NAME.as_bytes());
    if targets_wasi {
        encoder = encoder
            .adapter(WASI_SNAPSHOT_PREVIEW1_ADAPTER_NAME, WASI_SNAPSHOT_PREVIEW1_REACTOR_ADAPTER)?;
    }
    let component = encoder.encode()?;
    std::fs::write(&output, &component)?;
    println!(
        "wrote {output} ({} bytes{})",
        component.len(),
        if targets_wasi { ", WASI preview1 adapter spliced in" } else { "" }
    );
    Ok(())
}
