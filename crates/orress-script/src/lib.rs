//! Scripting for ORRESS: a sandboxed, pure-Rust [Rhai](https://rhai.rs) engine that exposes the
//! analysis of the open binary to a script, so analysts (and third-party extensions) can automate
//! queries and transforms without recompiling — "iterate every function, flag the ones that call
//! `strcpy`", "dump the bytes at this address", "disassemble the entry point", etc.
//!
//! The engine is read-only over an owned snapshot of the analysis and is bounded (operation,
//! recursion, string and array limits) so a runaway or hostile script cannot hang or exhaust the
//! UI. It links no C and uses no `unsafe`. PyO3/CPython embedding is intentionally *not* used — it
//! is a C dependency, which this project avoids; Rhai (and the WASM-component extension host in
//! `orress-ext`) cover scripting and extensibility in pure Rust.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use orress_analysis::{Memory, Program};
use orress_arch::Isa;
use rhai::{Array, Dynamic, Engine};

pub mod exploit;
pub use exploit::{ExploitCtx, run_exploit};

/// An owned, read-only snapshot of the analysis the script queries.
struct Ctx {
    memory: Memory,
    isa: Isa,
    /// (entry, name, block count) per function, in address order.
    funcs: Vec<(u64, String, i64)>,
    names: HashMap<u64, String>,
    strings: Vec<String>,
}

impl Ctx {
    fn new(p: &Program, strings: &[&str]) -> Self {
        let funcs = p
            .functions
            .iter()
            .map(|(&e, f)| {
                let name = p
                    .name(e)
                    .map_or_else(|| format!("sub_{e:x}"), |n| n.text.clone());
                (e, name, f.blocks.len() as i64)
            })
            .collect();
        let names = p.names.iter().map(|(&a, n)| (a, n.text.clone())).collect();
        Self {
            memory: p.memory.clone(),
            isa: p.isa,
            funcs,
            names,
            strings: strings.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn disasm(&self, mut addr: u64, count: usize) -> String {
        let mut out = String::new();
        for _ in 0..count.min(4096) {
            let Some(bytes) = self.memory.read(addr, 16) else {
                break;
            };
            let Some(ins) = orress_arch::decode(self.isa, bytes, addr) else {
                break;
            };
            out.push_str(&format!("{addr:#x}: {}\n", ins.text()));
            if ins.len == 0 {
                break;
            }
            addr += u64::from(ins.len);
        }
        out
    }
}

/// Runs `src` against the analysis of `program` (with the recovered `strings`), returning whatever
/// the script printed followed by its final value. Errors carry the Rhai diagnostic.
pub fn run(src: &str, program: &Program, strings: &[&str]) -> Result<String, String> {
    let ctx = Rc::new(Ctx::new(program, strings));
    let out = Rc::new(RefCell::new(String::new()));
    let mut engine = Engine::new();
    // Bound a runaway or hostile script so it can never hang or exhaust the UI.
    engine.set_max_operations(5_000_000);
    engine.set_max_call_levels(64);
    engine.set_max_string_size(2_000_000);
    engine.set_max_array_size(2_000_000);

    let line = out.clone();
    engine.on_print(move |s| {
        let mut b = line.borrow_mut();
        b.push_str(s);
        b.push('\n');
    });
    let dbg = out.clone();
    engine.on_debug(move |s, _, _| {
        let mut b = dbg.borrow_mut();
        b.push_str(s);
        b.push('\n');
    });

    register(&mut engine, &ctx);

    let result = engine.eval::<Dynamic>(src).map_err(|e| e.to_string())?;
    let mut text = out.borrow().clone();
    if !result.is_unit() {
        text.push_str(&result.to_string());
    }
    Ok(text)
}

/// Registers the read-only analysis API on the engine.
fn register(engine: &mut Engine, ctx: &Rc<Ctx>) {
    let c = ctx.clone();
    engine.register_fn("function_count", move || c.funcs.len() as i64);

    let c = ctx.clone();
    engine.register_fn("functions", move || {
        c.funcs
            .iter()
            .map(|f| Dynamic::from(f.0 as i64))
            .collect::<Array>()
    });

    let c = ctx.clone();
    engine.register_fn("func_name", move |addr: i64| {
        c.funcs
            .iter()
            .find(|f| f.0 == addr as u64)
            .map_or_else(String::new, |f| f.1.clone())
    });

    let c = ctx.clone();
    engine.register_fn("func_blocks", move |addr: i64| {
        c.funcs
            .iter()
            .find(|f| f.0 == addr as u64)
            .map_or(0, |f| f.2)
    });

    let c = ctx.clone();
    engine.register_fn("name", move |addr: i64| {
        c.names.get(&(addr as u64)).cloned().unwrap_or_default()
    });

    let c = ctx.clone();
    engine.register_fn("strings", move || {
        c.strings
            .iter()
            .map(|s| Dynamic::from(s.clone()))
            .collect::<Array>()
    });

    let c = ctx.clone();
    engine.register_fn("string_count", move || c.strings.len() as i64);

    let c = ctx.clone();
    engine.register_fn("read", move |addr: i64, len: i64| {
        let bytes = c
            .memory
            .read(addr as u64, len.max(0) as usize)
            .unwrap_or(&[]);
        bytes
            .iter()
            .map(|&b| Dynamic::from(i64::from(b)))
            .collect::<Array>()
    });

    let c = ctx.clone();
    engine.register_fn("disasm", move |addr: i64, count: i64| {
        c.disasm(addr as u64, count.max(0) as usize)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use orress_loaders::{BinaryInfo, Format, Kind, Perms, Section};
    use std::sync::Arc;

    /// A tiny one-function x86-64 program: `xor eax,eax; ret` at 0x1000.
    fn tiny_program() -> Program {
        let base = 0x1000u64;
        let mut file = vec![0u8; 0x200];
        file.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax,eax ; ret
        let info = BinaryInfo {
            format: Format::Elf,
            kind: Kind::Executable,
            arch: "x86-64".into(),
            bits: Some(64),
            entry: Some(base),
            image_base: 0,
            sections: vec![Section {
                name: ".text".into(),
                offset: 0x200,
                file_size: 3,
                address: base,
                virtual_size: 3,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                entropy: None,
            }],
            ..BinaryInfo::default()
        };
        Program::analyze(&info, Arc::new(file), &[]).expect("analyze")
    }

    #[test]
    fn evaluates_and_captures_output() {
        let p = tiny_program();
        let out = run("print(\"hi\"); 1 + 2", &p, &[]).unwrap();
        assert_eq!(out, "hi\n3");
    }

    #[test]
    fn exposes_functions_and_bytes() {
        let p = tiny_program();
        // One function was discovered at the entry.
        assert_eq!(run("function_count()", &p, &[]).unwrap(), "1");
        // Its first two bytes are the `xor eax,eax` opcode 0x31 0xc0.
        let out = run("let b = read(0x1000, 2); b[0] + \", \" + b[1]", &p, &[]).unwrap();
        assert_eq!(out, "49, 192");
        // And it disassembles.
        let dis = run("disasm(0x1000, 2)", &p, &[]).unwrap();
        assert!(dis.contains("xor") && dis.contains("ret"), "disasm: {dis}");
    }

    #[test]
    fn exposes_strings() {
        let p = tiny_program();
        let out = run(
            "strings()[0] + \"/\" + string_count()",
            &p,
            &["hello", "world"],
        )
        .unwrap();
        assert_eq!(out, "hello/2");
    }

    #[test]
    fn a_runaway_loop_is_bounded_not_hung() {
        let p = tiny_program();
        // An infinite loop must terminate with an error (operation budget), never hang.
        let err = run("let i = 0; loop { i += 1; }", &p, &[]).unwrap_err();
        assert!(
            err.to_lowercase().contains("operation"),
            "expected a budget error, got: {err}"
        );
    }
}
