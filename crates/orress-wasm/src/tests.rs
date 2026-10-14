use super::*;
use wasm_encoder::{
    CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection, GlobalSection,
    GlobalType, ImportSection, Instruction, MemorySection, MemoryType, Module, NameSection,
    TypeSection, ValType,
};

/// The canonical hand-assembled "add two i32s" module (41 bytes), exported as `add`.
const ADDER: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // \0asm, version 1
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type: (i32,i32)->i32
    0x03, 0x02, 0x01, 0x00, // function: 1 func, type 0
    0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd', 0x00, 0x00, // export "add" func 0
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a,
    0x0b, // code: local.get 0/1; i32.add
];

#[test]
fn detects_magic() {
    assert!(is_wasm(ADDER));
    assert!(!is_wasm(b"MZ\x90\x00"));
    assert!(!is_wasm(b"no"));
}

#[test]
fn parses_the_adder() {
    let m = parse(ADDER);
    assert!(m.parse_error.is_none(), "{:?}", m.parse_error);
    assert_eq!(m.version, 1);
    assert!(!m.is_component);
    assert_eq!(m.types.len(), 1);
    assert_eq!(m.types[0].signature(), "(i32, i32) -> i32");
    assert_eq!(m.imported_func_count, 0);
    assert_eq!(m.functions.len(), 1);
    assert_eq!(m.total_funcs(), 1);

    let f = &m.functions[0];
    assert_eq!(f.index, 0);
    assert_eq!(f.type_index, 0);
    assert_eq!(f.locals, 0);
    // local.get, local.get, i32.add, end
    assert_eq!(f.ops, 4);
    // Name comes from the export.
    assert_eq!(f.name.as_deref(), Some("add"));

    assert_eq!(m.exports.len(), 1);
    assert_eq!(m.exports[0].name, "add");
    assert_eq!(m.exports[0].kind, "func");
}

#[test]
fn disassembles_adder_to_wat() {
    let wat = disassemble(ADDER).unwrap();
    assert!(wat.contains("i32.add"), "{wat}");
    assert!(wat.contains("(export \"add\""), "{wat}");
    assert!(wat.contains("local.get"), "{wat}");
}

#[test]
fn disassembles_a_single_function() {
    let lines = disassemble_function(ADDER, 0).unwrap();
    let text: Vec<&str> = lines.iter().map(|(_, t)| t.trim()).collect();
    assert_eq!(text, vec!["local.get 0", "local.get 1", "i32.add", "end"]);
    // Offsets are monotonically increasing and within the file.
    assert!(lines.windows(2).all(|w| w[0].0 < w[1].0));
    assert!(lines.iter().all(|(off, _)| *off < ADDER.len()));
}

#[test]
fn records_parse_error_on_truncation() {
    // Valid header, then a bogus section id/length.
    let bad = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x40];
    let m = parse(&bad);
    assert_eq!(m.version, 1);
    assert!(m.parse_error.is_some());
}

/// Build a richer module with wasm-encoder: an imported function, a memory, a mutable global,
/// two defined functions (one named via the name section), and exports.
fn rich_module() -> Vec<u8> {
    let mut types = TypeSection::new();
    types.ty().function([ValType::I32], [ValType::I32]); // type 0: (i32)->i32
    types.ty().function([], []); // type 1: ()->()

    let mut imports = ImportSection::new();
    imports.import("env", "log", EntityType::Function(0)); // imported func 0

    let mut funcs = FunctionSection::new();
    funcs.function(0); // defined func 1: (i32)->i32
    funcs.function(1); // defined func 2: ()->()

    let mut mems = MemorySection::new();
    mems.memory(MemoryType {
        minimum: 1,
        maximum: Some(16),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });

    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &wasm_encoder::ConstExpr::i32_const(0),
    );

    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, 1);
    exports.export("mem", ExportKind::Memory, 0);

    let mut code = CodeSection::new();
    let mut f1 = Function::new([(1, ValType::I32)]); // one i32 local
    f1.instruction(&Instruction::LocalGet(0));
    f1.instruction(&Instruction::Call(0)); // call imported log
    f1.instruction(&Instruction::LocalGet(0));
    f1.instruction(&Instruction::End);
    code.function(&f1);
    let mut f2 = Function::new([]);
    f2.instruction(&Instruction::End);
    code.function(&f2);

    let mut names = NameSection::new();
    let mut fnames = wasm_encoder::NameMap::new();
    fnames.append(2, "do_nothing"); // name for defined func at absolute index 2
    names.functions(&fnames);

    let mut module = Module::new();
    module.section(&types);
    module.section(&imports);
    module.section(&funcs);
    module.section(&mems);
    module.section(&globals);
    module.section(&exports);
    module.section(&code);
    module.section(&names);
    module.finish()
}

#[test]
fn parses_rich_module() {
    let bytes = rich_module();
    let m = parse(&bytes);
    assert!(m.parse_error.is_none(), "{:?}", m.parse_error);

    assert_eq!(m.imported_func_count, 1);
    assert_eq!(m.functions.len(), 2);
    assert_eq!(m.total_funcs(), 3);

    assert_eq!(m.imports.len(), 1);
    assert_eq!(m.imports[0].module, "env");
    assert_eq!(m.imports[0].name, "log");
    assert_eq!(m.imports[0].kind.label(), "func");

    assert_eq!(m.memories.len(), 1);
    assert_eq!(m.memories[0].min_pages, 1);
    assert_eq!(m.memories[0].max_pages, Some(16));

    assert_eq!(m.globals.len(), 1);
    assert_eq!(m.globals[0].ty, "i32");
    assert!(m.globals[0].mutable);

    // Defined func at absolute index 1 is exported as "run".
    let run = m.functions.iter().find(|f| f.index == 1).unwrap();
    assert_eq!(run.name.as_deref(), Some("run"));
    assert_eq!(run.sig.as_ref().unwrap().signature(), "(i32) -> i32");

    // Defined func at absolute index 2 gets its name from the name section.
    assert!(m.has_names);
    let nothing = m.functions.iter().find(|f| f.index == 2).unwrap();
    assert_eq!(nothing.name.as_deref(), Some("do_nothing"));
}

#[test]
fn disassembles_function_with_import_offset() {
    let bytes = rich_module();
    // Absolute index 1 is the first *defined* function (import occupies index 0).
    let lines = disassemble_function(&bytes, 1).unwrap();
    let text: Vec<&str> = lines.iter().map(|(_, t)| t.trim()).collect();
    assert_eq!(text, vec!["local.get 0", "call 0", "local.get 0", "end"]);
}

#[test]
fn mnemonic_fallback_formats_ops() {
    assert_eq!(debug_to_mnemonic("I32Add"), "i32.add");
    assert_eq!(debug_to_mnemonic("Nop"), "nop");
    assert_eq!(
        debug_to_mnemonic("MemoryGrow { mem: 0 }"),
        "memory.grow (mem: 0)"
    );
    assert_eq!(debug_to_mnemonic("I32TruncF64S"), "i32.trunc_f64_s");
}
