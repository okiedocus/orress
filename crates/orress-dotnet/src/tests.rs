use super::*;

/// A controlled assembly compiled by the .NET Framework C# compiler (`Add-Type -OutputAssembly`).
const DLL: &[u8] = include_bytes!("../tests/fixtures/Check.dll");

fn parsed() -> DotNet {
    parse(DLL).expect("parse Check.dll")
}

#[test]
fn detects_dotnet() {
    assert!(is_dotnet(DLL));
    assert!(!is_dotnet(b"MZ\x90\x00 not really a PE"));
    assert!(!is_dotnet(&[0u8; 4]));
}

#[test]
fn reads_names_and_runtime() {
    let a = parsed();
    assert_eq!(a.runtime_version, "v4.0.30319");
    assert_eq!(a.module_name, "Check.dll");
    assert_eq!(a.assembly_name.as_deref(), Some("Check"));
}

#[test]
fn recovers_types_and_methods() {
    let a = parsed();
    // The special <Module> type plus our Check class.
    assert!(a.types.iter().any(|t| t.name == "<Module>"));
    let check = a
        .types
        .iter()
        .find(|t| t.name == "Check")
        .expect("Check type");
    assert_eq!(check.full_name(), "Check");
    for m in ["Verify", "Main", ".ctor"] {
        assert!(
            check.methods.iter().any(|x| x.name == m),
            "missing method {m} in {:?}",
            check.methods
        );
    }
}

#[test]
fn decodes_method_signatures() {
    let a = parsed();
    let check = a.types.iter().find(|t| t.name == "Check").unwrap();
    let sig = |name: &str| {
        check
            .methods
            .iter()
            .find(|m| m.name == name)
            .unwrap()
            .signature
            .as_str()
    };
    assert_eq!(sig("Verify"), "(string) : bool");
    assert_eq!(sig("Main"), "() : void");
    assert_eq!(sig(".ctor"), "() : void");
}

#[test]
fn disassembles_il() {
    let a = parsed();
    let check = a.types.iter().find(|t| t.name == "Check").unwrap();

    // Main() { Console.WriteLine("enter password:"); } — a clean, predictable body.
    let main = check.methods.iter().find(|m| m.name == "Main").unwrap();
    let il = a.disassemble(DLL, main.rva).unwrap();
    let ops: Vec<&str> = il.iter().map(|i| i.opcode).collect();
    assert!(ops.contains(&"ldstr"), "{ops:?}");
    assert!(ops.contains(&"call"), "{ops:?}");
    assert!(ops.last() == Some(&"ret"), "{ops:?}");

    // ldstr resolves the literal; call resolves the method name.
    let ldstr = il.iter().find(|i| i.opcode == "ldstr").unwrap();
    assert_eq!(ldstr.operand, "\"enter password:\"");
    let call = il.iter().find(|i| i.opcode == "call").unwrap();
    assert!(
        call.operand.contains("WriteLine"),
        "call operand was {:?}",
        call.operand
    );

    // Verify() has a real loop, so it must contain at least one branch with a target.
    let verify = check.methods.iter().find(|m| m.name == "Verify").unwrap();
    let vil = a.disassemble(DLL, verify.rva).unwrap();
    assert!(vil.iter().any(|i| i.branch_target.is_some()));
    assert!(vil.iter().any(|i| i.is_branch_target));
}

#[test]
fn recovers_user_strings() {
    let a = parsed();
    // The one string literal in the IL — where real malware hides its C2/commands.
    assert_eq!(a.user_strings, ["enter password:"]);
}

#[test]
fn reports_table_rows() {
    let a = parsed();
    let find = |n: &str| {
        a.table_rows
            .iter()
            .find(|(name, _)| *name == n)
            .map(|(_, c)| *c)
    };
    assert_eq!(find("TypeDef"), Some(2));
    assert_eq!(find("MethodDef"), Some(3));
    assert_eq!(find("Assembly"), Some(1));
    assert_eq!(find("AssemblyRef"), Some(1)); // references mscorlib
}

#[test]
fn rejects_non_dotnet() {
    assert!(parse(b"not a PE at all").is_err());
}

/// A synthetic `#~` stream: header, row counts for the tables in `valid`, then `body`.
fn tilde(heapsizes: u8, valid: u64, rows: &[u32], extra: &[u8], body: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 6];
    d.push(heapsizes);
    d.push(1);
    d.extend(valid.to_le_bytes());
    d.extend(0u64.to_le_bytes()); // sorted
    for r in rows {
        d.extend(r.to_le_bytes());
    }
    d.extend(extra);
    d.extend(body);
    d
}

#[test]
fn heapsizes_extra_data_is_skipped() {
    // Module row: Generation u16, Name str(2), Mvid/EncId/EncBaseId guid(2 each) = 10 bytes.
    let row = [0, 0, 0x2a, 0, 1, 0, 0, 0, 0, 0];
    let d = tilde(0x40, 1, &[1], &[0xEE; 4], &row);
    let t = MdTables::parse(&d, 0, d.len()).unwrap();
    assert_eq!(t.base[0], 24 + 4 + 4);
    assert_eq!(t.cell(&d, 0x00, 1, 1), Some(0x2a));
}

#[test]
fn hostile_row_counts_are_rejected() {
    // Four billion TypeDef rows in a 40-byte stream: must be an error, not a 4 GB allocation.
    let d = tilde(0, 1 << 2, &[0xFFFF_FFFF], &[], &[0; 16]);
    assert!(MdTables::parse(&d, 0, d.len()).is_err());

    // Same thing through the full parser: patch the fixture's TypeDef row count.
    let mut dll = DLL.to_vec();
    let (md, _) = metadata_offset(&dll).unwrap();
    let ver_len = u32a(&dll, md + 12).unwrap() as usize;
    let mut p = md + 16 + ((ver_len + 3) & !3);
    let nstreams = u16a(&dll, p + 2).unwrap();
    p += 4;
    let mut tilde_off = None;
    for _ in 0..nstreams {
        let off = u32a(&dll, p).unwrap() as usize;
        p += 8;
        let start = p;
        while dll[p] != 0 {
            p += 1;
        }
        if &dll[start..p] == b"#~" {
            tilde_off = Some(md + off);
        }
        p = (p + 1 + 3) & !3;
    }
    let off = tilde_off.unwrap();
    let valid = u64::from_le_bytes(dll[off + 8..off + 16].try_into().unwrap());
    let idx = (valid & 0b11).count_ones() as usize; // row-count slot of table 0x02
    dll[off + 24 + idx * 4..off + 28 + idx * 4].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert!(parse(&dll).is_err());
}

#[test]
fn rva_mapping_does_not_overflow() {
    let sections = [(0xFFFF_F000, 0x2000, 0xFFFF_FFF0)];
    assert_eq!(
        rva_to_off(&sections, 0xFFFF_FFF0).map(|o| o as u64),
        Some(0xFFFF_FFF0u64 + 0xFF0)
    );
    assert_eq!(rva_to_off(&sections, 0x10), None);
}
