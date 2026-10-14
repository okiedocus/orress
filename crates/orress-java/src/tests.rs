use super::*;

/// A real class compiled by `javac 17` from `tests/fixtures/Check.java`.
const CLASS: &[u8] = include_bytes!("../tests/fixtures/Check.class");

fn parsed() -> ClassFile {
    parse(CLASS).expect("parse Check.class")
}

fn method<'a>(cf: &'a ClassFile, name: &str) -> &'a Member {
    cf.methods.iter().find(|m| m.name == name).expect("method")
}

#[test]
fn detects_and_parses_header() {
    assert!(is_class(CLASS));
    assert!(!is_class(b"MZ\x90\x00"));

    let cf = parsed();
    assert_eq!(cf.major, 61);
    assert_eq!(cf.minor, 0);
    assert_eq!(cf.java_version(), "Java 17");
    assert_eq!(cf.this_class, "Check");
    assert_eq!(cf.super_class.as_deref(), Some("java/lang/Object"));
    assert_eq!(cf.source_file.as_deref(), Some("Check.java"));
}

#[test]
fn recovers_fields_with_constant_value() {
    let cf = parsed();
    let names: Vec<&str> = cf.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["SECRET", "total"]);

    let secret = cf.fields.iter().find(|f| f.name == "SECRET").unwrap();
    assert_eq!(secret.descriptor, "Ljava/lang/String;");
    assert_eq!(access_flag_names(secret.access), ["static", "final"]);
    // The compile-time constant value is recovered — often where a flag hides.
    let cv = secret.constant_value.expect("ConstantValue");
    assert_eq!(cf.cp.resolve(cv), "\"flag{jvm_r3v3rs3}\"");

    let total = cf.fields.iter().find(|f| f.name == "total").unwrap();
    assert_eq!(total.descriptor, "I");
    assert!(total.constant_value.is_none());
}

#[test]
fn recovers_methods_and_descriptors() {
    let cf = parsed();
    let sigs: Vec<(&str, &str)> = cf
        .methods
        .iter()
        .map(|m| (m.name.as_str(), m.descriptor.as_str()))
        .collect();
    assert_eq!(
        sigs,
        [
            ("<init>", "()V"),
            ("check", "(Ljava/lang/String;)Z"),
            ("main", "([Ljava/lang/String;)V"),
        ]
    );
    assert_eq!(
        access_flag_names(method(&cf, "main").access),
        ["public", "static"]
    );
    assert!(method(&cf, "check").code.is_some());
}

#[test]
fn disassembles_check_like_javap() {
    let cf = parsed();
    let code = method(&cf, "check").code.as_ref().unwrap();
    assert_eq!(code.max_locals, 4);
    let ins = disassemble(code, &cf.cp);

    let got: Vec<(usize, &str)> = ins.iter().map(|i| (i.offset, i.mnemonic)).collect();
    let expect: Vec<(usize, &str)> = vec![
        (0, "iconst_0"),
        (1, "istore_2"),
        (2, "iconst_0"),
        (3, "istore_3"),
        (4, "iload_3"),
        (5, "aload_1"),
        (6, "invokevirtual"),
        (9, "if_icmpge"),
        (12, "iload_2"),
        (13, "aload_1"),
        (14, "iload_3"),
        (15, "invokevirtual"),
        (18, "iload_3"),
        (19, "bipush"),
        (21, "iadd"),
        (22, "ixor"),
        (23, "iadd"),
        (24, "istore_2"),
        (25, "iinc"),
        (28, "goto"),
        (31, "iload_2"),
        (32, "sipush"),
        (35, "if_icmpne"),
        (38, "iconst_1"),
        (39, "goto"),
        (42, "iconst_0"),
        (43, "ireturn"),
    ];
    assert_eq!(got, expect);
}

#[test]
fn resolves_operands_and_branch_targets() {
    let cf = parsed();
    let code = method(&cf, "check").code.as_ref().unwrap();
    let ins = disassemble(code, &cf.cp);
    let at = |off: usize| ins.iter().find(|i| i.offset == off).unwrap();

    // Constant-pool references resolve to Class.name:descriptor.
    assert!(at(6).operands.contains("java/lang/String.length:()I"));
    assert!(at(15).operands.contains("java/lang/String.charAt:(I)C"));
    // Immediate operands.
    assert_eq!(at(19).operands, "7"); // bipush 7
    assert_eq!(at(32).operands, "1337"); // sipush 1337
    assert_eq!(at(25).operands, "3, 1"); // iinc 3, 1

    // Branch targets are absolute (relative offset + instruction address).
    assert_eq!(at(9).branch_target, Some(31)); // if_icmpge 31
    assert_eq!(at(28).branch_target, Some(4)); // goto 4 (loop back)
    assert_eq!(at(35).branch_target, Some(42)); // if_icmpne 42
    assert_eq!(at(39).branch_target, Some(43)); // goto 43

    // Landing sites are flagged.
    assert!(at(4).is_branch_target);
    assert!(at(31).is_branch_target);
    assert!(at(42).is_branch_target);
    assert!(at(43).is_branch_target);
    assert!(!at(0).is_branch_target);
}

#[test]
fn main_loads_the_string_literal() {
    let cf = parsed();
    let code = method(&cf, "main").code.as_ref().unwrap();
    let ins = disassemble(code, &cf.cp);
    // println("enter password:") → a ldc of the String constant.
    assert!(
        ins.iter()
            .any(|i| i.mnemonic == "ldc" && i.operands.contains("enter password:"))
    );
    assert!(ins.iter().any(
        |i| i.mnemonic == "invokevirtual" && i.operands.contains("java/io/PrintStream.println")
    ));
}

#[test]
fn rejects_non_class() {
    assert!(parse(b"not a class file").is_err());
}
