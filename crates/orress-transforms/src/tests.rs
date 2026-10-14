use crate::*;

fn run(recipe: &str, input: &[u8]) -> Vec<u8> {
    Recipe::parse(recipe)
        .unwrap_or_else(|e| panic!("{recipe}: {e}"))
        .output(input)
        .unwrap_or_else(|e| panic!("{recipe}: {e}"))
}

#[test]
fn encodings_round_trip() {
    let data: Vec<u8> = (0..=255).collect();
    for (enc, dec) in [
        ("to_hex", "from_hex"),
        ("to_base64", "from_base64"),
        ("to_base32", "from_base32"),
        ("to_base58", "from_base58"),
        ("to_url", "from_url"),
        ("to_escaped", "from_escaped"),
    ] {
        assert_eq!(run(&format!("{enc} | {dec}"), &data), data, "{enc}");
    }
    assert_eq!(run("to_base58", b"\0\0abc"), b"11ZiCa");
    assert_eq!(run("to_base64", b"hello"), b"aGVsbG8=");
    assert_eq!(
        run("from_base64", b"aGVsbG8"),
        b"hello",
        "missing padding is fine"
    );
    assert_eq!(run("to_base32", b"hi"), b"NBUQ====");
    assert_eq!(run("from_hex", b"\\x48\\x69, 0x21"), b"Hi!");
    assert_eq!(
        run("utf8_to_utf16le | utf16le_to_utf8", "héllo".as_bytes()),
        "héllo".as_bytes()
    );
}

#[test]
fn custom_base64_alphabet() {
    // A shuffled alphabet, as CTF challenges and malware like to use.
    let alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/";
    let encoded = run(&format!("to_base64 alphabet={alphabet}"), b"secret");
    assert_ne!(encoded, b"c2VjcmV0");
    assert_eq!(
        run(&format!("from_base64 alphabet={alphabet}"), &encoded),
        b"secret"
    );
    assert!(
        Recipe::parse("from_base64 alphabet=abc")
            .unwrap()
            .output(b"x")
            .is_err()
    );
}

#[test]
fn url_and_escape_decoding_never_panic_on_separators() {
    // `from_hex` strips separators, so "% ," used to become an empty Vec and
    // the decoders indexed `[0]` → panic. These must be clean errors.
    for (op, input) in [
        ("from_url", &b"100% , done"[..]),
        ("from_url", b"%0x"),
        ("from_url", b"%,,"),
        ("from_escaped", b"\\x0x"),
        ("from_escaped", b"\\x ,"),
        ("from_escaped", b"\\x\\x"),
    ] {
        let recipe = Recipe::parse(op).unwrap();
        assert!(recipe.output(input).is_err(), "{op} {input:?}");
    }
    assert_eq!(run("from_url", b"a%41+b"), b"aA b");
    assert_eq!(run("from_escaped", b"\\x41\\x4a"), b"AJ");
    // magic() on prose containing '%' must not panic either.
    let _ = magic(b"100% , done and 50%x complete", 2);
}

#[test]
fn base64_padding_resets_alignment() {
    assert_eq!(run("from_base64", b"QQ==QQ=="), b"AA");
    assert_eq!(run("from_base64", b"aGk=aGk="), b"hihi");
    // A custom alphabet that uses '=' as a digit must decode it as a digit.
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=/";
    let encoded = crate::codec::to_base64(b"\xfb\xff", alphabet, false).unwrap();
    assert!(encoded.contains(&b'='));
    assert_eq!(
        crate::codec::from_base64(&encoded, alphabet).unwrap(),
        b"\xfb\xff"
    );
}

#[test]
fn xor_and_friends() {
    assert_eq!(run("xor key=0x01", b"AB"), b"@C");
    assert_eq!(run("xor key=key | xor key=key", b"secret"), b"secret");
    assert_eq!(run("xor key=hex:00ff", &[1, 1]), vec![1, 0xfe]);
    assert_eq!(run("rol bits=1 | ror bits=1", b"z"), b"z");
    assert_eq!(run("add value=1 | sub value=1", b"z"), b"z");
    assert_eq!(run("not", &[0x0f]), vec![0xf0]);
    assert_eq!(run("swap_endian width=4", &[1, 2, 3, 4]), vec![4, 3, 2, 1]);
    assert_eq!(run("rot13 | rot13", b"Hello"), b"Hello");
    assert_eq!(run("caesar shift=1", b"abz"), b"bca");
    // Known-plaintext key recovery.
    let encrypted = run("xor key=K3y", b"flag{known_plaintext}");
    let out = run("xor_known known=flag{", &encrypted);
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("key: 0x4b3379"), "{text}");
    assert!(text.contains("flag{known_plaintext}"));
}

#[test]
fn crypto_known_answers() {
    // RC4 test vector: key "Key", plaintext "Plaintext".
    assert_eq!(
        run("rc4 key=Key | to_hex separator=", b"Plaintext"),
        b"bbf316e8d940af0ad3"
    );
    // AES-128 ECB, FIPS-197 appendix C.1.
    let ct = run(
        "aes_encrypt key=0x000102030405060708090a0b0c0d0e0f mode=ECB padding=none | to_hex separator=",
        &codec::from_hex(b"00112233445566778899aabbccddeeff").unwrap(),
    );
    assert_eq!(ct, b"69c4e0d86a7b0430d8cdb78070b4c55a");
    // CBC and CTR round trips with padding.
    for mode in ["CBC", "CTR"] {
        let key = "0x2b7e151628aed2a6abf7158809cf4f3c";
        let iv = "0x000102030405060708090a0b0c0d0e0f";
        let r = format!(
            "aes_encrypt key={key} iv={iv} mode={mode} | aes_decrypt key={key} iv={iv} mode={mode}"
        );
        assert_eq!(
            run(&r, b"a secret message!"),
            b"a secret message!",
            "{mode}"
        );
    }
    // Wrong key gives a clear padding error.
    let enc = run(
        "aes_encrypt key=0x00000000000000000000000000000000",
        b"hello",
    );
    assert!(
        Recipe::parse("aes_decrypt key=0x11111111111111111111111111111111")
            .unwrap()
            .output(&enc)
            .unwrap_err()
            .contains("padding")
    );
}

#[test]
fn tea_and_xtea_decrypt_known_vectors() {
    // XTEA, 32 rounds, all-zero key and block (big-endian words):
    // ciphertext DEE9D4D8F7131ED9 decrypts to zeros.
    let out = run(
        "xtea_decrypt key=0x00000000000000000000000000000000 endian=big",
        &codec::from_hex(b"dee9d4d8f7131ed9").unwrap(),
    );
    assert_eq!(out, vec![0; 8]);
    // TEA, zero key and block: ciphertext 41EA3A0A94BAA940 (big-endian words).
    let out = run(
        "tea_decrypt key=0x00000000000000000000000000000000 endian=big",
        &codec::from_hex(b"41ea3a0a94baa940").unwrap(),
    );
    assert_eq!(out, vec![0; 8]);
}

#[test]
fn compression_and_hashes() {
    let text = b"compress me compress me compress me".repeat(10);
    assert_eq!(run("zlib_deflate | zlib_inflate", &text), text);
    // gzip of "hi\n" (from the gzip tool).
    let gz = codec::from_hex(b"1f8b08000000000000ffcbc8e40200d78d2e7a03000000").unwrap();
    assert_eq!(run("gzip_decompress", &gz), b"hi\n");
    assert_eq!(run("md5", b"abc"), b"900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(run("crc32", b"123456789"), b"cbf43926");
    assert_eq!(run("fnv1a32", b"a"), b"e40c292c");
    // ROR13 of "LoadLibraryA" is the well-known shellcode constant 0xec0e4e8e.
    assert_eq!(run("ror13", b"LoadLibraryA"), b"ec0e4e8e");
}

#[test]
fn data_ops() {
    assert_eq!(run("slice offset=2 length=3", b"abcdefg"), b"cde");
    assert_eq!(run("slice offset=4", b"abcdefg"), b"efg");
    assert_eq!(
        run("strings min=4", b"\x00\x01hello\x00world"),
        b"hello\nworld"
    );
    assert!(
        String::from_utf8(run("entropy", b"aaaa"))
            .unwrap()
            .starts_with("0.000")
    );
}

#[test]
fn recipe_text_round_trips() {
    let r = Recipe::parse("from_base64 | xor key=0x41 | caesar shift=5 | to_hex separator=\" \"")
        .unwrap();
    assert_eq!(r.0.len(), 4);
    let again = Recipe::parse(&r.to_string()).unwrap();
    assert_eq!(again, r);
    assert!(
        Recipe::parse("nope")
            .unwrap_err()
            .contains("unknown operation")
    );
    assert!(
        Recipe::parse("xor colour=red")
            .unwrap_err()
            .contains("has no parameter")
    );
    let outputs = Recipe::parse("from_hex | from_base64").unwrap().run(b"zz");
    assert_eq!(outputs.len(), 1, "stops at the first error");
    assert!(outputs[0].is_err());
}

#[test]
fn every_op_is_documented_and_runs_on_empty_input() {
    for op in ops() {
        assert!(!op.explain.is_empty(), "{}", op.id);
        // Must not panic on empty or odd input; errors are fine.
        let _ = Step::new(op.id).apply(b"");
        let _ = Step::new(op.id).apply(&[0xff; 7]);
    }
}

#[test]
fn magic_finds_layered_encodings() {
    // base64(xor(flag, 0x5a))
    let encrypted = run("xor key=0x5a | to_base64", b"flag{magic_decoding_works}");
    let suggestions = magic(&encrypted, 3);
    let best = &suggestions[0];
    assert_eq!(
        String::from_utf8_lossy(&best.output),
        "flag{magic_decoding_works}"
    );
    assert_eq!(best.recipe.to_string(), "from_base64 | xor key=0x5a");

    // hex(zlib(text))
    let compressed = run(
        "zlib_deflate | to_hex",
        b"the password is swordfish and the user is admin",
    );
    let s = magic(&compressed, 3);
    assert_eq!(
        s[0].output,
        b"the password is swordfish and the user is admin"
    );

    // Already readable text: nothing much to suggest, and no panic.
    let _ = magic(b"just some normal text here", 3);
    let _ = magic(&[], 3);
}
