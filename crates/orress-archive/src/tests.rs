use super::*;

/// A real JAR built by `jar 17` containing a manifest and `Check.class`.
const JAR: &[u8] = include_bytes!("../tests/fixtures/app.jar");

#[test]
fn detects_and_lists_entries() {
    assert!(looks_like_zip(JAR));
    assert!(!looks_like_zip(b"MZ\x90\x00"));

    let ar = Archive::open(JAR).unwrap();
    let names: Vec<&str> = ar.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"META-INF/MANIFEST.MF"));
    assert!(names.contains(&"Check.class"));
    // The META-INF/ directory entry is recognised as a directory.
    assert!(
        ar.entries
            .iter()
            .any(|e| e.name == "META-INF/" && e.is_dir())
    );
}

#[test]
fn extracts_class_and_parses_manifest() {
    let ar = Archive::open(JAR).unwrap();

    // The stored/deflated Check.class round-trips to a valid class file.
    let class_entry = ar.by_name("Check.class").unwrap();
    let class_bytes = ar.read(class_entry).unwrap();
    assert_eq!(class_bytes.len() as u64, class_entry.uncompressed_size);
    assert_eq!(&class_bytes[..4], &[0xCA, 0xFE, 0xBA, 0xBE]);

    // The manifest names the main class we set when building the jar.
    let mf = ar
        .read(ar.by_name("META-INF/MANIFEST.MF").unwrap())
        .unwrap();
    let fields = parse_manifest(&mf);
    assert_eq!(
        fields
            .iter()
            .find(|(k, _)| k == "Main-Class")
            .map(|(_, v)| v.as_str()),
        Some("Check")
    );
}

#[test]
fn rejects_non_zip() {
    assert!(Archive::open(b"not a zip at all, just some text").is_err());
}

fn le16(out: &mut Vec<u8>, v: u16) {
    out.extend(v.to_le_bytes());
}
fn le32(out: &mut Vec<u8>, v: u32) {
    out.extend(v.to_le_bytes());
}
fn le64(out: &mut Vec<u8>, v: u64) {
    out.extend(v.to_le_bytes());
}

/// Hand-builds a one-member stored archive. With `zip64`, every size/offset/count is a sentinel
/// and the real values live in ZIP64 extra fields and the ZIP64 end-of-directory record.
fn build_zip(name: &str, body: &[u8], flags: u16, zip64: bool) -> Vec<u8> {
    let mut z = Vec::new();
    let len = body.len() as u64;
    let (size32, extra_local) = if zip64 {
        let mut e = Vec::new();
        le16(&mut e, 0x0001);
        le16(&mut e, 16);
        le64(&mut e, len);
        le64(&mut e, len);
        (0xFFFF_FFFF, e)
    } else {
        (len as u32, Vec::new())
    };
    // Local file header.
    le32(&mut z, 0x0403_4b50);
    le16(&mut z, 45);
    le16(&mut z, flags);
    le16(&mut z, 0); // stored
    le32(&mut z, 0); // time/date
    le32(&mut z, 0); // crc (not checked)
    le32(&mut z, size32);
    le32(&mut z, size32);
    le16(&mut z, name.len() as u16);
    le16(&mut z, extra_local.len() as u16);
    z.extend(name.as_bytes());
    z.extend(&extra_local);
    z.extend(body);

    // Central directory.
    let cd_off = z.len() as u64;
    let extra_cd = if zip64 {
        let mut e = Vec::new();
        le16(&mut e, 0x0001);
        le16(&mut e, 24);
        le64(&mut e, len); // uncompressed
        le64(&mut e, len); // compressed
        le64(&mut e, 0); // local header offset
        e
    } else {
        Vec::new()
    };
    le32(&mut z, 0x0201_4b50);
    le16(&mut z, 45);
    le16(&mut z, 45);
    le16(&mut z, flags);
    le16(&mut z, 0);
    le32(&mut z, 0);
    le32(&mut z, 0);
    le32(&mut z, size32);
    le32(&mut z, size32);
    le16(&mut z, name.len() as u16);
    le16(&mut z, extra_cd.len() as u16);
    le16(&mut z, 0); // comment
    le16(&mut z, 0); // disk
    le16(&mut z, 0); // internal attrs
    le32(&mut z, 0); // external attrs
    le32(&mut z, if zip64 { 0xFFFF_FFFF } else { 0 });
    z.extend(name.as_bytes());
    z.extend(&extra_cd);
    let cd_size = z.len() as u64 - cd_off;

    if zip64 {
        let rec = z.len() as u64;
        le32(&mut z, 0x0606_4b50);
        le64(&mut z, 44); // size of the rest of the record
        le16(&mut z, 45);
        le16(&mut z, 45);
        le32(&mut z, 0);
        le32(&mut z, 0);
        le64(&mut z, 1); // entries on this disk
        le64(&mut z, 1); // total entries
        le64(&mut z, cd_size);
        le64(&mut z, cd_off);
        // Locator.
        le32(&mut z, 0x0706_4b50);
        le32(&mut z, 0);
        le64(&mut z, rec);
        le32(&mut z, 1);
    }
    // Classic EOCD.
    le32(&mut z, 0x0605_4b50);
    le16(&mut z, 0);
    le16(&mut z, 0);
    let (n16, cs, co) = if zip64 {
        (0xFFFF, 0xFFFF_FFFF, 0xFFFF_FFFF)
    } else {
        (1, cd_size as u32, cd_off as u32)
    };
    le16(&mut z, n16);
    le16(&mut z, n16);
    le32(&mut z, cs);
    le32(&mut z, co);
    le16(&mut z, 0);
    z
}

#[test]
fn reads_zip64_archives() {
    let zip = build_zip("big.bin", b"zip64 payload", 0, true);
    let ar = Archive::open(&zip).unwrap();
    assert_eq!(ar.entries.len(), 1);
    let e = &ar.entries[0];
    assert_eq!(e.name, "big.bin");
    assert_eq!(e.uncompressed_size, 13);
    assert_eq!(e.compressed_size, 13);
    assert_eq!(e.local_header_offset, 0);
    assert_eq!(ar.read(e).unwrap(), b"zip64 payload");

    // Sentinels without a locator are a clean error.
    let mut broken = zip.clone();
    let loc = broken.len() - 22 - 20;
    broken[loc] = 0;
    assert!(Archive::open(&broken).is_err());
}

#[test]
fn plain_builder_archive_round_trips() {
    let zip = build_zip("a.txt", b"hello", 0, false);
    let ar = Archive::open(&zip).unwrap();
    assert_eq!(ar.read(&ar.entries[0]).unwrap(), b"hello");
}

#[test]
fn encrypted_members_are_reported() {
    let zip = build_zip("secret.txt", b"\x01\x02ciphertext", 1, false);
    let ar = Archive::open(&zip).unwrap();
    let e = &ar.entries[0];
    assert!(e.is_encrypted());
    let err = ar.read(e).unwrap_err();
    assert!(err.contains("encrypted"), "{err}");
}

#[test]
fn hostile_entry_counts_are_capped() {
    // A ZIP64 record claiming 2^60 entries in a tiny directory.
    let mut zip = build_zip("x", b"y", 0, true);
    let rec = zip.len() - 22 - 20 - 56;
    zip[rec + 32..rec + 40].copy_from_slice(&(1u64 << 60).to_le_bytes());
    let ar = Archive::open(&zip).unwrap();
    assert_eq!(ar.entries.len(), 1);

    // A locator pointing at u64::MAX, and a directory offset at u64::MAX: errors, no panics.
    let mut zip = build_zip("x", b"y", 0, true);
    let loc = zip.len() - 22 - 20;
    zip[loc + 8..loc + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Archive::open(&zip).is_err());
    let mut zip = build_zip("x", b"y", 0, true);
    zip[rec + 48..rec + 56].copy_from_slice(&u64::MAX.to_le_bytes());
    let _ = Archive::open(&zip);
}
