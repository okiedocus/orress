//! The operation table and implementations.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::codec;
use crate::{Args, Category, Op, Param, ParamKind};

const fn param(
    name: &'static str,
    kind: ParamKind,
    default: &'static str,
    explain: &'static str,
) -> Param {
    Param {
        name,
        kind,
        default,
        explain,
    }
}

const ALPHABET: Param = param(
    "alphabet",
    ParamKind::Text,
    codec::BASE64_STANDARD,
    "The 64 characters used, in order. CTF challenges and malware often shuffle them; paste the custom alphabet here.",
);
const KEY: Param = param(
    "key",
    ParamKind::Key,
    "0x00",
    "The key: text (secret), hex with 0x (0x41424344) or hex:41 42 43 44.",
);

pub static ALL: &[Op] = &[
    // Encoding
    Op {
        id: "from_hex",
        name: "From hex",
        category: Category::Encoding,
        explain: "Turns hex text like `48 65 6c 6c 6f` or `\\x48\\x65` into bytes.",
        params: &[],
        run: |i, _| codec::from_hex(i),
    },
    Op {
        id: "to_hex",
        name: "To hex",
        category: Category::Encoding,
        explain: "Shows bytes as hex text.",
        params: &[param(
            "separator",
            ParamKind::Text,
            " ",
            "Text between bytes; empty for none.",
        )],
        run: |i, a| Ok(codec::to_hex(i, &a.text("separator"))),
    },
    Op {
        id: "from_base64",
        name: "From base64",
        category: Category::Encoding,
        explain: "Decodes base64: text made of A–Z, a–z, 0–9, + and /, often ending in =. Very common for hiding strings and payloads.",
        params: &[ALPHABET],
        run: |i, a| codec::from_base64(i, &a.text("alphabet")),
    },
    Op {
        id: "to_base64",
        name: "To base64",
        category: Category::Encoding,
        explain: "Encodes bytes as base64 text.",
        params: &[ALPHABET],
        run: |i, a| codec::to_base64(i, &a.text("alphabet"), true),
    },
    Op {
        id: "from_base32",
        name: "From base32",
        category: Category::Encoding,
        explain: "Decodes base32: uppercase letters and digits 2–7, padded with =.",
        params: &[],
        run: |i, _| codec::from_base32(i),
    },
    Op {
        id: "to_base32",
        name: "To base32",
        category: Category::Encoding,
        explain: "Encodes bytes as base32 text.",
        params: &[],
        run: |i, _| Ok(codec::to_base32(i)),
    },
    Op {
        id: "from_base58",
        name: "From base58",
        category: Category::Encoding,
        explain: "Decodes base58 (Bitcoin alphabet, no 0, O, I or l).",
        params: &[],
        run: |i, _| codec::from_base58(i),
    },
    Op {
        id: "to_base58",
        name: "To base58",
        category: Category::Encoding,
        explain: "Encodes bytes as base58 text.",
        params: &[],
        run: |i, _| Ok(codec::to_base58(i)),
    },
    Op {
        id: "from_url",
        name: "URL decode",
        category: Category::Encoding,
        explain: "Turns %41 sequences back into characters, as in web addresses.",
        params: &[],
        run: |i, _| codec::from_url(i),
    },
    Op {
        id: "to_url",
        name: "URL encode",
        category: Category::Encoding,
        explain: "Encodes special characters as %XX.",
        params: &[],
        run: |i, _| Ok(codec::to_url(i)),
    },
    Op {
        id: "from_escaped",
        name: "Unescape",
        category: Category::Encoding,
        explain: "Turns escapes like \\x41, \\n and \\t into bytes, as written in Rust, C or Python strings.",
        params: &[],
        run: |i, _| codec::from_escaped(i),
    },
    Op {
        id: "to_escaped",
        name: "Escape",
        category: Category::Encoding,
        explain: "Writes unprintable bytes as \\xNN escapes.",
        params: &[],
        run: |i, _| Ok(codec::to_escaped(i)),
    },
    Op {
        id: "utf16le_to_utf8",
        name: "UTF-16 to text",
        category: Category::Encoding,
        explain: "Decodes Windows \"wide\" text (UTF-16 little-endian) into normal text.",
        params: &[],
        run: |i, _| utf16le_to_utf8(i),
    },
    Op {
        id: "utf8_to_utf16le",
        name: "Text to UTF-16",
        category: Category::Encoding,
        explain: "Encodes text as UTF-16 little-endian, the way Windows stores wide strings.",
        params: &[],
        run: |i, _| {
            Ok(String::from_utf8_lossy(i)
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect())
        },
    },
    // Text
    Op {
        id: "rot13",
        name: "ROT13",
        category: Category::Text,
        explain: "Shifts every letter 13 places in the alphabet. Doing it twice gives the original back.",
        params: &[],
        run: |i, _| Ok(caesar(i, 13)),
    },
    Op {
        id: "caesar",
        name: "Caesar shift",
        category: Category::Text,
        explain: "Shifts every letter by a fixed amount (a=b with shift 1).",
        params: &[param(
            "shift",
            ParamKind::Int,
            "3",
            "How many places to shift; negative shifts back.",
        )],
        run: |i, a| Ok(caesar(i, a.int("shift")?.rem_euclid(26) as u8)),
    },
    Op {
        id: "reverse",
        name: "Reverse",
        category: Category::Text,
        explain: "Reverses the order of the bytes.",
        params: &[],
        run: |i, _| Ok(i.iter().rev().copied().collect()),
    },
    // Bitwise
    Op {
        id: "xor",
        name: "XOR",
        category: Category::Bitwise,
        explain: "XORs every byte with the key, repeating the key. The most common simple encryption: XOR with the same key again decrypts.",
        params: &[KEY],
        run: |i, a| xor(i, &a.key("key")?),
    },
    Op {
        id: "xor_brute",
        name: "XOR brute force",
        category: Category::Bitwise,
        explain: "Tries all 256 single-byte keys and lists the most readable results.",
        params: &[],
        run: |i, _| Ok(xor_brute(i)),
    },
    Op {
        id: "xor_known",
        name: "XOR key from known text",
        category: Category::Bitwise,
        explain: "If you know how the plaintext starts (e.g. flag{), this recovers a repeating XOR key and decrypts with it.",
        params: &[
            param(
                "known",
                ParamKind::Text,
                "flag{",
                "Text the decrypted data starts with.",
            ),
            param(
                "key_length",
                ParamKind::Int,
                "0",
                "Key length in bytes; 0 tries every length up to the known text's length.",
            ),
        ],
        run: |i, a| xor_known(i, a.text("known").as_bytes(), a.int("key_length")?),
    },
    Op {
        id: "add",
        name: "Add",
        category: Category::Bitwise,
        explain: "Adds a value to every byte (wrapping at 256).",
        params: &[param("value", ParamKind::Int, "1", "Value to add.")],
        run: |i, a| {
            let v = a.int("value")? as u8;
            Ok(i.iter().map(|b| b.wrapping_add(v)).collect())
        },
    },
    Op {
        id: "sub",
        name: "Subtract",
        category: Category::Bitwise,
        explain: "Subtracts a value from every byte (wrapping at 0).",
        params: &[param("value", ParamKind::Int, "1", "Value to subtract.")],
        run: |i, a| {
            let v = a.int("value")? as u8;
            Ok(i.iter().map(|b| b.wrapping_sub(v)).collect())
        },
    },
    Op {
        id: "rol",
        name: "Rotate left",
        category: Category::Bitwise,
        explain: "Rotates the bits of every byte to the left.",
        params: &[param("bits", ParamKind::Int, "1", "How many bits.")],
        run: |i, a| {
            let n = a.int("bits")?.rem_euclid(8) as u32;
            Ok(i.iter().map(|b| b.rotate_left(n)).collect())
        },
    },
    Op {
        id: "ror",
        name: "Rotate right",
        category: Category::Bitwise,
        explain: "Rotates the bits of every byte to the right.",
        params: &[param("bits", ParamKind::Int, "1", "How many bits.")],
        run: |i, a| {
            let n = a.int("bits")?.rem_euclid(8) as u32;
            Ok(i.iter().map(|b| b.rotate_right(n)).collect())
        },
    },
    Op {
        id: "not",
        name: "NOT",
        category: Category::Bitwise,
        explain: "Flips every bit.",
        params: &[],
        run: |i, _| Ok(i.iter().map(|b| !b).collect()),
    },
    Op {
        id: "swap_endian",
        name: "Swap byte order",
        category: Category::Bitwise,
        explain: "Reverses the bytes inside each 2-, 4- or 8-byte group: little-endian to big-endian and back.",
        params: &[param(
            "width",
            ParamKind::Choice(&["2", "4", "8"]),
            "4",
            "Group size in bytes.",
        )],
        run: |i, a| {
            let w = a.int("width")?.clamp(1, 64) as usize;
            Ok(i.chunks(w)
                .flat_map(|c| c.iter().rev().copied().collect::<Vec<_>>())
                .collect())
        },
    },
    // Crypto
    Op {
        id: "rc4",
        name: "RC4",
        category: Category::Crypto,
        explain: "The RC4 stream cipher; the same operation encrypts and decrypts. Popular in malware for configurations.",
        params: &[KEY],
        run: |i, a| rc4(i, &a.key("key")?),
    },
    Op {
        id: "aes_decrypt",
        name: "AES decrypt",
        category: Category::Crypto,
        explain: "Decrypts AES-128/192/256 (key length decides). ECB has no IV; CBC and CTR need a 16-byte IV.",
        params: &[
            KEY,
            param(
                "iv",
                ParamKind::Key,
                "0x00000000000000000000000000000000",
                "Initialization vector (16 bytes) for CBC and CTR.",
            ),
            param(
                "mode",
                ParamKind::Choice(&["CBC", "ECB", "CTR"]),
                "CBC",
                "Block cipher mode.",
            ),
            param(
                "padding",
                ParamKind::Choice(&["pkcs7", "none"]),
                "pkcs7",
                "Remove PKCS#7 padding after decrypting.",
            ),
        ],
        run: |i, a| aes(i, a, false),
    },
    Op {
        id: "aes_encrypt",
        name: "AES encrypt",
        category: Category::Crypto,
        explain: "Encrypts with AES-128/192/256.",
        params: &[
            KEY,
            param(
                "iv",
                ParamKind::Key,
                "0x00000000000000000000000000000000",
                "Initialization vector (16 bytes) for CBC and CTR.",
            ),
            param(
                "mode",
                ParamKind::Choice(&["CBC", "ECB", "CTR"]),
                "CBC",
                "Block cipher mode.",
            ),
            param(
                "padding",
                ParamKind::Choice(&["pkcs7", "none"]),
                "pkcs7",
                "Add PKCS#7 padding before encrypting.",
            ),
        ],
        run: |i, a| aes(i, a, true),
    },
    Op {
        id: "tea_decrypt",
        name: "TEA decrypt",
        category: Category::Crypto,
        explain: "Decrypts the Tiny Encryption Algorithm (16-byte key, 8-byte blocks). Recognized by the constant 0x9E3779B9.",
        params: &[
            KEY,
            param(
                "endian",
                ParamKind::Choice(&["little", "big"]),
                "little",
                "Byte order of the 32-bit words.",
            ),
        ],
        run: |i, a| tea(i, a, false),
    },
    Op {
        id: "xtea_decrypt",
        name: "XTEA decrypt",
        category: Category::Crypto,
        explain: "Decrypts XTEA, TEA's successor (16-byte key, 8-byte blocks, usually 32 rounds).",
        params: &[
            KEY,
            param("rounds", ParamKind::Int, "32", "Number of cycles."),
            param(
                "endian",
                ParamKind::Choice(&["little", "big"]),
                "little",
                "Byte order of the 32-bit words.",
            ),
        ],
        run: |i, a| tea(i, a, true),
    },
    // Compression
    Op {
        id: "zlib_inflate",
        name: "Zlib decompress",
        category: Category::Compression,
        explain: "Decompresses zlib data (usually starts with the byte 0x78).",
        params: &[],
        run: |i, _| inflate(i, true),
    },
    Op {
        id: "raw_inflate",
        name: "Deflate decompress",
        category: Category::Compression,
        explain: "Decompresses raw DEFLATE data without a header.",
        params: &[],
        run: |i, _| inflate(i, false),
    },
    Op {
        id: "gzip_decompress",
        name: "Gzip decompress",
        category: Category::Compression,
        explain: "Decompresses gzip data (starts with 1F 8B).",
        params: &[],
        run: |i, _| gunzip(i),
    },
    Op {
        id: "zlib_deflate",
        name: "Zlib compress",
        category: Category::Compression,
        explain: "Compresses with zlib.",
        params: &[],
        run: |i, _| Ok(miniz_oxide::deflate::compress_to_vec_zlib(i, 6)),
    },
    // Hashes (output as hex text)
    Op {
        id: "md5",
        name: "MD5",
        category: Category::Hash,
        explain: "MD5 hash, as hex text.",
        params: &[],
        run: |i, _| Ok(codec::to_hex(&Md5::digest(i), "")),
    },
    Op {
        id: "sha1",
        name: "SHA-1",
        category: Category::Hash,
        explain: "SHA-1 hash, as hex text.",
        params: &[],
        run: |i, _| Ok(codec::to_hex(&Sha1::digest(i), "")),
    },
    Op {
        id: "sha256",
        name: "SHA-256",
        category: Category::Hash,
        explain: "SHA-256 hash, as hex text.",
        params: &[],
        run: |i, _| Ok(codec::to_hex(&Sha256::digest(i), "")),
    },
    Op {
        id: "crc32",
        name: "CRC-32",
        category: Category::Hash,
        explain: "CRC-32 checksum (as used by zip and PNG), as hex.",
        params: &[],
        run: |i, _| Ok(format!("{:08x}", crc32(i)).into_bytes()),
    },
    Op {
        id: "fnv1a32",
        name: "FNV-1a (32-bit)",
        category: Category::Hash,
        explain: "A fast hash often used to look up API names in shellcode and malware.",
        params: &[],
        run: |i, _| Ok(format!("{:08x}", fnv1a32(i)).into_bytes()),
    },
    Op {
        id: "ror13",
        name: "ROR13 API hash",
        category: Category::Hash,
        explain: "The classic shellcode hash of a function name: rotate right by 13 and add each character.",
        params: &[],
        run: |i, _| Ok(format!("{:08x}", ror13(i)).into_bytes()),
    },
    // Data
    Op {
        id: "slice",
        name: "Slice",
        category: Category::Data,
        explain: "Keeps `length` bytes starting at `offset` (0 = to the end).",
        params: &[
            param("offset", ParamKind::Int, "0", "First byte to keep."),
            param(
                "length",
                ParamKind::Int,
                "0",
                "How many bytes; 0 keeps the rest.",
            ),
        ],
        run: |i, a| slice(i, a.int("offset")?, a.int("length")?),
    },
    Op {
        id: "strings",
        name: "Extract strings",
        category: Category::Data,
        explain: "Lists readable text inside the data, one string per line.",
        params: &[param("min", ParamKind::Int, "4", "Minimum length.")],
        run: |i, a| {
            Ok(
                orress_bytes::strings::extract(i, a.int("min")?.max(1) as usize, 100_000)
                    .into_iter()
                    .map(|s| s.text)
                    .collect::<Vec<_>>()
                    .join("\n")
                    .into_bytes(),
            )
        },
    },
    Op {
        id: "entropy",
        name: "Entropy",
        category: Category::Data,
        explain: "How random the data is, from 0 to 8. Close to 8: compressed or encrypted.",
        params: &[],
        run: |i, _| {
            let e = orress_bytes::entropy::shannon(i);
            Ok(format!(
                "{e:.3} bits per byte: {}",
                orress_bytes::entropy::describe(e)
            )
            .into_bytes())
        },
    },
];

fn utf16le_to_utf8(input: &[u8]) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("UTF-16 data must have an even number of bytes".into());
    }
    let units: Vec<u16> = input
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units).into_bytes())
}

fn caesar(input: &[u8], shift: u8) -> Vec<u8> {
    input
        .iter()
        .map(|&b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + shift) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + shift) % 26,
            _ => b,
        })
        .collect()
}

fn xor(input: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("the key is empty".into());
    }
    Ok(input
        .iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect())
}

fn xor_brute(input: &[u8]) -> Vec<u8> {
    let sample = &input[..input.len().min(4096)];
    let mut results: Vec<(f32, u8)> = (0..=255u8)
        .map(|k| {
            let out: Vec<u8> = sample.iter().map(|b| b ^ k).collect();
            (crate::score::score(&out), k)
        })
        .collect();
    results.sort_by(|a, b| b.0.total_cmp(&a.0));
    let mut text = String::new();
    for (score, key) in results.iter().take(8) {
        let out: Vec<u8> = input.iter().take(80).map(|b| b ^ key).collect();
        text += &format!(
            "key 0x{key:02x} (score {score:.2}): {}\n",
            String::from_utf8_lossy(&codec::to_escaped(&out))
        );
    }
    text.into_bytes()
}

/// Recovers a repeating XOR key from known plaintext at the start of the data.
pub fn recover_xor_key(input: &[u8], known: &[u8], key_len: usize) -> Option<Vec<u8>> {
    if known.is_empty() || input.len() < known.len() {
        return None;
    }
    let lengths: Vec<usize> = if key_len == 0 {
        (1..=known.len()).collect()
    } else {
        vec![key_len]
    };
    for len in lengths {
        if len > known.len() {
            continue;
        }
        let key: Vec<u8> = input[..len].iter().zip(known).map(|(c, p)| c ^ p).collect();
        // The key must reproduce all of the known text.
        let consistent = known
            .iter()
            .enumerate()
            .all(|(i, &p)| input[i] ^ key[i % len] == p);
        if consistent {
            return Some(key);
        }
    }
    None
}

fn xor_known(input: &[u8], known: &[u8], key_len: i64) -> Result<Vec<u8>, String> {
    let key = recover_xor_key(input, known, key_len.max(0) as usize)
        .ok_or("no repeating key fits: the data may not start with this text, or the key is longer than the known text")?;
    let mut out = format!(
        "key: 0x{} (\"{}\")\n",
        String::from_utf8_lossy(&codec::to_hex(&key, "")),
        String::from_utf8_lossy(&codec::to_escaped(&key))
    )
    .into_bytes();
    out.extend(xor(input, &key)?);
    Ok(out)
}

fn rc4(input: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() || key.len() > 256 {
        return Err("RC4 keys are 1 to 256 bytes".into());
    }
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    Ok(input
        .iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            b ^ s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))]
        })
        .collect())
}

enum AesKey {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl AesKey {
    fn new(key: &[u8]) -> Result<Self, String> {
        let bad = |_| "invalid AES key".to_owned();
        Ok(match key.len() {
            16 => Self::A128(aes::Aes128::new_from_slice(key).map_err(bad)?),
            24 => Self::A192(aes::Aes192::new_from_slice(key).map_err(bad)?),
            32 => Self::A256(aes::Aes256::new_from_slice(key).map_err(bad)?),
            n => return Err(format!("AES keys are 16, 24 or 32 bytes; this one is {n}")),
        })
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        let b: &mut aes::Block = (&mut block[..]).try_into().expect("16 bytes");
        match self {
            Self::A128(c) => c.encrypt_block(b),
            Self::A192(c) => c.encrypt_block(b),
            Self::A256(c) => c.encrypt_block(b),
        }
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        let b: &mut aes::Block = (&mut block[..]).try_into().expect("16 bytes");
        match self {
            Self::A128(c) => c.decrypt_block(b),
            Self::A192(c) => c.decrypt_block(b),
            Self::A256(c) => c.decrypt_block(b),
        }
    }
}

fn aes(input: &[u8], a: &Args<'_>, encrypt: bool) -> Result<Vec<u8>, String> {
    let cipher = AesKey::new(&a.key("key")?)?;
    let mode = a.text("mode");
    let pkcs7 = a.text("padding") == "pkcs7";
    let iv: [u8; 16] = if mode == "ECB" {
        [0; 16]
    } else {
        a.key("iv")?
            .try_into()
            .map_err(|v: Vec<u8>| format!("the IV must be 16 bytes, it is {}", v.len()))?
    };
    let mut data = input.to_vec();
    if mode == "CTR" {
        let mut counter = iv;
        for chunk in data.chunks_mut(16) {
            let mut stream = counter;
            cipher.encrypt(&mut stream);
            chunk.iter_mut().zip(stream).for_each(|(b, s)| *b ^= s);
            // Big-endian increment of the whole counter block.
            for byte in counter.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
        return Ok(data);
    }
    if encrypt && pkcs7 {
        let pad = 16 - data.len() % 16;
        data.extend(std::iter::repeat_n(pad as u8, pad));
    }
    if !data.len().is_multiple_of(16) {
        return Err(format!(
            "{mode} works on 16-byte blocks; the data is {} bytes",
            data.len()
        ));
    }
    let mut previous = iv;
    for chunk in data.chunks_mut(16) {
        let mut block: [u8; 16] = chunk.try_into().expect("16 bytes");
        if encrypt {
            if mode == "CBC" {
                block.iter_mut().zip(previous).for_each(|(b, p)| *b ^= p);
            }
            cipher.encrypt(&mut block);
            previous = block;
        } else {
            let saved = block;
            cipher.decrypt(&mut block);
            if mode == "CBC" {
                block.iter_mut().zip(previous).for_each(|(b, p)| *b ^= p);
            }
            previous = saved;
        }
        chunk.copy_from_slice(&block);
    }
    if !encrypt && pkcs7 {
        let pad = usize::from(*data.last().ok_or("no data")?);
        let valid = (1..=16).contains(&pad)
            && data.len() >= pad
            && data[data.len() - pad..]
                .iter()
                .all(|&b| usize::from(b) == pad);
        if !valid {
            return Err("wrong key or IV: the PKCS#7 padding is invalid (set padding=none to see the raw result)".into());
        }
        data.truncate(data.len() - pad);
    }
    Ok(data)
}

fn tea(input: &[u8], a: &Args<'_>, xtea: bool) -> Result<Vec<u8>, String> {
    let key = a.key("key")?;
    if key.len() != 16 {
        return Err(format!("TEA keys are 16 bytes; this one is {}", key.len()));
    }
    if !input.len().is_multiple_of(8) {
        return Err("TEA works on 8-byte blocks".into());
    }
    let big = a.text("endian") == "big";
    let word = |b: &[u8]| {
        let arr = [b[0], b[1], b[2], b[3]];
        if big {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }
    };
    let k: Vec<u32> = key.chunks(4).map(word).collect();
    let rounds = if xtea {
        a.int("rounds")?.clamp(1, 1024) as u32
    } else {
        32
    };
    const DELTA: u32 = 0x9E37_79B9;
    let mut out = Vec::with_capacity(input.len());
    for block in input.chunks(8) {
        let (mut v0, mut v1) = (word(&block[..4]), word(&block[4..]));
        if xtea {
            let mut sum = DELTA.wrapping_mul(rounds);
            for _ in 0..rounds {
                v1 = v1.wrapping_sub(
                    ((v0 << 4 ^ v0 >> 5).wrapping_add(v0))
                        ^ sum.wrapping_add(k[(sum >> 11 & 3) as usize]),
                );
                sum = sum.wrapping_sub(DELTA);
                v0 = v0.wrapping_sub(
                    ((v1 << 4 ^ v1 >> 5).wrapping_add(v1))
                        ^ sum.wrapping_add(k[(sum & 3) as usize]),
                );
            }
        } else {
            let mut sum = DELTA.wrapping_mul(32);
            for _ in 0..32 {
                v1 = v1.wrapping_sub(
                    (v0 << 4).wrapping_add(k[2])
                        ^ v0.wrapping_add(sum)
                        ^ (v0 >> 5).wrapping_add(k[3]),
                );
                v0 = v0.wrapping_sub(
                    (v1 << 4).wrapping_add(k[0])
                        ^ v1.wrapping_add(sum)
                        ^ (v1 >> 5).wrapping_add(k[1]),
                );
                sum = sum.wrapping_sub(DELTA);
            }
        }
        for v in [v0, v1] {
            out.extend(if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            });
        }
    }
    Ok(out)
}

fn inflate(input: &[u8], zlib: bool) -> Result<Vec<u8>, String> {
    let result = if zlib {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(input, 256 << 20)
    } else {
        miniz_oxide::inflate::decompress_to_vec_with_limit(input, 256 << 20)
    };
    result.map_err(|e| format!("not valid compressed data ({:?})", e.status))
}

fn gunzip(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 18 || input[0] != 0x1f || input[1] != 0x8b || input[2] != 8 {
        return Err("not gzip data (gzip starts with 1F 8B 08)".into());
    }
    let flags = input[3];
    let mut pos = 10;
    if flags & 4 != 0 {
        let extra = usize::from(u16::from_le_bytes([input[pos], input[pos + 1]]));
        pos += 2 + extra;
    }
    for flag in [8u8, 16] {
        if flags & flag != 0 {
            while *input.get(pos).ok_or("truncated gzip header")? != 0 {
                pos += 1;
            }
            pos += 1;
        }
    }
    if flags & 2 != 0 {
        pos += 2;
    }
    inflate(
        input
            .get(pos..input.len() - 8)
            .ok_or("truncated gzip data")?,
        false,
    )
}

pub fn crc32(input: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in input {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn fnv1a32(input: &[u8]) -> u32 {
    input.iter().fold(0x811c_9dc5u32, |h, &b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

fn ror13(input: &[u8]) -> u32 {
    input
        .iter()
        .fold(0u32, |h, &b| h.rotate_right(13).wrapping_add(u32::from(b)))
}

fn slice(input: &[u8], offset: i64, length: i64) -> Result<Vec<u8>, String> {
    let start = usize::try_from(offset).map_err(|_| "offset cannot be negative")?;
    if start > input.len() {
        return Err(format!(
            "offset {start} is past the end ({} bytes)",
            input.len()
        ));
    }
    let end = if length <= 0 {
        input.len()
    } else {
        (start + length as usize).min(input.len())
    };
    Ok(input[start..end].to_vec())
}
