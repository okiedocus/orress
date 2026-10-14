use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::Import;

/// File hashes, used to look samples up in threat-intel databases and to tell
/// files apart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// Import hash (PE only): MD5 of the imported functions. Malware built from the
    /// same source often shares it even when the file hash differs.
    pub imphash: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl Hashes {
    pub fn compute(data: &[u8], imports: &[Import], is_pe: bool) -> Self {
        Self {
            md5: hex(&Md5::digest(data)),
            sha1: hex(&Sha1::digest(data)),
            sha256: hex(&Sha256::digest(data)),
            imphash: (is_pe && !imports.is_empty()).then(|| imphash(imports)),
        }
    }
}

/// pefile's `ordlookup` table for `ws2_32.dll` (also used for `wsock32.dll`): the classic
/// Winsock ordinals. Only the stable, well-documented ordinals are listed here (1–23, 51–57,
/// 101–116, 151, 500); pefile's table has more entries in 24–50 / 58–100, which fall back to
/// `ord<N>` below, so imphashes of samples importing those by ordinal may still differ.
const WS2_32_ORDINALS: &[(u32, &str)] = &[
    (1, "accept"),
    (2, "bind"),
    (3, "closesocket"),
    (4, "connect"),
    (5, "getpeername"),
    (6, "getsockname"),
    (7, "getsockopt"),
    (8, "htonl"),
    (9, "htons"),
    (10, "ioctlsocket"),
    (11, "inet_addr"),
    (12, "inet_ntoa"),
    (13, "listen"),
    (14, "ntohl"),
    (15, "ntohs"),
    (16, "recv"),
    (17, "recvfrom"),
    (18, "select"),
    (19, "send"),
    (20, "sendto"),
    (21, "setsockopt"),
    (22, "shutdown"),
    (23, "socket"),
    (51, "gethostbyaddr"),
    (52, "gethostbyname"),
    (53, "getprotobyname"),
    (54, "getprotobynumber"),
    (55, "getservbyname"),
    (56, "getservbyport"),
    (57, "gethostname"),
    (101, "WSAAsyncSelect"),
    (102, "WSAAsyncGetHostByAddr"),
    (103, "WSAAsyncGetHostByName"),
    (104, "WSAAsyncGetProtoByNumber"),
    (105, "WSAAsyncGetProtoByName"),
    (106, "WSAAsyncGetServByPort"),
    (107, "WSAAsyncGetServByName"),
    (108, "WSACancelAsyncRequest"),
    (109, "WSASetBlockingHook"),
    (110, "WSAUnhookBlockingHook"),
    (111, "WSAGetLastError"),
    (112, "WSASetLastError"),
    (113, "WSACancelBlockingCall"),
    (114, "WSAIsBlocking"),
    (115, "WSAStartup"),
    (116, "WSACleanup"),
    (151, "__WSAFDIsSet"),
    (500, "WEP"),
];

/// pefile's `ordlookup` table for `oleaut32.dll`, limited to the ordinals that are certain (the
/// BSTR/VARIANT basics that VB/COM binaries import by ordinal). Others fall back to `ord<N>`.
const OLEAUT32_ORDINALS: &[(u32, &str)] = &[
    (2, "SysAllocString"),
    (3, "SysReAllocString"),
    (4, "SysAllocStringLen"),
    (5, "SysReAllocStringLen"),
    (6, "SysFreeString"),
    (7, "SysStringLen"),
    (8, "VariantInit"),
    (9, "VariantClear"),
    (10, "VariantCopy"),
    (11, "VariantCopyInd"),
    (12, "VariantChangeType"),
    (15, "SafeArrayCreate"),
    (16, "SafeArrayDestroy"),
    (149, "SysStringByteLen"),
    (150, "SysAllocStringByteLen"),
];

/// pefile's `ordLookup`: an ordinal import's name for the few libraries it knows, keyed by the
/// full lowercase DLL name (as pefile does).
fn ord_lookup(library_lower: &str, ordinal: u32) -> Option<&'static str> {
    let table = match library_lower {
        "ws2_32.dll" | "wsock32.dll" => WS2_32_ORDINALS,
        "oleaut32.dll" => OLEAUT32_ORDINALS,
        _ => return None,
    };
    table
        .binary_search_by_key(&ordinal, |&(o, _)| o)
        .ok()
        .map(|i| table[i].1)
}

/// The pefile/VirusTotal imphash: `library.function` pairs, lowercase, library without
/// its extension, joined with commas, then MD5. Ordinal imports are resolved to names for
/// `ws2_32`/`wsock32`/`oleaut32` (pefile's `ordlookup`), and use `ord<N>` otherwise.
pub fn imphash(imports: &[Import]) -> String {
    let joined = imports
        .iter()
        .map(|i| {
            let full = i.library.to_ascii_lowercase();
            let lib = ["dll", "ocx", "sys"]
                .iter()
                .find_map(|ext| full.strip_suffix(&format!(".{ext}")))
                .unwrap_or(&full)
                .to_owned();
            let func = match i.name.strip_prefix('#') {
                Some(ordinal) => ordinal
                    .parse::<u32>()
                    .ok()
                    .and_then(|o| ord_lookup(&full, o))
                    .map(str::to_ascii_lowercase)
                    .unwrap_or_else(|| format!("ord{ordinal}")),
                None => i.name.to_ascii_lowercase(),
            };
            format!("{lib}.{func}")
        })
        .collect::<Vec<_>>()
        .join(",");
    hex(&Md5::digest(joined.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        let h = Hashes::compute(b"abc", &[], false);
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.imphash, None);
    }

    #[test]
    fn imphash_normalizes_names() {
        let imports = [
            Import {
                library: "KERNEL32.dll".into(),
                name: "ExitProcess".into(),
            },
            Import {
                library: "ws2_32.dll".into(),
                name: "#115".into(),
            },
            Import {
                library: "OLEAUT32.dll".into(),
                name: "#6".into(),
            },
            Import {
                library: "WSOCK32.dll".into(),
                name: "#9999".into(),
            },
            Import {
                library: "mylib.dll".into(),
                name: "#3".into(),
            },
        ];
        // Like pefile: known ordinals resolve to lowercase names, unknown ones stay `ord<N>`.
        let expected = hex(&Md5::digest(
            b"kernel32.exitprocess,ws2_32.wsastartup,oleaut32.sysfreestring,\
              wsock32.ord9999,mylib.ord3",
        ));
        assert_eq!(imphash(&imports), expected);
    }

    #[test]
    fn ordinal_tables_are_sorted() {
        for t in [WS2_32_ORDINALS, OLEAUT32_ORDINALS] {
            assert!(t.windows(2).all(|w| w[0].0 < w[1].0));
        }
        assert_eq!(ord_lookup("wsock32.dll", 23), Some("socket"));
        assert_eq!(ord_lookup("ws2_32", 23), None);
    }
}
