//! Compiler, language, packer and file-type detection from section names, byte
//! signatures and entropy. Each detection says what was found, so the user can check it.

use memchr::memmem;

use crate::model::*;

fn contains(data: &[u8], needle: &[u8]) -> bool {
    memmem::find(data, needle).is_some()
}

struct Rule {
    category: DetectionCategory,
    name: &'static str,
    sections: &'static [&'static str],
    markers: &'static [&'static [u8]],
    explain: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        category: DetectionCategory::Packer,
        name: "UPX",
        sections: &["UPX0", "UPX1", ".UPX0", ".UPX1"],
        markers: &[b"UPX!"],
        explain: "UPX is a common, free executable packer: the real program is compressed and \
            unpacked in memory at start-up. Standard UPX files unpack with `upx -d`. CTF and \
            malware authors sometimes modify UPX so that fails; then you unpack in a debugger.",
    },
    Rule {
        category: DetectionCategory::Packer,
        name: "ASPack",
        sections: &[".aspack", ".adata"],
        markers: &[],
        explain: "ASPack is a commercial packer that compresses the program. Unpack in a \
            debugger by finding the original entry point (OEP).",
    },
    Rule {
        category: DetectionCategory::Packer,
        name: "MPRESS",
        sections: &[".MPRESS1", ".MPRESS2"],
        markers: &[],
        explain: "MPRESS is a free packer that compresses PE and .NET files.",
    },
    Rule {
        category: DetectionCategory::Packer,
        name: "Themida / WinLicense",
        sections: &[".themida", ".winlice"],
        markers: &[],
        explain: "Themida is a strong commercial protector with virtualization and \
            anti-debugging. Expect a hard target; dynamic analysis works better than static.",
    },
    Rule {
        category: DetectionCategory::Packer,
        name: "VMProtect",
        sections: &[".vmp0", ".vmp1", ".vmp2"],
        markers: &[],
        explain: "VMProtect turns code into bytecode for a custom virtual machine. Protected \
            functions cannot be read directly; you analyze the VM instead (Academy level 5).",
    },
    Rule {
        category: DetectionCategory::Packer,
        name: "Enigma Protector",
        sections: &[".enigma1", ".enigma2"],
        markers: &[],
        explain: "Enigma is a commercial protector with packing and anti-debugging.",
    },
    Rule {
        category: DetectionCategory::Packer,
        name: "PECompact",
        sections: &["PEC2", "pec1", "pec2", "PEC2TO", "PEC2MO"],
        markers: &[],
        explain: "PECompact is a commercial packer that compresses the program.",
    },
    Rule {
        category: DetectionCategory::Language,
        name: "Go",
        sections: &[
            ".gopclntab",
            "__gopclntab",
            ".go.buildinfo",
            "__go_buildinfo",
        ],
        markers: &[b"\xff Go buildinf:", b"Go build ID: \""],
        explain: "Written in Go. Go binaries are large (the runtime is included) and strings \
            are not zero-terminated, so they run together in the strings list. Function names \
            survive in the pclntab table even when stripped; main.main is the real main.",
    },
    Rule {
        category: DetectionCategory::Language,
        name: "Rust",
        sections: &[],
        markers: &[b"/rustc/", b"RUST_BACKTRACE", b"rust_panic"],
        explain: "Written in Rust. Expect long mangled function names, many small helper \
            functions and panic messages with source file paths, which help orient you. \
            The user's code is usually under the crate name, not std or core.",
    },
    Rule {
        category: DetectionCategory::Language,
        name: "Nim",
        sections: &[],
        markers: &[b"fatal.nim", b"@nim", b"NimMain"],
        explain: "Written in Nim, which compiles to C first. NimMain leads to the user's code.",
    },
    Rule {
        category: DetectionCategory::Language,
        name: "Delphi / C++Builder",
        sections: &["CODE", "DATA", ".itext"],
        markers: &[b"Embarcadero", b"Borland", b"FastMM"],
        explain: "Built with Delphi (Object Pascal). Delphi programs use their own calling \
            convention (register) and store class and form information you can recover.",
    },
    Rule {
        category: DetectionCategory::Compiler,
        name: "GCC",
        sections: &[],
        markers: &[b"GCC: ("],
        explain: "Compiled with the GNU C/C++ compiler, the standard on Linux. The exact \
            version is in the .comment section.",
    },
    Rule {
        category: DetectionCategory::Compiler,
        name: "Clang / LLVM",
        sections: &[],
        markers: &[b"clang version ", b"Apple clang"],
        explain: "Compiled with Clang (LLVM), the default on macOS and common for Android and \
            Rust-adjacent code.",
    },
    Rule {
        category: DetectionCategory::Compiler,
        name: "MinGW",
        sections: &[],
        markers: &[b"Mingw-w64 runtime failure", b"mingw_", b"__mingw"],
        explain: "Compiled with MinGW: GCC targeting Windows. Common for CTF Windows \
            challenges built on Linux.",
    },
    Rule {
        category: DetectionCategory::Installer,
        name: "PyInstaller",
        sections: &[],
        markers: &[
            b"MEI\x0c\x0b\x0a\x0b\x0e",
            b"pyi-windows-manifest-filename",
            b"_PYI_",
        ],
        explain: "A Python program bundled with PyInstaller. The interesting code is Python \
            bytecode inside the archive: extract it (pyinstxtractor) and decompile the .pyc \
            files instead of reversing the C loader.",
    },
    Rule {
        category: DetectionCategory::Installer,
        name: "py2exe",
        sections: &[],
        markers: &[b"PYTHONSCRIPT"],
        explain: "A Python program bundled with py2exe. The Python code is stored as a resource.",
    },
    Rule {
        category: DetectionCategory::Installer,
        name: "AutoIt",
        sections: &[],
        markers: &[b"AU3!EA06", b">>>AUTOIT SCRIPT<<<"],
        explain: "A compiled AutoIt script, popular with commodity malware. Extract the script \
            (e.g. with AutoIt-Ripper) rather than reversing the interpreter.",
    },
    Rule {
        category: DetectionCategory::Installer,
        name: "NSIS installer",
        sections: &[],
        // Only the full banner: shorter markers also occur inside Windows system DLLs.
        markers: &[b"Nullsoft Install System v"],
        explain: "An installer made with NSIS. The payload is in a compressed archive after the \
            installer stub; 7-Zip can often extract it.",
    },
    Rule {
        category: DetectionCategory::Installer,
        name: "Inno Setup",
        sections: &[],
        markers: &[b"Inno Setup Setup Data"],
        explain: "An installer made with Inno Setup. innoextract can unpack it.",
    },
];

/// Signatures for non-executable files, checked at offset 0.
const MAGIC: &[(&[u8], &str, &str)] = &[
    (
        b"PK\x03\x04",
        "ZIP archive",
        "A ZIP archive. Also the container for .jar, .apk, .docx and .xlsx files.",
    ),
    (
        b"%PDF",
        "PDF document",
        "A PDF document. Malicious PDFs carry JavaScript or embedded files.",
    ),
    (
        b"\x89PNG\r\n\x1a\n",
        "PNG image",
        "A PNG image. Steganography challenges hide data in images.",
    ),
    (b"\xff\xd8\xff", "JPEG image", "A JPEG image."),
    (b"GIF8", "GIF image", "A GIF image."),
    (b"\x1f\x8b", "gzip data", "gzip-compressed data."),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "A 7-Zip archive."),
    (b"Rar!\x1a\x07", "RAR archive", "A RAR archive."),
    (
        b"MSCF",
        "Microsoft Cabinet",
        "A Windows cabinet (.cab) archive.",
    ),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "OLE compound file",
        "An old Office document (.doc/.xls/.msi). Malicious ones carry VBA macros.",
    ),
    (
        b"\xca\xfe\xba\xbe",
        "Java class or Mach-O universal binary",
        "Either a compiled Java class file or a macOS universal (fat) binary; both start with CAFEBABE.",
    ),
    (
        b"dex\n",
        "Android DEX",
        "Dalvik bytecode from an Android app (classes.dex).",
    ),
    (
        b"\x1bLua",
        "Lua bytecode",
        "Compiled Lua bytecode. Decompilers such as unluac can recover the source.",
    ),
    (
        b"#!",
        "Script",
        "A script with an interpreter line (#!/bin/sh, #!/usr/bin/python ...). Read it as text.",
    ),
    (
        b"L\x00\x00\x00\x01\x14\x02\x00",
        "Windows shortcut (LNK)",
        "A Windows shortcut. Malicious LNK files run hidden commands.",
    ),
    (
        b"\x7fELF",
        "ELF (damaged)",
        "Starts like an ELF file but could not be parsed: the header may be corrupted on purpose to break tools.",
    ),
    (
        b"MZ",
        "DOS/PE (damaged)",
        "Starts like a Windows executable but could not be parsed: the headers may be corrupted on purpose.",
    ),
];

pub fn detect(data: &[u8], info: &BinaryInfo) -> Vec<Detection> {
    let mut out = Vec::new();

    for rule in RULES {
        let by_section = info
            .sections
            .iter()
            .find(|s| rule.sections.contains(&s.name.as_str()))
            .map(|s| format!("section \"{}\"", s.name));
        let by_marker = || {
            rule.markers
                .iter()
                .find(|m| contains(data, m))
                .map(|m| format!("bytes \"{}\"", m.escape_ascii()))
        };
        if let Some(evidence) = by_section.or_else(by_marker) {
            out.push(Detection {
                category: rule.category,
                name: rule.name.to_owned(),
                evidence,
                explain: rule.explain,
            });
        }
    }

    if let Some(pe) = &info.pe {
        if pe.is_dotnet {
            out.push(Detection {
                category: DetectionCategory::Language,
                name: ".NET (C#, VB.NET, F#)".into(),
                evidence: "CLR runtime header present".into(),
                explain: "A .NET program: the code is CIL bytecode, not machine code. A .NET \
                    decompiler (dnSpy, ILSpy) gives you near-original C#. Native disassembly \
                    only shows a tiny loader.",
            });
        }
        if !pe.rich.is_empty() {
            out.push(Detection {
                category: DetectionCategory::Compiler,
                name: "Microsoft Visual C++".into(),
                evidence: format!("Rich header with {} tool entries", pe.rich.len()),
                explain: "Built with Microsoft's toolchain. The Rich header lists the tool \
                    versions used; malware families often share the same build setup.",
            });
        }
    }

    // Packed-code heuristic: an executable section with near-random contents.
    let packed_section = info
        .sections
        .iter()
        .find(|s| s.perms.execute && s.file_size > 1024 && s.entropy.unwrap_or(0.0) > 7.2);
    let already_packer = out.iter().any(|d| d.category == DetectionCategory::Packer);
    if let Some(s) = packed_section
        && !already_packer
    {
        out.push(Detection {
            category: DetectionCategory::Packer,
            name: "Unknown packer or encryption (heuristic)".into(),
            evidence: format!(
                "executable section \"{}\" has entropy {:.2}",
                s.name,
                s.entropy.unwrap_or(0.0)
            ),
            explain: "Code normally has an entropy around 5–6.5. Close to 8 means the bytes \
                are compressed or encrypted, so the real code only appears in memory at run \
                time. Run it in a debugger or emulator and dump it after unpacking.",
        });
    }

    if info.format == Format::Unknown
        && let Some((_, name, explain)) = MAGIC.iter().find(|(magic, _, _)| data.starts_with(magic))
    {
        out.push(Detection {
            category: DetectionCategory::FileType,
            name: (*name).to_owned(),
            evidence: "file signature (magic bytes) at offset 0".into(),
            explain,
        });
    }

    out.sort_by_key(|d| d.category);
    out
}
