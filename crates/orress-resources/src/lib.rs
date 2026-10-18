//! Pull the contents out of an executable: native Win32 resources (icons, bitmaps, manifest,
//! version info, string tables, RCDATA…), embedded files found by magic-byte signatures
//! (PNG/JPEG/GIF/BMP/ZIP/GZIP/PDF/WAV…), each PE section, and any overlay (bytes appended after
//! the image). The input is only read, never executed.
//!
//! [`extract`] lists what it finds as [`Resource`]s (each with its own bytes); [`write_all`]
//! writes a selection to a folder with sequence-numbered names and a manifest.

use std::path::{Path, PathBuf};

use object::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, PeFile};

/// The biggest single item we will hold/extract (guards against a corrupt size field).
const MAX_ITEM: usize = 256 * 1024 * 1024;
/// The most items we will list (guards against a pathological resource tree).
const MAX_ITEMS: usize = 4000;
/// When an embedded file's end cannot be determined, carve at most this many bytes.
const CARVE_FALLBACK: usize = 16 * 1024 * 1024;

// Resource type ids (level 0 of the resource tree). `object` only exposes these behind its
// `names` feature, so we spell them out.
const RT_CURSOR: u16 = 1;
const RT_BITMAP: u16 = 2;
const RT_ICON: u16 = 3;
const RT_MENU: u16 = 4;
const RT_DIALOG: u16 = 5;
const RT_STRING: u16 = 6;
const RT_RCDATA: u16 = 10;
const RT_GROUP_CURSOR: u16 = 12;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
const RT_HTML: u16 = 23;
const RT_MANIFEST: u16 = 24;

/// What an extracted item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    /// A native Win32 resource from the `.rsrc` directory.
    Resource,
    /// A whole PE section's bytes.
    Section,
    /// Data appended after the image (installers, self-extractors, signatures).
    Overlay,
    /// A file found inside the binary by its magic-byte signature.
    Embedded,
}

impl ResourceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Section => "section",
            Self::Overlay => "overlay",
            Self::Embedded => "embedded",
        }
    }
}

/// One extractable item.
#[derive(Clone)]
pub struct Resource {
    pub kind: ResourceKind,
    /// A human label, e.g. `manifest`, `.text` or `icon_1`.
    pub name: String,
    /// The file extension to save it under (no dot), e.g. `ico`, `bmp`, `bin`.
    pub ext: &'static str,
    /// File offset in the source, when known.
    pub offset: Option<u64>,
    /// The item's bytes.
    pub data: Vec<u8>,
}

impl Resource {
    fn new(
        kind: ResourceKind,
        name: impl Into<String>,
        ext: &'static str,
        offset: Option<u64>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            ext,
            offset,
            data,
        }
    }

    /// The suggested file name (`<index>_<name>.<ext>`), used by [`write_all`].
    fn file_name(&self, index: usize) -> String {
        let safe: String = self
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{index:03}_{safe}.{}", self.ext)
    }
}

/// Finds everything extractable in `data`.
pub fn extract(data: &[u8]) -> Vec<Resource> {
    let mut out = Vec::new();
    // Record the file ranges already covered, so carving does not re-report them.
    let mut covered: Vec<(usize, usize)> = Vec::new();

    if let Ok(file) = object::File::parse(data) {
        match file {
            object::File::Pe32(pe) => pe_items(&pe, data, &mut out, &mut covered),
            object::File::Pe64(pe) => pe_items(&pe, data, &mut out, &mut covered),
            _ => {}
        }
    }
    carve(data, &covered, &mut out);
    out.truncate(MAX_ITEMS);
    out
}

/// Writes the chosen resources to `dest`, with an `export_manifest.txt`. Returns the paths written.
pub fn write_all(resources: &[Resource], dest: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let mut written = Vec::new();
    let mut manifest = String::from("ORRESS resource export\n\n");
    for (i, res) in resources.iter().enumerate() {
        let name = res.file_name(i + 1);
        let path = dest.join(&name);
        std::fs::write(&path, &res.data).map_err(|e| format!("{}: {e}", path.display()))?;
        let off = res
            .offset
            .map(|o| format!("0x{o:x}"))
            .unwrap_or_else(|| "-".into());
        manifest.push_str(&format!(
            "{name}\t{}\t{} bytes\toffset {off}\n",
            res.kind.label(),
            res.data.len()
        ));
        written.push(path);
    }
    let _ = std::fs::write(dest.join("export_manifest.txt"), manifest);
    Ok(written)
}

// --- PE resources, sections, overlay ---------------------------------------

fn pe_items<Pe: ImageNtHeaders>(
    pe: &PeFile<Pe>,
    data: &[u8],
    out: &mut Vec<Resource>,
    covered: &mut Vec<(usize, usize)>,
) {
    let sections = pe.section_table();

    // 1. Native resources.
    if let Ok(Some(dir)) = pe.data_directories().resource_directory(data, &sections)
        && let Ok(root) = dir.root()
    {
        let mut icons: Vec<Vec<u8>> = Vec::new();
        for type_entry in root.entries {
            let Some(type_id) = type_entry.name_or_id().id() else {
                continue;
            };
            let Some(names) = type_entry.data(dir).ok().and_then(|d| d.table()) else {
                continue;
            };
            for name_entry in names.entries {
                let Some(langs) = name_entry.data(dir).ok().and_then(|d| d.table()) else {
                    continue;
                };
                for lang_entry in langs.entries {
                    let Some(leaf) = lang_entry.data(dir).ok().and_then(|d| d.data()) else {
                        continue;
                    };
                    let rva = leaf.offset_to_data.get(LE);
                    let size = leaf.size.get(LE) as usize;
                    if size == 0 || size > MAX_ITEM {
                        continue;
                    }
                    let Some(bytes) = sections.pe_data_at(data, rva).and_then(|b| b.get(..size))
                    else {
                        continue;
                    };
                    let file_off = sections.pe_file_range_at(rva).map(|(o, _)| u64::from(o));
                    if let Some(start) = file_off {
                        covered.push((start as usize, start as usize + size));
                    }
                    let id = name_entry.name_or_id().id().unwrap_or(0);
                    emit_resource(type_id, id, bytes, file_off, out, &mut icons);
                }
            }
        }
        for (n, ico) in icons.into_iter().enumerate() {
            out.push(Resource::new(
                ResourceKind::Resource,
                format!("icon_{}", n + 1),
                "ico",
                None,
                ico,
            ));
        }
    }

    // 2. Sections.
    let mut image_end = 0u64;
    for section in sections.iter() {
        let (off, size) = section.pe_file_range();
        if size == 0 {
            continue;
        }
        image_end = image_end.max(u64::from(off) + u64::from(size));
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        if let Some(bytes) = data.get(off as usize..(off as usize).saturating_add(size as usize)) {
            out.push(Resource::new(
                ResourceKind::Section,
                format!("section_{}", name.trim_start_matches('.')),
                "bin",
                Some(u64::from(off)),
                bytes.to_vec(),
            ));
        }
    }

    // 3. Overlay (bytes after the last section).
    if (image_end as usize) < data.len() {
        let overlay = &data[image_end as usize..];
        covered.push((image_end as usize, data.len()));
        out.push(Resource::new(
            ResourceKind::Overlay,
            "overlay",
            "bin",
            Some(image_end),
            overlay.to_vec(),
        ));
    }
}

/// Classifies one native resource and pushes it (icons are collected to rebuild `.ico` files).
fn emit_resource(
    type_id: u16,
    id: u16,
    bytes: &[u8],
    offset: Option<u64>,
    out: &mut Vec<Resource>,
    icons: &mut Vec<Vec<u8>>,
) {
    match type_id {
        RT_ICON => icons.push(wrap_icon(bytes)),
        RT_BITMAP => out.push(Resource::new(
            ResourceKind::Resource,
            format!("bitmap_{id}"),
            "bmp",
            offset,
            wrap_bmp(bytes),
        )),
        RT_MANIFEST => out.push(Resource::new(
            ResourceKind::Resource,
            format!("manifest_{id}"),
            "manifest",
            offset,
            bytes.to_vec(),
        )),
        RT_VERSION => {
            let text = utf16_strings(bytes).join("\n");
            out.push(Resource::new(
                ResourceKind::Resource,
                format!("version_{id}"),
                "txt",
                offset,
                text.into_bytes(),
            ));
        }
        RT_STRING => {
            let text = string_table(bytes);
            if !text.is_empty() {
                out.push(Resource::new(
                    ResourceKind::Resource,
                    format!("strings_{id}"),
                    "txt",
                    offset,
                    text.into_bytes(),
                ));
            }
        }
        RT_HTML => out.push(Resource::new(
            ResourceKind::Resource,
            format!("html_{id}"),
            "html",
            offset,
            bytes.to_vec(),
        )),
        other => {
            let base = match other {
                RT_RCDATA => "rcdata",
                RT_GROUP_ICON => "group_icon",
                RT_GROUP_CURSOR => "group_cursor",
                RT_CURSOR => "cursor",
                RT_MENU => "menu",
                RT_DIALOG => "dialog",
                _ => "resource",
            };
            out.push(Resource::new(
                ResourceKind::Resource,
                format!("{base}_{id}"),
                "bin",
                offset,
                bytes.to_vec(),
            ));
        }
    }
}

/// Wraps a single RT_ICON image (a DIB or PNG) in a one-image `.ico` container.
fn wrap_icon(payload: &[u8]) -> Vec<u8> {
    let (mut w, mut h, mut bits) = (0u8, 0u8, 0u16);
    if payload.len() >= 40
        && u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) == 40
    {
        let biw = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let bih = i32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        bits = u16::from_le_bytes([payload[14], payload[15]]);
        w = (biw & 0xff) as u8;
        h = ((bih / 2) & 0xff) as u8; // icon DIB height counts the AND mask twice
    }
    let mut ico = Vec::with_capacity(22 + payload.len());
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // ICONDIR: reserved, type=1, count=1
    ico.push(w);
    ico.push(h);
    ico.push(0); // color count
    ico.push(0); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // planes
    ico.extend_from_slice(&bits.to_le_bytes()); // bit count
    ico.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // bytes in resource
    ico.extend_from_slice(&22u32.to_le_bytes()); // offset to image
    ico.extend_from_slice(payload);
    ico
}

/// Prepends a 14-byte `BITMAPFILEHEADER` to a DIB so RT_BITMAP data opens as a `.bmp`.
fn wrap_bmp(dib: &[u8]) -> Vec<u8> {
    let mut pixel_offset = 14u32;
    if dib.len() >= 40 {
        let header_size = u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]);
        let bit_count = u16::from_le_bytes([dib[14], dib[15]]);
        let mut clr_used = u32::from_le_bytes([dib[32], dib[33], dib[34], dib[35]]);
        if clr_used == 0 && bit_count <= 8 {
            clr_used = 1 << bit_count;
        }
        pixel_offset = 14 + header_size + clr_used * 4;
    }
    let file_size = 14u32.saturating_add(dib.len() as u32);
    let mut bmp = Vec::with_capacity(14 + dib.len());
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes()); // reserved
    bmp.extend_from_slice(&pixel_offset.to_le_bytes());
    bmp.extend_from_slice(dib);
    bmp
}

/// Decodes an RT_STRING block: 16 UTF-16LE strings, each a u16 length then that many code units.
fn string_table(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    for _ in 0..16 {
        if i + 2 > bytes.len() {
            break;
        }
        let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
        i += 2;
        if len == 0 {
            continue;
        }
        let end = (i + len * 2).min(bytes.len());
        let s = utf16_to_string(&bytes[i..end]);
        i = end;
        if !s.trim().is_empty() {
            out.push_str(s.trim());
            out.push('\n');
        }
    }
    out
}

/// Pulls printable UTF-16LE runs (length >= 3) out of a blob — a pragmatic read of version info.
fn utf16_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        i += 2;
        match char::from_u32(u32::from(c)) {
            Some(ch) if !ch.is_control() => cur.push(ch),
            _ => {
                if cur.trim().chars().count() >= 3 {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
        }
    }
    if cur.trim().chars().count() >= 3 {
        out.push(cur.trim().to_string());
    }
    out
}

fn utf16_to_string(bytes: &[u8]) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&units)
}

// --- signature carving -----------------------------------------------------

/// A magic-byte signature for an embedded file.
struct Sig {
    magic: &'static [u8],
    ext: &'static str,
    name: &'static str,
}

const SIGS: &[Sig] = &[
    Sig {
        magic: b"\x89PNG\r\n\x1a\n",
        ext: "png",
        name: "png",
    },
    Sig {
        magic: b"\xff\xd8\xff",
        ext: "jpg",
        name: "jpeg",
    },
    Sig {
        magic: b"GIF87a",
        ext: "gif",
        name: "gif",
    },
    Sig {
        magic: b"GIF89a",
        ext: "gif",
        name: "gif",
    },
    Sig {
        magic: b"BM",
        ext: "bmp",
        name: "bmp",
    },
    Sig {
        magic: b"RIFF",
        ext: "wav",
        name: "riff",
    },
    Sig {
        magic: b"PK\x03\x04",
        ext: "zip",
        name: "zip",
    },
    Sig {
        magic: b"\x1f\x8b\x08",
        ext: "gz",
        name: "gzip",
    },
    Sig {
        magic: b"%PDF",
        ext: "pdf",
        name: "pdf",
    },
    Sig {
        magic: b"7z\xbc\xaf\x27\x1c",
        ext: "7z",
        name: "7z",
    },
    Sig {
        magic: b"Rar!\x1a\x07",
        ext: "rar",
        name: "rar",
    },
    Sig {
        magic: b"OggS",
        ext: "ogg",
        name: "ogg",
    },
    Sig {
        magic: b"fLaC",
        ext: "flac",
        name: "flac",
    },
    Sig {
        magic: b"\x25\x21PS",
        ext: "ps",
        name: "postscript",
    },
];

fn carve(data: &[u8], covered: &[(usize, usize)], out: &mut Vec<Resource>) {
    let mut ranges: Vec<(usize, usize)> = covered.to_vec();
    let mut found = 0usize;
    for sig in SIGS {
        for pos in memchr::memmem::find_iter(data, sig.magic) {
            // Skip offset 0 (that is the host file itself) and anything inside an already
            // reported range (a resource, a section, the overlay, or an earlier carve).
            if pos == 0 || ranges.iter().any(|&(s, e)| pos >= s && pos < e) {
                continue;
            }
            let Some(end) = carve_end(sig, data, pos) else {
                continue;
            };
            if end <= pos || end - pos > MAX_ITEM {
                continue;
            }
            ranges.push((pos, end));
            out.push(Resource::new(
                ResourceKind::Embedded,
                format!("{}_{:x}", sig.name, pos),
                sig.ext,
                Some(pos as u64),
                data[pos..end].to_vec(),
            ));
            found += 1;
            if found >= MAX_ITEMS {
                return;
            }
        }
    }
}

/// Best-effort end offset of an embedded file starting at `pos`.
fn carve_end(sig: &Sig, data: &[u8], pos: usize) -> Option<usize> {
    let rest = &data[pos..];
    match sig.ext {
        "png" => memchr::memmem::find(rest, b"IEND").map(|i| pos + i + 8),
        "jpg" => memchr::memmem::find(&rest[2..], b"\xff\xd9").map(|i| pos + 2 + i + 2),
        "pdf" => rfind(rest, b"%%EOF").map(|i| pos + i + 5),
        "gif" => rest.iter().position(|&b| b == 0x3b).map(|i| pos + i + 1),
        "bmp" => read_u32(rest, 2)
            .map(|n| pos + n as usize)
            .filter(|&e| e <= data.len()),
        "wav" => {
            if rest.len() < 12 || &rest[8..12] != b"WAVE" {
                return None;
            }
            read_u32(rest, 4)
                .map(|n| pos + 8 + n as usize)
                .filter(|&e| e <= data.len())
        }
        "zip" => zip_end(rest).map(|n| pos + n),
        _ => Some((pos + CARVE_FALLBACK).min(data.len())),
    }
}

/// End of a ZIP: locate the End Of Central Directory record (PK\x05\x06) and add its comment.
fn zip_end(rest: &[u8]) -> Option<usize> {
    let eocd = rfind(rest, b"PK\x05\x06")?;
    let comment_len = read_u16(rest, eocd + 20)? as usize;
    Some((eocd + 22 + comment_len).min(rest.len()))
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::rfind(hay, needle)
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_table_decodes_utf16() {
        // Two strings "hi" and "yo" in one RT_STRING block.
        let mut b = Vec::new();
        for s in ["hi", "yo"] {
            b.extend_from_slice(&(s.len() as u16).to_le_bytes());
            for ch in s.encode_utf16() {
                b.extend_from_slice(&ch.to_le_bytes());
            }
        }
        let text = string_table(&b);
        assert!(text.contains("hi") && text.contains("yo"));
    }

    #[test]
    fn carve_finds_embedded_png_and_zip() {
        let mut data = vec![0u8; 64]; // some header-ish filler
        let png_start = data.len();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(b"IEND\xae\x42\x60\x82"); // IEND + CRC
        let after_png = data.len();
        // A tiny ZIP: a local-file-header signature, then the EOCD record (comment length 0).
        let zip_start = data.len();
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 18]); // disk numbers … + comment length 0
        let mut out = Vec::new();
        carve(&data, &[], &mut out);
        let png = out.iter().find(|r| r.ext == "png").expect("png carved");
        assert_eq!(png.offset, Some(png_start as u64));
        assert_eq!(png.data.len(), after_png - png_start);
        assert!(
            out.iter()
                .any(|r| r.ext == "zip" && r.offset == Some(zip_start as u64))
        );
    }

    #[test]
    fn wrap_bmp_adds_a_file_header() {
        let mut dib = vec![40, 0, 0, 0]; // biSize = 40
        dib.extend_from_slice(&[0u8; 36]);
        let bmp = wrap_bmp(&dib);
        assert_eq!(&bmp[..2], b"BM");
        assert_eq!(bmp.len(), dib.len() + 14);
    }

    #[test]
    fn write_all_writes_files_and_manifest() {
        let dir = std::env::temp_dir().join(format!("orress-res-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let res = vec![Resource::new(
            ResourceKind::Embedded,
            "png_0",
            "png",
            Some(0),
            vec![1, 2, 3],
        )];
        let written = write_all(&res, &dir).expect("write");
        assert_eq!(written.len(), 1);
        assert!(dir.join("export_manifest.txt").exists());
        assert_eq!(std::fs::read(&written[0]).unwrap(), vec![1, 2, 3]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
