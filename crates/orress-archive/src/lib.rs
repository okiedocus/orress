//! A pure-Rust ZIP archive reader for ORRESS — the basis for JAR (Java), APK (Android) and the
//! many ZIP-based container formats. It reads the central directory to list entries and extracts
//! stored (method 0) or deflated (method 8) members (deflate via `miniz_oxide`). It never runs
//! anything and tolerates hostile input (bounded sizes, errors instead of panics).
//!
//! Scope: standard ZIP and ZIP64 (the 64-bit end-of-directory record and the per-entry `0x0001`
//! extra field). Other compression methods are listed but not decompressed, and encrypted
//! members are reported as such rather than inflated as ciphertext.

const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
/// The fixed part of a central-directory record; real entries are at least this long.
const CEN_LEN: usize = 46;
const CEN_SIG: u32 = 0x0201_4b50;
const LOC_SIG: u32 = 0x0403_4b50;
/// Cap on a single extracted member, so a crafted header can't exhaust memory.
const MAX_EXTRACT: usize = 512 * 1024 * 1024;

/// One archive member (from the central directory).
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    /// Compression method: 0 = stored, 8 = deflate (others are listed but not extractable).
    pub method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub local_header_offset: u64,
    /// General-purpose bit flags (bit 0 = encrypted).
    pub flags: u16,
}

impl Entry {
    /// True if the member is encrypted (traditional PKWARE or strong encryption).
    pub fn is_encrypted(&self) -> bool {
        self.flags & 1 != 0
    }
    /// A directory entry (its name ends with `/`).
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
    /// A human name for the compression method.
    pub fn method_name(&self) -> &'static str {
        match self.method {
            0 => "store",
            8 => "deflate",
            12 => "bzip2",
            14 => "lzma",
            93 => "zstd",
            _ => "other",
        }
    }
}

/// A parsed ZIP archive borrowing the file bytes.
pub struct Archive<'a> {
    data: &'a [u8],
    pub entries: Vec<Entry>,
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off.checked_add(8)?)
        .map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
}

/// Reads the ZIP64 end-of-central-directory record via its locator (just before the EOCD).
/// Returns `(total entries, central directory size, central directory offset)`.
fn zip64_eocd(data: &[u8], eocd: usize) -> Result<(u64, u64, u64), String> {
    let loc = eocd
        .checked_sub(20)
        .filter(|&l| u32_at(data, l) == Some(ZIP64_LOCATOR_SIG))
        .ok_or("ZIP64 archive without a ZIP64 end-of-directory locator")?;
    let rec = usize::try_from(u64_at(data, loc + 8).ok_or("truncated ZIP64 locator")?)
        .map_err(|_| "ZIP64 record offset out of range")?;
    if u32_at(data, rec) != Some(ZIP64_EOCD_SIG) {
        return Err("bad ZIP64 end-of-central-directory record".into());
    }
    let total = u64_at(data, rec + 32).ok_or("truncated ZIP64 record")?;
    let cd_size = u64_at(data, rec + 40).ok_or("truncated ZIP64 record")?;
    let cd_offset = u64_at(data, rec + 48).ok_or("truncated ZIP64 record")?;
    Ok((total, cd_size, cd_offset))
}

/// Applies a central-directory entry's ZIP64 extended-information extra field (id `0x0001`):
/// it holds a `u64` for each of uncompressed size, compressed size and local-header offset —
/// in that order, and only for the fields whose 32-bit value is the `0xFFFFFFFF` sentinel.
fn apply_zip64_extra(extra: &[u8], uncomp: &mut u64, comp: &mut u64, lho: &mut u64) {
    let mut p = 0;
    while let (Some(id), Some(len)) = (u16_at(extra, p), u16_at(extra, p + 2)) {
        let body_start = p + 4;
        let body = extra
            .get(body_start..body_start + len as usize)
            .unwrap_or(&[]);
        if id == 0x0001 {
            let mut q = 0;
            for field in [uncomp, comp, lho] {
                if *field == 0xFFFF_FFFF {
                    let Some(v) = u64_at(body, q) else {
                        return;
                    };
                    *field = v;
                    q += 8;
                }
            }
            return;
        }
        p = body_start + len as usize;
    }
}

/// True if `data` looks like a ZIP (local-file or empty-archive signature at the start).
pub fn looks_like_zip(data: &[u8]) -> bool {
    matches!(u32_at(data, 0), Some(LOC_SIG) | Some(EOCD_SIG))
}

impl<'a> Archive<'a> {
    /// Opens an archive, reading its central directory.
    pub fn open(data: &'a [u8]) -> Result<Self, String> {
        let eocd =
            find_eocd(data).ok_or("not a ZIP archive (no end-of-central-directory record)")?;
        let cd_entries = u16_at(data, eocd + 8).ok_or("truncated EOCD")?;
        let total16 = u16_at(data, eocd + 10).ok_or("truncated EOCD")?;
        let cd_size32 = u32_at(data, eocd + 12).ok_or("truncated EOCD")?;
        let cd_offset32 = u32_at(data, eocd + 16).ok_or("truncated EOCD")?;

        // Any sentinel means the real values live in the ZIP64 end-of-directory record.
        let (total, cd_size, cd_offset) = if total16 == 0xFFFF
            || cd_entries == 0xFFFF
            || cd_size32 == 0xFFFF_FFFF
            || cd_offset32 == 0xFFFF_FFFF
        {
            zip64_eocd(data, eocd)?
        } else {
            (
                u64::from(total16),
                u64::from(cd_size32),
                u64::from(cd_offset32),
            )
        };

        // Each record is at least 46 bytes, so the directory size bounds the entry count (and the
        // file size bounds the directory) — a hostile count can't drive a huge allocation.
        let max_entries = cd_size.min(data.len() as u64) / CEN_LEN as u64;
        let total = total.min(max_entries) as usize;
        let mut entries = Vec::with_capacity(total.min(1 << 16));
        let mut p = usize::try_from(cd_offset).map_err(|_| "central directory out of range")?;
        for _ in 0..total {
            if u32_at(data, p) != Some(CEN_SIG) {
                break; // Tolerate a short/garbled directory.
            }
            let flags = u16_at(data, p + 8).ok_or("truncated central directory")?;
            let method = u16_at(data, p + 10).ok_or("truncated central directory")?;
            let crc32 = u32_at(data, p + 16).ok_or("truncated central directory")?;
            let mut comp = u32_at(data, p + 20).ok_or("truncated central directory")? as u64;
            let mut uncomp = u32_at(data, p + 24).ok_or("truncated central directory")? as u64;
            let name_len = u16_at(data, p + 28).ok_or("truncated central directory")? as usize;
            let extra_len = u16_at(data, p + 30).ok_or("truncated central directory")? as usize;
            let comment_len = u16_at(data, p + 32).ok_or("truncated central directory")? as usize;
            let mut lho = u32_at(data, p + 42).ok_or("truncated central directory")? as u64;
            let name_end = p + CEN_LEN + name_len;
            let name_bytes = data
                .get(p + CEN_LEN..name_end)
                .ok_or("truncated entry name")?;
            if comp == 0xFFFF_FFFF || uncomp == 0xFFFF_FFFF || lho == 0xFFFF_FFFF {
                let extra = data
                    .get(name_end..name_end + extra_len)
                    .ok_or("truncated extra field")?;
                apply_zip64_extra(extra, &mut uncomp, &mut comp, &mut lho);
            }
            entries.push(Entry {
                name: String::from_utf8_lossy(name_bytes).into_owned(),
                method,
                compressed_size: comp,
                uncompressed_size: uncomp,
                crc32,
                local_header_offset: lho,
                flags,
            });
            p = name_end + extra_len + comment_len;
        }

        Ok(Archive { data, entries })
    }

    /// Finds an entry by exact name.
    pub fn by_name(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Extracts (decompresses) a member's bytes.
    pub fn read(&self, entry: &Entry) -> Result<Vec<u8>, String> {
        if entry.is_encrypted() {
            return Err(format!(
                "`{}` is encrypted (password-protected); ORRESS does not decrypt ZIP members",
                entry.name
            ));
        }
        let lho = usize::try_from(entry.local_header_offset)
            .map_err(|_| "local header offset out of range")?;
        if u32_at(self.data, lho) != Some(LOC_SIG) {
            return Err("bad local file header".into());
        }
        let name_len = u16_at(self.data, lho + 26).ok_or("truncated local header")? as usize;
        let extra_len = u16_at(self.data, lho + 28).ok_or("truncated local header")? as usize;
        let start = lho + 30 + name_len + extra_len;
        let raw = usize::try_from(entry.compressed_size)
            .ok()
            .and_then(|comp| start.checked_add(comp))
            .and_then(|end| self.data.get(start..end))
            .ok_or("compressed data out of bounds")?;

        match entry.method {
            0 if raw.len() > MAX_EXTRACT => Err("stored member too large to extract".into()),
            0 => Ok(raw.to_vec()),
            8 => {
                let limit = usize::try_from(entry.uncompressed_size)
                    .unwrap_or(MAX_EXTRACT)
                    .clamp(1, MAX_EXTRACT);
                miniz_oxide::inflate::decompress_to_vec_with_limit(raw, limit)
                    .map_err(|e| format!("deflate failed: {e:?}"))
            }
            m => Err(format!("compression method {m} not supported")),
        }
    }
}

/// Scans backward for the end-of-central-directory signature (allowing a trailing comment).
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    // The EOCD is the last 22 bytes plus an optional comment of up to 65535 bytes.
    let last = data.len() - 22;
    let min = last.saturating_sub(0xFFFF);
    (min..=last)
        .rev()
        .find(|&off| u32_at(data, off) == Some(EOCD_SIG))
}

/// Parses a JAR/`MANIFEST.MF` into `(key, value)` pairs, joining 72-column continuation lines
/// (which start with a single space).
pub fn parse_manifest(bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(bytes);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(cont) = line.strip_prefix(' ') {
            if let Some(last) = out.last_mut() {
                last.1.push_str(cont);
            }
        } else if let Some((k, v)) = line.split_once(": ") {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests;
