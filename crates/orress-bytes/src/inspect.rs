//! The data inspector: the same bytes read as many different types. Reverse engineers
//! constantly ask "what is this value?"; this answers every common possibility at once.

use crate::Endian;

#[derive(Clone, Debug, PartialEq)]
pub struct Interpretation {
    pub label: &'static str,
    pub value: String,
    pub explain: &'static str,
}

fn arr<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.get(..N)?.try_into().ok()
}

macro_rules! int {
    ($bytes:expr, $endian:expr, $t:ty) => {
        arr::<{ std::mem::size_of::<$t>() }>($bytes).map(|a| match $endian {
            Endian::Little => <$t>::from_le_bytes(a),
            Endian::Big => <$t>::from_be_bytes(a),
        })
    };
}

/// Interprets the bytes starting at the cursor. Entries whose type needs more bytes
/// than are available are left out.
pub fn interpret(bytes: &[u8], endian: Endian) -> Vec<Interpretation> {
    let mut out = Vec::new();
    let mut add = |label, value: Option<String>, explain| {
        if let Some(value) = value {
            out.push(Interpretation {
                label,
                value,
                explain,
            });
        }
    };

    let b0 = bytes.first().copied();
    add(
        "binary",
        b0.map(|b| format!("{b:08b}")),
        "The byte as 8 bits. Useful for flags, where each bit means something on its own.",
    );
    add(
        "u8 / i8",
        b0.map(|b| format!("{b} / {}", b as i8)),
        "One byte as an unsigned number (0–255) and as a signed number (-128–127). \
         Signed numbers use two's complement: values from 0x80 up are negative.",
    );
    add(
        "char",
        b0.map(|b| match b {
            0x20..=0x7e => format!("'{}'", b as char),
            0 => "NUL (string terminator)".into(),
            b'\n' => "'\\n' (newline)".into(),
            b'\r' => "'\\r' (carriage return)".into(),
            b'\t' => "'\\t' (tab)".into(),
            _ => "not printable".into(),
        }),
        "The byte as an ASCII character. C strings end with a 0 byte (NUL).",
    );
    add(
        "u16 / i16",
        int!(bytes, endian, u16).map(|v| format!("{v} / {}", v as i16)),
        "Two bytes as one number (a C `short`).",
    );
    add(
        "u32 / i32",
        int!(bytes, endian, u32).map(|v| format!("{v} / {} (0x{v:08X})", v as i32)),
        "Four bytes as one number (a C `int`). The most common size for counters, \
         lengths and 32-bit addresses.",
    );
    add(
        "u64 / i64",
        int!(bytes, endian, u64).map(|v| format!("{v} / {}", v as i64)),
        "Eight bytes as one number (a C `long long`), also the size of a 64-bit pointer.",
    );
    add(
        "pointer (64-bit)",
        int!(bytes, endian, u64).map(|v| format!("0x{v:016X}")),
        "If this is an address in a 64-bit program, it points here.",
    );
    add(
        "f32",
        int!(bytes, endian, u32).map(|v| format_float(f64::from(f32::from_bits(v)))),
        "Four bytes as a floating-point number (a C `float`).",
    );
    add(
        "f64",
        int!(bytes, endian, u64).map(|v| format_float(f64::from_bits(v))),
        "Eight bytes as a floating-point number (a C `double`).",
    );
    add(
        "UTF-8",
        utf8_char(bytes),
        "The character encoded at this position in UTF-8, the encoding of most text \
         files and Linux programs. Characters take 1 to 4 bytes.",
    );
    add(
        "UTF-16",
        int!(bytes, endian, u16).map(|v| match char::from_u32(u32::from(v)) {
            Some(c) if !c.is_control() => format!("'{c}' (U+{v:04X})"),
            _ => format!("U+{v:04X} (not printable)"),
        }),
        "The character in UTF-16, the encoding Windows uses for \"wide\" strings: \
         ASCII letters followed by a 0 byte.",
    );
    add(
        "Unix time",
        int!(bytes, endian, u32).and_then(|v| unix_time(i64::from(v))),
        "Seconds since 1970-01-01 UTC. Used in ELF/PE headers (the PE compile time) \
         and everywhere on Linux. Only shown for plausible dates (1990–2040).",
    );
    add(
        "FILETIME",
        int!(bytes, endian, u64).and_then(filetime),
        "Windows timestamp: 100-nanosecond steps since 1601-01-01 UTC. Found in file \
         metadata, the registry and many Windows structures.",
    );
    add(
        "GUID",
        arr::<16>(bytes).map(|g| guid(&g)),
        "A 16-byte globally unique ID, as used by COM objects and Windows APIs. The \
         first three groups are little-endian.",
    );
    out
}

fn format_float(v: f64) -> String {
    if v.is_finite() && v != 0.0 && (v.abs() < 1e-6 || v.abs() >= 1e15) {
        format!("{v:e}")
    } else {
        format!("{v}")
    }
}

fn utf8_char(bytes: &[u8]) -> Option<String> {
    let first = *bytes.first()?;
    let len = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return Some("continuation or invalid byte".into()),
    };
    let s = std::str::from_utf8(bytes.get(..len)?).ok()?;
    let c = s.chars().next()?;
    Some(if c.is_control() {
        format!("U+{:04X} (control)", c as u32)
    } else {
        format!(
            "'{c}' (U+{:04X}, {len} byte{})",
            c as u32,
            if len == 1 { "" } else { "s" }
        )
    })
}

/// Converts days since 1970-01-01 to a calendar date (proleptic Gregorian).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

pub fn format_unix(secs: i64) -> String {
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn plausible(secs: i64) -> bool {
    // 1990-01-01 .. 2040-01-01
    (631_152_000..2_208_988_800).contains(&secs)
}

fn unix_time(secs: i64) -> Option<String> {
    plausible(secs).then(|| format_unix(secs))
}

fn filetime(v: u64) -> Option<String> {
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = i64::try_from(v / 10_000_000).ok()? - EPOCH_DIFF;
    unix_time(secs)
}

fn guid(g: &[u8; 16]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(items: &[Interpretation], label: &str) -> Option<String> {
        items
            .iter()
            .find(|i| i.label == label)
            .map(|i| i.value.clone())
    }

    #[test]
    fn integers_respect_endianness() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        let le = interpret(&bytes, Endian::Little);
        let be = interpret(&bytes, Endian::Big);
        assert_eq!(value(&le, "u16 / i16").unwrap(), "513 / 513");
        assert_eq!(value(&be, "u16 / i16").unwrap(), "258 / 258");
        assert!(value(&le, "u32 / i32").unwrap().contains("0x04030201"));
        assert_eq!(value(&le, "u64 / i64"), None, "only 4 bytes available");
    }

    #[test]
    fn signed_and_chars() {
        let items = interpret(&[0xff], Endian::Little);
        assert_eq!(value(&items, "u8 / i8").unwrap(), "255 / -1");
        assert_eq!(value(&items, "binary").unwrap(), "11111111");
        assert_eq!(
            value(&interpret(b"A", Endian::Little), "char").unwrap(),
            "'A'"
        );
        assert!(
            value(&interpret("é".as_bytes(), Endian::Little), "UTF-8")
                .unwrap()
                .contains("'é'")
        );
    }

    #[test]
    fn timestamps() {
        assert_eq!(format_unix(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_unix(1_700_000_000), "2023-11-14 22:13:20 UTC");
        // 2023-11-14 22:13:20 as FILETIME
        let ft: u64 = (1_700_000_000 + 11_644_473_600) * 10_000_000;
        assert_eq!(filetime(ft).unwrap(), "2023-11-14 22:13:20 UTC");
        assert_eq!(unix_time(5), None);
    }

    #[test]
    fn guid_format() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        assert_eq!(guid(&g), "{12345678-1234-5678-9ABC-DEF012345678}");
    }
}
