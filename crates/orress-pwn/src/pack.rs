//! Integer packing and unpacking, the pwntools `p*`/`u*` primitives everything else is built on.

/// Byte order for packing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Packs the low `width` bytes of `value` (1, 2, 4 or 8) in the given byte order.
pub fn pack(value: u64, width: usize, endian: Endian) -> Vec<u8> {
    let width = width.min(8);
    let mut out = value.to_le_bytes()[..width].to_vec();
    if endian == Endian::Big {
        out.reverse();
    }
    out
}

/// Unpacks up to 8 bytes into a `u64` in the given byte order (shorter input is zero-extended).
pub fn unpack(bytes: &[u8], endian: Endian) -> u64 {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    match endian {
        Endian::Little => buf[..n].copy_from_slice(&bytes[..n]),
        Endian::Big => {
            for (i, b) in bytes[..n].iter().rev().enumerate() {
                buf[i] = *b;
            }
        }
    }
    u64::from_le_bytes(buf)
}

pub fn p8(v: u64) -> Vec<u8> {
    pack(v, 1, Endian::Little)
}
pub fn p16(v: u64) -> Vec<u8> {
    pack(v, 2, Endian::Little)
}
pub fn p32(v: u64) -> Vec<u8> {
    pack(v, 4, Endian::Little)
}
pub fn p64(v: u64) -> Vec<u8> {
    pack(v, 8, Endian::Little)
}

pub fn u8v(b: &[u8]) -> u64 {
    unpack(&b[..b.len().min(1)], Endian::Little)
}
pub fn u16v(b: &[u8]) -> u64 {
    unpack(&b[..b.len().min(2)], Endian::Little)
}
pub fn u32v(b: &[u8]) -> u64 {
    unpack(&b[..b.len().min(4)], Endian::Little)
}
pub fn u64v(b: &[u8]) -> u64 {
    unpack(&b[..b.len().min(8)], Endian::Little)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_round_trips() {
        assert_eq!(p64(0x0102030405060708), vec![8, 7, 6, 5, 4, 3, 2, 1]); // little-endian
        assert_eq!(p32(0xdeadbeef), vec![0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(
            pack(0xdeadbeef, 4, Endian::Big),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(u64v(&p64(0x1122334455667788)), 0x1122334455667788);
        assert_eq!(u32v(&[0xef, 0xbe, 0xad, 0xde]), 0xdeadbeef);
        assert_eq!(unpack(&[0xde, 0xad, 0xbe, 0xef], Endian::Big), 0xdeadbeef);
    }
}
