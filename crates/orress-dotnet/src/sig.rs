//! Decodes ECMA-335 method signature blobs (`#Blob` heap) into readable return/parameter types.
//! A signature is a calling-convention byte, an optional generic-parameter count, a parameter
//! count, then the return type and each parameter type — each a recursive `ELEMENT_TYPE_*` form.

/// A decoded method signature.
pub struct MethodSig {
    pub ret: String,
    pub params: Vec<String>,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }

    /// ECMA-335 compressed unsigned integer.
    fn cuint(&mut self) -> Option<u32> {
        let b0 = self.u8()? as u32;
        if b0 & 0x80 == 0 {
            Some(b0)
        } else if b0 & 0xC0 == 0x80 {
            let b1 = self.u8()? as u32;
            Some(((b0 & 0x3f) << 8) | b1)
        } else {
            let b1 = self.u8()? as u32;
            let b2 = self.u8()? as u32;
            let b3 = self.u8()? as u32;
            Some(((b0 & 0x1f) << 24) | (b1 << 16) | (b2 << 8) | b3)
        }
    }

    /// A `TypeDefOrRef` coded token (2 tag bits select the table).
    fn ctoken(&mut self) -> Option<(u8, u32)> {
        let v = self.cuint()?;
        let table = match v & 3 {
            0 => 0x02, // TypeDef
            1 => 0x01, // TypeRef
            2 => 0x1b, // TypeSpec
            _ => return None,
        };
        Some((table, v >> 2))
    }
}

/// Decodes a method signature blob. `resolve` turns a `(table, row)` type reference into a name.
pub fn decode_method(bytes: &[u8], resolve: &impl Fn(u8, u32) -> String) -> Option<MethodSig> {
    let mut c = Cursor { b: bytes, i: 0 };
    let cc = c.u8()?;
    if cc & 0x10 != 0 {
        c.cuint()?; // generic parameter count
    }
    let nparams = c.cuint()? as usize;
    let ret = read_type(&mut c, resolve, 0)?;
    let mut params = Vec::new();
    for _ in 0..nparams.min(1024) {
        match read_type(&mut c, resolve, 0) {
            Some(t) => params.push(t),
            None => break,
        }
    }
    Some(MethodSig { ret, params })
}

fn read_type(c: &mut Cursor, resolve: &impl Fn(u8, u32) -> String, depth: u32) -> Option<String> {
    if depth > 32 {
        return Some("…".into());
    }
    let et = c.u8()?;
    Some(match et {
        0x01 => "void".into(),
        0x02 => "bool".into(),
        0x03 => "char".into(),
        0x04 => "sbyte".into(),
        0x05 => "byte".into(),
        0x06 => "short".into(),
        0x07 => "ushort".into(),
        0x08 => "int".into(),
        0x09 => "uint".into(),
        0x0a => "long".into(),
        0x0b => "ulong".into(),
        0x0c => "float".into(),
        0x0d => "double".into(),
        0x0e => "string".into(),
        0x16 => "TypedReference".into(),
        0x18 => "IntPtr".into(),
        0x19 => "UIntPtr".into(),
        0x1c => "object".into(),
        0x0f => format!("{}*", read_type(c, resolve, depth + 1)?), // PTR
        0x10 => format!("ref {}", read_type(c, resolve, depth + 1)?), // BYREF
        0x1d => format!("{}[]", read_type(c, resolve, depth + 1)?), // SZARRAY
        0x11 | 0x12 => {
            // VALUETYPE / CLASS
            let (table, row) = c.ctoken()?;
            resolve(table, row)
        }
        0x13 => format!("!{}", c.cuint()?), // VAR (class generic param)
        0x1e => format!("!!{}", c.cuint()?), // MVAR (method generic param)
        0x15 => {
            // GENERICINST <type> <argc> <args…>
            let base = read_type(c, resolve, depth + 1)?;
            let argc = c.cuint()? as usize;
            let args: Vec<String> = (0..argc.min(64))
                .map(|_| read_type(c, resolve, depth + 1).unwrap_or_else(|| "?".into()))
                .collect();
            format!("{base}<{}>", args.join(", "))
        }
        0x14 => {
            // ARRAY <type> <rank> <numsizes> sizes… <numlobounds> lobounds…
            let t = read_type(c, resolve, depth + 1)?;
            let rank = c.cuint()?;
            let nsizes = c.cuint()? as usize;
            for _ in 0..nsizes.min(64) {
                c.cuint();
            }
            let nlo = c.cuint()? as usize;
            for _ in 0..nlo.min(64) {
                c.cuint();
            }
            format!("{t}[{}]", ",".repeat(rank.saturating_sub(1) as usize))
        }
        // Custom modifiers / pinned / sentinel: skip and continue to the real type.
        0x1f | 0x20 => {
            c.ctoken()?;
            read_type(c, resolve, depth + 1)?
        }
        0x41 | 0x45 => read_type(c, resolve, depth + 1)?,
        0x1b => "fnptr".into(), // FNPTR (signature not expanded)
        other => format!("type#{other:#x}"),
    })
}
