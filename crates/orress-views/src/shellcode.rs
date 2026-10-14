//! The Shellcode workbench: a triage view for a raw code blob an analyst has captured. It
//! decodes the blob (hex / base64 / C array / escaped bytes), lists its disassembly, and runs
//! it in the `orress-emu` sandbox to observe its effects. Read-only inspection of bytes the
//! user supplies; nothing here is executed on the host.

use egui::{RichText, Ui};
use orress_arch::Isa;
use orress_emu::Emulator;
use orress_ui::muted;

/// The address the blob is loaded at for disassembly and emulation.
const BASE: u64 = 0x1_0000;

/// Persistent UI state for the Shellcode tab.
#[derive(Default)]
pub struct ShellcodeView {
    input: String,
    decoded: Vec<u8>,
    message: String,
    run: Option<String>,
    hashes: Option<Vec<crate::apihash::HashMatch>>,
}

/// Decodes a pasted blob: a C/escaped array (`0x..`, `\x..`), plain hex, or base64.
///
/// The forms are tried strictly, so one cannot be misread as another: if the text has any
/// `0x`/`\x` tokens, only those tokens count (the rest is C syntax like `unsigned char
/// buf[]`); otherwise the text must be hex digits and separators only; otherwise base64.
pub fn decode_blob(text: &str) -> Result<Vec<u8>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("Paste a blob of bytes to inspect.".into());
    }
    if let Some(bytes) = prefixed_hex_bytes(t) {
        return Ok(bytes);
    }
    if let Some(bytes) = plain_hex(t) {
        return Ok(bytes);
    }
    base64_decode(t).map_err(|()| "Could not read this as hex, a C array, or base64.".into())
}

/// The bytes of every `0x..` / `\x..` token (one or two hex digits each), or `None` if the
/// text has no such token.
fn prefixed_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let prefix = matches!(bytes[i], b'0' | b'\\') && (bytes[i + 1] | 0x20) == b'x';
        // `0x` must start a token: the `0` of `10x3` is not a prefix.
        let starts = bytes[i] == b'\\' || i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if !(prefix && starts) {
            i += 1;
            continue;
        }
        let digits = bytes[i + 2..]
            .iter()
            .take(2)
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        if digits > 0 {
            let token = std::str::from_utf8(&bytes[i + 2..i + 2 + digits]).ok()?;
            out.push(u8::from_str_radix(token, 16).ok()?);
        }
        i += 2 + digits;
    }
    (!out.is_empty()).then_some(out)
}

/// Decodes text made only of hex digit pairs and separators (whitespace, `,` and `:`).
fn plain_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b',' && *b != b':')
        .collect();
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let clean: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    if clean.len() < 4 {
        return Err(());
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut acc = 0u32;
        let mut bits = 0u32;
        for &c in chunk {
            let v = rev[c as usize];
            if v == 255 {
                return Err(());
            }
            acc = (acc << 6) | u32::from(v);
            bits += 6;
        }
        acc <<= 32 - bits;
        for k in 0..(bits / 8) {
            out.push((acc >> (24 - k * 8)) as u8);
        }
    }
    Ok(out)
}

/// A disassembled line of the blob.
struct Line {
    offset: usize,
    bytes: String,
    text: String,
}

/// Disassembles the blob as x86-64 starting at [`BASE`].
fn disassemble(blob: &[u8]) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut off = 0usize;
    while off < blob.len() {
        let addr = BASE + off as u64;
        match orress_arch::decode(Isa::X64, &blob[off..], addr) {
            Some(insn) => {
                let len = insn.len as usize;
                let raw: String = blob[off..(off + len).min(blob.len())]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                lines.push(Line {
                    offset: off,
                    bytes: raw,
                    text: insn.text(),
                });
                off += len.max(1);
            }
            None => {
                lines.push(Line {
                    offset: off,
                    bytes: format!("{:02x}", blob[off]),
                    text: "(bad)".into(),
                });
                off += 1;
            }
        }
    }
    lines
}

/// Runs the blob in the emulator sandbox, reporting where it stopped and the register state.
fn emulate(blob: &[u8]) -> String {
    let mut emu = Emulator::new();
    emu.budget = 200_000;
    emu.map(BASE, blob);
    emu.setup_stack();
    emu.cpu.rip = BASE;
    let outcome = match emu.run_until(None) {
        Ok(stop) => format!("{stop:?}"),
        Err(e) => e.to_string(),
    };
    let names = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    ];
    let vals = [
        emu.cpu.regs[0],
        emu.cpu.regs[3],
        emu.cpu.regs[1],
        emu.cpu.regs[2],
        emu.cpu.regs[6],
        emu.cpu.regs[7],
        emu.cpu.regs[5],
        emu.cpu.regs[4],
        emu.cpu.rip,
    ];
    let regs: Vec<String> = names
        .iter()
        .zip(vals)
        .map(|(n, v)| format!("{n}={v:#018x}"))
        .collect();
    format!(
        "ran {} instructions, stopped: {outcome}\n{}",
        emu.steps,
        regs.join("  ")
    )
}

/// The Shellcode workbench tab.
pub fn shellcode_view(ui: &mut Ui, view: &mut ShellcodeView) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Shellcode", ui.max_rect());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Shellcode workbench").strong());
        ui.label(muted("decode · disassemble · emulate (sandboxed)"));
    });
    ui.separator();
    ui.label(muted(
        "Paste a captured code blob as hex, a C array, \\x escapes, or base64.",
    ));
    ui.add(
        egui::TextEdit::multiline(&mut view.input)
            .desired_rows(4)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace)
            .hint_text(r#"\x48\x31\xc0...  or  { 0x48, 0x31, 0xc0 }  or  base64"#),
    );
    ui.horizontal(|ui| {
        if ui.button("Decode").clicked() {
            match decode_blob(&view.input) {
                Ok(b) => {
                    view.message = format!("{} bytes", b.len());
                    view.decoded = b;
                    view.run = None;
                    view.hashes = None;
                }
                Err(e) => {
                    view.message = e;
                    view.decoded.clear();
                }
            }
        }
        if !view.decoded.is_empty() && ui.button("▶ Emulate").clicked() {
            view.run = Some(emulate(&view.decoded));
        }
        if !view.decoded.is_empty()
            && ui
                .button("# API hashes")
                .on_hover_text("Label 32-bit constants that match a known Windows API name hash")
                .clicked()
        {
            view.hashes = Some(crate::apihash::scan(&view.decoded));
        }
        if !view.message.is_empty() {
            ui.label(muted(&view.message));
        }
    });

    if let Some(report) = &view.run {
        ui.add_space(4.0);
        ui.label(RichText::new(report).monospace());
    }

    if let Some(matches) = &view.hashes {
        ui.add_space(4.0);
        if matches.is_empty() {
            ui.label(muted("No API-name-hash constants recognised."));
        } else {
            ui.label(RichText::new("API hashes:").strong());
            for m in matches {
                ui.label(
                    RichText::new(format!(
                        "  +{:#06x}  {:#010x}  {}",
                        m.offset, m.value, m.name
                    ))
                    .monospace(),
                );
            }
        }
    }

    if view.decoded.is_empty() {
        return;
    }
    ui.add_space(6.0);
    ui.separator();
    let lines = disassemble(&view.decoded);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("shellcode-disasm")
                .num_columns(3)
                .striped(true)
                .spacing([16.0, 2.0])
                .show(ui, |ui| {
                    for l in &lines {
                        ui.label(
                            RichText::new(format!("{:#06x}", BASE + l.offset as u64))
                                .monospace()
                                .weak(),
                        );
                        ui.label(RichText::new(&l.bytes).monospace().weak());
                        ui.label(RichText::new(&l.text).monospace());
                        ui.end_row();
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_escaped_hex() {
        assert_eq!(
            decode_blob(r"\x48\x31\xc0").unwrap(),
            vec![0x48, 0x31, 0xc0]
        );
    }

    #[test]
    fn decodes_c_array() {
        assert_eq!(
            decode_blob("{ 0x90, 0x90, 0xc3 }").unwrap(),
            vec![0x90, 0x90, 0xc3]
        );
    }

    #[test]
    fn decodes_plain_hex() {
        assert_eq!(decode_blob("90 90 c3").unwrap(), vec![0x90, 0x90, 0xc3]);
    }

    #[test]
    fn decodes_base64() {
        // "kJDD" base64-decodes to 90 90 c3.
        assert_eq!(decode_blob("kJDD").unwrap(), vec![0x90, 0x90, 0xc3]);
    }

    #[test]
    fn c_declaration_is_not_read_as_hex() {
        // "unsigned" and "char" hold hex digits ("ed", "ca"), which must not become bytes.
        assert_eq!(
            decode_blob("unsigned char buf[] = { 0x90 };").unwrap(),
            vec![0x90]
        );
        assert_eq!(
            decode_blob(r#"char sc[] = "\x48\x31\xc0";"#).unwrap(),
            vec![0x48, 0x31, 0xc0]
        );
        assert_eq!(decode_blob("{0x9, 0xa}").unwrap(), vec![0x09, 0x0a]);
    }

    #[test]
    fn base64_with_hex_letters_is_base64() {
        // "SDHA" holds hex-looking pairs but is base64 for 48 31 c0.
        assert_eq!(decode_blob("SDHA").unwrap(), vec![0x48, 0x31, 0xc0]);
        assert_eq!(
            decode_blob("AAEC").unwrap(),
            vec![0xaa, 0xec],
            "pure hex wins"
        );
    }

    #[test]
    fn separated_hex() {
        assert_eq!(
            decode_blob("48:31:c0, 90").unwrap(),
            vec![0x48, 0x31, 0xc0, 0x90]
        );
        assert!(decode_blob("zz").is_err());
    }

    #[test]
    fn disassembles_and_emulates_nop_ret() {
        // nop; nop; ret — a clean, inert blob.
        let blob = vec![0x90u8, 0x90, 0xc3];
        let lines = disassemble(&blob);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].text.contains("nop"));
        let report = emulate(&blob);
        assert!(report.contains("ran"));
    }
}
