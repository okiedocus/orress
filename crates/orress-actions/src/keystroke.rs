use egui::{Key, KeyboardShortcut, Modifiers};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A key plus modifiers, written in Zed's keymap syntax: `ctrl-shift-p`, `alt-f4`, `f1`.
///
/// Modifier names:
/// - `ctrl`, `alt`, `shift`
/// - `cmd` / `secondary`: Ctrl on Windows and Linux, Cmd on macOS
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Keystroke {
    pub modifiers: Modifiers,
    pub key: Key,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeystrokeParseError {
    #[error("empty keystroke")]
    Empty,
    #[error("unknown modifier `{0}`")]
    UnknownModifier(String),
    #[error("unknown key `{0}`")]
    UnknownKey(String),
}

impl Keystroke {
    pub const fn new(modifiers: Modifiers, key: Key) -> Self {
        Self { modifiers, key }
    }

    pub fn parse(source: &str) -> Result<Self, KeystrokeParseError> {
        let source = source.trim();
        if source.is_empty() {
            return Err(KeystrokeParseError::Empty);
        }
        // `ctrl--` means ctrl + minus: the last part may itself be "-".
        let (mods_part, key_part) = match source.strip_suffix("--") {
            Some(rest) => (rest, "-"),
            None => match source.rsplit_once('-') {
                Some((mods, key)) => (mods, key),
                None => ("", source),
            },
        };

        let mut modifiers = Modifiers::NONE;
        for part in mods_part.split('-').filter(|p| !p.is_empty()) {
            modifiers |= match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => Modifiers::CTRL,
                "alt" | "option" => Modifiers::ALT,
                "shift" => Modifiers::SHIFT,
                "cmd" | "secondary" | "command" => Modifiers::COMMAND,
                other => return Err(KeystrokeParseError::UnknownModifier(other.to_owned())),
            };
        }

        let key = Key::from_name(key_part)
            .or_else(|| {
                Key::ALL
                    .iter()
                    .copied()
                    .find(|k| k.name().eq_ignore_ascii_case(key_part))
            })
            .ok_or_else(|| KeystrokeParseError::UnknownKey(key_part.to_owned()))?;
        Ok(Self { modifiers, key })
    }

    pub fn shortcut(&self) -> KeyboardShortcut {
        KeyboardShortcut::new(self.modifiers, self.key)
    }

    /// Platform-aware label such as `Ctrl+Shift+P` (or `⇧⌘P` on macOS).
    pub fn label(&self, ctx: &egui::Context) -> String {
        ctx.format_shortcut(&self.shortcut())
    }

    /// Number of modifiers. Used to try more specific shortcuts first, because egui
    /// ignores a pressed Shift when the pattern does not mention it.
    pub fn specificity(&self) -> u32 {
        let m = self.modifiers;
        u32::from(m.ctrl || m.command) + u32::from(m.alt) + u32::from(m.shift)
    }
}

impl std::fmt::Display for Keystroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.modifiers;
        if m.command && !m.ctrl {
            f.write_str("cmd-")?;
        } else if m.ctrl {
            f.write_str("ctrl-")?;
        }
        if m.alt {
            f.write_str("alt-")?;
        }
        if m.shift {
            f.write_str("shift-")?;
        }
        f.write_str(&self.key.name().to_ascii_lowercase())
    }
}

impl Serialize for Keystroke {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Keystroke {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zed_style_keystrokes() {
        let k = Keystroke::parse("ctrl-shift-p").unwrap();
        assert_eq!(k.key, Key::P);
        assert!(k.modifiers.ctrl && k.modifiers.shift && !k.modifiers.alt);

        assert_eq!(Keystroke::parse("f1").unwrap().key, Key::F1);
        assert_eq!(Keystroke::parse("ctrl--").unwrap().key, Key::Minus);
        assert_eq!(Keystroke::parse("ctrl-=").unwrap().key, Key::Equals);
        assert!(Keystroke::parse("cmd-b").unwrap().modifiers.command);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Keystroke::parse(""), Err(KeystrokeParseError::Empty));
        assert!(matches!(
            Keystroke::parse("hyper-x"),
            Err(KeystrokeParseError::UnknownModifier(_))
        ));
        assert!(matches!(
            Keystroke::parse("ctrl-nope"),
            Err(KeystrokeParseError::UnknownKey(_))
        ));
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "ctrl-shift-p",
            "ctrl-alt-b",
            "f1",
            "ctrl-w",
            "escape",
            "ctrl--",
            "pageup",
        ] {
            let k = Keystroke::parse(s).unwrap();
            assert_eq!(Keystroke::parse(&k.to_string()).unwrap(), k, "{s}");
        }
    }

    #[test]
    fn specificity_counts_modifiers() {
        assert_eq!(Keystroke::parse("ctrl-shift-p").unwrap().specificity(), 2);
        assert_eq!(Keystroke::parse("f1").unwrap().specificity(), 0);
    }
}
