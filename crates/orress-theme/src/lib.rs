//! Themes. A theme is a small set of named colors, stored as JSON with `#rrggbb` values,
//! and turned into egui visuals. Besides UI colors it carries the "syntax" colors the
//! reverse-engineering views use (addresses, mnemonics, registers, ...), so every view
//! colors the same concept the same way.

use std::collections::HashMap;

use egui::{Color32, Stroke, Visuals};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A color written as `#rrggbb` or `#rrggbbaa` in theme files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hex(pub Color32);

impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let [r, g, b, a] = self.0.to_srgba_unmultiplied();
        if a == 255 {
            s.collect_str(&format_args!("#{r:02x}{g:02x}{b:02x}"))
        } else {
            s.collect_str(&format_args!("#{r:02x}{g:02x}{b:02x}{a:02x}"))
        }
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Color32::from_hex(&s)
            .map(Hex)
            .map_err(|_| serde::de::Error::custom(format!("invalid color `{s}`, expected #rrggbb")))
    }
}

/// Colors for the shell (panels, text, accents).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiColors {
    pub background: Hex,
    pub panel: Hex,
    pub elevated: Hex,
    pub border: Hex,
    pub text: Hex,
    pub text_muted: Hex,
    pub accent: Hex,
    pub selection: Hex,
    pub warning: Hex,
    pub error: Hex,
    pub success: Hex,
}

/// Colors shared by disassembly, decompiler, hex and debugger views.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyntaxColors {
    pub address: Hex,
    pub bytes: Hex,
    pub mnemonic: Hex,
    pub register: Hex,
    pub immediate: Hex,
    pub string: Hex,
    pub comment: Hex,
    pub function: Hex,
    pub label: Hex,
    pub keyword: Hex,
    pub type_name: Hex,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Theme {
    pub name: String,
    pub dark: bool,
    pub ui: UiColors,
    pub syntax: SyntaxColors,
}

fn c(hex: &str) -> Hex {
    Hex(Color32::from_hex(hex).expect("built-in theme colors are valid"))
}

/// A Zed color string, or the given fallback when it is absent or unparseable.
fn pick(opt: Option<&str>, fallback: Hex) -> Hex {
    opt.and_then(|h| Color32::from_hex(h).ok())
        .map(Hex)
        .unwrap_or(fallback)
}

/// The shape of a Zed theme-family file (only the fields ORRESS maps; unknown keys are ignored).
#[derive(Deserialize)]
struct ZedFamily {
    #[serde(default)]
    themes: Vec<ZedTheme>,
}

#[derive(Deserialize)]
struct ZedTheme {
    #[serde(default)]
    name: String,
    #[serde(default)]
    appearance: String,
    #[serde(default)]
    style: ZedStyle,
}

#[derive(Default, Deserialize)]
struct ZedStyle {
    #[serde(default)]
    background: Option<String>,
    #[serde(rename = "editor.background", default)]
    editor_background: Option<String>,
    #[serde(rename = "editor.foreground", default)]
    editor_foreground: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(rename = "text.muted", default)]
    text_muted: Option<String>,
    #[serde(rename = "text.accent", default)]
    text_accent: Option<String>,
    #[serde(default)]
    border: Option<String>,
    #[serde(rename = "elevated_surface.background", default)]
    elevated: Option<String>,
    #[serde(rename = "surface.background", default)]
    surface: Option<String>,
    #[serde(rename = "panel.background", default)]
    panel: Option<String>,
    #[serde(rename = "element.selected", default)]
    element_selected: Option<String>,
    #[serde(rename = "editor.selection.background", default)]
    editor_selection: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    success: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    syntax: HashMap<String, ZedSyntaxStyle>,
}

#[derive(Deserialize)]
struct ZedSyntaxStyle {
    #[serde(default)]
    color: Option<String>,
}

impl Theme {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("theme serializes")
    }

    /// Imports a **Zed** theme-family JSON (the format Zed theme extensions ship: a `themes`
    /// array, each with a `style` map) into one ORRESS `Theme` per entry. Zed's style keys are
    /// mapped onto our UI and syntax colors; whatever a Zed theme omits keeps the matching ORRESS
    /// default (for the appearance), so the result is always a complete theme. Zed's `#rrggbbaa`
    /// colors are accepted (alpha is kept). This is the first, no-WASM slice of Zed-extension
    /// compatibility.
    pub fn from_zed_json(json: &str) -> Result<Vec<Theme>, serde_json::Error> {
        let family: ZedFamily = serde_json::from_str(json)?;
        Ok(family.themes.into_iter().map(Theme::from_zed).collect())
    }

    fn from_zed(z: ZedTheme) -> Theme {
        let dark = !z.appearance.eq_ignore_ascii_case("light");
        let mut t = if dark {
            Theme::rusty_dark()
        } else {
            Theme::rusty_light()
        };
        if !z.name.is_empty() {
            t.name = z.name;
        }
        t.dark = dark;
        let s = &z.style;
        // The editor surface is the truest "background"; panels sit on the surface colors.
        t.ui.background = pick(
            s.editor_background.as_deref().or(s.background.as_deref()),
            t.ui.background,
        );
        t.ui.panel = pick(s.panel.as_deref().or(s.surface.as_deref()), t.ui.panel);
        t.ui.elevated = pick(
            s.elevated.as_deref().or(s.surface.as_deref()),
            t.ui.elevated,
        );
        t.ui.border = pick(s.border.as_deref(), t.ui.border);
        t.ui.text = pick(
            s.editor_foreground.as_deref().or(s.text.as_deref()),
            t.ui.text,
        );
        t.ui.text_muted = pick(s.text_muted.as_deref(), t.ui.text_muted);
        t.ui.accent = pick(s.text_accent.as_deref(), t.ui.accent);
        t.ui.selection = pick(
            s.editor_selection
                .as_deref()
                .or(s.element_selected.as_deref()),
            t.ui.selection,
        );
        t.ui.warning = pick(s.warning.as_deref(), t.ui.warning);
        t.ui.error = pick(s.error.as_deref(), t.ui.error);
        t.ui.success = pick(s.success.as_deref().or(s.created.as_deref()), t.ui.success);
        // Syntax highlighting keys (each Zed entry is `{ "color": "#..", ... }`). RE-specific
        // concepts map to the nearest source concept: a mnemonic reads like a keyword, a register
        // like a variable, an immediate like a number, raw bytes like a comment (dim).
        let syn =
            |name: &str| -> Option<&str> { s.syntax.get(name).and_then(|v| v.color.as_deref()) };
        t.syntax.keyword = pick(syn("keyword"), t.syntax.keyword);
        t.syntax.function = pick(syn("function"), t.syntax.function);
        t.syntax.type_name = pick(syn("type"), t.syntax.type_name);
        t.syntax.string = pick(syn("string"), t.syntax.string);
        t.syntax.comment = pick(
            syn("comment").or_else(|| syn("comment.doc")),
            t.syntax.comment,
        );
        t.syntax.immediate = pick(syn("number"), t.syntax.immediate);
        t.syntax.register = pick(
            syn("variable").or_else(|| syn("variable.special")),
            t.syntax.register,
        );
        t.syntax.label = pick(syn("label").or_else(|| syn("tag")), t.syntax.label);
        t.syntax.mnemonic = pick(syn("keyword"), t.syntax.mnemonic);
        t.syntax.address = pick(s.text_muted.as_deref(), t.syntax.address);
        t.syntax.bytes = pick(syn("comment"), t.syntax.bytes);
        t
    }

    /// Default dark theme, loosely inspired by Zed's One Dark.
    pub fn rusty_dark() -> Self {
        Self {
            name: "ORRESS Dark".into(),
            dark: true,
            ui: UiColors {
                background: c("#1e2127"),
                panel: c("#21252b"),
                elevated: c("#2c313a"),
                border: c("#363c46"),
                text: c("#d7dae0"),
                text_muted: c("#8b929e"),
                accent: c("#61afef"),
                selection: c("#3e4f6a"),
                warning: c("#e5c07b"),
                error: c("#e06c75"),
                success: c("#98c379"),
            },
            syntax: SyntaxColors {
                address: c("#7f8896"),
                bytes: c("#5c6370"),
                mnemonic: c("#61afef"),
                register: c("#e06c75"),
                immediate: c("#d19a66"),
                string: c("#98c379"),
                comment: c("#7f848e"),
                function: c("#e5c07b"),
                label: c("#56b6c2"),
                keyword: c("#c678dd"),
                type_name: c("#56b6c2"),
            },
        }
    }

    pub fn rusty_light() -> Self {
        Self {
            name: "ORRESS Light".into(),
            dark: false,
            ui: UiColors {
                background: c("#fafafa"),
                panel: c("#f0f0f1"),
                elevated: c("#ffffff"),
                border: c("#d4d4d8"),
                text: c("#383a42"),
                text_muted: c("#6b6f7a"),
                accent: c("#2f6fdd"),
                selection: c("#cfe0fc"),
                warning: c("#a76d00"),
                error: c("#c4302b"),
                success: c("#3c8a2e"),
            },
            syntax: SyntaxColors {
                address: c("#7a7f8a"),
                bytes: c("#9da0a8"),
                mnemonic: c("#2f6fdd"),
                register: c("#c4302b"),
                immediate: c("#a35200"),
                string: c("#3c8a2e"),
                comment: c("#8a8f99"),
                function: c("#8a5d00"),
                label: c("#0f7f8f"),
                keyword: c("#a626a4"),
                type_name: c("#0f7f8f"),
            },
        }
    }

    /// Maximum contrast for low vision and bright rooms.
    pub fn high_contrast() -> Self {
        Self {
            name: "High Contrast".into(),
            dark: true,
            ui: UiColors {
                background: c("#000000"),
                panel: c("#0a0a0a"),
                elevated: c("#141414"),
                border: c("#ffffff"),
                text: c("#ffffff"),
                text_muted: c("#d0d0d0"),
                accent: c("#ffd700"),
                selection: c("#0050c8"),
                warning: c("#ffd700"),
                error: c("#ff6060"),
                success: c("#60ff60"),
            },
            syntax: SyntaxColors {
                address: c("#c0c0c0"),
                bytes: c("#a0a0a0"),
                mnemonic: c("#5fd7ff"),
                register: c("#ff8787"),
                immediate: c("#ffd75f"),
                string: c("#87ff87"),
                comment: c("#bcbcbc"),
                function: c("#ffff5f"),
                label: c("#87ffff"),
                keyword: c("#ff87ff"),
                type_name: c("#87ffff"),
            },
        }
    }

    pub fn built_in() -> Vec<Self> {
        vec![
            Self::rusty_dark(),
            Self::rusty_light(),
            Self::high_contrast(),
        ]
    }

    pub fn visuals(&self) -> Visuals {
        let ui = &self.ui;
        let mut v = if self.dark {
            Visuals::dark()
        } else {
            Visuals::light()
        };
        v.override_text_color = Some(ui.text.0);
        v.panel_fill = ui.panel.0;
        v.window_fill = ui.elevated.0;
        v.extreme_bg_color = ui.background.0;
        v.faint_bg_color = ui.elevated.0;
        v.code_bg_color = ui.background.0;
        v.hyperlink_color = ui.accent.0;
        v.warn_fg_color = ui.warning.0;
        v.error_fg_color = ui.error.0;
        v.selection.bg_fill = ui.selection.0;
        v.selection.stroke = Stroke::new(1.0, ui.accent.0);
        v.window_stroke = Stroke::new(1.0, ui.border.0);
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, ui.border.0);
        v.widgets.noninteractive.bg_fill = ui.panel.0;
        v.widgets.inactive.weak_bg_fill = ui.elevated.0;
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, ui.accent.0);
        v.widgets.active.bg_stroke = Stroke::new(1.0, ui.accent.0);
        v
    }

    /// Applies the theme to every egui style (dark and light slots).
    pub fn apply(&self, ctx: &egui::Context) {
        let theme = if self.dark {
            egui::Theme::Dark
        } else {
            egui::Theme::Light
        };
        ctx.set_theme(theme);
        ctx.set_visuals_of(theme, self.visuals());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_themes_round_trip_through_json() {
        for theme in Theme::built_in() {
            let back = Theme::from_json(&theme.to_json()).unwrap();
            assert_eq!(back, theme);
        }
    }

    #[test]
    fn bad_color_is_a_clear_error() {
        let mut json = Theme::rusty_dark().to_json();
        json = json.replacen("#61afef", "blue", 1);
        let err = Theme::from_json(&json).unwrap_err().to_string();
        assert!(err.contains("invalid color `blue`"), "{err}");
    }

    #[test]
    fn imports_a_zed_theme_family() {
        // A trimmed Zed theme family (the real files carry dozens more style keys we ignore).
        let json = r##"{
            "name": "Demo",
            "themes": [
                {
                    "name": "Demo Dark",
                    "appearance": "dark",
                    "style": {
                        "editor.background": "#101418",
                        "editor.foreground": "#c8ccd4",
                        "text.muted": "#767b85",
                        "border": "#2a2f38",
                        "editor.selection.background": "#2d4f67aa",
                        "error": "#e05252",
                        "syntax": {
                            "keyword": { "color": "#c678ddff", "font_weight": 700 },
                            "function": { "color": "#61afef" },
                            "type": { "color": "#56b6c2" },
                            "string": { "color": "#98c379" },
                            "comment": { "color": "#5c6370" },
                            "number": { "color": "#d19a66" },
                            "variable": { "color": "#e06c75" }
                        }
                    }
                },
                { "name": "Demo Light", "appearance": "light", "style": {} }
            ]
        }"##;
        let themes = Theme::from_zed_json(json).expect("imports");
        assert_eq!(themes.len(), 2);

        let dark = &themes[0];
        assert_eq!(dark.name, "Demo Dark");
        assert!(dark.dark);
        assert_eq!(dark.ui.background, c("#101418"));
        assert_eq!(dark.ui.text, c("#c8ccd4"));
        assert_eq!(dark.syntax.keyword, c("#c678dd")); // alpha ff folds to opaque
        assert_eq!(dark.syntax.mnemonic, c("#c678dd")); // mnemonic maps to the keyword color
        assert_eq!(dark.syntax.immediate, c("#d19a66")); // number → immediate
        assert_eq!(dark.syntax.register, c("#e06c75")); // variable → register
        assert_eq!(
            dark.ui.selection,
            Theme::from_json(&dark.to_json()).unwrap().ui.selection
        );

        // The light entry has an empty style, so it keeps the ORRESS light defaults but its name.
        let light = &themes[1];
        assert_eq!(light.name, "Demo Light");
        assert!(!light.dark);
        assert_eq!(light.ui.background, Theme::rusty_light().ui.background);
    }
}
