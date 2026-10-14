use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ActionId, KeyContext, Keystroke};

/// One key binding. `action: None` unbinds the keystroke in that context
/// (written as `null` in JSON, like in Zed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub keystroke: Keystroke,
    pub context: KeyContext,
    pub action: Option<ActionId>,
}

#[derive(Debug, thiserror::Error)]
pub enum KeymapError {
    #[error("invalid keymap JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// A keymap section in Zed's JSON format:
///
/// ```json
/// [
///   { "context": "Global", "bindings": { "ctrl-shift-p": "command_palette::Toggle" } },
///   { "context": "Hex",    "bindings": { "ctrl-g": "hex::GoToOffset", "ctrl-w": null } }
/// ]
/// ```
#[derive(Serialize, Deserialize)]
struct Section {
    #[serde(default)]
    context: KeyContext,
    bindings: BTreeMap<Keystroke, Option<ActionId>>,
}

// BTreeMap keys need Ord; order by the textual form so JSON output is stable.
impl PartialOrd for Keystroke {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Keystroke {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Keymap {
    bindings: Vec<Binding>,
}

impl Keymap {
    pub fn from_json(json: &str) -> Result<Self, KeymapError> {
        let sections: Vec<Section> = serde_json::from_str(json)?;
        let mut keymap = Self::default();
        for section in sections {
            for (keystroke, action) in section.bindings {
                keymap.bind(keystroke, section.context, action);
            }
        }
        Ok(keymap)
    }

    pub fn to_json(&self) -> String {
        let mut sections: Vec<Section> = Vec::new();
        for context in KeyContext::ALL {
            let bindings: BTreeMap<_, _> = self
                .bindings
                .iter()
                .filter(|b| b.context == context)
                .map(|b| (b.keystroke, b.action.clone()))
                .collect();
            if !bindings.is_empty() {
                sections.push(Section { context, bindings });
            }
        }
        serde_json::to_string_pretty(&sections).expect("keymap serializes")
    }

    /// Adds or replaces the binding for `keystroke` in `context`.
    pub fn bind(&mut self, keystroke: Keystroke, context: KeyContext, action: Option<ActionId>) {
        self.bindings
            .retain(|b| !(b.keystroke == keystroke && b.context == context));
        self.bindings.push(Binding {
            keystroke,
            context,
            action,
        });
    }

    /// Layers `other` on top of `self`: the user keymap overrides the defaults.
    pub fn merge(&mut self, other: &Keymap) {
        for b in &other.bindings {
            self.bind(b.keystroke, b.context, b.action.clone());
        }
    }

    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// The keystroke shown next to an action in menus and the palette.
    /// Prefers a binding in `context`, then a global one.
    pub fn keystroke_for(&self, action: &ActionId, context: KeyContext) -> Option<Keystroke> {
        let find = |ctx: KeyContext| {
            self.bindings
                .iter()
                .find(|b| b.context == ctx && b.action.as_ref() == Some(action))
                .map(|b| b.keystroke)
        };
        find(context).or_else(|| find(KeyContext::Global))
    }

    /// Like [`Keymap::keystroke_for`], but falls back to any other context that binds the action,
    /// returning that context too — so a menu or the shortcut list can show e.g. a Hex-only
    /// shortcut as "Ctrl+Shift+C (Hex)" instead of nothing.
    pub fn keystroke_anywhere(
        &self,
        action: &ActionId,
        context: KeyContext,
    ) -> Option<(Keystroke, KeyContext)> {
        if let Some(k) = self.keystroke_for(action, context) {
            let ctx = if self
                .bindings
                .iter()
                .any(|b| b.context == context && b.keystroke == k)
            {
                context
            } else {
                KeyContext::Global
            };
            return Some((k, ctx));
        }
        KeyContext::ALL.into_iter().find_map(|ctx| {
            self.bindings
                .iter()
                .find(|b| b.context == ctx && b.action.as_ref() == Some(action))
                .map(|b| (b.keystroke, ctx))
        })
    }

    /// Resolves what `keystroke` does in `context`, falling back to `Global`.
    pub fn resolve(&self, keystroke: Keystroke, context: KeyContext) -> Option<&ActionId> {
        let lookup = |ctx: KeyContext| {
            self.bindings
                .iter()
                .find(|b| b.context == ctx && b.keystroke == keystroke)
        };
        // A binding in the specific context (even `null`) shadows the global one.
        match lookup(context) {
            Some(b) => b.action.as_ref(),
            None => lookup(KeyContext::Global).and_then(|b| b.action.as_ref()),
        }
    }

    /// Consumes the first matching key press from egui's input and returns its action.
    pub fn dispatch(&self, ctx: &egui::Context, context: KeyContext) -> Option<ActionId> {
        let mut candidates: Vec<&Binding> = self
            .bindings
            .iter()
            .filter(|b| b.context == context || b.context == KeyContext::Global)
            .collect();
        // Most modifiers first: otherwise `ctrl-p` would also fire on `ctrl-shift-p`.
        candidates.sort_by_key(|b| std::cmp::Reverse(b.keystroke.specificity()));

        ctx.input_mut(|input| {
            for b in candidates {
                // Skip global bindings shadowed in this context.
                if self.resolve(b.keystroke, context) != b.action.as_ref() {
                    continue;
                }
                if input.consume_shortcut(&b.keystroke.shortcut()) {
                    return b.action.clone();
                }
            }
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"[
        { "context": "Global", "bindings": {
            "ctrl-shift-p": "command_palette::Toggle",
            "ctrl-w": "workspace::CloseActiveTab"
        } },
        { "context": "Hex", "bindings": { "ctrl-w": null, "ctrl-g": "hex::GoTo" } }
    ]"#;

    fn ks(s: &str) -> Keystroke {
        Keystroke::parse(s).unwrap()
    }

    #[test]
    fn loads_zed_format() {
        let km = Keymap::from_json(JSON).unwrap();
        assert_eq!(km.bindings().len(), 4);
        assert_eq!(
            km.resolve(ks("ctrl-shift-p"), KeyContext::Hex),
            Some(&ActionId::from("command_palette::Toggle"))
        );
    }

    #[test]
    fn context_shadows_global_including_null() {
        let km = Keymap::from_json(JSON).unwrap();
        assert_eq!(km.resolve(ks("ctrl-w"), KeyContext::Hex), None);
        assert_eq!(
            km.resolve(ks("ctrl-w"), KeyContext::Notes),
            Some(&ActionId::from("workspace::CloseActiveTab"))
        );
    }

    #[test]
    fn merge_overrides_defaults() {
        let mut km = Keymap::from_json(JSON).unwrap();
        let user = Keymap::from_json(r#"[{ "bindings": { "ctrl-shift-p": "workspace::Open" } }]"#)
            .unwrap();
        km.merge(&user);
        assert_eq!(
            km.resolve(ks("ctrl-shift-p"), KeyContext::Global),
            Some(&ActionId::from("workspace::Open"))
        );
        assert_eq!(km.bindings().len(), 4);
    }

    #[test]
    fn json_round_trip() {
        let km = Keymap::from_json(JSON).unwrap();
        let again = Keymap::from_json(&km.to_json()).unwrap();
        assert_eq!(again.bindings().len(), km.bindings().len());
    }

    #[test]
    fn keystroke_lookup_for_menus() {
        let km = Keymap::from_json(JSON).unwrap();
        assert_eq!(
            km.keystroke_for(&"hex::GoTo".into(), KeyContext::Hex),
            Some(ks("ctrl-g"))
        );
    }

    #[test]
    fn keystroke_anywhere_finds_other_contexts() {
        let km = Keymap::from_json(JSON).unwrap();
        // A Hex-only binding is found from the Workspace context, tagged with its context.
        assert_eq!(
            km.keystroke_anywhere(&"hex::GoTo".into(), KeyContext::Workspace),
            Some((ks("ctrl-g"), KeyContext::Hex))
        );
        // A global binding is reported as Global.
        assert_eq!(
            km.keystroke_anywhere(&"command_palette::Toggle".into(), KeyContext::Workspace),
            Some((ks("ctrl-shift-p"), KeyContext::Global))
        );
        assert_eq!(
            km.keystroke_anywhere(&"nothing::Here".into(), KeyContext::Workspace),
            None
        );
    }
}
