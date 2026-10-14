use std::collections::HashMap;

use crate::ActionId;

/// Metadata for one action. The behavior lives in the app; this describes it so the
/// command palette, menus, keybinding list and Explain Mode can all show it.
#[derive(Clone, Debug)]
pub struct Action {
    pub id: ActionId,
    /// Short title shown in the command palette, e.g. "Toggle Left Dock".
    pub title: String,
    /// Plain-language explanation for beginners, shown in Explain Mode.
    pub explain: String,
}

#[derive(Default)]
pub struct ActionRegistry {
    actions: Vec<Action>,
    by_id: HashMap<ActionId, usize>,
}

impl ActionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an action. Registering the same id twice replaces the metadata.
    pub fn register(&mut self, id: &str, title: &str, explain: &str) -> &mut Self {
        let action = Action {
            id: ActionId::new(id),
            title: title.to_owned(),
            explain: explain.to_owned(),
        };
        match self.by_id.get(&action.id) {
            Some(&index) => self.actions[index] = action,
            None => {
                self.by_id.insert(action.id.clone(), self.actions.len());
                self.actions.push(action);
            }
        }
        self
    }

    pub fn get(&self, id: &ActionId) -> Option<&Action> {
        self.by_id.get(id).map(|&i| &self.actions[i])
    }

    pub fn contains(&self, id: &ActionId) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.actions.iter()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_replace() {
        let mut r = ActionRegistry::new();
        r.register("a::One", "One", "first");
        r.register("a::Two", "Two", "second");
        r.register("a::One", "One again", "replaced");
        assert_eq!(r.len(), 2);
        assert_eq!(r.get(&"a::One".into()).unwrap().title, "One again");
        assert_eq!(ActionId::from("a::One").namespace(), "a");
    }
}
