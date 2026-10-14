//! The shared CRDT document: the collaborative state a team edits together over a relay. Built on
//! a Yjs ([`yrs`]) document, so concurrent edits from every peer merge deterministically without a
//! central authority. Everything a team shares while solving a CTF lives here — renames, comments,
//! recovered types, free-form notes, bookmarks, challenge claims and chat.
//!
//! Sync is update-based: a peer encodes the changes the other side is missing ([`CollabDoc::encode_update`]
//! from a remote [`CollabDoc::state_vector`]) and applies incoming updates ([`CollabDoc::apply_update`]);
//! the result converges regardless of order or duplication.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{
    Any, Array, ArrayRef, Doc, Map, MapRef, Out, ReadTxn, StateVector, Transact, TransactionMut,
    Update,
};

/// An error from decoding or applying a sync message.
#[derive(Debug)]
pub enum CollabError {
    Decode(String),
    Apply(String),
}

impl std::fmt::Display for CollabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollabError::Decode(e) => write!(f, "could not decode sync message: {e}"),
            CollabError::Apply(e) => write!(f, "could not apply sync update: {e}"),
        }
    }
}

impl std::error::Error for CollabError {}

/// A chat message, with an optional address so teammates can jump to what is being discussed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub peer: String,
    pub text: String,
    /// Unix-millis timestamp (set by the sender).
    pub ts: u64,
    /// An address this message refers to, rendered as a clickable link in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<u64>,
}

/// The team's shared CRDT state.
pub struct CollabDoc {
    doc: Doc,
    /// address -> user-chosen name.
    renames: MapRef,
    /// address -> comment text.
    comments: MapRef,
    /// address -> bookmark label.
    bookmarks: MapRef,
    /// key (caller-chosen, e.g. a function address) -> recovered type / signature.
    types: MapRef,
    /// key -> free-form note.
    notes: MapRef,
    /// challenge id -> the peer who claimed it.
    claims: MapRef,
    /// Append-only chat log (each entry a JSON [`ChatMessage`]).
    chat: ArrayRef,
    /// Updates produced by local edits (through this type's mutators) not yet taken for broadcast.
    /// Remote updates applied via [`CollabDoc::apply_update`] are never recorded here, so they are
    /// not echoed back to the room.
    outbox: Mutex<Vec<Vec<u8>>>,
}

impl Default for CollabDoc {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads a string value out of a yrs map entry (ignoring non-string values).
fn as_string(out: Option<Out>) -> Option<String> {
    match out {
        Some(Out::Any(Any::String(s))) => Some(s.to_string()),
        _ => None,
    }
}

impl CollabDoc {
    pub fn new() -> Self {
        let doc = Doc::new();
        let renames = doc.get_or_insert_map("renames");
        let comments = doc.get_or_insert_map("comments");
        let bookmarks = doc.get_or_insert_map("bookmarks");
        let types = doc.get_or_insert_map("types");
        let notes = doc.get_or_insert_map("notes");
        let claims = doc.get_or_insert_map("claims");
        let chat = doc.get_or_insert_array("chat");
        Self {
            doc,
            renames,
            comments,
            bookmarks,
            types,
            notes,
            claims,
            chat,
            outbox: Mutex::new(Vec::new()),
        }
    }

    /// Queues the changes made in `txn` (a local edit) for broadcast, if it changed anything.
    fn record(&self, txn: &TransactionMut) {
        let update = txn.encode_update_v1();
        if !update_is_empty(&update) {
            self.outbox
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(update);
        }
    }

    fn set(&self, map: &MapRef, key: String, value: &str) {
        let mut txn = self.doc.transact_mut();
        map.insert(&mut txn, key, value.to_string());
        self.record(&txn);
    }

    fn remove(&self, map: &MapRef, key: &str) {
        let mut txn = self.doc.transact_mut();
        map.remove(&mut txn, key);
        self.record(&txn);
    }

    fn string_map(&self, map: &MapRef) -> BTreeMap<String, String> {
        let txn = self.doc.transact();
        map.iter(&txn)
            .filter_map(|(k, v)| match v {
                Out::Any(Any::String(s)) => Some((k.to_string(), s.to_string())),
                _ => None,
            })
            .collect()
    }

    fn addr_map(&self, map: &MapRef) -> BTreeMap<u64, String> {
        self.string_map(map)
            .into_iter()
            .filter_map(|(k, v)| parse_addr(&k).map(|a| (a, v)))
            .collect()
    }

    // --- Renames / comments / bookmarks (keyed by address). --------------------------------
    pub fn set_rename(&self, addr: u64, name: &str) {
        self.set(&self.renames, addr_key(addr), name);
    }
    pub fn rename(&self, addr: u64) -> Option<String> {
        as_string(self.renames.get(&self.doc.transact(), &addr_key(addr)))
    }
    pub fn renames(&self) -> BTreeMap<u64, String> {
        self.addr_map(&self.renames)
    }

    pub fn remove_rename(&self, addr: u64) {
        self.remove(&self.renames, &addr_key(addr));
    }

    pub fn set_comment(&self, addr: u64, text: &str) {
        self.set(&self.comments, addr_key(addr), text);
    }
    pub fn comments(&self) -> BTreeMap<u64, String> {
        self.addr_map(&self.comments)
    }
    pub fn remove_comment(&self, addr: u64) {
        self.remove(&self.comments, &addr_key(addr));
    }

    pub fn set_bookmark(&self, addr: u64, label: &str) {
        self.set(&self.bookmarks, addr_key(addr), label);
    }
    pub fn remove_bookmark(&self, addr: u64) {
        self.remove(&self.bookmarks, &addr_key(addr));
    }
    pub fn bookmarks(&self) -> BTreeMap<u64, String> {
        self.addr_map(&self.bookmarks)
    }

    // --- Types / notes (keyed by a caller-chosen string). ----------------------------------
    pub fn set_type(&self, key: &str, ty: &str) {
        self.set(&self.types, key.to_string(), ty);
    }
    pub fn types(&self) -> BTreeMap<String, String> {
        self.string_map(&self.types)
    }

    pub fn set_note(&self, key: &str, text: &str) {
        self.set(&self.notes, key.to_string(), text);
    }
    pub fn notes(&self) -> BTreeMap<String, String> {
        self.string_map(&self.notes)
    }

    // --- Claims ("taking challenge 3"), keyed by challenge id. ------------------------------
    pub fn claim(&self, challenge: &str, peer: &str) {
        self.set(&self.claims, challenge.to_string(), peer);
    }
    pub fn release_claim(&self, challenge: &str) {
        self.remove(&self.claims, challenge);
    }
    pub fn claims(&self) -> BTreeMap<String, String> {
        self.string_map(&self.claims)
    }

    // --- Chat. ------------------------------------------------------------------------------
    pub fn post_chat(&self, msg: &ChatMessage) {
        let json = serde_json::to_string(msg).unwrap_or_default();
        let mut txn = self.doc.transact_mut();
        self.chat.push_back(&mut txn, json);
        self.record(&txn);
    }
    pub fn chat(&self) -> Vec<ChatMessage> {
        let txn = self.doc.transact();
        (0..self.chat.len(&txn))
            .filter_map(|i| self.chat.get(&txn, i))
            .filter_map(|out| match out {
                Out::Any(Any::String(s)) => serde_json::from_str(&s).ok(),
                _ => None,
            })
            .collect()
    }

    // --- Sync. ------------------------------------------------------------------------------
    /// This document's state vector (what it already has), for a peer to diff against.
    pub fn state_vector(&self) -> Vec<u8> {
        self.doc.transact().state_vector().encode_v1()
    }

    /// The update carrying everything the holder of `remote_state_vector` is missing.
    pub fn encode_update(&self, remote_state_vector: &[u8]) -> Result<Vec<u8>, CollabError> {
        let sv = StateVector::decode_v1(remote_state_vector)
            .map_err(|e| CollabError::Decode(e.to_string()))?;
        Ok(self.doc.transact().encode_diff_v1(&sv))
    }

    /// The full state as a single update (for a peer that is just joining).
    pub fn encode_full(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    /// Takes the updates produced by local edits since the last call, merged into one (`None` if
    /// nothing changed locally). Unlike diffing state vectors this also catches pure deletions,
    /// which do not advance the state vector.
    pub fn take_local_update(&self) -> Option<Vec<u8>> {
        let pending = std::mem::take(&mut *self.outbox.lock().unwrap_or_else(|e| e.into_inner()));
        match pending.len() {
            0 => None,
            1 => pending.into_iter().next(),
            _ => match yrs::merge_updates_v1(&pending) {
                Ok(merged) => Some(merged),
                // Merging should not fail on our own updates; if it does, fall back to the full
                // state (idempotent on the receiving side).
                Err(_) => Some(self.encode_full()),
            },
        }
    }

    /// Applies an update produced by [`CollabDoc::encode_update`]/[`CollabDoc::encode_full`] on
    /// another peer.
    pub fn apply_update(&self, bytes: &[u8]) -> Result<(), CollabError> {
        let update = Update::decode_v1(bytes).map_err(|e| CollabError::Decode(e.to_string()))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| CollabError::Apply(e.to_string()))
    }
}

/// Whether an encoded (v1) update carries no changes at all (an empty yrs update still encodes
/// to a couple of bytes, so `bytes.is_empty()` is not enough). Undecodable bytes count as
/// non-empty so the caller surfaces the decode error instead of silently dropping them.
pub(crate) fn update_is_empty(bytes: &[u8]) -> bool {
    Update::decode_v1(bytes).is_ok_and(|u| u.is_empty())
}

/// Addresses are stored as fixed-width lowercase hex so they sort and round-trip cleanly.
fn addr_key(addr: u64) -> String {
    format!("{addr:016x}")
}

fn parse_addr(key: &str) -> Option<u64> {
    u64::from_str_radix(key, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_peers_converge_after_exchanging_updates() {
        let alice = CollabDoc::new();
        let bob = CollabDoc::new();

        // Concurrent, independent edits on each side.
        alice.set_rename(0x401000, "check_flag");
        alice.set_comment(0x401000, "validates the password");
        bob.set_bookmark(0x401200, "key schedule");
        bob.claim("web-3", "bob");

        // Exchange only what each side is missing, in both directions.
        let a_to_b = alice.encode_update(&bob.state_vector()).unwrap();
        let b_to_a = bob.encode_update(&alice.state_vector()).unwrap();
        bob.apply_update(&a_to_b).unwrap();
        alice.apply_update(&b_to_a).unwrap();

        // Both documents now hold the union.
        for doc in [&alice, &bob] {
            assert_eq!(doc.rename(0x401000).as_deref(), Some("check_flag"));
            assert_eq!(
                doc.comments().get(&0x401000).map(String::as_str),
                Some("validates the password")
            );
            assert_eq!(
                doc.bookmarks().get(&0x401200).map(String::as_str),
                Some("key schedule")
            );
            assert_eq!(doc.claims().get("web-3").map(String::as_str), Some("bob"));
        }
    }

    #[test]
    fn concurrent_edits_to_the_same_key_converge_to_one_value() {
        let alice = CollabDoc::new();
        let bob = CollabDoc::new();
        alice.set_rename(0x1000, "alpha");
        bob.set_rename(0x1000, "beta");

        // Full-state exchange both ways; a map key is last-writer-wins, and both pick the SAME winner.
        let a_full = alice.encode_full();
        let b_full = bob.encode_full();
        alice.apply_update(&b_full).unwrap();
        bob.apply_update(&a_full).unwrap();
        assert_eq!(alice.rename(0x1000), bob.rename(0x1000));
        assert!(matches!(
            alice.rename(0x1000).as_deref(),
            Some("alpha") | Some("beta")
        ));
    }

    #[test]
    fn chat_is_an_ordered_append_log_that_merges() {
        let alice = CollabDoc::new();
        let bob = CollabDoc::new();
        alice.post_chat(&ChatMessage {
            peer: "alice".into(),
            text: "look at 0x401000".into(),
            ts: 1,
            addr: Some(0x401000),
        });
        bob.post_chat(&ChatMessage {
            peer: "bob".into(),
            text: "on it".into(),
            ts: 2,
            addr: None,
        });

        bob.apply_update(&alice.encode_update(&bob.state_vector()).unwrap())
            .unwrap();
        alice
            .apply_update(&bob.encode_update(&alice.state_vector()).unwrap())
            .unwrap();

        for doc in [&alice, &bob] {
            let chat = doc.chat();
            assert_eq!(chat.len(), 2);
            assert!(
                chat.iter()
                    .any(|m| m.peer == "alice" && m.addr == Some(0x401000))
            );
            assert!(chat.iter().any(|m| m.peer == "bob" && m.text == "on it"));
        }
    }

    #[test]
    fn local_updates_are_recorded_only_for_real_changes() {
        let alice = CollabDoc::new();
        let bob = CollabDoc::new();
        assert_eq!(
            alice.take_local_update(),
            None,
            "a fresh doc has nothing to send"
        );
        // An empty diff still encodes to bytes; it must not count as a change.
        assert!(update_is_empty(
            &alice.encode_update(&alice.state_vector()).unwrap()
        ));

        alice.set_rename(0x10, "a");
        alice.set_comment(0x10, "c");
        let u = alice.take_local_update().expect("edits produce an update");
        assert_eq!(
            alice.take_local_update(),
            None,
            "taken updates are not resent"
        );
        bob.apply_update(&u).unwrap();
        assert_eq!(bob.rename(0x10).as_deref(), Some("a"));
        // Applying a remote update is not a local change (no echo).
        assert_eq!(bob.take_local_update(), None);

        // A pure delete does not advance the state vector but must still be broadcast.
        let sv = alice.state_vector();
        alice.remove_comment(0x10);
        assert_eq!(alice.state_vector(), sv);
        let del = alice.take_local_update().expect("a delete is a change");
        bob.apply_update(&del).unwrap();
        assert!(bob.comments().is_empty());

        // Removing something that is not there changes nothing.
        alice.remove_comment(0x999);
        assert_eq!(alice.take_local_update(), None);
    }

    #[test]
    fn applying_the_same_update_twice_is_idempotent() {
        let alice = CollabDoc::new();
        let bob = CollabDoc::new();
        alice.set_note("plan", "diff the two firmware dumps");
        let u = alice.encode_full();
        bob.apply_update(&u).unwrap();
        bob.apply_update(&u).unwrap(); // duplicate delivery is harmless
        assert_eq!(
            bob.notes().get("plan").map(String::as_str),
            Some("diff the two firmware dumps")
        );
    }
}
