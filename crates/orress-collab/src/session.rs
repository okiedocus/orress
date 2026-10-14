//! A live collaboration session: the glue the app drives. It owns the shared [`CollabDoc`], the
//! [`Presence`] awareness and the [`RelayClient`], and reconciles them each frame via [`poll`]:
//!
//! - local CRDT edits (made directly on [`CollabSession::doc`]) are recorded as they happen and
//!   broadcast once; an idle session sends no document traffic at all,
//! - incoming updates are applied, incoming state-vectors are answered with the diff they lack,
//! - presence is broadcast on a heartbeat and pruned when peers go quiet.
//!
//! [`poll`]: CollabSession::poll

use crate::client::RelayClient;
use crate::doc::{CollabDoc, update_is_empty};
use crate::presence::{Peer, Presence};
use crate::protocol::ClientMessage;

/// How often to re-announce our presence, and how long before a silent peer is pruned (millis).
const HEARTBEAT_MS: u64 = 3_000;
const PRESENCE_TTL_MS: u64 = 12_000;

/// A connected collaboration session for one room.
pub struct CollabSession {
    /// The shared state. Mutate it directly (e.g. `session.doc.set_rename(..)`); [`CollabSession::poll`]
    /// broadcasts the changes.
    pub doc: CollabDoc,
    presence: Presence,
    client: RelayClient,
    last_heartbeat: u64,
}

impl CollabSession {
    /// Connects to `url` and joins `room` (sealed with `passphrase`), announcing our presence and
    /// state so peers send us what we are missing.
    pub fn connect(
        url: &str,
        room: &str,
        passphrase: &str,
        local: Peer,
    ) -> Result<CollabSession, String> {
        let client = RelayClient::connect(url, room, passphrase)?;
        let doc = CollabDoc::new();
        let presence = Presence::new(local);
        // Tell the room what we have (they reply with the diff we lack) and who we are.
        client.send(ClientMessage::StateVector(doc.state_vector()));
        client.send(ClientMessage::Presence(presence.local().clone()));
        Ok(CollabSession {
            doc,
            presence,
            client,
            last_heartbeat: 0,
        })
    }

    /// Reconciles local and remote state once. Call every UI frame with `now` in unix-millis.
    /// Returns whether anything changed (so the UI can repaint).
    pub fn poll(&mut self, now: u64) -> bool {
        let mut changed = false;

        // 1. Broadcast local edits made since the last poll. These are recorded by the doc's
        //    mutators as they happen (not by diffing state vectors, which deletions do not
        //    advance), so an idle session sends nothing.
        if let Some(update) = self.doc.take_local_update() {
            self.client.send(ClientMessage::Update(update));
        }

        // 2. Apply everything peers sent us. Remote updates are not recorded as local edits, so
        //    they are not echoed back.
        while let Some(msg) = self.client.try_recv() {
            match msg {
                ClientMessage::StateVector(sv) => {
                    if let Ok(diff) = self.doc.encode_update(&sv)
                        && !update_is_empty(&diff)
                    {
                        self.client.send(ClientMessage::Update(diff));
                    }
                }
                ClientMessage::Update(update) => {
                    if !update_is_empty(&update) && self.doc.apply_update(&update).is_ok() {
                        changed = true;
                    }
                }
                ClientMessage::Presence(peer) => {
                    self.presence.apply_at(peer, now);
                    changed = true;
                }
            }
        }

        // 3. Heartbeat our presence and prune peers that have gone quiet.
        if now.saturating_sub(self.last_heartbeat) >= HEARTBEAT_MS {
            let peer = self.presence.heartbeat(now);
            self.client.send(ClientMessage::Presence(peer));
            self.last_heartbeat = now;
        }
        self.presence.prune(now, PRESENCE_TTL_MS);

        changed
    }

    /// Updates where this session is looking and broadcasts it immediately (so follow mode is
    /// responsive), without waiting for the heartbeat.
    pub fn set_local_addr(&mut self, addr: Option<u64>, now: u64) {
        let peer = self.presence.set_local_addr(addr, now);
        self.client.send(ClientMessage::Presence(peer));
    }

    pub fn presence(&self) -> &Presence {
        &self.presence
    }

    pub fn follow(&mut self, id: &str) {
        self.presence.follow(id);
    }
    pub fn unfollow(&mut self) {
        self.presence.unfollow();
    }
    /// The address to jump to when following a teammate, if any.
    pub fn follow_addr(&self) -> Option<u64> {
        self.presence.follow_addr()
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }

    pub fn error(&self) -> Option<String> {
        self.client.error()
    }
}
