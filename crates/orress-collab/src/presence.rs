//! Presence and follow mode: the *ephemeral* awareness layer (separate from the CRDT, which holds
//! durable state). Each peer periodically broadcasts where it is looking — its name, a stable
//! colour, and the address it is viewing — so the team sees presence avatars ("Alice is at
//! `check_flag`") and can **follow** a teammate's cursor through the binary.
//!
//! Awareness is last-write-wins per peer and self-expiring: a peer not heard from within a TTL is
//! pruned, so a crashed client disappears on its own.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One peer's current awareness state (broadcast as-is).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// Stable per-session id (also used to route follow mode).
    pub id: String,
    pub name: String,
    /// Avatar colour as `0xRRGGBB` (derived from the id if not set).
    pub color: u32,
    /// The address this peer is currently viewing, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<u64>,
    /// Sender's unix-millis timestamp; used for TTL pruning and last-write-wins.
    pub last_seen: u64,
}

impl Peer {
    /// A new peer with a colour derived from its id.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let id = id.into();
        let color = color_for(&id);
        Self {
            id,
            name: name.into(),
            color,
            addr: None,
            last_seen: 0,
        }
    }
}

/// A deterministic, readable avatar colour for an id (stable across peers and sessions): the id is
/// hashed to a hue, with fixed high saturation/value so colours stay distinct and legible.
pub fn color_for(id: &str) -> u32 {
    let mut hash: u64 = 1469598103934665603; // FNV-1a
    for b in id.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(1099511628211);
    }
    let hue = (hash % 360) as f32;
    hsv_to_rgb(hue, 0.65, 0.95)
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> u32 {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match h as u32 / 60 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let to = |f: f32| ((f + m) * 255.0).round() as u32;
    (to(r) << 16) | (to(g) << 8) | to(b)
}

/// The team's awareness: this session's own peer plus the remote peers last heard from.
pub struct Presence {
    local: Peer,
    remote: BTreeMap<String, Peer>,
    /// peer id -> when *we* last heard from it (our clock, unix millis). Pruning uses this rather
    /// than the sender's `last_seen`, so clock skew between machines cannot expire (or immortalise)
    /// a peer.
    received: BTreeMap<String, u64>,
    following: Option<String>,
}

impl Presence {
    pub fn new(local: Peer) -> Self {
        Self {
            local,
            remote: BTreeMap::new(),
            received: BTreeMap::new(),
            following: None,
        }
    }

    pub fn local(&self) -> &Peer {
        &self.local
    }

    /// Updates where this session is looking and stamps it `now` (unix millis), returning the
    /// update to broadcast.
    pub fn set_local_addr(&mut self, addr: Option<u64>, now: u64) -> Peer {
        self.local.addr = addr;
        self.local.last_seen = now;
        self.local.clone()
    }

    /// A fresh copy of the local peer to broadcast as a heartbeat, stamped `now`.
    pub fn heartbeat(&mut self, now: u64) -> Peer {
        self.local.last_seen = now;
        self.local.clone()
    }

    /// Records a remote peer's broadcast (ignoring our own echo and older timestamps). Without a
    /// local receive time, the sender's own `last_seen` stands in for it; prefer
    /// [`Presence::apply_at`], which is immune to clock skew between machines.
    pub fn apply(&mut self, peer: Peer) {
        let at = peer.last_seen;
        self.apply_at(peer, at);
    }

    /// Records a remote peer's broadcast received at `received_at` (unix millis on *our* clock),
    /// ignoring our own echo and updates older (by the sender's clock) than what we hold.
    pub fn apply_at(&mut self, peer: Peer, received_at: u64) {
        if peer.id == self.local.id {
            return;
        }
        // Any broadcast proves the peer is alive, even a reordered stale one.
        let seen = self.received.entry(peer.id.clone()).or_insert(received_at);
        *seen = (*seen).max(received_at);
        match self.remote.get(&peer.id) {
            Some(existing) if existing.last_seen > peer.last_seen => {}
            _ => {
                self.remote.insert(peer.id.clone(), peer);
            }
        }
    }

    /// Drops remote peers not heard from within `ttl_ms` of `now` (our clock, compared against
    /// when we received their last broadcast). If the followed peer expires, following stops.
    pub fn prune(&mut self, now: u64, ttl_ms: u64) {
        let received = &self.received;
        self.remote.retain(|id, p| {
            let at = received.get(id).copied().unwrap_or(p.last_seen);
            now.saturating_sub(at) <= ttl_ms
        });
        let remote = &self.remote;
        self.received.retain(|id, _| remote.contains_key(id));
        if let Some(id) = &self.following
            && !self.remote.contains_key(id)
        {
            self.following = None;
        }
    }

    /// Remote peers, ordered by id (stable for rendering avatars).
    pub fn peers(&self) -> Vec<&Peer> {
        self.remote.values().collect()
    }

    pub fn peer(&self, id: &str) -> Option<&Peer> {
        self.remote.get(id)
    }

    // --- Follow mode. -----------------------------------------------------------------------
    pub fn follow(&mut self, id: &str) {
        self.following = Some(id.to_string());
    }

    pub fn unfollow(&mut self) {
        self.following = None;
    }

    pub fn following(&self) -> Option<&str> {
        self.following.as_deref()
    }

    /// The address to jump to when following: the followed peer's current address. `None` if not
    /// following, the peer is gone, or it has no address.
    pub fn follow_addr(&self) -> Option<u64> {
        let id = self.following.as_ref()?;
        self.remote.get(id).and_then(|p| p.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_are_deterministic_and_vary_by_id() {
        assert_eq!(color_for("alice"), color_for("alice"));
        assert_ne!(color_for("alice"), color_for("bob"));
        assert!(color_for("x") <= 0xFFFFFF);
    }

    #[test]
    fn apply_ignores_self_and_keeps_the_newest() {
        let mut p = Presence::new(Peer::new("me", "Me"));
        p.apply(Peer {
            id: "me".into(),
            name: "echo".into(),
            color: 0,
            addr: Some(1),
            last_seen: 9,
        });
        assert!(p.peers().is_empty(), "own echo is ignored");

        let mut bob = Peer::new("bob", "Bob");
        bob.addr = Some(0x1000);
        bob.last_seen = 10;
        p.apply(bob.clone());
        assert_eq!(p.peer("bob").unwrap().addr, Some(0x1000));

        // An older update does not clobber a newer one.
        let mut stale = bob.clone();
        stale.addr = Some(0x9999);
        stale.last_seen = 5;
        p.apply(stale);
        assert_eq!(p.peer("bob").unwrap().addr, Some(0x1000));
    }

    #[test]
    fn prune_drops_stale_peers_and_stops_following_them() {
        let mut p = Presence::new(Peer::new("me", "Me"));
        let mut bob = Peer::new("bob", "Bob");
        bob.addr = Some(0x2000);
        bob.last_seen = 1000;
        p.apply(bob);
        p.follow("bob");
        assert_eq!(p.follow_addr(), Some(0x2000));

        p.prune(1500, 1000); // within TTL
        assert_eq!(p.peers().len(), 1);
        p.prune(3000, 1000); // now stale
        assert!(p.peers().is_empty());
        assert_eq!(p.following(), None, "following a gone peer stops");
        assert_eq!(p.follow_addr(), None);
    }

    #[test]
    fn prune_uses_the_local_receive_time_not_the_senders_clock() {
        let mut p = Presence::new(Peer::new("me", "Me"));
        // Bob's clock is an hour behind ours; he is still alive.
        let mut bob = Peer::new("bob", "Bob");
        bob.last_seen = 1_000;
        p.apply_at(bob, 3_601_000);
        p.prune(3_602_000, 12_000);
        assert_eq!(p.peers().len(), 1, "a skewed but live peer is kept");
        // ... and is pruned once *we* have not heard from him for longer than the TTL.
        p.prune(3_601_000 + 12_001, 12_000);
        assert!(p.peers().is_empty());

        // Carol's clock runs ahead: she is still pruned after going quiet locally.
        let mut carol = Peer::new("carol", "Carol");
        carol.last_seen = 99_999_999;
        p.apply_at(carol, 10_000);
        p.prune(10_000 + 12_001, 12_000);
        assert!(p.peers().is_empty());
    }

    #[test]
    fn follow_tracks_the_peers_moving_cursor() {
        let mut p = Presence::new(Peer::new("me", "Me"));
        let mut bob = Peer::new("bob", "Bob");
        bob.last_seen = 1;
        p.apply(bob.clone());
        assert_eq!(p.follow_addr(), None, "not following yet");
        p.follow("bob");
        assert_eq!(p.follow_addr(), None, "bob has no address yet");

        bob.addr = Some(0x401000);
        bob.last_seen = 2;
        p.apply(bob);
        assert_eq!(p.follow_addr(), Some(0x401000));
    }
}
