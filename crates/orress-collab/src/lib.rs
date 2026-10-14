//! ORRESS collaboration (M13): shared project state for team CTFs.
//!
//! The pieces, bottom-up:
//! - [`CollabDoc`] — the Yjs CRDT shared state (renames, comments, types, notes, bookmarks,
//!   claims, chat) that merges concurrent edits from every peer.
//!
//! More layers (presence/follow mode, the end-to-end-encrypted relay client) build on this.

mod client;
mod crypto;
mod doc;
mod presence;
mod protocol;
mod session;

pub use client::RelayClient;
pub use crypto::RoomKey;
pub use doc::{ChatMessage, CollabDoc, CollabError};
pub use presence::{Peer, Presence, color_for};
pub use protocol::{ClientMessage, Envelope};
pub use session::CollabSession;
