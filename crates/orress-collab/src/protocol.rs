//! The two wire layers used over the relay's WebSocket:
//!
//! - [`Envelope`] — the **relay-visible** framing. A client first sends `Join { room }`, then
//!   `Data { payload }` frames the relay broadcasts to every other member of the room. The relay
//!   never looks inside `payload`; it only routes by room. Encoded as a compact tagged binary blob.
//! - [`ClientMessage`] — the **end-to-end** payload, sealed with the room [`RoomKey`] before it
//!   becomes an `Envelope::Data`. It carries CRDT sync (`StateVector`/`Update`) and ephemeral
//!   `Presence`.

use serde::{Deserialize, Serialize};

use crate::crypto::RoomKey;
use crate::presence::Peer;

/// The relay-visible frame. Binary: a 1-byte tag then the content (room name, or opaque payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// Join (or create) a room. Sent once, first.
    Join { room: String },
    /// An opaque, end-to-end-encrypted payload to broadcast to the rest of the room.
    Data { payload: Vec<u8> },
}

const TAG_JOIN: u8 = 0;
const TAG_DATA: u8 = 1;

impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Envelope::Join { room } => {
                let mut out = vec![TAG_JOIN];
                out.extend_from_slice(room.as_bytes());
                out
            }
            Envelope::Data { payload } => {
                let mut out = vec![TAG_DATA];
                out.extend_from_slice(payload);
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Envelope> {
        let (&tag, rest) = bytes.split_first()?;
        match tag {
            TAG_JOIN => Some(Envelope::Join {
                room: String::from_utf8(rest.to_vec()).ok()?,
            }),
            TAG_DATA => Some(Envelope::Data {
                payload: rest.to_vec(),
            }),
            _ => None,
        }
    }
}

/// The end-to-end message peers actually exchange (inside an encrypted `Envelope::Data`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "kebab-case")]
pub enum ClientMessage {
    /// "Here is what I already have" — on join, so a peer can reply with the diff I am missing.
    StateVector(Vec<u8>),
    /// A CRDT update (from `CollabDoc::encode_update`/`encode_full`).
    Update(Vec<u8>),
    /// An ephemeral presence broadcast.
    Presence(Peer),
}

impl ClientMessage {
    /// Serializes and seals this message into an `Envelope::Data` payload with the room key.
    pub fn seal(&self, key: &RoomKey) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        key.seal(&json)
    }

    /// Opens and deserializes a sealed payload.
    pub fn open(payload: &[u8], key: &RoomKey) -> Result<ClientMessage, String> {
        let json = key.open(payload)?;
        serde_json::from_slice(&json).map_err(|e| format!("bad client message: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips() {
        let join = Envelope::Join {
            room: "ctf/web".into(),
        };
        assert_eq!(Envelope::decode(&join.encode()), Some(join));
        let data = Envelope::Data {
            payload: vec![1, 2, 3, 0, 255],
        };
        assert_eq!(Envelope::decode(&data.encode()), Some(data));
        assert_eq!(Envelope::decode(&[]), None); // empty frame
        assert_eq!(Envelope::decode(&[9, 9]), None); // unknown tag
    }

    #[test]
    fn client_message_seals_and_opens_with_the_room_key() {
        let key = RoomKey::derive("room", "pw").unwrap();
        let msg = ClientMessage::Update(vec![10, 20, 30]);
        let sealed = msg.seal(&key).unwrap();
        assert_eq!(ClientMessage::open(&sealed, &key).unwrap(), msg);

        // A different key cannot open it (end-to-end).
        let other = RoomKey::derive("room", "nope").unwrap();
        assert!(ClientMessage::open(&sealed, &other).is_err());
    }

    #[test]
    fn presence_message_carries_the_peer() {
        let key = RoomKey::derive("r", "p").unwrap();
        let peer = Peer::new("bob", "Bob");
        let sealed = ClientMessage::Presence(peer.clone()).seal(&key).unwrap();
        match ClientMessage::open(&sealed, &key).unwrap() {
            ClientMessage::Presence(p) => assert_eq!(p, peer),
            other => panic!("expected presence, got {other:?}"),
        }
    }
}
