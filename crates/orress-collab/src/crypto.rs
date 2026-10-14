//! End-to-end encryption for a collaboration room. The relay only ever sees ciphertext: every
//! message peers exchange is sealed with a key derived from the room's passphrase, so a hosted or
//! self-hosted relay (and anyone on the wire) cannot read renames, comments, chat or presence —
//! important when the team is reversing malware.
//!
//! The key is Argon2id over the passphrase with a salt derived deterministically from the room
//! name (so every peer in the room derives the same key); messages use XChaCha20Poly1305 with a
//! random 192-bit nonce prepended to each ciphertext.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

const NONCE_LEN: usize = 24;

/// A room's symmetric key, ready to seal/open messages.
pub struct RoomKey {
    cipher: XChaCha20Poly1305,
}

impl RoomKey {
    /// Derives the room key from its name and passphrase (Argon2id). Every peer that joins the same
    /// room with the same passphrase derives the same key; a wrong passphrase derives a different
    /// key, so its messages simply fail to open.
    pub fn derive(room: &str, passphrase: &str) -> Result<Self, String> {
        let salt = derive_salt(room);
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| format!("key derivation failed: {e}"))?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("bad key length: {e}"))?;
        Ok(Self { cipher })
    }

    /// Encrypts `plaintext`, returning `nonce || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| "encryption failed".to_string())?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce); // GenericArray derefs to &[u8]
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts a `nonce || ciphertext` blob. Fails on a wrong key or any tampering (AEAD).
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.len() < NONCE_LEN {
            return Err("sealed message too short".to_string());
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let mut nonce = XNonce::default();
        nonce.copy_from_slice(nonce_bytes);
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| "could not decrypt (wrong passphrase or tampered message)".to_string())
    }
}

/// A 16-byte Argon2 salt derived deterministically from the room name (FNV-1a expanded), so all
/// peers in a room agree without exchanging a salt.
fn derive_salt(room: &str) -> [u8; 16] {
    let mut salt = [0u8; 16];
    let mut hash: u64 = 1469598103934665603;
    for (i, slot) in salt.iter_mut().enumerate() {
        for b in room.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(1099511628211);
        }
        hash = hash.wrapping_add(i as u64 + 1);
        *slot = (hash >> ((i % 8) * 8)) as u8;
    }
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_room_and_passphrase_round_trips() {
        let a = RoomKey::derive("ctf-2026/web", "correct horse battery staple").unwrap();
        let b = RoomKey::derive("ctf-2026/web", "correct horse battery staple").unwrap();
        let sealed = a.seal(b"rename 0x401000 = check_flag").unwrap();
        assert_eq!(b.open(&sealed).unwrap(), b"rename 0x401000 = check_flag");
        // The nonce makes each sealing distinct even for the same plaintext.
        assert_ne!(a.seal(b"x").unwrap(), a.seal(b"x").unwrap());
    }

    #[test]
    fn wrong_passphrase_cannot_open() {
        let good = RoomKey::derive("room", "hunter2").unwrap();
        let bad = RoomKey::derive("room", "hunter3").unwrap();
        let sealed = good.seal(b"secret").unwrap();
        assert!(bad.open(&sealed).is_err());
    }

    #[test]
    fn a_different_room_derives_a_different_key() {
        let one = RoomKey::derive("room-a", "pw").unwrap();
        let two = RoomKey::derive("room-b", "pw").unwrap();
        let sealed = one.seal(b"hi").unwrap();
        assert!(two.open(&sealed).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let k = RoomKey::derive("r", "p").unwrap();
        let mut sealed = k.seal(b"important").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff; // flip a ciphertext byte
        assert!(k.open(&sealed).is_err());
    }
}
