//! The relay client: connects to an [`orress-relay`](../orress_relay) over a WebSocket on a
//! background thread (blocking `tungstenite`, like the LSP/DAP transports), joins a room, and
//! bridges between the app and the wire — sealing outgoing [`ClientMessage`]s with the room key
//! into `Data` frames, and opening incoming `Data` frames back into `ClientMessage`s.
//!
//! Both `ws://` and `wss://` are supported (TLS via rustls with bundled webpki roots); the payloads
//! are end-to-end encrypted regardless, so `wss://` only adds transport privacy/integrity on top.

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tungstenite::Message;
use tungstenite::stream::MaybeTlsStream;

use crate::crypto::RoomKey;
use crate::protocol::{ClientMessage, Envelope};

const POLL: Duration = Duration::from_millis(40);

/// A connected relay client. Dropping it signals the worker thread to stop.
pub struct RelayClient {
    outgoing: Sender<ClientMessage>,
    incoming: Receiver<ClientMessage>,
    connected: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
}

impl RelayClient {
    /// Connects to `url` (`ws://` or `wss://`, e.g. `ws://host:8787`) and joins `room`, sealing
    /// traffic with the key derived from `room` + `passphrase`. The connect, TLS and WebSocket
    /// handshakes happen here (so a bad URL fails fast); the send/receive loop then runs on a
    /// background thread.
    pub fn connect(url: &str, room: &str, passphrase: &str) -> Result<RelayClient, String> {
        let key = RoomKey::derive(room, passphrase)?;
        let url = normalize_url(url)?;
        let (mut ws, _resp) =
            tungstenite::connect(&url).map_err(|e| format!("could not reach relay {url}: {e}"))?;
        ws.send(Message::Binary(
            Envelope::Join {
                room: room.to_string(),
            }
            .encode(),
        ))
        .map_err(|e| format!("could not join the room: {e}"))?;
        set_read_timeout(ws.get_mut(), POLL);

        let (out_tx, out_rx) = channel::<ClientMessage>();
        let (in_tx, in_rx) = channel::<ClientMessage>();
        let connected = Arc::new(AtomicBool::new(true));
        let error = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));

        let worker = Worker {
            ws,
            key,
            out_rx,
            in_tx,
            connected: Arc::clone(&connected),
            error: Arc::clone(&error),
            stop: Arc::clone(&stop),
        };
        std::thread::spawn(move || worker.run());

        Ok(RelayClient {
            outgoing: out_tx,
            incoming: in_rx,
            connected,
            error,
            stop,
        })
    }

    /// Queues a message to seal and broadcast (non-blocking).
    pub fn send(&self, msg: ClientMessage) {
        let _ = self.outgoing.send(msg);
    }

    /// The next decrypted message from a peer, if any (non-blocking).
    pub fn try_recv(&self) -> Option<ClientMessage> {
        self.incoming.try_recv().ok()
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Worker {
    ws: tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    key: RoomKey,
    out_rx: Receiver<ClientMessage>,
    in_tx: Sender<ClientMessage>,
    connected: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
}

impl Worker {
    fn run(mut self) {
        use std::io::ErrorKind;
        while !self.stop.load(Ordering::Relaxed) {
            // Seal and send anything the app queued.
            let mut ok = true;
            while let Ok(msg) = self.out_rx.try_recv() {
                match msg.seal(&self.key) {
                    Ok(payload) => {
                        if let Err(e) = self
                            .ws
                            .send(Message::Binary(Envelope::Data { payload }.encode()))
                        {
                            self.fail(format!("relay connection lost while sending: {e}"));
                            ok = false;
                            break;
                        }
                    }
                    Err(e) => self.fail(e),
                }
            }
            if !ok {
                break;
            }
            match self.ws.read() {
                Ok(Message::Binary(bytes)) => {
                    // A message we cannot open (wrong key / noise) is skipped, not fatal.
                    if let Some(Envelope::Data { payload }) = Envelope::decode(&bytes)
                        && let Ok(msg) = ClientMessage::open(&payload, &self.key)
                    {
                        let _ = self.in_tx.send(msg);
                    }
                }
                Ok(Message::Close(_)) => break,
                // Pings are answered by tungstenite itself (the queued Pong is flushed on the next
                // read/write), so nothing to do here.
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => {
                    self.fail(format!("relay connection lost: {e}"));
                    break;
                }
            }
        }
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.ws.close(None);
    }

    fn fail(&self, message: String) {
        *self.error.lock().unwrap() = Some(message);
    }
}

/// Sets a read timeout on the underlying TCP socket (through TLS if present) so the worker can poll
/// reads and interleave sends. A plain stream and a rustls stream both reach the `TcpStream`.
fn set_read_timeout(stream: &mut MaybeTlsStream<TcpStream>, timeout: Duration) {
    match stream {
        MaybeTlsStream::Plain(s) => {
            s.set_read_timeout(Some(timeout)).ok();
        }
        MaybeTlsStream::Rustls(tls) => {
            tls.get_ref().set_read_timeout(Some(timeout)).ok();
        }
        _ => {}
    }
}

/// Normalises a relay URL for `tungstenite::connect`: defaults the scheme to `ws://` and, when no
/// port is given, appends the relay's default port 8787 (`wss://` without a port keeps 443 via the
/// scheme default only if one is written, matching how servers are addressed).
fn normalize_url(url: &str) -> Result<String, String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("wss://") {
        ("wss://", r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        ("ws://", r)
    } else {
        ("ws://", url)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("no host in relay URL `{url}`"));
    }
    let authority = if authority.contains(':') || scheme == "wss://" {
        authority.to_string()
    } else {
        format!("{authority}:8787")
    };
    Ok(format!("{scheme}{authority}{path}"))
}

#[cfg(test)]
mod tests {
    use super::normalize_url;

    #[test]
    fn normalizes_relay_urls() {
        assert_eq!(
            normalize_url("ws://10.0.0.5:9000").unwrap(),
            "ws://10.0.0.5:9000"
        );
        // Bare ws:// host with no port gets the relay default.
        assert_eq!(
            normalize_url("ws://relay.example/room").unwrap(),
            "ws://relay.example:8787/room"
        );
        // No scheme defaults to ws:// (+ default port).
        assert_eq!(
            normalize_url("127.0.0.1:1234").unwrap(),
            "ws://127.0.0.1:1234"
        );
        // wss:// is preserved (port left to the scheme/explicit value).
        assert_eq!(
            normalize_url("wss://relay.example/r").unwrap(),
            "wss://relay.example/r"
        );
        assert!(normalize_url("ws://").is_err());
    }
}
