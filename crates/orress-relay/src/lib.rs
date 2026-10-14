//! A self-hostable collaboration relay: a WebSocket server that routes end-to-end-encrypted room
//! traffic between team members. It is deliberately dumb — it reads each client's [`Envelope`],
//! routes `Data` frames to the other members of the same room, and never decrypts anything (the
//! payloads are sealed with the room key, which the relay does not have). That keeps a hosted or
//! self-hosted relay unable to read the team's work, which matters for malware analysis.
//!
//! Blocking and thread-per-connection (no async runtime): each connection polls its socket with a
//! short read timeout and, between reads, flushes anything queued for it by other connections.
//!
//! Because a relay is meant to be internet-facing, it is bounded everywhere ([`RelayConfig`]): a
//! cap on concurrent connections, a handshake deadline, a maximum message/frame size, a bounded
//! per-member outgoing queue (a peer too slow to drain it is disconnected rather than buffering
//! without limit), and an idle timeout backed by WebSocket pings.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use orress_collab::Envelope;
use tungstenite::Message;
use tungstenite::protocol::WebSocketConfig;

/// How long a connection blocks on a read before looping to flush its outgoing queue.
const POLL: Duration = Duration::from_millis(40);

/// Limits that keep an internet-facing relay from being exhausted by misbehaving clients.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Maximum simultaneous connections; further connections are closed immediately.
    pub max_connections: usize,
    /// Maximum size of one incoming WebSocket message (and frame), in bytes.
    pub max_message_size: usize,
    /// How long a client has to complete the WebSocket handshake.
    pub handshake_timeout: Duration,
    /// How many messages may wait in a member's outgoing queue. A member whose queue is full (it
    /// is not reading fast enough) is disconnected instead of buffering without bound.
    pub queue_capacity: usize,
    /// After this long without hearing from a client the relay pings it; after
    /// [`RelayConfig::idle_timeout`] of silence it is disconnected.
    pub ping_interval: Duration,
    /// Disconnect a client that has sent nothing (not even a pong) for this long.
    pub idle_timeout: Duration,
    /// Blocking-write deadline, so a peer that stops reading cannot wedge its connection thread.
    pub write_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            max_connections: 512,
            max_message_size: 4 << 20,
            handshake_timeout: Duration::from_secs(10),
            queue_capacity: 1024,
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            write_timeout: Duration::from_secs(10),
        }
    }
}

impl RelayConfig {
    fn websocket(&self) -> WebSocketConfig {
        WebSocketConfig {
            max_message_size: Some(self.max_message_size),
            max_frame_size: Some(self.max_message_size),
            // Bound what can pile up in tungstenite's own write buffer behind a stalled peer.
            max_write_buffer_size: (self.max_message_size * 4).max(256 * 1024),
            ..WebSocketConfig::default()
        }
    }
}

type Members = HashMap<usize, SyncSender<Vec<u8>>>;

/// The live rooms and their members' outgoing queues.
#[derive(Default)]
pub struct Rooms {
    inner: Mutex<HashMap<String, Members>>,
}

impl Rooms {
    fn join(&self, room: &str, id: usize, tx: SyncSender<Vec<u8>>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(room.to_string())
            .or_default()
            .insert(id, tx);
    }

    fn leave(&self, room: &str, id: usize) {
        let mut rooms = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(members) = rooms.get_mut(room) {
            members.remove(&id);
            if members.is_empty() {
                rooms.remove(room);
            }
        }
    }

    /// Queues `payload` for every member of `room` except the sender. A member whose queue is full
    /// (too slow) or gone is removed from the room; dropping its sender makes its connection
    /// thread see the queue disconnect and close the socket.
    fn broadcast(&self, room: &str, from: usize, payload: &[u8]) {
        let mut rooms = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(members) = rooms.get_mut(room) else {
            return;
        };
        members.retain(|&id, tx| {
            id == from
                || match tx.try_send(payload.to_vec()) {
                    Ok(()) => true,
                    Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
                }
        });
        if members.is_empty() {
            rooms.remove(room);
        }
    }

    /// Number of live rooms (for tests / status).
    pub fn room_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Decrements the live-connection count when a connection thread ends (however it ends).
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serves connections on `listener` with the default [`RelayConfig`] until it stops yielding (i.e.
/// forever for a normal listener). Each connection is handled on its own thread.
pub fn run(listener: TcpListener) {
    run_with(listener, RelayConfig::default());
}

/// [`run`] with explicit limits.
pub fn run_with(listener: TcpListener, config: RelayConfig) {
    let config = Arc::new(config);
    let rooms = Arc::new(Rooms::default());
    let ids = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => {
                // e.g. out of file descriptors: back off instead of spinning.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if live.fetch_add(1, Ordering::AcqRel) >= config.max_connections {
            live.fetch_sub(1, Ordering::AcqRel);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            continue;
        }
        let slot = ConnectionSlot(Arc::clone(&live));
        let rooms = Arc::clone(&rooms);
        let config = Arc::clone(&config);
        let id = ids.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            let _slot = slot;
            handle(stream, id, &rooms, &config);
        });
    }
}

fn handle(stream: TcpStream, id: usize, rooms: &Rooms, config: &RelayConfig) {
    // Bound the handshake: a client that connects and never speaks times out here.
    stream.set_read_timeout(Some(config.handshake_timeout)).ok();
    stream.set_write_timeout(Some(config.write_timeout)).ok();
    let Ok(mut ws) = tungstenite::accept_with_config(stream, Some(config.websocket())) else {
        return;
    };
    // After the handshake, poll with a short timeout so we can interleave fan-out.
    ws.get_ref().set_read_timeout(Some(POLL)).ok();
    let (tx, rx): (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) =
        sync_channel(config.queue_capacity.max(1));
    // Handed to the room on join; after that the room holds the only sender, so the room dropping
    // it (slow member) disconnects `rx` and ends this connection.
    let mut tx = Some(tx);
    let mut room: Option<String> = None;
    let mut last_heard = Instant::now();
    let mut pinged = false;

    'conn: loop {
        // Flush anything other members queued for us.
        loop {
            match rx.try_recv() {
                Ok(payload) => {
                    if ws
                        .send(Message::Binary(Envelope::Data { payload }.encode()))
                        .is_err()
                    {
                        break 'conn;
                    }
                }
                Err(TryRecvError::Empty) => break,
                // Removed from the room for being too slow.
                Err(TryRecvError::Disconnected) => break 'conn,
            }
        }

        // Liveness: ping a quiet client, drop one that stays silent.
        let quiet = last_heard.elapsed();
        if quiet >= config.idle_timeout {
            break;
        }
        if quiet >= config.ping_interval && !pinged {
            if ws.send(Message::Ping(Vec::new())).is_err() {
                break;
            }
            pinged = true;
        }

        match ws.read() {
            Ok(msg) => {
                last_heard = Instant::now();
                pinged = false;
                match msg {
                    Message::Binary(bytes) => match Envelope::decode(&bytes) {
                        Some(Envelope::Join { room: r }) => {
                            if room.is_none()
                                && let Some(tx) = tx.take()
                            {
                                rooms.join(&r, id, tx);
                                room = Some(r);
                            }
                        }
                        Some(Envelope::Data { payload }) => {
                            if let Some(r) = &room {
                                rooms.broadcast(r, id, &payload);
                            }
                        }
                        None => {}
                    },
                    // Pings are answered by tungstenite itself (flushed on the next read/write).
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            // Idle (read timed out): loop back to flush the outgoing queue.
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }

    if let Some(r) = &room {
        rooms.leave(r, id);
    }
    let _ = ws.close(None);
    let _ = ws.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_with_a_full_queue_is_dropped_from_the_room() {
        let rooms = Rooms::default();
        let (fast_tx, fast_rx) = sync_channel(8);
        let (slow_tx, slow_rx) = sync_channel(1);
        rooms.join("r", 1, fast_tx);
        rooms.join("r", 2, slow_tx);
        rooms.broadcast("r", 0, b"a");
        rooms.broadcast("r", 0, b"b"); // slow member's queue (cap 1) is full -> removed
        assert_eq!(fast_rx.try_recv().unwrap(), b"a");
        assert_eq!(fast_rx.try_recv().unwrap(), b"b");
        assert_eq!(slow_rx.try_recv().unwrap(), b"a");
        // The room dropped the slow member's sender, so its connection sees the disconnect.
        assert!(matches!(
            slow_rx.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
        assert_eq!(rooms.room_count(), 1);
    }
}
