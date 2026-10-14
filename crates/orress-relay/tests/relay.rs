//! Integration test: a real relay over loopback. Two clients join a room; one broadcasts, the
//! other receives it; a third client in a different room does not.

use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use orress_collab::{ClientMessage, CollabSession, Envelope, Peer, RoomKey};
use tungstenite::{Message, WebSocket};

type Client = WebSocket<TcpStream>;

fn connect(addr: &str) -> Client {
    let stream = TcpStream::connect(addr).expect("connect");
    let (ws, _resp) = tungstenite::client(format!("ws://{addr}/"), stream).expect("handshake");
    // Poll reads (after the blocking handshake) so read_data can wait with a deadline.
    ws.get_ref()
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    ws
}

fn join(ws: &mut Client, room: &str) {
    ws.send(Message::Binary(
        Envelope::Join {
            room: room.to_string(),
        }
        .encode(),
    ))
    .unwrap();
}

/// Reads until a `Data` frame arrives or `timeout` elapses.
fn read_data(ws: &mut Client, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match ws.read() {
            Ok(Message::Binary(bytes)) => {
                if let Some(Envelope::Data { payload }) = Envelope::decode(&bytes) {
                    return Some(payload);
                }
            }
            Ok(_) => {}
            Err(tungstenite::Error::Io(_)) => {} // read timed out; keep waiting
            Err(_) => break,
        }
    }
    None
}

#[test]
fn broadcasts_within_a_room_but_not_across_rooms() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || orress_relay::run(listener));

    let mut alice = connect(&addr);
    let mut bob = connect(&addr);
    let mut eve = connect(&addr); // a different room

    join(&mut alice, "ctf/web");
    join(&mut bob, "ctf/web");
    join(&mut eve, "ctf/pwn");
    // Let the server register all three joins.
    std::thread::sleep(Duration::from_millis(150));

    let payload = b"sealed-update".to_vec();
    alice
        .send(Message::Binary(
            Envelope::Data {
                payload: payload.clone(),
            }
            .encode(),
        ))
        .unwrap();

    // Bob (same room) receives the opaque payload verbatim.
    assert_eq!(read_data(&mut bob, Duration::from_secs(3)), Some(payload));
    // Eve (other room) does not.
    assert_eq!(read_data(&mut eve, Duration::from_millis(400)), None);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn two_sessions_sync_crdt_and_presence_over_the_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || orress_relay::run(listener));

    let mut alice =
        CollabSession::connect(&url, "ctf/re", "team-pw", Peer::new("alice", "Alice")).unwrap();
    let mut bob =
        CollabSession::connect(&url, "ctf/re", "team-pw", Peer::new("bob", "Bob")).unwrap();

    // Alice renames a function and marks where she is looking.
    alice.doc.set_rename(0x401000, "check_flag");
    alice.set_local_addr(Some(0x401000), now_ms());

    // Pump both sessions until Bob converges (or a deadline).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut synced = false;
    while Instant::now() < deadline {
        alice.poll(now_ms());
        bob.poll(now_ms());
        if bob.doc.rename(0x401000).as_deref() == Some("check_flag")
            && bob.presence().peer("alice").and_then(|p| p.addr) == Some(0x401000)
        {
            synced = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        synced,
        "bob should see alice's rename and presence over the relay"
    );

    // Follow mode: Bob follows Alice and lands on her address.
    bob.follow("alice");
    assert_eq!(bob.follow_addr(), Some(0x401000));
}

#[test]
fn an_idle_session_sends_no_document_updates() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || orress_relay::run(listener));

    // A raw observer in the room that can open the sealed traffic.
    let key = RoomKey::derive("ctf/idle", "pw").unwrap();
    let mut observer = connect(&addr);
    join(&mut observer, "ctf/idle");
    std::thread::sleep(Duration::from_millis(150));

    let mut alice = CollabSession::connect(
        &format!("ws://{addr}"),
        "ctf/idle",
        "pw",
        Peer::new("alice", "Alice"),
    )
    .unwrap();
    // Many idle frames at a fixed time (so only the first heartbeat fires).
    let now = now_ms();
    for _ in 0..50 {
        alice.poll(now);
        std::thread::sleep(Duration::from_millis(5));
    }
    let count_updates = |observer: &mut Client, wait: Duration| {
        let mut updates = 0;
        while let Some(payload) = read_data(observer, wait) {
            if let Ok(ClientMessage::Update(_)) = ClientMessage::open(&payload, &key) {
                updates += 1;
            }
        }
        updates
    };
    assert_eq!(
        count_updates(&mut observer, Duration::from_millis(400)),
        0,
        "an idle session must not broadcast document updates"
    );

    // A real edit is broadcast exactly once.
    alice.doc.set_rename(0x1000, "main");
    for _ in 0..20 {
        alice.poll(now);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(count_updates(&mut observer, Duration::from_millis(400)), 1);
}

#[test]
fn connections_beyond_the_cap_are_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let config = orress_relay::RelayConfig {
        max_connections: 1,
        ..Default::default()
    };
    std::thread::spawn(move || orress_relay::run_with(listener, config));

    let _first = connect(&addr);
    std::thread::sleep(Duration::from_millis(100));
    let stream = TcpStream::connect(&addr).expect("tcp connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert!(
        tungstenite::client(format!("ws://{addr}/"), stream).is_err(),
        "the second connection exceeds the cap"
    );
}

#[test]
fn oversized_messages_close_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let config = orress_relay::RelayConfig {
        max_message_size: 1024,
        ..Default::default()
    };
    std::thread::spawn(move || orress_relay::run_with(listener, config));

    let mut alice = connect(&addr);
    let mut bob = connect(&addr);
    join(&mut alice, "r");
    join(&mut bob, "r");
    std::thread::sleep(Duration::from_millis(150));
    let _ = alice.send(Message::Binary(
        Envelope::Data {
            payload: vec![0u8; 4096],
        }
        .encode(),
    ));
    // The oversized frame is never relayed.
    assert_eq!(read_data(&mut bob, Duration::from_millis(500)), None);
}
