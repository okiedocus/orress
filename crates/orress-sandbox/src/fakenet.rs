//! A tiny fake-network responder (INetSim / FakeNet-NG style). A detonated sample, with its VM
//! network pointed here, gets an answer for every DNS query and HTTP request — so instead of
//! reaching real infrastructure it talks to us, and we **log** exactly what it tried to do.
//!
//! Pure `std` networking: a minimal DNS A-record responder and an HTTP responder that returns a
//! canned 200. Ports are configurable (the real `53`/`80` need privileges; tests use ephemeral
//! ports). Listeners run on background threads and stop on drop; each HTTP connection gets its
//! own (bounded) thread, and the event log is capped.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::event_log::EventLog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    Dns,
    Http,
}

/// One observed network attempt.
#[derive(Debug, Clone)]
pub struct NetEvent {
    pub seq: usize,
    pub kind: NetKind,
    pub summary: String,
}

/// Fake-network configuration.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// The IPv4 address every DNS A query is answered with.
    pub answer_ip: Ipv4Addr,
    pub dns_port: u16,
    pub http_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            answer_ip: Ipv4Addr::new(127, 0, 0, 1),
            dns_port: 53,
            http_port: 80,
        }
    }
}

/// A running fake network. Dropping it stops the listeners.
pub struct FakeNet {
    log: Arc<Mutex<EventLog<NetEvent>>>,
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub dns_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    pub errors: Vec<String>,
}

impl FakeNet {
    /// Binds the responders and starts serving. Bind failures (e.g. no privilege for port 53)
    /// are recorded in `errors` rather than failing the whole start.
    pub fn start(cfg: Config) -> Self {
        let log = Arc::new(Mutex::new(EventLog::default()));
        let seq = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let mut errors = Vec::new();
        let mut dns_addr = None;
        let mut http_addr = None;

        match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, cfg.dns_port)) {
            Ok(sock) => {
                sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
                dns_addr = sock.local_addr().ok();
                let (log, seq, shutdown) = (log.clone(), seq.clone(), shutdown.clone());
                let answer = cfg.answer_ip;
                threads.push(std::thread::spawn(move || {
                    dns_loop(&sock, answer, &log, &seq, &shutdown)
                }));
            }
            Err(e) => errors.push(format!("DNS :{} — {e}", cfg.dns_port)),
        }

        match TcpListener::bind((Ipv4Addr::UNSPECIFIED, cfg.http_port)) {
            Ok(listener) => {
                listener.set_nonblocking(true).ok();
                http_addr = listener.local_addr().ok();
                let (log, seq, shutdown) = (log.clone(), seq.clone(), shutdown.clone());
                threads.push(std::thread::spawn(move || {
                    http_loop(&listener, &log, &seq, &shutdown)
                }));
            }
            Err(e) => errors.push(format!("HTTP :{} — {e}", cfg.http_port)),
        }

        FakeNet {
            log,
            shutdown,
            threads,
            dns_addr,
            http_addr,
            errors,
        }
    }

    /// A snapshot of the captured network events. Prefer [`events_since`](Self::events_since)
    /// for periodic refreshes, or [`with_events`](Self::with_events) to read without copying.
    pub fn events(&self) -> Vec<NetEvent> {
        self.log.lock().unwrap().events().to_vec()
    }

    /// Runs `f` over the retained events (oldest first) without copying them. The log is locked
    /// meanwhile, so keep `f` short.
    pub fn with_events<R>(&self, f: impl FnOnce(&[NetEvent]) -> R) -> R {
        f(self.log.lock().unwrap().events())
    }

    /// The events captured since a reader had seen `seen` of them (start at 0), and the count to
    /// pass next time — so a periodic refresh copies only what is new.
    pub fn events_since(&self, seen: usize) -> (Vec<NetEvent>, usize) {
        self.log.lock().unwrap().since(seen)
    }

    /// Whether any listener is serving.
    pub fn is_listening(&self) -> bool {
        self.dns_addr.is_some() || self.http_addr.is_some()
    }

    /// Stops the listeners and joins their threads.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for FakeNet {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The most events kept; beyond this the oldest are dropped (a chatty sample can't exhaust
/// memory).
const MAX_EVENTS: usize = 50_000;
/// The most HTTP connections served at once; more are closed unanswered.
const MAX_HTTP_CONNECTIONS: usize = 64;

fn record(log: &Mutex<EventLog<NetEvent>>, seq: &AtomicUsize, kind: NetKind, summary: String) {
    let n = seq.fetch_add(1, Ordering::SeqCst);
    log.lock().unwrap().push(
        NetEvent {
            seq: n,
            kind,
            summary,
        },
        MAX_EVENTS,
    );
}

// --- DNS ------------------------------------------------------------------

fn dns_loop(
    sock: &UdpSocket,
    answer: Ipv4Addr,
    log: &Mutex<EventLog<NetEvent>>,
    seq: &AtomicUsize,
    shutdown: &AtomicBool,
) {
    let mut buf = [0u8; 512];
    while !shutdown.load(Ordering::SeqCst) {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some((domain, resp)) = dns_reply(&buf[..n], answer) {
                    let _ = sock.send_to(&resp, src);
                    record(log, seq, NetKind::Dns, format!("A? {domain}  →  {answer}"));
                }
            }
            Err(e) if is_timeout(&e) => continue,
            Err(_) => break,
        }
    }
}

/// Parses a DNS query and builds an A-record reply, returning the queried name and the response.
fn dns_reply(query: &[u8], answer: Ipv4Addr) -> Option<(String, Vec<u8>)> {
    if query.len() < 12 {
        return None;
    }
    // QR set: this is a response, not a query — never answer it (that could loop two
    // responders against each other).
    if query[2] & 0x80 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    // Parse QNAME starting at offset 12.
    let mut i = 12;
    let mut labels = Vec::new();
    let mut name_len = 0usize;
    loop {
        let len = *query.get(i)?;
        if len == 0 {
            i += 1;
            break;
        }
        // The top two bits mark a compression pointer (0xC0) or a reserved label type; a
        // query's own question name never needs one, so reject rather than misread it as a
        // length.
        if len & 0xC0 != 0 {
            return None;
        }
        let start = i + 1;
        let end = start + len as usize;
        let label = query.get(start..end)?;
        name_len += len as usize + 1;
        if name_len > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        i = end;
    }
    let qtype = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
    let question_end = i + 4; // QTYPE(2) + QCLASS(2)
    let domain = labels.join(".");

    let mut resp = Vec::with_capacity(question_end + 16);
    resp.extend_from_slice(&query[0..2]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    let is_a = qtype == 1;
    resp.extend_from_slice(if is_a { &[0x00, 0x01] } else { &[0x00, 0x00] }); // ANCOUNT
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT
    resp.extend_from_slice(query.get(12..question_end)?); // the question
    if is_a {
        resp.extend_from_slice(&[0xc0, 0x0c]); // NAME: pointer to qname
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        resp.extend_from_slice(&answer.octets()); // RDATA
    }
    Some((domain, resp))
}

// --- HTTP -----------------------------------------------------------------

fn http_loop(
    listener: &TcpListener,
    log: &Arc<Mutex<EventLog<NetEvent>>>,
    seq: &Arc<AtomicUsize>,
    shutdown: &AtomicBool,
) {
    // Each connection is served on its own thread, so one slow client (the read waits up to
    // 2 s) can't stall the rest; the count is bounded.
    let active = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, src)) => {
                if active.load(Ordering::SeqCst) >= MAX_HTTP_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (log, seq, slot) = (Arc::clone(log), Arc::clone(seq), Arc::clone(&active));
                let spawned = std::thread::Builder::new()
                    .name("fakenet-http".into())
                    .spawn(move || {
                        handle_http(stream, src, &log, &seq);
                        slot.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn handle_http(
    mut stream: TcpStream,
    src: SocketAddr,
    log: &Mutex<EventLog<NetEvent>>,
    seq: &AtomicUsize,
) {
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    // Read until the end of the headers (or the buffer fills, or the client stops sending).
    let mut buf = [0u8; 8192];
    let mut n = 0;
    while n < buf.len() {
        match stream.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                n += k;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("").trim().to_string();
    let host = header(&req, "host");
    let agent = header(&req, "user-agent");
    let mut summary = format!("{line}  (from {src})");
    if let Some(h) = host {
        summary.push_str(&format!("  Host: {h}"));
    }
    if let Some(a) = agent {
        summary.push_str(&format!("  UA: {a}"));
    }
    record(log, seq, NetKind::Http, summary);

    let body = b"OK";
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    req.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ephemeral() -> Config {
        Config {
            answer_ip: Ipv4Addr::new(10, 1, 2, 3),
            dns_port: 0,
            http_port: 0,
        }
    }

    #[test]
    fn dns_answers_and_logs() {
        let net = FakeNet::start(ephemeral());
        let addr = net.dns_addr.expect("dns bound");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // Query "evil.example.com" A: id=0x1234, flags=0x0100, qd=1, name, A/IN.
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 4, b'e', b'v', b'i', b'l', 7,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01,
        ];
        client
            .send_to(&query, (Ipv4Addr::LOCALHOST, addr.port()))
            .unwrap();
        let mut resp = [0u8; 512];
        let n = client.recv(&mut resp).unwrap();
        // The answer's last 4 bytes are the A record IP we configured.
        assert_eq!(&resp[n - 4..n], &[10, 1, 2, 3]);
        std::thread::sleep(Duration::from_millis(50));
        let events = net.events();
        assert!(
            events
                .iter()
                .any(|e| e.kind == NetKind::Dns && e.summary.contains("evil.example.com"))
        );
    }

    #[test]
    fn dns_ignores_responses_and_pointer_labels() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0x00, 0x01, 0x00,
            0x01,
        ];
        assert!(dns_reply(&query, ip).is_some());
        // The same packet with QR set is a response: no answer.
        let mut response = query;
        response[2] |= 0x80;
        assert!(dns_reply(&response, ip).is_none());
        // A compression pointer in the question name is rejected, not read as a length.
        let pointer = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0x00, 0x01, 0x00,
            0x01,
        ];
        assert!(dns_reply(&pointer, ip).is_none());
        // A truncated name is rejected too.
        assert!(dns_reply(&query[..14], ip).is_none());
    }

    #[test]
    fn http_serves_connections_concurrently() {
        let net = FakeNet::start(ephemeral());
        let addr = net.http_addr.expect("http bound");
        // A client that connects and sends nothing must not block the next one.
        let _idle = TcpStream::connect((Ipv4Addr::LOCALHOST, addr.port())).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = std::time::Instant::now();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, addr.port())).unwrap();
        stream.write_all(b"GET /x HTTP/1.1\r\n\r\n").unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut resp = String::new();
        let _ = stream.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(start.elapsed() < Duration::from_millis(1500));
    }

    #[test]
    fn http_responds_and_logs() {
        let net = FakeNet::start(ephemeral());
        let addr = net.http_addr.expect("http bound");
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, addr.port())).unwrap();
        stream
            .write_all(
                b"GET /gate.php HTTP/1.1\r\nHost: c2.bad.example\r\nUser-Agent: EvilBot\r\n\r\n",
            )
            .unwrap();
        let mut resp = String::new();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _ = stream.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 200"));
        std::thread::sleep(Duration::from_millis(50));
        let events = net.events();
        let http = events
            .iter()
            .find(|e| e.kind == NetKind::Http)
            .expect("http event");
        assert!(http.summary.contains("/gate.php"));
        assert!(http.summary.contains("c2.bad.example"));
        assert!(http.summary.contains("EvilBot"));
    }
}
