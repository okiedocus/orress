//! Tubes: talk to a target over its standard I/O (a spawned local process) or over a TCP socket
//! (a remote service), with the pwntools `send`/`recvuntil`/… surface. A background reader thread
//! fills a shared buffer so `recvuntil` can wait for a delimiter with a timeout.
//!
//! Every call blocks (bounded by the timeout), so a tube is only ever driven from a worker thread,
//! never the UI thread.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The bytes read so far, and whether the far end has closed.
#[derive(Default)]
struct Buffer {
    data: Vec<u8>,
    closed: bool,
}

type Shared = Arc<(Mutex<Buffer>, Condvar)>;

/// A connection to a target. Dropping it kills a spawned child.
pub struct Tube {
    shared: Shared,
    writer: Box<dyn Write + Send>,
    child: Option<Child>,
    timeout: Duration,
}

impl Tube {
    /// Spawns `path` with `args` and talks to it over its stdin/stdout (stderr is discarded).
    pub fn process(path: &str, args: &[String]) -> std::io::Result<Self> {
        let mut child = Command::new(path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let writer = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        Ok(Self::from_parts(
            Box::new(stdout),
            Box::new(writer),
            Some(child),
        ))
    }

    /// Connects to a remote `host:port` over TCP.
    pub fn remote(host: &str, port: u16) -> std::io::Result<Self> {
        let stream = TcpStream::connect((host, port))?;
        let reader = stream.try_clone()?;
        Ok(Self::from_parts(Box::new(reader), Box::new(stream), None))
    }

    fn from_parts(
        mut reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        child: Option<Child>,
    ) -> Self {
        let shared: Shared = Arc::new((Mutex::new(Buffer::default()), Condvar::new()));
        let worker = Arc::clone(&shared);
        let _ = std::thread::Builder::new()
            .name("tube-reader".into())
            .spawn(move || {
                let (lock, cv) = &*worker;
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            lock.lock().unwrap_or_else(|e| e.into_inner())
                                .data
                                .extend_from_slice(&buf[..n]);
                            cv.notify_all();
                        }
                    }
                }
                lock.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
                cv.notify_all();
            });
        Self {
            shared,
            writer,
            child,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sets the receive timeout in seconds.
    pub fn set_timeout(&mut self, secs: f64) {
        self.timeout = Duration::from_secs_f64(secs.max(0.0));
    }

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()
    }

    pub fn sendline(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(data)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    /// Receives up to `n` bytes (fewer if that is all that arrives before the timeout).
    pub fn recv(&mut self, n: usize) -> Vec<u8> {
        self.wait_until(|b| !b.data.is_empty() || b.closed);
        let (lock, _) = &*self.shared;
        let mut b = lock.lock().unwrap_or_else(|e| e.into_inner());
        let take = n.min(b.data.len());
        b.data.drain(..take).collect()
    }

    /// Receives until `delim` appears (inclusive). On timeout or close, returns what is buffered.
    pub fn recvuntil(&mut self, delim: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + self.timeout;
        let (lock, cv) = &*self.shared;
        let mut b = lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(pos) = memchr::memmem::find(&b.data, delim) {
                return b.data.drain(..pos + delim.len()).collect();
            }
            if b.closed {
                return std::mem::take(&mut b.data);
            }
            let now = Instant::now();
            if now >= deadline {
                return std::mem::take(&mut b.data);
            }
            b = cv
                .wait_timeout(b, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    pub fn recvline(&mut self) -> Vec<u8> {
        self.recvuntil(b"\n")
    }

    /// Receives everything until the far end closes (bounded by the timeout).
    pub fn recvall(&mut self) -> Vec<u8> {
        self.wait_until(|b| b.closed);
        let (lock, _) = &*self.shared;
        let mut b = lock.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut b.data)
    }

    /// Closes the connection (and kills a spawned child).
    pub fn close(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn wait_until(&self, done: impl Fn(&Buffer) -> bool) {
        let deadline = Instant::now() + self.timeout;
        let (lock, cv) = &*self.shared;
        let mut b = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !done(&b) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            b = cv
                .wait_timeout(b, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

impl Drop for Tube {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[test]
    fn remote_tube_echoes_a_line() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // A one-shot echo server: read a line, write it back with a prompt.
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut w = stream;
            w.write_all(b"> ").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            w.write_all(format!("you said: {line}").as_bytes()).unwrap();
        });

        let mut t = Tube::remote("127.0.0.1", port).unwrap();
        t.set_timeout(5.0);
        let prompt = t.recvuntil(b"> ");
        assert_eq!(prompt, b"> ");
        t.sendline(b"hello").unwrap();
        let reply = t.recvuntil(b"\n");
        assert_eq!(reply, b"you said: hello\n");
        server.join().unwrap();
    }
}
