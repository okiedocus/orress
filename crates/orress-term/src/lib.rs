//! ORRESS integrated terminal: a real PTY-backed shell (ConPTY on Windows, a pty
//! elsewhere) whose output is parsed into a `vt100` screen the UI renders. The model is
//! UI-agnostic; the egui renderer lives in `orress-views`.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

pub type Notify = Arc<dyn Fn() + Send + Sync>;

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

/// A running shell with a terminal screen model.
pub struct Terminal {
    parser: Arc<Mutex<vt100::Parser>>,
    master: Box<dyn MasterPty + Send>,
    writer: Writer,
    /// Always `Some` until dropped (taken there to be reaped).
    child: Option<Box<dyn Child + Send + Sync>>,
    rows: u16,
    cols: u16,
    alive: Arc<AtomicBool>,
    _reader: JoinHandle<()>,
}

/// The default interactive shell for this platform.
pub fn default_shell() -> (String, Vec<String>) {
    if cfg!(windows) {
        ("powershell.exe".to_string(), vec!["-NoLogo".to_string()])
    } else {
        (
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string()),
            Vec::new(),
        )
    }
}

fn to_io(e: anyhow::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// The device queries we answer.
const CPR_QUERY: &[u8] = b"\x1b[6n";
const DA_QUERIES: [&[u8]; 2] = [b"\x1b[c", b"\x1b[0c"];

/// Which queries a chunk of PTY output contains, taking into account a query split across two
/// reads: `carry` holds the tail of the previous chunk that was an incomplete query prefix, and is
/// updated with this chunk's incomplete tail. Returns `(cursor_position, device_attributes)`.
fn scan_queries(carry: &mut Vec<u8>, chunk: &[u8]) -> (bool, bool) {
    let mut data = std::mem::take(carry);
    data.extend_from_slice(chunk);
    let cpr = find(&data, CPR_QUERY);
    let da = DA_QUERIES.iter().any(|q| find(&data, q));
    // Keep the longest suffix that is a proper prefix of some query (at most 3 bytes).
    let all = [CPR_QUERY, DA_QUERIES[0], DA_QUERIES[1]];
    let max = all.iter().map(|q| q.len() - 1).max().unwrap_or(0);
    for len in (1..=max.min(data.len())).rev() {
        let tail = &data[data.len() - len..];
        if all.iter().any(|q| q.len() > len && q.starts_with(tail)) {
            carry.extend_from_slice(tail);
            break;
        }
    }
    (cpr, da)
}

/// Replies to the terminal device queries a program sends through the PTY — without a
/// reply, ConPTY and many shells stall. Handles the cursor-position report (`ESC[6n`) and
/// primary device-attributes (`ESC[c` / `ESC[0c`), including ones split across reads.
fn answer_queries(chunk: &[u8], carry: &mut Vec<u8>, parser: &vt100::Parser, writer: &Writer) {
    let (cpr, da) = scan_queries(carry, chunk);
    let mut reply: Vec<u8> = Vec::new();
    if cpr {
        let (row, col) = parser.screen().cursor_position();
        reply.extend_from_slice(format!("\x1b[{};{}R", row + 1, col + 1).as_bytes());
    }
    if da {
        // Claim to be a VT100 with advanced video.
        reply.extend_from_slice(b"\x1b[?1;2c");
    }
    if !reply.is_empty()
        && let Ok(mut w) = writer.lock()
    {
        let _ = w.write_all(&reply);
        let _ = w.flush();
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

impl Terminal {
    /// Spawns `shell` in a new PTY of `rows` x `cols`, reading its output on a thread.
    pub fn spawn(
        shell: &str,
        args: &[String],
        cwd: Option<&Path>,
        rows: u16,
        cols: u16,
        notify: Notify,
    ) -> std::io::Result<Self> {
        let rows = rows.max(1);
        let cols = cols.max(1);
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(to_io)?;
        let mut cmd = CommandBuilder::new(shell);
        for a in args {
            cmd.arg(a);
        }
        if let Some(cwd) = cwd {
            cmd.cwd(cwd);
        }
        let child = pair.slave.spawn_command(cmd).map_err(to_io)?;
        let mut reader = pair.master.try_clone_reader().map_err(to_io)?;
        let writer: Writer = Arc::new(Mutex::new(pair.master.take_writer().map_err(to_io)?));

        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 5000)));
        let alive = Arc::new(AtomicBool::new(true));
        let (pr, al, nf, wr) = (
            Arc::clone(&parser),
            Arc::clone(&alive),
            Arc::clone(&notify),
            Arc::clone(&writer),
        );
        let reader = std::thread::Builder::new()
            .name("orress-term-read".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                let mut carry = Vec::new();
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let chunk = &buf[..n];
                            if let Ok(mut p) = pr.lock() {
                                p.process(chunk);
                                // Answer the terminal queries the shell/ConPTY sends, or it
                                // waits for a reply and produces no output.
                                answer_queries(chunk, &mut carry, &p, &wr);
                            }
                            nf();
                        }
                    }
                }
                al.store(false, Ordering::SeqCst);
                nf();
            })
            .expect("spawn terminal reader");

        Ok(Self {
            parser,
            master: pair.master,
            writer,
            child: Some(child),
            rows,
            cols,
            alive,
            _reader: reader,
        })
    }

    /// The vt100 screen model, locked by the caller for rendering.
    pub fn parser(&self) -> &Arc<Mutex<vt100::Parser>> {
        &self.parser
    }

    /// Sends bytes to the shell (keyboard input).
    pub fn input(&mut self, bytes: &[u8]) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(bytes);
            let _ = w.flush();
        }
    }

    /// Resizes the PTY and the screen model to `rows` x `cols`.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        let (rows, cols) = (rows.max(1), cols.max(1));
        if (rows, cols) == (self.rows, self.cols) {
            return;
        }
        self.rows = rows;
        self.cols = cols;
        let _ = self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
        if let Ok(mut p) = self.parser.lock() {
            p.screen_mut().set_size(rows, cols);
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    /// Whether the shell is still running.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl Drop for Terminal {
    /// Kills the shell and reaps it (so it does not linger as a zombie). Reaping waits briefly
    /// inline; a process that takes longer to exit is reaped on a background thread so dropping a
    /// terminal never blocks the UI.
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let _ = std::thread::Builder::new()
            .name("orress-term-reap".into())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_queries_split_across_reads() {
        let mut carry = Vec::new();
        assert_eq!(scan_queries(&mut carry, b"hello \x1b["), (false, false));
        assert_eq!(carry, b"\x1b[");
        assert_eq!(scan_queries(&mut carry, b"6n more"), (true, false));
        assert!(carry.is_empty());

        assert_eq!(scan_queries(&mut carry, b"x\x1b"), (false, false));
        assert_eq!(scan_queries(&mut carry, b"[c"), (false, true));

        assert_eq!(scan_queries(&mut carry, b"\x1b[0"), (false, false));
        assert_eq!(scan_queries(&mut carry, b"c\x1b[6n"), (true, true));

        // An ordinary escape sequence is not carried.
        assert_eq!(scan_queries(&mut carry, b"\x1b[31m"), (false, false));
        assert!(carry.is_empty());
    }
}
