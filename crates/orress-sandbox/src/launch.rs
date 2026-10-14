//! A minimal process launcher that records a sample's lifecycle (start, output, exit) with a
//! timeout. This is the safe foundation for dynamic analysis; richer monitoring (file/registry/
//! network via ETW, a fake network, in-memory YARA) builds on top. Callers must pass the
//! guard before calling [`run`].
//!
//! Containment: the sample runs with no stdin, and its whole process tree is tracked — a Job
//! Object on Windows (the process starts suspended and is assigned before it runs a single
//! instruction; the job kills everything in it when closed), its own process group on Unix.
//! When the run ends (the timeout, or the sample exits) whatever is left of the tree is killed,
//! so a sample can't leave children running behind. (On Unix a descendant that leaves the
//! process group — `setsid` — escapes this.) Output is read as raw bytes (invalid UTF-8 is
//! replaced, never dropped) and capped, and the run never blocks forever on a pipe an escaped
//! process still holds.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Total bytes of stdout + stderr recorded per run; the rest is drained and dropped.
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
/// The longest single line recorded; longer lines are split.
const MAX_LINE: usize = 64 * 1024;
/// After the tree is killed, how long to wait for the output readers to see end-of-file.
const READER_GRACE: Duration = Duration::from_secs(2);

/// An event observed while a sample ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    Started(u32),
    Stdout(String),
    Stderr(String),
    Exited(i32),
    Timeout,
    Error(String),
}

/// The record of one sandboxed run.
#[derive(Debug, Clone, Default)]
pub struct RunLog {
    pub events: Vec<RunEvent>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration: Duration,
}

type Events = Arc<Mutex<Vec<RunEvent>>>;

/// The sample's whole process tree.
struct Tree {
    #[cfg(windows)]
    job: Option<crate::job::Job>,
    #[cfg(unix)]
    pgid: i32,
}

impl Tree {
    /// Starts tracking `child`'s tree (and, on Windows, lets the suspended child run).
    fn attach(child: &Child) -> Tree {
        #[cfg(windows)]
        {
            let job = crate::job::Job::new().filter(|j| j.assign(child));
            // Always resume: a child left suspended would just sit until the timeout.
            crate::job::resume_process(child.id());
            Tree { job }
        }
        #[cfg(unix)]
        {
            Tree {
                pgid: child.id() as i32,
            }
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = child;
            Tree {}
        }
    }

    /// Kills every process still in the tree.
    fn kill(&self) {
        #[cfg(windows)]
        if let Some(job) = &self.job {
            job.terminate();
        }
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, killpg};
            use nix::unistd::Pid;
            let _ = killpg(Pid::from_raw(self.pgid), Signal::SIGKILL);
        }
    }
}

/// Runs `exe` with `args` (in `cwd` if given), capturing its output and exit, killing it after
/// `timeout`. The caller is responsible for having passed the execution guard first.
pub fn run(exe: &Path, args: &[String], cwd: Option<&Path>, timeout: Duration) -> RunLog {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let push = |e: RunEvent| events.lock().unwrap().push(e);
    let start = Instant::now();
    let deadline = start + timeout;

    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group, so the whole tree can be killed at once.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Suspended until it is inside the job, so nothing it spawns can escape the job.
        cmd.creation_flags(crate::job::CREATE_SUSPENDED);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            push(RunEvent::Error(format!("could not start: {e}")));
            return RunLog {
                events: take_events(&events),
                duration: start.elapsed(),
                ..Default::default()
            };
        }
    };
    let tree = Tree::attach(&child);
    push(RunEvent::Started(child.id()));

    // Stream stdout/stderr on helper threads into the shared log.
    let budget = Arc::new(AtomicUsize::new(0));
    let (done_tx, done_rx) = channel();
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        readers.push(spawn_reader(
            out,
            RunEvent::Stdout,
            Arc::clone(&events),
            Arc::clone(&budget),
            done_tx.clone(),
        ));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(spawn_reader(
            err,
            RunEvent::Stderr,
            Arc::clone(&events),
            Arc::clone(&budget),
            done_tx.clone(),
        ));
    }
    drop(done_tx);

    // Wait with a timeout (std has no wait-with-timeout, so poll).
    let mut exit_code = None;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    tree.kill();
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(e) => {
                events.lock().unwrap().push(RunEvent::Error(e.to_string()));
                break;
            }
        }
    }

    let mut pending = readers.len();
    if !timed_out {
        // The sample exited, but processes it started may still be writing to the pipes:
        // they get the rest of the time budget too.
        pending -= wait_readers(&done_rx, pending, deadline);
        if pending > 0 {
            timed_out = true;
        }
    }
    // Nothing the sample started outlives the run.
    tree.kill();
    pending -= wait_readers(&done_rx, pending, Instant::now() + READER_GRACE);
    for r in readers {
        // A reader still blocked (a pipe held by a process that escaped the tree) is left
        // detached rather than hanging the run.
        if pending == 0 || r.is_finished() {
            let _ = r.join();
        }
    }

    if let Some(code) = exit_code {
        events.lock().unwrap().push(RunEvent::Exited(code));
    }
    if timed_out {
        events.lock().unwrap().push(RunEvent::Timeout);
    }

    RunLog {
        events: take_events(&events),
        exit_code,
        timed_out,
        duration: start.elapsed(),
    }
}

/// Moves the recorded events out (a detached reader may still hold the `Arc`).
fn take_events(events: &Events) -> Vec<RunEvent> {
    std::mem::take(&mut *events.lock().unwrap())
}

/// Waits until `pending` readers have finished or `until` passes; returns how many finished.
fn wait_readers(done: &Receiver<()>, pending: usize, until: Instant) -> usize {
    let mut finished = 0;
    while finished < pending {
        let left = until.saturating_duration_since(Instant::now());
        match done.recv_timeout(left) {
            Ok(()) => finished += 1,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }
    finished
}

/// Reads `src` line by line into the log on its own thread. Lines are raw bytes up to `\n`
/// (lossily decoded, so invalid UTF-8 never stops the capture), split at [`MAX_LINE`]; once
/// the shared `budget` passes [`MAX_OUTPUT`] the rest is drained without being recorded.
fn spawn_reader<R: Read + Send + 'static>(
    src: R,
    wrap: fn(String) -> RunEvent,
    events: Events,
    budget: Arc<AtomicUsize>,
    done: Sender<()>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        read_lines(src, wrap, &events, &budget);
        let _ = done.send(());
    })
}

fn read_lines<R: Read>(
    src: R,
    wrap: fn(String) -> RunEvent,
    events: &Mutex<Vec<RunEvent>>,
    budget: &AtomicUsize,
) {
    let mut reader = BufReader::new(src);
    let mut line = Vec::new();
    let mut truncated = false;
    loop {
        line.clear();
        match reader
            .by_ref()
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut line)
        {
            Ok(0) => break,
            Ok(n) => {
                let used = budget.fetch_add(n, Ordering::SeqCst);
                if used.saturating_add(n) > MAX_OUTPUT {
                    if !truncated {
                        truncated = true;
                        events
                            .lock()
                            .unwrap()
                            .push(wrap("[output truncated]".into()));
                    }
                    continue;
                }
                if line.last() == Some(&b'\n') {
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                }
                let text = String::from_utf8_lossy(&line).into_owned();
                events.lock().unwrap().push(wrap(text));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn echo() -> (&'static str, Vec<String>) {
        ("cmd", vec!["/c".into(), "echo sandbox_ok".into()])
    }
    #[cfg(not(windows))]
    fn echo() -> (&'static str, Vec<String>) {
        ("echo", vec!["sandbox_ok".into()])
    }

    #[test]
    fn captures_output_and_exit() {
        let (exe, args) = echo();
        let log = run(Path::new(exe), &args, None, Duration::from_secs(10));
        assert_eq!(log.exit_code, Some(0));
        assert!(!log.timed_out);
        assert!(
            log.events
                .iter()
                .any(|e| matches!(e, RunEvent::Stdout(s) if s.contains("sandbox_ok")))
        );
        assert!(matches!(log.events.first(), Some(RunEvent::Started(_))));
    }

    #[test]
    fn reports_a_missing_binary() {
        let log = run(
            Path::new("this_binary_does_not_exist_orress"),
            &[],
            None,
            Duration::from_secs(2),
        );
        assert!(log.events.iter().any(|e| matches!(e, RunEvent::Error(_))));
    }

    /// A grandchild holding the output pipe must not hang the run past its timeout.
    #[test]
    fn timeout_kills_the_whole_tree() {
        #[cfg(windows)]
        let (exe, args) = (
            "cmd",
            vec!["/c".to_string(), "ping -n 30 127.0.0.1".to_string()],
        );
        #[cfg(not(windows))]
        let (exe, args) = (
            "sh",
            vec!["-c".to_string(), "sleep 30; echo done".to_string()],
        );
        let log = run(Path::new(exe), &args, None, Duration::from_millis(800));
        assert!(log.timed_out);
        assert!(
            log.duration < Duration::from_secs(10),
            "took {:?}",
            log.duration
        );
        assert!(log.events.contains(&RunEvent::Timeout));
    }

    #[test]
    fn invalid_utf8_does_not_stop_the_capture() {
        let events = Mutex::new(Vec::new());
        let budget = AtomicUsize::new(0);
        let src = std::io::Cursor::new(b"first\r\n\xff\xfe bad\nafter\nno newline".to_vec());
        read_lines(src, RunEvent::Stdout, &events, &budget);
        let got = events.into_inner().unwrap();
        assert_eq!(
            got,
            vec![
                RunEvent::Stdout("first".into()),
                RunEvent::Stdout("\u{fffd}\u{fffd} bad".into()),
                RunEvent::Stdout("after".into()),
                RunEvent::Stdout("no newline".into()),
            ]
        );
    }

    #[test]
    fn output_is_capped() {
        let events = Mutex::new(Vec::new());
        let budget = AtomicUsize::new(MAX_OUTPUT - 3);
        let src = std::io::Cursor::new(b"ab\ncd\nef\n".to_vec());
        read_lines(src, RunEvent::Stdout, &events, &budget);
        let got = events.into_inner().unwrap();
        assert_eq!(
            got,
            vec![
                RunEvent::Stdout("ab".into()),
                RunEvent::Stdout("[output truncated]".into()),
            ]
        );
    }
}
