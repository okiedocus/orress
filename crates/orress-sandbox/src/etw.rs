//! A kernel-level activity monitor via ETW (Event Tracing for Windows). While a sample runs, it
//! records process, file, registry, network and image-load events system-wide; the UI filters to
//! the sample's PID. The NT Kernel Logger requires **administrator** privileges, so starting the
//! trace fails cleanly (with that hint) when ORRESS is not elevated. Windows-only; other
//! platforms return an error.

#[cfg(windows)]
use std::sync::Mutex;

#[cfg(windows)]
use crate::event_log::EventLog;

/// The kind of activity an event represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Process,
    File,
    Registry,
    Network,
    Image,
    Other,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Process => "Process",
            Self::File => "File",
            Self::Registry => "Registry",
            Self::Network => "Network",
            Self::Image => "Image",
            Self::Other => "Other",
        }
    }
}

/// One recorded activity event.
#[derive(Debug, Clone)]
pub struct ActivityEvent {
    pub seq: usize,
    pub pid: u32,
    pub category: Category,
    pub op: String,
    pub detail: String,
}

/// The largest number of events kept in memory.
#[cfg(windows)]
const MAX_EVENTS: usize = 50_000;

#[cfg(windows)]
pub use imp::Monitor;

/// Starts the activity monitor (Windows + admin only).
#[cfg(windows)]
pub fn start() -> Result<Monitor, String> {
    imp::start()
}

#[cfg(not(windows))]
pub struct Monitor;

#[cfg(not(windows))]
impl Monitor {
    pub fn events(&self) -> Vec<ActivityEvent> {
        Vec::new()
    }
    pub fn with_events<R>(&self, f: impl FnOnce(&[ActivityEvent]) -> R) -> R {
        f(&[])
    }
    pub fn events_since(&self, seen: usize) -> (Vec<ActivityEvent>, usize) {
        (Vec::new(), seen)
    }
    pub fn stop(&mut self) {}
}

#[cfg(not(windows))]
pub fn start() -> Result<Monitor, String> {
    Err("the ETW activity monitor is only available on Windows".into())
}

/// Appends an event, capping the log so it can't grow without bound.
#[cfg(windows)]
fn record(log: &Mutex<EventLog<ActivityEvent>>, ev: ActivityEvent) {
    log.lock().unwrap().push(ev, MAX_EVENTS);
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::provider::kernel_providers::{
        FILE_IO_PROVIDER, IMAGE_LOAD_PROVIDER, PROCESS_PROVIDER, REGISTRY_PROVIDER,
        TCP_IP_PROVIDER, THREAD_PROVIDER,
    };
    use ferrisetw::trace::{TraceTrait, stop_trace_by_name};
    use ferrisetw::{EventRecord, GUID, KernelTrace, SchemaLocator};

    use super::{ActivityEvent, Category};
    use crate::event_log::EventLog;

    const TRACE_NAME: &str = "ORRESS-Activity";

    /// A running ETW activity monitor. Stops on drop.
    pub struct Monitor {
        log: Arc<Mutex<EventLog<ActivityEvent>>>,
        trace: Option<KernelTrace>,
        thread: Option<JoinHandle<()>>,
    }

    impl Monitor {
        /// A copy of every retained event. Prefer [`events_since`](Self::events_since) for
        /// periodic refreshes, or [`with_events`](Self::with_events) to read without copying.
        pub fn events(&self) -> Vec<ActivityEvent> {
            self.log.lock().unwrap().events().to_vec()
        }

        /// Runs `f` over the retained events (oldest first) without copying them. The log is
        /// locked meanwhile, so keep `f` short.
        pub fn with_events<R>(&self, f: impl FnOnce(&[ActivityEvent]) -> R) -> R {
            f(self.log.lock().unwrap().events())
        }

        /// The events recorded since a reader had seen `seen` of them (start at 0), and the count
        /// to pass next time — so a periodic refresh copies only what is new.
        pub fn events_since(&self, seen: usize) -> (Vec<ActivityEvent>, usize) {
            self.log.lock().unwrap().since(seen)
        }

        pub fn stop(&mut self) {
            if let Some(trace) = self.trace.take() {
                let _ = trace.stop();
            }
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    impl Drop for Monitor {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn categorize(guid: GUID) -> Category {
        for (provider, cat) in [
            (&PROCESS_PROVIDER, Category::Process),
            (&FILE_IO_PROVIDER, Category::File),
            (&REGISTRY_PROVIDER, Category::Registry),
            (&TCP_IP_PROVIDER, Category::Network),
            (&IMAGE_LOAD_PROVIDER, Category::Image),
        ] {
            if provider.guid == guid {
                return cat;
            }
        }
        Category::Other
    }

    /// Best-effort extraction of the most useful string field for a category.
    fn detail_for(cat: Category, parser: &Parser) -> String {
        let fields: &[&str] = match cat {
            Category::Image => &["FileName"],
            Category::Process => &["ImageFileName", "ProcessName", "CommandLine"],
            Category::File => &["FileName", "OpenPath"],
            Category::Registry => &["KeyName", "RelativeName", "ValueName"],
            Category::Network => &["daddr", "DestinationIp"],
            Category::Other => &[],
        };
        for f in fields {
            if let Ok(v) = parser.try_parse::<String>(f)
                && !v.is_empty()
            {
                return v;
            }
        }
        String::new()
    }

    /// The header PID kernel events carry when they were logged outside any process context
    /// (common for FileIo, which the kernel logs from wherever the I/O completes).
    const NO_PID: u32 = u32::MAX;
    /// Bound on the thread→process map (cleared and relearned if a trace churns past it).
    const MAX_THREADS: usize = 200_000;

    /// Thread id -> owning process id, learned from Thread events and from every event whose
    /// header names both, so context-less events can be attributed to the right process.
    type ThreadMap = Mutex<HashMap<u32, u32>>;

    fn learn(threads: &ThreadMap, tid: u32, pid: u32) {
        if tid == NO_PID || pid == NO_PID || pid == 0 {
            return;
        }
        let mut m = threads.lock().unwrap();
        if m.len() >= MAX_THREADS {
            m.clear();
        }
        m.insert(tid, pid);
    }

    fn handle(
        record: &EventRecord,
        locator: &SchemaLocator,
        log: &Arc<Mutex<EventLog<ActivityEvent>>>,
        seq: &AtomicUsize,
        threads: &ThreadMap,
    ) {
        let schema = locator.event_schema(record).ok();
        let parser = schema.as_ref().map(|s| Parser::create(record, s));

        // Thread events only feed the thread→process map; they aren't activity themselves.
        if record.provider_id() == THREAD_PROVIDER.guid {
            if let Some(p) = &parser
                && let (Ok(pid), Ok(tid)) = (
                    p.try_parse::<u32>("ProcessId"),
                    p.try_parse::<u32>("TThreadId"),
                )
            {
                learn(threads, tid, pid);
            }
            return;
        }

        let mut pid = record.process_id();
        learn(threads, record.thread_id(), pid);
        if pid == NO_PID {
            // No process context in the header: attribute the event through the issuing
            // thread (FileIo payloads carry it as TTID) if we know which process owns it.
            let tid = Some(record.thread_id())
                .filter(|&t| t != NO_PID)
                .or_else(|| parser.as_ref()?.try_parse::<u32>("TTID").ok());
            if let Some(owner) = tid.and_then(|t| threads.lock().unwrap().get(&t).copied()) {
                pid = owner;
            }
        }

        let category = categorize(record.provider_id());
        let (op, detail) = match (&schema, &parser) {
            (Some(schema), Some(parser)) => {
                let name = schema.opcode_name();
                let op = if name.is_empty() {
                    format!("opcode {}", record.opcode())
                } else {
                    name
                };
                (op, detail_for(category, parser))
            }
            _ => (format!("opcode {}", record.opcode()), String::new()),
        };
        let ev = ActivityEvent {
            seq: seq.fetch_add(1, Ordering::SeqCst),
            pid,
            category,
            op,
            detail,
        };
        super::record(log, ev);
    }

    pub fn start() -> Result<Monitor, String> {
        // Clean up a leftover session from a previous (crashed) run.
        let _ = stop_trace_by_name(TRACE_NAME);

        let log = Arc::new(Mutex::new(EventLog::default()));
        let seq = Arc::new(AtomicUsize::new(0));
        let threads: Arc<ThreadMap> = Arc::new(Mutex::new(HashMap::new()));
        let provider = |kp| {
            let (log, seq, threads) = (Arc::clone(&log), Arc::clone(&seq), Arc::clone(&threads));
            Provider::kernel(kp)
                .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                    handle(rec, loc, &log, &seq, &threads)
                })
                .build()
        };

        let (trace, handle) = KernelTrace::new()
            .named(TRACE_NAME.to_string())
            // Thread start/end (and the rundown of existing threads) map thread ids to
            // processes, for events that arrive without a process context.
            .enable(provider(&THREAD_PROVIDER))
            .enable(provider(&PROCESS_PROVIDER))
            .enable(provider(&FILE_IO_PROVIDER))
            .enable(provider(&REGISTRY_PROVIDER))
            .enable(provider(&TCP_IP_PROVIDER))
            .enable(provider(&IMAGE_LOAD_PROVIDER))
            .start()
            .map_err(|e| {
                let raw = format!("{e:?}");
                // 0x80070005 / errno 5 is ERROR_ACCESS_DENIED — by far the most common cause.
                if raw.contains("-2147024891") || raw.to_lowercase().contains("denied") {
                    "ETW kernel tracing requires running ORRESS as administrator (access denied)."
                        .to_string()
                } else {
                    format!("could not start ETW kernel trace: {raw}")
                }
            })?;

        let thread = std::thread::spawn(move || {
            let _ = KernelTrace::process_from_handle(handle);
        });

        Ok(Monitor {
            log,
            trace: Some(trace),
            thread: Some(thread),
        })
    }
}
