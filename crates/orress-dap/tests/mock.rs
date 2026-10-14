//! Verifies the full DAP client state machine against the mock adapter.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use orress_dap::{DapSession, Status};

#[test]
fn drives_to_a_stop_with_variables() {
    let adapter = env!("CARGO_BIN_EXE_orress_dap_mock");
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    let mut bps = HashMap::new();
    bps.insert(PathBuf::from("/tmp/demo.rs"), vec![3u32]);
    let session = DapSession::launch(adapter, &[], &PathBuf::from("/tmp/demo"), None, bps, notify)
        .expect("launch");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let st = session.state();
        if st.status == Some(Status::Stopped) && !st.frames.is_empty() {
            assert_eq!(st.stop_reason.as_deref(), Some("breakpoint"));
            assert_eq!(st.current.as_ref().map(|(_, l)| *l), Some(3));
            assert_eq!(st.frames[0].name, "main");
            assert!(
                st.variables
                    .iter()
                    .any(|v| v.name == "a" && v.value == "41"),
                "vars: {:?}",
                st.variables
            );
            break;
        }
        assert!(
            st.status != Some(Status::Failed),
            "failed: {:?}",
            st.last_error
        );
        assert!(
            Instant::now() < deadline,
            "timed out; status {:?}",
            st.status
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(hits.load(Ordering::SeqCst) > 0);
    session.stop();
}
