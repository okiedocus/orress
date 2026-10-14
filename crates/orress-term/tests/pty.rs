use std::sync::Arc;
use std::time::{Duration, Instant};

use orress_term::Terminal;

#[test]
fn shell_runs_and_echoes() {
    let (shell, args) = if cfg!(windows) {
        ("cmd.exe".to_string(), Vec::new())
    } else {
        ("/bin/sh".to_string(), Vec::new())
    };
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let mut term = match Terminal::spawn(&shell, &args, None, 24, 80, notify) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("could not spawn shell: {e}; skipping");
            return;
        }
    };
    std::thread::sleep(Duration::from_millis(600));
    term.input(b"echo orress_marker\r\n");

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut contents = String::new();
    while Instant::now() < deadline {
        if let Ok(p) = term.parser().lock() {
            contents = p.screen().contents();
        }
        if contents.contains("orress_marker") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("screen:\n{contents}");
    assert!(
        contents.contains("orress_marker"),
        "shell output not seen on screen"
    );
}
