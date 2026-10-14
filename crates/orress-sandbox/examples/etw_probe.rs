//! Probes the ETW activity monitor: starts it, captures for ~2s, prints a summary. On a non-admin
//! shell this should fail cleanly with the "run as administrator" hint; elevated it prints events.
//!
//! Run with: `cargo run -p orress-sandbox --example etw_probe`

fn main() {
    match orress_sandbox::etw::start() {
        Err(e) => {
            println!("monitor did not start (expected without admin):\n  {e}");
        }
        Ok(mut monitor) => {
            println!("monitor started — capturing for 2s…");
            std::thread::sleep(std::time::Duration::from_secs(2));
            let events = monitor.events();
            println!("captured {} event(s)", events.len());
            for e in events.iter().take(15) {
                println!(
                    "  [{:>8}] pid {:<6} {} {}",
                    e.category.label(),
                    e.pid,
                    e.op,
                    e.detail
                );
            }
            monitor.stop();
        }
    }
}
