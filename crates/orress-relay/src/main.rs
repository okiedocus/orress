//! The ORRESS collaboration relay server. Run it to let a team share a project:
//!
//! ```text
//! orress-relay 0.0.0.0:8787
//! ```
//!
//! It only forwards end-to-end-encrypted room traffic; it never sees the team's data. Pair it with
//! a TLS-terminating reverse proxy for `wss://` if you want transport encryption on top.
//!
//! Limits can be tuned with environment variables: `ORRESS_RELAY_MAX_CONNECTIONS` (default 512)
//! and `ORRESS_RELAY_MAX_MESSAGE_BYTES` (default 4 MiB).

use std::net::TcpListener;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".to_string());
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            let actual = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr);
            println!("ORRESS relay listening on ws://{actual}");
            orress_relay::run_with(listener, config_from_env());
        }
        Err(e) => {
            eprintln!("could not bind {addr}: {e}");
            std::process::exit(1);
        }
    }
}

/// The default [`orress_relay::RelayConfig`], with limits overridden from the environment.
fn config_from_env() -> orress_relay::RelayConfig {
    let mut config = orress_relay::RelayConfig::default();
    let num = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
    };
    if let Some(n) = num("ORRESS_RELAY_MAX_CONNECTIONS") {
        config.max_connections = n;
    }
    if let Some(n) = num("ORRESS_RELAY_MAX_MESSAGE_BYTES") {
        config.max_message_size = n;
    }
    config
}
