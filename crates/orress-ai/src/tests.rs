use super::*;
use std::io::Read;
use std::net::TcpListener;

#[test]
fn builds_prompt_and_bodies() {
    let p = build_prompt("where is the flag?", "format: PE");
    assert!(p.contains("# Question\nwhere is the flag?"));
    assert!(p.contains("format: PE"));

    let ob = build_openai_body("gpt-4o", "sys", "hi");
    assert_eq!(ob["model"], "gpt-4o");
    assert_eq!(ob["messages"][0]["role"], "system");
    assert_eq!(ob["messages"][1]["content"], "hi");

    let ab = build_anthropic_body("claude-x", "sys", "hi");
    assert_eq!(ab["system"], "sys");
    assert_eq!(ab["messages"][0]["content"], "hi");
    assert!(ab["max_tokens"].is_number());
}

#[test]
fn key_persistence_is_opt_in_and_the_default_model_is_current() {
    assert!(!Config::default().remember_key);
    assert_eq!(DEFAULT_CLAUDE_MODEL, "claude-opus-5-5");
    assert!(
        build_anthropic_body("m", "s", "u")["max_tokens"]
            .as_u64()
            .unwrap()
            >= 4096
    );
}

#[test]
fn mcp_config_temp_files_are_unique_and_private() {
    let a = write_private_temp("{\"secret\":1}").unwrap();
    let b = write_private_temp("{}").unwrap();
    assert_ne!(a, b);
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "{\"secret\":1}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&a).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let _ = std::fs::remove_file(a);
    let _ = std::fs::remove_file(b);
}

#[test]
fn parses_responses() {
    let o = json!({ "choices": [{ "message": { "content": " hello " } }] });
    assert_eq!(parse_openai_response(&o).unwrap(), "hello");
    assert!(parse_openai_response(&json!({ "error": "nope" })).is_err());

    let a = json!({ "content": [{ "type": "text", "text": "hi there" }] });
    assert_eq!(parse_anthropic_response(&a).unwrap(), "hi there");
    assert!(parse_anthropic_response(&json!({ "content": [] })).is_err());
}

#[test]
fn config_defaults_and_env_key() {
    let cfg = Config {
        provider: Provider::OpenAi,
        ..Default::default()
    };
    assert_eq!(cfg.base(), "https://api.openai.com/v1");

    // A configured key wins; otherwise the env var is used.
    let cfg2 = Config {
        provider: Provider::ClaudeApi,
        api_key: "sk-xyz".into(),
        ..Default::default()
    };
    assert_eq!(cfg2.key().as_deref(), Some("sk-xyz"));
    assert_eq!(cfg2.base(), "https://api.anthropic.com");
}

#[test]
fn remember_key_controls_persistence() {
    let dir = std::env::temp_dir().join(format!("orress_ai_cfg_{}", std::process::id()));
    let path = dir.join("ai.json");

    // remember_key on → the key is written and loads back.
    let cfg = Config {
        provider: Provider::OpenAi,
        model: "m".into(),
        base_url: "http://x/v1".into(),
        remember_key: true,
        api_key: "sk-secret".into(),
    };
    save_config(&path, &cfg).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("sk-secret")
    );
    assert_eq!(load_config(&path).api_key, "sk-secret");

    // remember_key off → the key is stripped from disk.
    let cfg2 = Config {
        remember_key: false,
        ..cfg
    };
    save_config(&path, &cfg2).unwrap();
    assert!(
        !std::fs::read_to_string(&path)
            .unwrap()
            .contains("sk-secret")
    );
    assert_eq!(load_config(&path).api_key, "");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn offline_has_no_model() {
    let cfg = Config {
        provider: Provider::Offline,
        ..Default::default()
    };
    assert!(ask(&cfg, "s", "u", &[]).is_err());
}

#[test]
fn mcp_config_json_matches_the_claude_cli_shape() {
    let servers = [McpServer {
        name: "docs".into(),
        command: "mcp-server".into(),
        args: vec!["--stdio".into()],
        env: vec![("TOKEN".into(), "x".into())],
    }];
    let v: serde_json::Value = serde_json::from_str(&mcp_config_json(&servers)).unwrap();
    assert_eq!(v["mcpServers"]["docs"]["command"], "mcp-server");
    assert_eq!(v["mcpServers"]["docs"]["args"][0], "--stdio");
    assert_eq!(v["mcpServers"]["docs"]["env"]["TOKEN"], "x");
    // No servers → an empty map, still valid config.
    assert_eq!(mcp_config_json(&[]), r#"{"mcpServers":{}}"#);
}

/// A one-shot HTTP server that returns `body` to the first request. Returns its base URL. It reads
/// the *whole* request (headers + Content-Length body) before replying, so the client has finished
/// sending and we don't reset its connection.
fn mock_server(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 1024];
            let mut header_end: Option<usize> = None;
            let mut content_len = 0usize;
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&tmp[..n]);
                        if header_end.is_none()
                            && let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n")
                        {
                            header_end = Some(pos + 4);
                            let headers = String::from_utf8_lossy(&req[..pos]).to_ascii_lowercase();
                            if let Some(line) =
                                headers.lines().find(|l| l.starts_with("content-length:"))
                            {
                                content_len = line[15..].trim().parse().unwrap_or(0);
                            }
                        }
                        if let Some(he) = header_end
                            && req.len() >= he + content_len
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            use std::io::Write as _;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn openai_round_trips_against_a_mock() {
    let base = mock_server(r#"{"choices":[{"message":{"content":"It is an XOR crackme."}}]}"#);
    let out = openai(
        &base,
        Some("test-key".into()),
        "gpt-4o-mini",
        "sys",
        "analyze this",
        &[],
    )
    .unwrap();
    assert_eq!(out, "It is an XOR crackme.");
}

#[test]
fn anthropic_round_trips_against_a_mock() {
    let base = mock_server(r#"{"content":[{"type":"text","text":"Anti-debug check present."}]}"#);
    let out = anthropic(&base, "sk-test", "claude-x", "sys", "analyze this", &[]).unwrap();
    assert_eq!(out, "Anti-debug check present.");
}

#[test]
fn http_error_is_reported() {
    // No server here → a transport error, surfaced not panicked.
    let r = openai("http://127.0.0.1:1", None, "m", "s", "u", &[]);
    assert!(r.is_err());
}
