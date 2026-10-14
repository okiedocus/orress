use super::*;

fn call(method: &str, params: Value) -> Value {
    dispatch(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .expect("a response")
}

#[test]
fn initialize_reports_server_info() {
    let r = call("initialize", json!({}));
    assert_eq!(r["result"]["serverInfo"]["name"], "orress-mcp");
    assert!(r["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn tools_list_advertises_the_tools() {
    let r = call("tools/list", json!({}));
    let names: Vec<&str> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for want in [
        "triage",
        "strings",
        "disassemble",
        "deobfuscate_js",
        "archive_list",
        "binary_diff",
        "detect_vm",
    ] {
        assert!(names.contains(&want), "missing tool {want}");
    }
    // Each tool declares a path input.
    assert_eq!(
        r["result"]["tools"][0]["inputSchema"]["required"][0],
        "path"
    );
}

#[test]
fn notifications_get_no_response() {
    // A message without an id is a notification.
    assert!(
        dispatch(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).is_none()
    );
}

#[test]
fn unknown_method_is_an_error() {
    let r = call("does/not/exist", json!({}));
    assert_eq!(r["error"]["code"], -32601);
}

#[test]
fn tool_call_deobfuscates_a_js_file() {
    let dir = std::env::temp_dir().join(format!("orress_mcp_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("drop.js");
    std::fs::write(
        &path,
        "var u=String.fromCharCode(104,116,116,112)+\"\\x3a//x\";",
    )
    .unwrap();

    let r = call(
        "tools/call",
        json!({ "name": "deobfuscate_js", "arguments": { "path": path.to_str().unwrap() } }),
    );
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("\"http://x\"") || text.contains("http"),
        "{text}"
    );
    assert_ne!(r["result"]["isError"], json!(true));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tool_call_missing_path_errors() {
    let r = call("tools/call", json!({ "name": "triage", "arguments": {} }));
    assert_eq!(r["result"]["isError"], json!(true));
    assert!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("path")
    );
}

#[test]
fn extract_strings_finds_runs() {
    let data = b"\x00\x01hello\x00\x02ab\x00world!!\x00";
    let s = tools::extract_strings(data, 5);
    assert!(s.contains(&"hello".to_string()));
    assert!(s.contains(&"world!!".to_string()));
    assert!(!s.iter().any(|x| x == "ab")); // too short
}

#[test]
fn cap_truncates_on_a_char_boundary() {
    // A multi-byte character straddling the limit must not panic.
    let s = format!("{}{}", "a".repeat(59_999), "é".repeat(10));
    let out = tools::cap(s);
    assert!(out.ends_with("(truncated)"));
    assert!(out.starts_with(&"a".repeat(59_999)));
}

#[test]
fn panic_payloads_become_messages() {
    let caught = std::panic::catch_unwind(|| panic!("boom {}", 1)).unwrap_err();
    assert_eq!(panic_message(caught.as_ref()), "boom 1");
    let caught = std::panic::catch_unwind(|| std::panic::panic_any(7u8)).unwrap_err();
    assert_eq!(panic_message(caught.as_ref()), "unknown panic");
}
