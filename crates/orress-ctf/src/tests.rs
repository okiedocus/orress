use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn parses_ctfd_challenges_and_verdicts() {
    let listing = serde_json::json!({
        "success": true,
        "data": [
            { "id": 1, "type": "standard", "name": "Sanity", "value": 50, "category": "misc", "solved_by_me": true },
            { "id": 2, "name": "RE 101", "value": 200, "category": "rev" }
        ]
    });
    let chs = parse_ctfd_challenges(&listing);
    assert_eq!(chs.len(), 2);
    assert_eq!(chs[0].id, "1");
    assert_eq!(chs[0].category, "misc");
    assert!(chs[0].solved);
    assert_eq!(chs[1].value, 200);
    assert!(!chs[1].solved);

    let correct = parse_ctfd_attempt(
        &serde_json::json!({ "success": true, "data": { "status": "correct", "message": "Correct!" } }),
    );
    assert!(correct.correct && !correct.already_solved && correct.message == "Correct!");
    let wrong = parse_ctfd_attempt(&serde_json::json!({ "data": { "status": "incorrect" } }));
    assert!(!wrong.correct);
    let dup = parse_ctfd_attempt(&serde_json::json!({ "data": { "status": "already_solved" } }));
    assert!(dup.already_solved);
}

#[test]
fn parses_rctf_challenges_and_verdicts() {
    let listing = serde_json::json!({
        "kind": "goodChallenges",
        "message": "ok",
        "data": [ { "id": "abc123", "name": "pwnme", "category": "pwn", "points": 300, "solved": false } ]
    });
    let chs = parse_rctf_challenges(&listing);
    assert_eq!(chs.len(), 1);
    assert_eq!(chs[0].id, "abc123");
    assert_eq!(chs[0].value, 300);

    assert!(
        parse_rctf_submit(&serde_json::json!({ "kind": "goodFlag", "message": "nice" })).correct
    );
    assert!(
        parse_rctf_submit(&serde_json::json!({ "kind": "badAlreadySolved", "message": "dup" }))
            .already_solved
    );
    assert!(
        !parse_rctf_submit(&serde_json::json!({ "kind": "badFlag", "message": "nope" })).correct
    );
}

/// A one-shot HTTP server: serves `body` to the first request, capturing it, and returns the base
/// URL plus a handle to read the captured request.
fn one_shot(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
    one_shot_status("200 OK", body)
}

/// [`one_shot`] answering with an explicit HTTP status line (e.g. `"400 Bad Request"`).
fn one_shot_status(
    status: &'static str,
    body: &'static str,
) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Read until the full request (headers + any Content-Length body) has arrived — the body
        // may land in a later segment than the request line.
        let mut data = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&data);
            if let Some(hdr_end) = text.find("\r\n\r\n") {
                let content_len = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if data.len() >= hdr_end + 4 + content_len {
                    break;
                }
            }
        }
        let request = String::from_utf8_lossy(&data).to_string();
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).unwrap();
        request
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn ctfd_client_sends_the_token_and_parses_the_listing() {
    let (base, handle) =
        one_shot(r#"{"success":true,"data":[{"id":7,"name":"x","value":10,"category":"misc"}]}"#);
    let client = CtfClient::new(Platform::Ctfd, base, "secrettoken");
    let chs = client.challenges().unwrap();
    assert_eq!(chs.len(), 1);
    assert_eq!(chs[0].id, "7");

    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /api/v1/challenges "), "{request}");
    assert!(
        request.contains("Authorization: Token secrettoken"),
        "{request}"
    );
}

#[test]
fn rctf_wrong_and_repeat_flags_are_verdicts_not_errors() {
    let (base, handle) = one_shot_status(
        "400 Bad Request",
        r#"{"kind":"badFlag","message":"The flag was incorrect."}"#,
    );
    let client = CtfClient::new(Platform::Rctf, base, "tok");
    let outcome = client.submit("chall/../x y", "flag{no}").unwrap();
    assert!(!outcome.correct && !outcome.already_solved);
    assert_eq!(outcome.message, "The flag was incorrect.");
    let request = handle.join().unwrap();
    // The id is percent-encoded into a single path segment.
    assert!(
        request.starts_with("POST /api/v1/challs/chall%2F..%2Fx%20y/submit "),
        "{request}"
    );

    let (base, _h) = one_shot_status(
        "409 Conflict",
        r#"{"kind":"badAlreadySolved","message":"already solved"}"#,
    );
    let outcome = CtfClient::new(Platform::Rctf, base, "tok")
        .submit("a", "f")
        .unwrap();
    assert!(outcome.already_solved);

    // A real failure (bad token) is still an error.
    let (base, _h) = one_shot_status(
        "401 Unauthorized",
        r#"{"kind":"badToken","message":"bad token"}"#,
    );
    assert!(
        CtfClient::new(Platform::Rctf, base, "tok")
            .submit("a", "f")
            .is_err()
    );
}

#[test]
fn rctf_solves_come_from_the_profile() {
    let profile = serde_json::json!({
        "kind": "goodUserData",
        "data": { "solves": [ { "id": "abc", "name": "x" }, { "id": "def" } ] }
    });
    let ids = parse_rctf_solved_ids(&profile);
    assert!(ids.contains("abc") && ids.contains("def") && ids.len() == 2);
    assert!(parse_rctf_solved_ids(&serde_json::json!({})).is_empty());
}

#[test]
fn ctfd_client_submits_a_flag() {
    let (base, handle) =
        one_shot(r#"{"success":true,"data":{"status":"correct","message":"Correct"}}"#);
    let client = CtfClient::new(Platform::Ctfd, base, "tok");
    let outcome = client.submit("7", "flag{abc}").unwrap();
    assert!(outcome.correct);

    let request = handle.join().unwrap();
    assert!(
        request.starts_with("POST /api/v1/challenges/attempt "),
        "{request}"
    );
    assert!(request.contains("\"challenge_id\":7"), "{request}");
    assert!(request.contains("flag{abc}"), "{request}");
}
