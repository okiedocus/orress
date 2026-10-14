use serde_json::json;

use crate::*;

#[test]
fn position_byte_roundtrip() {
    let text = "fn main() {\n    let x = 1;\n}\n";
    // Start of line 1 (the `let`): byte offset of 'l'.
    let byte = text.find("let").unwrap();
    let pos = position_at(text, byte);
    assert_eq!(
        pos,
        Position {
            line: 1,
            character: 4
        }
    );
    assert_eq!(byte_at(text, pos), byte);
}

#[test]
fn position_utf8_characters() {
    // "café" + newline, then a token: character offsets are UTF-8 bytes.
    let text = "// café\nx";
    let byte = text.find('x').unwrap();
    let pos = position_at(text, byte);
    assert_eq!(pos.line, 1);
    assert_eq!(pos.character, 0);
    assert_eq!(byte_at(text, pos), byte);
}

#[test]
fn parses_markup_hover() {
    let v = json!({"contents": {"kind": "markdown", "value": "```rust\nfn main()\n```"}});
    assert_eq!(hover_text(&v).unwrap(), "```rust\nfn main()\n```");
}

#[test]
fn parses_scalar_hover_and_empty() {
    assert_eq!(hover_text(&json!({"contents": "u32"})).unwrap(), "u32");
    assert!(hover_text(&json!({"contents": "   "})).is_none());
}

#[test]
fn parses_definition_forms() {
    let loc = json!({"uri": "file:///tmp/a.rs", "range": {"start": {"line": 1, "character": 2}, "end": {"line": 1, "character": 5}}});
    assert!(definition_location(&loc).is_some());
    let arr = json!([loc]);
    assert!(definition_location(&arr).is_some());
    // LocationLink form.
    let link = json!([{
        "targetUri": "file:///tmp/b.rs",
        "targetRange": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
        "targetSelectionRange": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}
    }]);
    let got = definition_location(&link).unwrap();
    assert_eq!(got.uri.to_string(), "file:///tmp/b.rs");
    assert!(definition_location(&json!(null)).is_none());
}

#[test]
fn cargo_root_detection() {
    // This crate lives in a Cargo workspace, so a root is found above its source.
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    assert!(cargo_root(&here).is_some());
}

#[test]
fn builtin_adapters_cover_the_bundled_languages() {
    let m = LspManager::new(Arc::new(|| {}));
    assert_eq!(m.adapter_for("Rust").unwrap().command, "rust-analyzer");
    assert_eq!(
        m.adapter_for("Python").unwrap().command,
        "pyright-langserver"
    );
    // C and C++ (the tree-sitter grammars just added) are both served by clangd.
    assert_eq!(m.adapter_for("C").unwrap().command, "clangd");
    assert_eq!(m.adapter_for("c++").unwrap().command, "clangd"); // case-insensitive
    assert!(m.adapter_for("Haskell").is_none());
}

#[test]
fn imported_adapter_overrides_a_builtin() {
    let json = r#"[
        { "language": "Rust", "command": "my-rust-ls", "args": ["--stdio"] },
        { "language": "Go", "command": "gopls", "root_markers": ["go.mod"] }
    ]"#;
    let parsed: Vec<LspAdapter> = match serde_json::from_str::<super::OneOrMany>(json).unwrap() {
        super::OneOrMany::Many(v) => v,
        super::OneOrMany::One(a) => vec![*a],
    };
    let mut m = LspManager::new(Arc::new(|| {}));
    m.add_adapters(parsed);
    // The imported Rust adapter wins over the built-in rust-analyzer.
    assert_eq!(m.adapter_for("Rust").unwrap().command, "my-rust-ls");
    // A new language is added; its languageId/key default to the lowercased name.
    let go = m.adapter_for("Go").unwrap();
    assert_eq!(go.command, "gopls");
    assert_eq!(go.language_id(), "go");
}

#[test]
fn root_markers_find_the_workspace() {
    let dir = std::env::temp_dir().join(format!("orress_lsp_root_{}", std::process::id()));
    let sub = dir.join("src");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(dir.join("compile_commands.json"), "[]").unwrap();
    let adapter = &builtin_adapters()[2]; // C (clangd)
    let root = adapter.root_for(&sub.join("main.c"));
    assert_eq!(root.as_deref(), Some(dir.as_path()));
    // No marker above an unrelated path → standalone (None).
    assert!(
        adapter
            .root_for(std::path::Path::new("/nowhere/x.c"))
            .is_none()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn byte_at_clamps_and_snaps_to_char_boundaries() {
    let text = "aé\nb";
    let at = |line, character| byte_at(text, Position { line, character });
    // A character past the end of the line lands on the line end, not in the next line.
    assert_eq!(at(0, 99), 3);
    // A UTF-8 column in the middle of `é` snaps back to its start (no mid-char slicing).
    assert_eq!(at(0, 2), 1);
    // A line past the end is the end of the text.
    assert_eq!(at(7, 0), text.len());
}

#[test]
fn utf16_positions_round_trip() {
    // `é` is 2 UTF-8 bytes / 1 UTF-16 unit; the crab is 4 bytes / 2 UTF-16 units.
    let text = "é🦀x";
    let x = text.find('x').unwrap();
    let pos = position_at_enc(text, x, PositionEncoding::Utf16);
    assert_eq!(pos.character, 3);
    assert_eq!(byte_at_enc(text, pos, PositionEncoding::Utf16), x);
    // Half a surrogate pair snaps to the crab's start.
    let half = Position {
        line: 0,
        character: 2,
    };
    assert_eq!(
        byte_at_enc(text, half, PositionEncoding::Utf16),
        text.find('🦀').unwrap()
    );
    // UTF-32 counts scalar values.
    assert_eq!(
        position_at_enc(text, x, PositionEncoding::Utf32).character,
        2
    );
    // A byte offset inside a character is treated as that character's start.
    assert_eq!(
        position_at_enc(text, 1, PositionEncoding::Utf8).character,
        0
    );
}

#[test]
fn user_settings_apply_to_builtin_adapters() {
    let mut m = LspManager::new(Arc::new(|| {}));
    m.set_server_settings(&json!({
        "rust-analyzer": {
            "binary": { "path": "/opt/ra", "arguments": ["--log"], "env": { "RA_LOG": "info" } },
            "initialization_options": { "cargo": { "allFeatures": true } },
            "settings": { "check": { "command": "clippy" } }
        },
        // pyright is configured under its short name, not `pyright-langserver`.
        "pyright": { "settings": { "python": { "analysis": {} } } }
    }));
    let file = std::path::Path::new("/nowhere/main.rs");
    let (spec, _, _) = m.resolve("Rust", file).unwrap();
    assert_eq!(spec.command, "/opt/ra");
    assert_eq!(spec.args, vec!["--log".to_string()]);
    assert!(
        spec.env
            .contains(&("RA_LOG".to_string(), "info".to_string()))
    );
    assert_eq!(
        spec.initialization_options.as_ref().unwrap()["cargo"]["allFeatures"],
        true
    );
    assert_eq!(
        spec.settings.as_ref().unwrap()["check"]["command"],
        "clippy"
    );

    let (py, _, _) = m
        .resolve("Python", std::path::Path::new("/nowhere/a.py"))
        .unwrap();
    assert_eq!(py.command, "pyright-langserver"); // no binary override
    assert!(py.settings.is_some());

    // Unconfigured servers keep their defaults.
    let (c, _, _) = m
        .resolve("C", std::path::Path::new("/nowhere/a.c"))
        .unwrap();
    assert_eq!(c.command, "clangd");
    assert!(c.initialization_options.is_none() && c.env.is_empty());
}

#[test]
fn adapter_env_reaches_the_spec() {
    let mut m = LspManager::new(Arc::new(|| {}));
    m.add_adapters(vec![LspAdapter {
        language: "Rust".into(),
        command: "rust-analyzer".into(),
        env: [("RUSTUP_TOOLCHAIN".to_string(), "stable".to_string())].into(),
        ..LspAdapter::default()
    }]);
    let (spec, _, _) = m
        .resolve("Rust", std::path::Path::new("/nowhere/main.rs"))
        .unwrap();
    assert_eq!(
        spec.env,
        vec![("RUSTUP_TOOLCHAIN".to_string(), "stable".to_string())]
    );
}

#[test]
fn user_settings_merge_over_adapter_options_and_configuration() {
    let mut m = LspManager::new(Arc::new(|| {}));
    // What a Zed extension resolved for its server.
    m.add_adapters(vec![LspAdapter {
        language: "Gleam".into(),
        command: "gleam".into(),
        key: Some("gleam".into()),
        env: [("PATH".to_string(), "/ext/bin".to_string())].into(),
        initialization_options: Some(json!({ "a": 1, "nested": { "x": 1, "y": 2 } })),
        workspace_configuration: Some(json!({ "gleam": { "lint": true, "list": [1, 2] } })),
        ..LspAdapter::default()
    }]);
    let file = std::path::Path::new("/nowhere/a.gleam");

    // Without user settings the adapter's own values are used as-is.
    let (spec, _, _) = m.resolve("Gleam", file).unwrap();
    assert_eq!(
        spec.initialization_options,
        Some(json!({ "a": 1, "nested": { "x": 1, "y": 2 } }))
    );
    assert_eq!(spec.settings.as_ref().unwrap()["gleam"]["lint"], true);

    // User settings win key by key; untouched adapter keys survive; arrays are replaced.
    m.set_server_settings(&json!({
        "gleam": {
            "binary": { "env": { "PATH": "/user/bin" } },
            "initialization_options": { "nested": { "y": 20, "z": 30 } },
            "settings": { "gleam": { "list": [9] } }
        }
    }));
    let (spec, _, _) = m.resolve("Gleam", file).unwrap();
    assert_eq!(
        spec.initialization_options,
        Some(json!({ "a": 1, "nested": { "x": 1, "y": 20, "z": 30 } }))
    );
    assert_eq!(
        spec.settings,
        Some(json!({ "gleam": { "lint": true, "list": [9] } }))
    );
    assert_eq!(
        spec.env,
        vec![("PATH".to_string(), "/user/bin".to_string())]
    );
}

#[test]
fn merge_json_replaces_non_objects() {
    let mut base = json!({ "a": { "b": 1 }, "c": [1] });
    merge_json(&mut base, &json!({ "a": 5, "c": [2, 3], "d": null }));
    assert_eq!(base, json!({ "a": 5, "c": [2, 3], "d": null }));
}

#[test]
fn standalone_init_options_keep_user_options_and_add_detached_file() {
    let doc = std::path::Path::new("/tmp/solve.rs");
    let opts = init_options(Some(json!({ "checkOnSave": false })), None, doc);
    assert_eq!(opts["checkOnSave"], false);
    assert!(opts["detachedFiles"].is_array());
    // Inside a workspace no detached file is added.
    let ws = init_options(None, Some(std::path::Path::new("/tmp")), doc);
    assert_eq!(ws, json!({}));
}

#[test]
fn servers_are_keyed_per_project_root() {
    let dir = std::env::temp_dir().join(format!("orress_lsp_roots_{}", std::process::id()));
    let (a, b) = (dir.join("a"), dir.join("b"));
    for d in [&a, &b] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("Cargo.toml"), "").unwrap();
    }
    let m = LspManager::new(Arc::new(|| {}));
    let (sa, _, _) = m.resolve("Rust", &a.join("main.rs")).unwrap();
    let (sb, _, _) = m.resolve("Rust", &b.join("main.rs")).unwrap();
    assert_ne!(sa.key, sb.key);
    let _ = std::fs::remove_dir_all(&dir);
}
