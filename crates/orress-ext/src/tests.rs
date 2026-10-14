use super::*;

/// A real extension component, built from `fixtures/guest` and encoded via `fixtures/encode`
/// (see `fixtures/README.md`). Exercises the full WIT host end to end.
const DEMO_GUEST: &[u8] = include_bytes!("../fixtures/demo-guest.wasm");

#[test]
fn runs_a_real_guest_extension_over_the_wit_world() {
    let host = Host::new();
    let mut ext = host
        .instantiate(DEMO_GUEST)
        .expect("instantiate the demo guest");

    // Exported function returning a record.
    let info = ext.info().expect("info()");
    assert_eq!(info.name, "demo");
    assert_eq!(info.version, "0.1.0");

    // Exported function with a string round-trip that calls the host `log` import.
    assert_eq!(ext.shout("hello").expect("shout()"), "HELLO");
    assert!(
        ext.logs().iter().any(|l| l.contains("shouting: hello")),
        "host import not invoked: {:?}",
        ext.logs()
    );
}

/// A real Zed extension (built with `zed_extension_api` in `fixtures/zed-guest`, encoded via
/// `fixtures/encode`). Proves ORRESS's clean-room Zed host runs unmodified Zed extension WASM.
const ZED_GUEST: &[u8] = include_bytes!("../fixtures/zed-guest.wasm");

#[test]
fn runs_a_real_zed_extension_and_resolves_its_language_server() {
    let host = Host::new();
    let mut ext = host
        .instantiate_zed(ZED_GUEST, &std::env::temp_dir())
        .expect("instantiate a real Zed extension");

    // `init-extension` runs with no trap.
    ext.init().expect("init-extension");

    // The extension resolves a language-server command against a host-provided worktree.
    let cmd = ext
        .language_server_command("demo", std::env::temp_dir())
        .expect("language-server-command");
    assert_eq!(cmd.command, "demo-language-server");
    assert_eq!(cmd.args, vec!["--stdio".to_string()]);
}

/// A Zed extension built against an *older* API version (`zed_extension_api = "=0.5.0"`, the
/// `since_v0.5.0` WIT world, which predates the `dap` interface). It is a distinct component shape
/// from `ZED_GUEST`: it neither imports `dap` nor exports the five `dap-*` functions. Proves the
/// host runs extensions regardless of which API version they were built against (older or newer).
const ZED_GUEST_OLD: &[u8] = include_bytes!("../fixtures/zed-guest-old.wasm");

#[test]
fn runs_an_older_api_version_zed_extension() {
    let host = Host::new();
    // The same host (whose linker exposes the full `since_v0.6.0` import surface) instantiates an
    // extension that only imports the older subset. The generated `Extension::instantiate` would
    // reject it for lacking the newer `dap-*` exports; our by-name export lookup accepts it.
    let mut ext = host
        .instantiate_zed(ZED_GUEST_OLD, &std::env::temp_dir())
        .expect("instantiate an older-API Zed extension");

    ext.init().expect("init-extension");

    let cmd = ext
        .language_server_command("old", std::env::temp_dir())
        .expect("language-server-command");
    assert_eq!(cmd.command, "old-language-server");
    assert_eq!(cmd.args, vec!["--stdio".to_string()]);
}

/// The same real Zed extension as `ZED_GUEST`, but built for **`wasm32-wasip1`** and componentized
/// with the WASI preview1 reactor adapter (the shape Zed actually ships extensions in). Its
/// `init-extension` touches `std::env`/the C runtime cwd, so it only runs if the host provides WASI.
const ZED_GUEST_WASI: &[u8] = include_bytes!("../fixtures/zed-guest-wasi.wasm");

#[test]
fn runs_a_wasi_zed_extension() {
    let work = std::env::temp_dir().join(format!("orress_zed_wasi_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let host = Host::new();
    // `work` becomes the extension's $PWD and its one preopened directory. Without WASI in the host
    // linker this component fails to instantiate (unresolved `wasi:*` imports); without $PWD its
    // init-extension would trap.
    let mut ext = host
        .instantiate_zed(ZED_GUEST_WASI, &work)
        .expect("instantiate a real WASI Zed extension");
    ext.init().expect("init-extension (WASI startup: env/cwd)");

    let cmd = ext
        .language_server_command("demo", work.clone())
        .expect("language-server-command");
    assert_eq!(cmd.command, "demo-language-server");
    assert_eq!(cmd.args, vec!["--stdio".to_string()]);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn project_root_walks_up_to_a_marker() {
    let base = std::env::temp_dir().join(format!("orress_root_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let nested = base.join("crate-a").join("src");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(base.join("Cargo.toml"), "[workspace]\n").unwrap();
    // A file deep in the tree resolves to the nearest ancestor with a marker (the repo root here).
    assert_eq!(project_root(&nested.join("main.rs")), base);
    // Add a nearer marker; it now wins.
    std::fs::write(base.join("crate-a").join("package.json"), "{}").unwrap();
    assert_eq!(project_root(&nested.join("main.rs")), base.join("crate-a"));
    let _ = std::fs::remove_dir_all(&base);

    // No marker in `lone` → the walk climbs past it. On a clean ancestor chain the fallback is the
    // file's own directory (`lone`); but the system temp dir is shared and may itself sit under a
    // stray marker (e.g. a leftover `Cargo.toml`), so we only require that the result is `lone` or
    // a marker-bearing strict ancestor of it — never a descendant, and never a marker-less dir.
    let lone = std::env::temp_dir().join(format!("orress_noroot_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&lone);
    std::fs::create_dir_all(&lone).unwrap();
    let got = project_root(&lone.join("x.txt"));
    assert!(
        got == lone
            || (lone.starts_with(&got)
                && got != lone
                && super::ROOT_MARKERS.iter().any(|m| got.join(m).exists())),
        "unexpected project root {got:?} for a marker-less file under {lone:?}",
    );
    let _ = std::fs::remove_dir_all(&lone);
}

#[test]
fn resolves_a_zed_language_server_command_from_wasm() {
    // An installed extension that ships `extension.wasm` (our real Zed guest) and declares a
    // WASM-resolved language server. Discover it, then resolve its command by running the WASM.
    let store = std::env::temp_dir().join(format!("orress_zed_ls_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\nname = \"Demo\"\n\n[language_servers.demo]\nlanguage = \"Demo\"\n",
    )
    .unwrap();
    std::fs::write(ext.join("extension.wasm"), ZED_GUEST).unwrap();

    let servers = zed_language_servers(&store);
    let server = servers
        .iter()
        .find(|s| s.language == "Demo")
        .expect("found the Zed language server");
    assert_eq!(server.server_id, "demo");

    let cmd = resolve_server_command(&server.wasm, &server.server_id, &ext, serde_json::json!({}))
        .expect("resolve");
    assert_eq!(cmd.command, "demo-language-server");
    assert_eq!(cmd.args, vec!["--stdio".to_string()]);

    // The one-shot resolver gives the same command (the fixture provides no options) and turns
    // it into an adapter for the native LSP client.
    let resolved =
        resolve_language_server(&server.wasm, &server.server_id, &ext, serde_json::json!({}))
            .expect("resolve all");
    assert_eq!(resolved.command, cmd);
    assert_eq!(resolved.initialization_options, None);
    assert_eq!(resolved.workspace_configuration, None);
    let adapter = resolved.into_adapter("Demo", "demo");
    assert_eq!(adapter.command, "demo-language-server");
    assert_eq!(adapter.key.as_deref(), Some("demo"));
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn resolves_lsp_initialization_options_and_workspace_configuration() {
    let store = std::env::temp_dir().join(format!("orress_zed_lsopts_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\n\n[language_servers.demo]\nlanguage = \"Demo\"\n",
    )
    .unwrap();
    for (wasm, name) in [(ZED_GUEST, "new.wasm"), (ZED_GUEST_OLD, "old.wasm")] {
        let path = ext.join(name);
        std::fs::write(&path, wasm).unwrap();
        // The fixtures keep the trait defaults, which provide none.
        let s = serde_json::json!({});
        assert_eq!(
            resolve_server_initialization_options(&path, "demo", &ext, s.clone()),
            Ok(None)
        );
        assert_eq!(
            resolve_server_workspace_configuration(&path, "demo", &ext, s.clone()),
            Ok(None)
        );
        assert_eq!(
            resolve_server_additional_initialization_options(
                &path,
                "demo",
                "other",
                &ext,
                s.clone()
            ),
            Ok(None)
        );
        assert_eq!(
            resolve_server_additional_workspace_configuration(&path, "demo", "other", &ext, s),
            Ok(None)
        );
    }
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn relative_commands_under_the_extension_dir_become_absolute() {
    let dir = std::env::temp_dir().join(format!("orress_zed_abscmd_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::write(dir.join("bin").join("server"), b"#!").unwrap();
    let got = absolutize_command("bin/server", &dir);
    assert!(Path::new(&got).is_absolute(), "{got}");
    assert!(Path::new(&got).is_file());
    // Bare PATH names, missing files and escapes are left alone.
    assert_eq!(absolutize_command("node", &dir), "node");
    assert_eq!(absolutize_command("bin/missing", &dir), "bin/missing");
    assert_eq!(absolutize_command("../server", &dir), "../server");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_capabilities_gate_run_command() {
    let toml = r#"
id = "x"
capabilities = [
  { kind = "process:exec", command = "node", args = ["*"] },
  { kind = "download_file", host = "example.com", path = ["**"] },
]
"#;
    let m: ExtensionManifest = toml::from_str(toml).unwrap();
    let caps = m.exec_capabilities();
    assert_eq!(caps.len(), 1);
    assert!(caps[0].allows("node", &["server.js".to_string()]));
    assert!(!caps[0].allows("sh", &["-c".to_string()]));
    // No manifest → nothing may run.
    let dir = std::env::temp_dir().join(format!("orress_zed_nomanifest_{}", std::process::id()));
    assert_eq!(manifest_exec_policy(&dir), ExecPolicy::Declared(vec![]));
}

#[test]
fn shared_engine_interrupts_a_looping_guest() {
    use wasm_encoder::{
        BlockType, CodeSection, ExportKind, ExportSection, Function, FunctionSection, Instruction,
        Module, TypeSection, ValType,
    };
    let mut m = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([], []);
    m.section(&types);
    let mut funcs = FunctionSection::new();
    funcs.function(0);
    m.section(&funcs);
    let mut exports = ExportSection::new();
    exports.export("spin", ExportKind::Func, 0);
    m.section(&exports);
    let mut code = CodeSection::new();
    let mut f = Function::new(Vec::<(u32, ValType)>::new());
    f.instruction(&Instruction::Loop(BlockType::Empty));
    f.instruction(&Instruction::Br(0));
    f.instruction(&Instruction::End);
    f.instruction(&Instruction::End);
    code.function(&f);
    m.section(&code);

    let engine = shared_engine();
    let module = wasmtime::Module::new(engine, m.finish()).unwrap();
    let mut store = Store::new(engine, ());
    store.set_epoch_deadline(2);
    let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
    let spin = instance
        .get_typed_func::<(), ()>(&mut store, "spin")
        .unwrap();
    let started = std::time::Instant::now();
    assert!(spin.call(&mut store, ()).is_err(), "an infinite loop traps");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn runs_context_server_and_slash_command_exports() {
    let host = Host::new();
    let mut ext = host
        .instantiate_zed(ZED_GUEST_OLD, &std::env::temp_dir())
        .expect("instantiate");
    ext.init().expect("init");

    // Context (MCP) server: launch command + setup configuration.
    let cmd = ext
        .context_server_command("mcp")
        .expect("context-server-command");
    assert_eq!(cmd.command, "mcp-server");
    assert_eq!(cmd.args, vec!["--stdio".to_string()]);
    let cfg = ext
        .context_server_configuration("mcp")
        .expect("config")
        .expect("some config");
    assert_eq!(cfg.installation_instructions, "Install with npm");
    assert_eq!(cfg.default_settings, "{}");

    // Slash command: argument completion + run.
    let spec = SlashCommandInfo {
        name: "greet".into(),
        description: "Greet".into(),
        tooltip_text: String::new(),
        requires_argument: true,
    };
    let completions = ext
        .complete_slash_command_argument(&spec, &["h".into()])
        .expect("completions");
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].new_text, "greet");
    assert!(completions[0].run_command);

    let out = ext
        .run_slash_command(&spec, &["hi".into()], None)
        .expect("run");
    assert_eq!(out.text, "/greet hi");
    assert_eq!(out.sections.len(), 1);
    assert_eq!(out.sections[0].label, "demo");
    assert_eq!(out.sections[0].range, (0, "/greet hi".len() as u32));
}

#[test]
fn discovers_and_runs_context_servers_and_slash_commands_from_an_installed_extension() {
    let store = std::env::temp_dir().join(format!("orress_zed_feat_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\nname = \"Demo\"\n\n[context_servers.mcp]\n\n\
         [slash_commands.greet]\ndescription = \"Greet files\"\nrequires_argument = true\n\
         tooltip_text = \"Say hi\"\n",
    )
    .unwrap();
    std::fs::write(ext.join("extension.wasm"), ZED_GUEST_OLD).unwrap();

    // Context server: discovered from the manifest, launch command resolved from the WASM.
    let servers = zed_context_servers(&store);
    let cs = servers
        .iter()
        .find(|s| s.server_id == "mcp")
        .expect("found the context server");
    let cmd = resolve_context_server_command(&cs.wasm, &cs.server_id, &[], serde_json::json!({}))
        .expect("resolve context server");
    assert_eq!(cmd.command, "mcp-server");

    // Slash command: discovered with its manifest metadata, then run via the WASM.
    let commands = zed_slash_commands(&store);
    let sc = commands
        .iter()
        .find(|c| c.command.name == "greet")
        .expect("found the slash command");
    assert_eq!(sc.command.description, "Greet files");
    assert!(sc.command.requires_argument);
    assert_eq!(sc.command.tooltip_text, "Say hi");
    let out = run_zed_slash_command(
        &sc.wasm,
        &sc.command,
        &["x".into()],
        None,
        serde_json::json!({}),
    )
    .expect("run slash command");
    assert_eq!(out.text, "/greet x");
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn runs_dap_exports() {
    let host = Host::new();
    let mut ext = host
        .instantiate_zed(ZED_GUEST, &std::env::temp_dir())
        .expect("instantiate");
    ext.init().expect("init");

    // launch vs attach.
    let kind = ext
        .dap_request_kind("demo", "{}")
        .expect("dap-request-kind");
    assert_eq!(kind, DapRequestKind::Launch);

    // The adapter launch binary.
    let def = DapTaskDefinition {
        label: "Debug".into(),
        adapter: "demo".into(),
        config: "{}".into(),
    };
    let bin = ext
        .get_dap_binary("demo", &def, None, std::env::temp_dir())
        .expect("get-dap-binary");
    assert_eq!(bin.command.as_deref(), Some("demo-debug-adapter"));
    assert_eq!(bin.arguments, vec!["--stdio".to_string()]);
    assert_eq!(bin.request, DapRequestKind::Launch);
    assert_eq!(bin.configuration, "{}");
    assert!(bin.tcp.is_none());
}

#[test]
fn discovers_and_resolves_a_debug_adapter_from_an_installed_extension() {
    let store = std::env::temp_dir().join(format!("orress_zed_dap_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\nname = \"Demo\"\n\n[debug_adapters.demo]\n",
    )
    .unwrap();
    std::fs::write(ext.join("extension.wasm"), ZED_GUEST).unwrap();

    let adapters = zed_debug_adapters(&store);
    let da = adapters
        .iter()
        .find(|a| a.adapter_name == "demo")
        .expect("found the debug adapter");
    let def = DapTaskDefinition {
        label: "Debug".into(),
        adapter: "demo".into(),
        config: "{}".into(),
    };
    let bin = resolve_dap_binary(
        &da.wasm,
        &da.adapter_name,
        &def,
        None,
        &store,
        serde_json::json!({}),
    )
    .expect("resolve dap binary");
    assert_eq!(bin.command.as_deref(), Some("demo-debug-adapter"));
    assert_eq!(bin.request, DapRequestKind::Launch);
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn runs_dap_scenario_and_locator_exports() {
    let host = Host::new();
    let mut ext = host
        .instantiate_zed(ZED_GUEST, &std::env::temp_dir())
        .expect("instantiate");
    ext.init().expect("init");

    // dap-config-to-scenario: a high-level config → an adapter-specific scenario.
    let config = DapConfig {
        label: "Debug main".into(),
        adapter: "demo".into(),
        request: DapRequest::Launch {
            program: "./a.out".into(),
            cwd: None,
            args: vec![],
            env: vec![],
        },
        stop_on_entry: Some(true),
    };
    let scenario = ext
        .dap_config_to_scenario(&config)
        .expect("dap-config-to-scenario");
    assert_eq!(scenario.label, "Debug main");
    assert_eq!(scenario.adapter, "demo");
    assert_eq!(scenario.config, "{\"scenario\":true}");

    // dap-locator-create-scenario: a build task → a scenario (Some).
    let build = DapTaskTemplate {
        label: "build".into(),
        command: "cargo".into(),
        args: vec!["build".into()],
        env: vec![],
        cwd: None,
    };
    let created = ext
        .dap_locator_create_scenario("cargo", &build, "Run", "demo")
        .expect("dap-locator-create-scenario");
    let created = created.expect("the locator applies");
    assert_eq!(created.label, "Run");
    assert_eq!(created.adapter, "demo");
    assert!(created.config.contains("cargo"));

    // run-dap-locator: a resolved task → a concrete launch request.
    match ext
        .run_dap_locator("cargo", &build)
        .expect("run-dap-locator")
    {
        DapRequest::Launch { program, args, .. } => {
            assert_eq!(program, "cargo");
            assert_eq!(args, vec!["build".to_string()]);
        }
        other => panic!("expected a launch request, got {other:?}"),
    }
}

#[test]
fn discovers_debug_locators_and_resolves_a_scenario() {
    let store = std::env::temp_dir().join(format!("orress_zed_loc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\nname = \"Demo\"\n\n[debug_locators.cargo]\n",
    )
    .unwrap();
    std::fs::write(ext.join("extension.wasm"), ZED_GUEST).unwrap();

    let locators = zed_debug_locators(&store);
    let loc = locators
        .iter()
        .find(|l| l.locator_name == "cargo")
        .expect("found the locator");
    let build = DapTaskTemplate {
        label: "build".into(),
        command: "cargo".into(),
        args: vec!["build".into()],
        env: vec![],
        cwd: None,
    };
    let scenario = create_dap_locator_scenario(
        &loc.wasm,
        &loc.locator_name,
        &build,
        "Run",
        "demo",
        serde_json::json!({}),
    )
    .expect("create scenario")
    .expect("locator applies");
    assert_eq!(scenario.adapter, "demo");

    match run_dap_locator(&loc.wasm, &loc.locator_name, &build, serde_json::json!({})).expect("run")
    {
        DapRequest::Launch { program, .. } => assert_eq!(program, "cargo"),
        other => panic!("expected launch, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn locates_a_debug_target_for_a_task() {
    // An extension that provides both a locator and a debug adapter.
    let store = std::env::temp_dir().join(format!("orress_zed_locate_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\nname = \"Demo\"\n\n[debug_adapters.demo]\n\n[debug_locators.cargo]\n",
    )
    .unwrap();
    std::fs::write(ext.join("extension.wasm"), ZED_GUEST).unwrap();

    // "Debug this task": a `cargo run` task is turned into a launchable target by the pipeline.
    let task = DapTaskTemplate {
        label: "cargo run".into(),
        command: "cargo".into(),
        args: vec!["run".into()],
        env: vec![],
        cwd: None,
    };
    let located = locate_debug_target(&store, &task, &store, serde_json::json!({}))
        .expect("pipeline runs")
        .expect("a locator + adapter handle the task");
    assert_eq!(located.adapter_command, "demo-debug-adapter");
    assert_eq!(located.adapter_args, vec!["--stdio".to_string()]);
    assert_eq!(located.locator_name, "cargo");
    match located.request {
        DapRequest::Launch { program, .. } => assert_eq!(program, "cargo"),
        other => panic!("expected a launch request, got {other:?}"),
    }

    // No locator installed → no target (not an error).
    let bare = std::env::temp_dir().join(format!("orress_zed_nolocate_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bare);
    std::fs::create_dir_all(&bare).unwrap();
    assert!(
        locate_debug_target(&bare, &task, &bare, serde_json::json!({}))
            .unwrap()
            .is_none()
    );
    let _ = std::fs::remove_dir_all(&bare);
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn a_broken_locator_does_not_abort_the_debug_target_search() {
    let store = std::env::temp_dir().join(format!("orress_zed_locate_bad_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    // A broken extension (invalid WASM) declaring a locator, sorted both before and after.
    for name in ["aaa-broken", "zzz-broken"] {
        let bad = store.join(name);
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(
            bad.join("extension.toml"),
            "id = \"broken\"\n\n[debug_locators.broken]\n",
        )
        .unwrap();
        std::fs::write(bad.join("extension.wasm"), b"not wasm").unwrap();
    }
    let ext = store.join("demo");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("extension.toml"),
        "id = \"demo\"\n\n[debug_adapters.demo]\n\n[debug_locators.cargo]\n",
    )
    .unwrap();
    std::fs::write(ext.join("extension.wasm"), ZED_GUEST).unwrap();
    let task = DapTaskTemplate {
        label: "cargo run".into(),
        command: "cargo".into(),
        args: vec!["run".into()],
        env: vec![],
        cwd: None,
    };
    let located = locate_debug_target(&store, &task, &store, serde_json::json!({}))
        .expect("the working pairing wins over the broken one")
        .expect("a target");
    assert_eq!(located.locator_name, "cargo");

    // With only the broken locator, its error is reported.
    let _ = std::fs::remove_dir_all(&ext);
    let only_bad = store.join("adapter");
    std::fs::create_dir_all(&only_bad).unwrap();
    std::fs::write(
        only_bad.join("extension.toml"),
        "id = \"adapter\"\n\n[debug_adapters.demo]\n",
    )
    .unwrap();
    std::fs::write(only_bad.join("extension.wasm"), ZED_GUEST).unwrap();
    assert!(locate_debug_target(&store, &task, &store, serde_json::json!({})).is_err());
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn host_loads_an_empty_component_and_rejects_core_modules() {
    let host = Host::new();
    let empty = wasm_encoder::Component::new().finish();
    assert!(
        host.load_component(&empty).is_ok(),
        "empty component should load"
    );
    // A core module (not a component) and garbage are both rejected.
    assert!(
        host.load_component(&wasm_encoder::Module::new().finish())
            .is_err()
    );
    assert!(host.load_component(b"not wasm at all").is_err());
}

/// Builds a temporary Zed-style extension directory and returns its path (plus a guard that
/// removes it on drop).
struct TempExt {
    dir: std::path::PathBuf,
}
impl Drop for TempExt {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn make_ext() -> TempExt {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let uniq = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("orress_ext_{}_{uniq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("themes")).unwrap();
    std::fs::create_dir_all(dir.join("languages/nim")).unwrap();
    std::fs::write(
        dir.join("extension.toml"),
        r#"
id = "nim"
name = "Nim"
version = "0.1.0"
description = "Nim language support"
authors = ["Someone"]
schema_version = 1

[grammars.nim]
repository = "https://github.com/alaviss/tree-sitter-nim"
rev = "abc123"

[language_servers.nimlangserver]
name = "nimlangserver"
language = "Nim"
command = "nimlangserver"
root_markers = ["nim.cfg", "*.nimble"]

[language_servers.needs_wasm]
language = "Nim"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("themes/demo.json"),
        r##"{ "name": "Fam", "themes": [ { "name": "Demo", "appearance": "dark",
            "style": { "editor.background": "#101010", "syntax": { "keyword": { "color": "#ff00ff" } } } } ] }"##,
    )
    .unwrap();
    std::fs::write(dir.join("languages/nim/config.toml"), "name = \"Nim\"\n").unwrap();
    std::fs::write(
        dir.join("languages/nim/highlights.scm"),
        "(comment) @comment\n",
    )
    .unwrap();
    TempExt { dir }
}

#[test]
fn loads_a_zed_style_extension() {
    let ext = make_ext();
    let loaded = load_extension(&ext.dir).expect("loads");

    assert_eq!(loaded.manifest.id, "nim");
    assert_eq!(loaded.manifest.name, "Nim");
    assert_eq!(loaded.manifest.schema_version, 1);
    assert!(loaded.manifest.grammars.contains_key("nim"));

    // The theme family imported one theme (a dark one).
    assert_eq!(loaded.themes.len(), 1);
    assert_eq!(loaded.themes[0].name, "Demo");
    assert!(loaded.themes[0].dark);

    // The grammar's highlight query is available, keyed by the config's language name.
    assert_eq!(loaded.grammar_queries.len(), 1);
    assert_eq!(loaded.grammar_queries[0].language, "Nim");
    assert!(loaded.grammar_queries[0].highlights.contains("@comment"));

    // The language server with a command becomes an adapter; the one without warns and is skipped.
    assert_eq!(loaded.lsp_adapters.len(), 1);
    let a = &loaded.lsp_adapters[0];
    assert_eq!(a.language, "Nim");
    assert_eq!(a.command, "nimlangserver");
    assert_eq!(
        a.root_markers,
        vec!["nim.cfg".to_string(), "*.nimble".to_string()]
    );
    assert!(
        loaded.warnings.iter().any(|w| w.contains("needs_wasm")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn registry_index_parses() {
    let json = r#"{ "extensions": [
        { "id": "nim", "name": "Nim", "description": "Nim support", "git": "https://x/nim", "zed": true },
        { "id": "ron", "name": "RON" }
    ] }"#;
    let index = RegistryIndex::from_json(json).unwrap();
    assert_eq!(index.extensions.len(), 2);
    let nim = index.find("nim").unwrap();
    assert_eq!(nim.git.as_deref(), Some("https://x/nim"));
    assert!(nim.zed);
    assert!(index.find("missing").is_none());
}

#[test]
fn install_scan_and_uninstall_round_trip() {
    let ext = make_ext(); // a valid extension directory (id = "nim")
    let store = std::env::temp_dir().join(format!("orress_ext_store_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);

    // Nothing installed yet.
    assert!(installed(&store).is_empty());
    assert!(!is_installed(&store, "nim"));

    // Install the local extension, then it is discoverable.
    let id = install_local(&ext.dir, &store).expect("installs");
    assert_eq!(id, "nim");
    assert!(is_installed(&store, "nim"));
    let list = installed(&store);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, "nim");
    assert_eq!(list[0].name, "Nim");
    assert_eq!(list[0].version, "0.1.0");
    // The copied install loads just like the source.
    assert!(load_extension(&list[0].dir).unwrap().themes.len() == 1);

    // Reinstalling replaces it (no error), then uninstall removes it.
    assert_eq!(install_local(&ext.dir, &store).unwrap(), "nim");
    uninstall(&store, "nim").expect("uninstalls");
    assert!(!is_installed(&store, "nim"));
    assert!(uninstall(&store, "nim").is_err()); // already gone
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn uninstall_rejects_a_path_traversal_id() {
    let store = std::env::temp_dir().join(format!("orress_ext_store2_{}", std::process::id()));
    assert!(uninstall(&store, "../evil").is_err());
}

#[test]
fn missing_manifest_is_an_error() {
    let dir = std::env::temp_dir().join(format!("orress_ext_none_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    assert!(load_extension(&dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
