//! A Zed extension guest built directly against the vendored **`since_v0.5.0`** WIT world (the
//! last `zed:extension` world before `since_v0.6.0` added the `dap` interface). It is hand-written
//! with `wit-bindgen` rather than `zed_extension_api` so it compiles for `wasm32-unknown-unknown`
//! without a WASI runtime, isolating the one thing under test: that ORRESS's host (whose linker
//! exposes the newer `since_v0.6.0` import surface) still instantiates and drives a component that
//! neither imports `dap` nor exports the five `dap-*` functions.
//!
//! `init-extension` and `language-server-command` carry behaviour, as do the context-server and
//! slash-command exports (`context-server-command`/`-configuration`, `run-slash-command`,
//! `complete-slash-command-argument`) so the host's wiring for those can be tested end to end. The
//! remaining exports are present (a valid component must export them all) but return empty results.

wit_bindgen::generate!({
    world: "extension",
    path: "wit",
});

// `SlashCommandOutputSection` is nested inside a record (not a direct export signature), so it
// stays in its interface module rather than being re-exported at the root like `Range`.
use zed::extension::slash_command::SlashCommandOutputSection;

struct OldExt;

impl Guest for OldExt {
    fn init_extension() {}

    fn language_server_command(
        _language_server_id: String,
        _worktree: &Worktree,
    ) -> Result<Command, String> {
        Ok(Command {
            command: "old-language-server".to_string(),
            args: vec!["--stdio".to_string()],
            env: vec![],
        })
    }

    fn language_server_initialization_options(
        _language_server_id: String,
        _worktree: &Worktree,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn language_server_workspace_configuration(
        _language_server_id: String,
        _worktree: &Worktree,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn language_server_additional_initialization_options(
        _language_server_id: String,
        _target_language_server_id: String,
        _worktree: &Worktree,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn language_server_additional_workspace_configuration(
        _language_server_id: String,
        _target_language_server_id: String,
        _worktree: &Worktree,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn labels_for_completions(
        _language_server_id: String,
        _completions: Vec<Completion>,
    ) -> Result<Vec<Option<CodeLabel>>, String> {
        Ok(vec![])
    }

    fn labels_for_symbols(
        _language_server_id: String,
        _symbols: Vec<Symbol>,
    ) -> Result<Vec<Option<CodeLabel>>, String> {
        Ok(vec![])
    }

    fn complete_slash_command_argument(
        _command: SlashCommand,
        _args: Vec<String>,
    ) -> Result<Vec<SlashCommandArgumentCompletion>, String> {
        Ok(vec![SlashCommandArgumentCompletion {
            label: "greet".to_string(),
            new_text: "greet".to_string(),
            run_command: true,
        }])
    }

    fn run_slash_command(
        command: SlashCommand,
        args: Vec<String>,
        _worktree: Option<&Worktree>,
    ) -> Result<SlashCommandOutput, String> {
        let text = format!("/{} {}", command.name, args.join(" "));
        let section = SlashCommandOutputSection {
            range: Range { start: 0, end: text.len() as u32 },
            label: "demo".to_string(),
        };
        Ok(SlashCommandOutput { text, sections: vec![section] })
    }

    fn context_server_command(
        _context_server_id: String,
        _project: &Project,
    ) -> Result<Command, String> {
        Ok(Command {
            command: "mcp-server".to_string(),
            args: vec!["--stdio".to_string()],
            env: vec![],
        })
    }

    fn context_server_configuration(
        _context_server_id: String,
        _project: &Project,
    ) -> Result<Option<ContextServerConfiguration>, String> {
        Ok(Some(ContextServerConfiguration {
            installation_instructions: "Install with npm".to_string(),
            settings_schema: "{}".to_string(),
            default_settings: "{}".to_string(),
        }))
    }

    fn suggest_docs_packages(_provider_name: String) -> Result<Vec<String>, String> {
        Ok(vec![])
    }

    fn index_docs(
        _provider_name: String,
        _package_name: String,
        _database: &KeyValueStore,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }
}

export!(OldExt);
