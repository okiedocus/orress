//! A minimal *real* Zed extension (built against `zed_extension_api`), used to verify that
//! ORRESS's clean-room Zed host can instantiate and drive unmodified Zed extension WASM.

use zed_extension_api::{
    self as zed, Command, DebugAdapterBinary, DebugConfig, DebugRequest, DebugScenario,
    DebugTaskDefinition, LanguageServerId, LaunchRequest, Result, StartDebuggingRequestArguments,
    StartDebuggingRequestArgumentsRequest, TaskTemplate, Worktree,
};

struct DemoExtension;

impl zed::Extension for DemoExtension {
    fn new() -> Self {
        DemoExtension
    }

    fn language_server_command(
        &mut self,
        _id: &LanguageServerId,
        _worktree: &Worktree,
    ) -> Result<Command> {
        Ok(Command {
            command: "demo-language-server".to_string(),
            args: vec!["--stdio".to_string()],
            env: vec![],
        })
    }

    fn get_dap_binary(
        &mut self,
        _adapter_name: String,
        _config: DebugTaskDefinition,
        _user_provided_debug_adapter_path: Option<String>,
        _worktree: &Worktree,
    ) -> Result<DebugAdapterBinary> {
        Ok(DebugAdapterBinary {
            command: Some("demo-debug-adapter".to_string()),
            arguments: vec!["--stdio".to_string()],
            envs: vec![],
            cwd: None,
            connection: None,
            request_args: StartDebuggingRequestArguments {
                configuration: "{}".to_string(),
                request: StartDebuggingRequestArgumentsRequest::Launch,
            },
        })
    }

    fn dap_request_kind(
        &mut self,
        _adapter_name: String,
        _config: zed::serde_json::Value,
    ) -> Result<StartDebuggingRequestArgumentsRequest> {
        Ok(StartDebuggingRequestArgumentsRequest::Launch)
    }

    fn dap_config_to_scenario(&mut self, config: DebugConfig) -> Result<DebugScenario> {
        Ok(DebugScenario {
            label: config.label,
            adapter: config.adapter,
            build: None,
            config: "{\"scenario\":true}".to_string(),
            tcp_connection: None,
        })
    }

    fn dap_locator_create_scenario(
        &mut self,
        _locator_name: String,
        build_task: TaskTemplate,
        resolved_label: String,
        debug_adapter_name: String,
    ) -> Option<DebugScenario> {
        Some(DebugScenario {
            label: resolved_label,
            adapter: debug_adapter_name,
            build: None,
            config: format!("{{\"command\":\"{}\"}}", build_task.command),
            tcp_connection: None,
        })
    }

    fn run_dap_locator(
        &mut self,
        _locator_name: String,
        build_task: TaskTemplate,
    ) -> Result<DebugRequest> {
        Ok(DebugRequest::Launch(LaunchRequest {
            program: build_task.command,
            cwd: build_task.cwd,
            args: build_task.args,
            envs: build_task.env,
        }))
    }
}

zed::register_extension!(DemoExtension);
