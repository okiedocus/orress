//! The host side of the `orress:extension` WIT world: wasmtime component bindings, the host-state
//! that implements the imports, and [`RunningExtension`], a handle to call an instantiated
//! extension's exports.

use wasmtime::Store;

wasmtime::component::bindgen!({
    world: "extension",
    path: "wit",
});

use orress::extension::host::Host;

/// The host state an extension runs against. Holds whatever the host imports need; for now just
/// the lines the extension logged.
#[derive(Default)]
pub struct HostState {
    pub log: Vec<String>,
}

impl Host for HostState {
    fn log(&mut self, message: String) {
        self.log.push(message);
    }
}

/// Metadata an extension reports (a stable, bindgen-free mirror of the WIT `info` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionInfo {
    pub name: String,
    pub version: String,
}

/// An instantiated extension: call its exports, and read what it logged.
pub struct RunningExtension {
    pub(crate) store: Store<HostState>,
    pub(crate) instance: Extension,
}

impl RunningExtension {
    /// The extension's metadata (`info` export).
    pub fn info(&mut self) -> Result<ExtensionInfo, String> {
        self.store.set_epoch_deadline(crate::guest_budget_ticks());
        let i = self
            .instance
            .call_info(&mut self.store)
            .map_err(|e| e.to_string())?;
        Ok(ExtensionInfo {
            name: i.name,
            version: i.version,
        })
    }

    /// The demo `shout` export (upper-cases `text`, logging via the host import).
    pub fn shout(&mut self, text: &str) -> Result<String, String> {
        self.store.set_epoch_deadline(crate::guest_budget_ticks());
        self.instance
            .call_shout(&mut self.store, text)
            .map_err(|e| e.to_string())
    }

    /// Lines the extension logged through the host.
    pub fn logs(&self) -> &[String] {
        &self.store.data().log
    }
}
