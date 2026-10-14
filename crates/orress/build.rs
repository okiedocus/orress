//! Build script: on Windows, embed the ORRESS icon and version/product metadata into the
//! executable, so `orress.exe` shows the logo in Explorer and taskbar pins and carries proper
//! Details (version, product name, description). A no-op on other targets.

fn main() {
    println!("cargo:rerun-if-changed=../../assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        #[cfg(windows)]
        {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("../../assets/icon.ico");
            res.set("ProductName", "ORRESS");
            res.set(
                "FileDescription",
                "Okiedocus Rusty Reverse Engineering Software Suite",
            );
            res.set("CompanyName", "Okiedocus");
            res.set("LegalCopyright", "Licensed MIT OR Apache-2.0");
            // FileVersion / ProductVersion are filled from CARGO_PKG_VERSION automatically.
            if let Err(e) = res.compile() {
                println!("cargo:warning=could not embed Windows resources (icon/version): {e}");
            }
        }
    }
}
