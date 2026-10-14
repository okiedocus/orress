// Release builds on Windows should not open a console window next to the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod actions;
mod app;
mod splash;

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,wgpu_hal=error,wgpu_core=warn,egui_wgpu=warn,eframe=warn".into()
            }),
        )
        .init();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("ORRESS")
        .with_app_id("orress")
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([800.0, 500.0])
        .with_drag_and_drop(true);
    // The window / taskbar icon, decoded from the embedded asset.
    if let Ok(icon) =
        eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/icons/icon-256.png"))
    {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "ORRESS",
        options,
        Box::new(|cc| Ok(Box::new(app::OrressApp::new(cc)))),
    )
}
