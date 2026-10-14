//! A tiny ORRESS extension guest, used only to test the component host. It implements the
//! `orress:extension` world: reports metadata and uppercases text while logging via the host.

wit_bindgen::generate!({
    world: "extension",
    path: "../../wit",
});

struct Component;

impl Guest for Component {
    fn info() -> Info {
        Info {
            name: "demo".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn shout(text: String) -> String {
        orress::extension::host::log(&format!("shouting: {text}"));
        text.to_uppercase()
    }
}

export!(Component);
