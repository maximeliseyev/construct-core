// WASM bindings
// wasm-bindgen automatically generates bindings from #[wasm_bindgen] attributes
// This module serves as a placeholder for future wasm-specific bindings

// Console logging module for WASM
pub mod console {
    use web_sys;

    pub fn log(msg: &str) {
        web_sys::console::log_1(&msg.into());
    }
}
