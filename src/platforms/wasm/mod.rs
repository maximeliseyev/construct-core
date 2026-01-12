// WASM platform-specific code
// wasm-bindgen bindings for Web

#[cfg(feature = "wasm")]
pub mod bindings;

#[cfg(feature = "wasm")]
pub use bindings::*;
