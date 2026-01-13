// Construct Core
// Cryptographic engine for Construct Messenger with E2EE

#![warn(clippy::all)]
#![allow(clippy::too_many_arguments)]
#![allow(unsafe_attr_outside_unsafe)]  // Allow UniFFI generated code

// Platform-specific modules
#[cfg(feature = "ios")]
pub mod platforms {
    pub mod ios;
    pub use ios::*;
}

#[cfg(feature = "wasm")]
pub mod platforms {
    pub mod wasm;
    pub use wasm::*;
}

// Core modules (platform-independent)
pub mod api;
pub mod config;
pub mod crypto;
pub mod error;
pub mod protocol;
pub mod utils;

// Re-exports for convenience
pub use api::MessengerAPI;
