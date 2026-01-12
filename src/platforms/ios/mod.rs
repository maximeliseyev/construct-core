// iOS platform-specific code
// UniFFI bindings for iOS/macOS

#[cfg(feature = "ios")]
pub mod uniffi_bindings;

#[cfg(feature = "ios")]
pub use uniffi_bindings::*;
