// iOS platform-specific code
// UniFFI bindings for iOS/macOS

#[cfg(feature = "ios")]
// Include the generated UniFFI scaffolding
include!(concat!(env!("OUT_DIR"), "/construct_core.uniffi.rs"));
