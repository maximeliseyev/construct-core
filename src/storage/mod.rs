// Модуль хранилища (IndexedDB для WASM)

pub mod indexeddb;
pub mod memory;
pub mod models;

#[cfg(target_arch = "wasm32")]
pub use indexeddb::KeyStorage;

#[cfg(not(target_arch = "wasm32"))]
pub use memory::KeyStorage;
