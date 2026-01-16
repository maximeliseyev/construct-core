// Модуль хранилища (IndexedDB для WASM, iOS callbacks для iOS)

pub mod indexeddb;
pub mod indexeddb_ops; // Базовые операции для IndexedDB
pub mod indexeddb_traits; // Реализация traits для IndexedDB
pub mod ios_adapter; // iOS storage adapter с trait реализациями
pub mod ios_callbacks; // iOS callback интерфейсы
pub mod memory;
pub mod models;
pub mod traits;

// Re-export traits для удобства
pub use traits::{AuthTokens, CombinedStorage, DataStorage, SecureStorage};

// Re-export models
pub use models::*;

// Re-export iOS adapter для удобства
pub use ios_adapter::create_ios_storage;
pub use ios_callbacks::{DataStorageCallback, IOSStorageAdapter, SecureStorageCallback};

#[cfg(target_arch = "wasm32")]
pub use indexeddb::KeyStorage;

// MemoryStorage больше не экспортирует KeyStorage - используется только для тестов
