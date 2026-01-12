// Сериализация

use serde::{Deserialize, Serialize};

pub fn to_bytes<T: Serialize>(data: &T) -> Result<Vec<u8>, String> {
    bincode::serialize(data).map_err(|e| format!("Serialization failed: {}", e))
}

pub fn from_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    bincode::deserialize(bytes).map_err(|e| format!("Deserialization failed: {}", e))
}
