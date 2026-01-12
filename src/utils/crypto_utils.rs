use base64::{engine::general_purpose, Engine as _};

pub mod b64 {
    use base64::engine::general_purpose;
    use base64::Engine;

    pub fn encode(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    pub fn decode(data: &str) -> Result<Vec<u8>, String> {
        general_purpose::STANDARD
            .decode(data)
            .map_err(|e| format!("Base64 decode failed: {}", e))
    }
}

pub mod uuid {
    pub fn generate_v4() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn is_valid(uuid: &str) -> bool {
        uuid::Uuid::parse_str(uuid).is_ok()
    }
}

pub mod serialization {
    use serde::{Deserialize, Serialize};

    pub fn to_bytes<T: Serialize>(data: &T) -> Result<Vec<u8>, String> {
        bincode::serialize(data).map_err(|e| format!("Serialization failed: {}", e))
    }

    pub fn from_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
        bincode::deserialize(bytes).map_err(|e| format!("Deserialization failed: {}", e))
    }
}

pub mod validation {
    pub fn validate_public_key(key: &[u8]) -> Result<(), String> {
        if key.len() != 32 {
            return Err("Public key must be 32 bytes".to_string());
        }
        Ok(())
    }

    pub fn validate_signature(sig: &[u8]) -> Result<(), String> {
        if sig.len() != 64 {
            return Err("Signature must be 64 bytes".to_string());
        }
        Ok(())
    }
}
