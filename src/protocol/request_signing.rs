// Request Signing для критичных операций
//
// Реализует подпись HTTP запросов с использованием Ed25519
// Формат: method:path:timestamp:body_hash (SHA256)
//
// Используется для защиты критичных операций (например, /keys/upload)
// от tampering и обеспечения дополнительной аутентификации

use crate::utils::error::Result;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

/// Подписать HTTP запрос
///
/// # Параметры
/// - `method`: HTTP метод (например, "POST")
/// - `path`: путь запроса (например, "/keys/upload")
/// - `body`: тело запроса в JSON формате
/// - `signing_key`: Ed25519 signing key (master_identity_key)
///
/// # Возвращает
/// Tuple (signature_base64, public_key_base64, timestamp)
pub fn sign_request(
    method: &str,
    path: &str,
    body: &str,
    signing_key: &SigningKey,
) -> Result<(String, String, i64)> {
    // 1. Получить timestamp
    let timestamp = crate::utils::time::current_timestamp();

    // 2. Вычислить SHA256 хэш body
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let body_hash = hasher.finalize();
    let body_hash_hex = hex::encode(body_hash);

    // 3. Создать canonical строку: method:path:timestamp:body_hash
    let canonical = format!("{}:{}:{}:{}", method, path, timestamp, body_hash_hex);

    // 4. Подписать canonical строку
    let signature: Signature = signing_key.sign(canonical.as_bytes());

    // 5. Получить public key
    let public_key = signing_key.verifying_key();

    // 6. Конвертировать в Base64
    let signature_base64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(public_key.to_bytes());

    Ok((signature_base64, public_key_base64, timestamp))
}

/// Проверить подпись запроса (для тестирования)
#[cfg(test)]
pub fn verify_request_signature(
    method: &str,
    path: &str,
    body: &str,
    signature_base64: &str,
    public_key_base64: &str,
    timestamp: i64,
) -> Result<bool> {
    use crate::utils::error::ConstructError;
    use base64::Engine;
    use ed25519_dalek::{Verifier, VerifyingKey};

    // 1. Декодировать signature и public key
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|e| {
            ConstructError::ValidationError(format!("Invalid signature base64: {:?}", e))
        })?;
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_base64)
        .map_err(|e| {
            ConstructError::ValidationError(format!("Invalid public key base64: {:?}", e))
        })?;

    let signature =
        Signature::from_bytes(signature_bytes.as_slice().try_into().map_err(|_| {
            ConstructError::ValidationError("Invalid signature length".to_string())
        })?);

    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ConstructError::ValidationError("Invalid public key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|e| ConstructError::ValidationError(format!("Invalid public key: {:?}", e)))?;

    // 2. Вычислить SHA256 хэш body
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let body_hash = hasher.finalize();
    let body_hash_hex = hex::encode(body_hash);

    // 3. Создать canonical строку
    let canonical = format!("{}:{}:{}:{}", method, path, timestamp, body_hash_hex);

    // 4. Проверить подпись
    match verifying_key.verify(canonical.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_and_verify_request() {
        // Создать signing key
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        // Подписать запрос
        let method = "POST";
        let path = "/keys/upload";
        let body = r#"{"key":"value"}"#;

        let (signature, public_key, timestamp) =
            sign_request(method, path, body, &signing_key).unwrap();

        // Проверить подпись
        let is_valid =
            verify_request_signature(method, path, body, &signature, &public_key, timestamp)
                .unwrap();

        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_signature_fails_with_modified_body() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let method = "POST";
        let path = "/keys/upload";
        let original_body = r#"{"key":"value"}"#;
        let modified_body = r#"{"key":"modified"}"#;

        let (signature, public_key, timestamp) =
            sign_request(method, path, original_body, &signing_key).unwrap();

        // Попытка проверить с модифицированным body
        let is_valid = verify_request_signature(
            method,
            path,
            modified_body,
            &signature,
            &public_key,
            timestamp,
        )
        .unwrap();

        assert!(!is_valid, "Signature should be invalid for modified body");
    }

    #[test]
    fn test_signature_fails_with_wrong_path() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let method = "POST";
        let original_path = "/keys/upload";
        let wrong_path = "/keys/download";
        let body = r#"{"key":"value"}"#;

        let (signature, public_key, timestamp) =
            sign_request(method, original_path, body, &signing_key).unwrap();

        // Попытка проверить с неправильным path
        let is_valid =
            verify_request_signature(method, wrong_path, body, &signature, &public_key, timestamp)
                .unwrap();

        assert!(!is_valid, "Signature should be invalid for wrong path");
    }
}
