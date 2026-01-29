// Invite Crypto - Dynamic Contact Invites
// 
// Provides cryptographic primitives for generating and verifying one-time invite links:
// - Ephemeral X25519 keypair generation (per invite)
// - Ed25519 signature creation and verification for invite authenticity
// - JTI-based one-time use tokens
//
// Security model:
// - Each invite has unique ephemeral X25519 public key
// - Invite data signed with long-term Ed25519 identity key
// - Server validates JTI for one-time use
// - 3-5 minute TTL enforced by server

use crate::uniffi_bindings::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifying, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

/// Ephemeral X25519 keypair for a single invite
/// Used once then discarded after invite is accepted
#[derive(Debug, Clone)]
pub struct EphemeralKeyPair {
    pub secret_key: Vec<u8>,  // 32 bytes
    pub public_key: Vec<u8>,  // 32 bytes
}

/// Ed25519 signature for invite verification
#[derive(Debug, Clone)]
pub struct InviteSignature {
    pub signature: Vec<u8>,  // 64 bytes
}

/// Generate ephemeral X25519 keypair
/// 
/// Returns a fresh keypair for a single invite.
/// The secret key should be discarded after the invite is created.
/// Only the public key is included in the invite object.
///
/// # Returns
/// - `EphemeralKeyPair` with 32-byte secret and public keys
pub fn generate_ephemeral_keypair() -> Result<EphemeralKeyPair, CryptoError> {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    
    Ok(EphemeralKeyPair {
        secret_key: secret.to_bytes().to_vec(),
        public_key: public.to_bytes().to_vec(),
    })
}

/// Sign invite data with Ed25519 identity key
///
/// Creates a detached signature over the invite data using the sender's
/// long-term Ed25519 identity key. The signature proves authenticity and
/// prevents tampering.
///
/// # Arguments
/// - `data`: UTF-8 string containing invite data (typically JSON)
/// - `identity_secret_key`: 32-byte Ed25519 secret key (from user's identity keypair)
///
/// # Returns
/// - `InviteSignature` with 64-byte signature
///
/// # Errors
/// - `InvalidKeyData` if secret key is not 32 bytes
pub fn sign_invite_data(
    data: &str,
    identity_secret_key: &[u8],
) -> Result<InviteSignature, CryptoError> {
    // Validate secret key length
    if identity_secret_key.len() != 32 {
        return Err(CryptoError::InvalidKeyData);
    }
    
    // Convert to SigningKey
    let secret_array: [u8; 32] = identity_secret_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let signing_key = SigningKey::from_bytes(&secret_array);
    
    // Sign the data
    let signature = signing_key.sign(data.as_bytes());
    
    Ok(InviteSignature {
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify invite signature with Ed25519 verifying key
///
/// Verifies that the invite was signed by the claimed identity key.
/// This prevents impersonation and ensures the invite hasn't been tampered with.
///
/// # Arguments
/// - `data`: UTF-8 string containing invite data (must match what was signed)
/// - `signature`: 64-byte Ed25519 signature
/// - `verifying_key`: 32-byte Ed25519 public key (from sender's public key bundle)
///
/// # Returns
/// - `true` if signature is valid
/// - `false` if signature is invalid or verification fails
///
/// # Errors
/// - `InvalidKeyData` if verifying key is not 32 bytes
/// - `InvalidCiphertext` if signature is not 64 bytes
pub fn verify_invite_signature(
    data: &str,
    signature: &[u8],
    verifying_key: &[u8],
) -> Result<bool, CryptoError> {
    // Validate key and signature lengths
    if verifying_key.len() != 32 {
        return Err(CryptoError::InvalidKeyData);
    }
    if signature.len() != 64 {
        return Err(CryptoError::InvalidCiphertext);
    }
    
    // Convert to VerifyingKey
    let key_array: [u8; 32] = verifying_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    
    // Convert to Signature
    let sig_array: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    let signature = Signature::from_bytes(&sig_array);
    
    // Verify signature
    match verifying_key.verify_strict(data.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ephemeral_keypair_generation() {
        let keypair = generate_ephemeral_keypair().expect("Failed to generate keypair");
        
        assert_eq!(keypair.secret_key.len(), 32, "Secret key should be 32 bytes");
        assert_eq!(keypair.public_key.len(), 32, "Public key should be 32 bytes");
        
        // Keys should be different each time
        let keypair2 = generate_ephemeral_keypair().expect("Failed to generate keypair");
        assert_ne!(keypair.secret_key, keypair2.secret_key, "Secret keys should be unique");
        assert_ne!(keypair.public_key, keypair2.public_key, "Public keys should be unique");
    }
    
    #[test]
    fn test_sign_and_verify() {
        // Generate identity keypair
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        
        // Test data
        let invite_data = r#"{"v":1,"jti":"abc123","uuid":"user123","server":"example.com","ephKey":"...","ts":1234567890}"#;
        
        // Sign
        let signature = sign_invite_data(invite_data, &signing_key.to_bytes())
            .expect("Failed to sign");
        
        assert_eq!(signature.signature.len(), 64, "Signature should be 64 bytes");
        
        // Verify (valid)
        let is_valid = verify_invite_signature(invite_data, &signature.signature, &verifying_key.to_bytes())
            .expect("Failed to verify");
        assert!(is_valid, "Signature should be valid");
        
        // Verify (tampered data)
        let tampered_data = r#"{"v":1,"jti":"TAMPERED","uuid":"user123","server":"example.com","ephKey":"...","ts":1234567890}"#;
        let is_valid = verify_invite_signature(tampered_data, &signature.signature, &verifying_key.to_bytes())
            .expect("Failed to verify");
        assert!(!is_valid, "Signature should be invalid for tampered data");
        
        // Verify (wrong key)
        let wrong_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_verifying_key = wrong_key.verifying_key();
        let is_valid = verify_invite_signature(invite_data, &signature.signature, &wrong_verifying_key.to_bytes())
            .expect("Failed to verify");
        assert!(!is_valid, "Signature should be invalid with wrong key");
    }
    
    #[test]
    fn test_invalid_key_lengths() {
        let data = "test data";
        
        // Invalid secret key (too short)
        let short_key = vec![0u8; 16];
        assert!(sign_invite_data(data, &short_key).is_err());
        
        // Invalid verifying key (too long)
        let long_key = vec![0u8; 64];
        let dummy_sig = vec![0u8; 64];
        assert!(verify_invite_signature(data, &dummy_sig, &long_key).is_err());
        
        // Invalid signature (wrong length)
        let key = vec![0u8; 32];
        let short_sig = vec![0u8; 32];
        assert!(verify_invite_signature(data, &short_sig, &key).is_err());
    }
}
