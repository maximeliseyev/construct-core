//! Post-quantum extensions for the X3DH protocol.
#![cfg(feature = "post-quantum")]

use pqc_kyber::KyberKeypair;
use x25519_dalek::{StaticSecret, PublicKey};

// TODO: These should be properly defined with actual key sizes from the pqc crates.
// Using Vec<u8> for now as per the documentation.
// Kyber-768 public key is 1184 bytes.
// Dilithium3 signature is 2701 bytes.

/// A post-quantum X3DH bundle, containing both classical and PQC keys.
pub struct PQX3DHBundle {
    // Классические ключи (для обратной совместимости)
    pub identity_public: [u8; 32],           // X25519
    pub signed_prekey_public: [u8; 32],      // X25519
    pub signature: [u8; 64],                 // Ed25519
    
    // Пост-квантовые ключи
    pub kyber_public_key: Vec<u8>,           // Kyber-768 (1184 байт)
    pub kyber_prekey_public: Vec<u8>,        // Kyber для prekey
    pub pq_signature: Vec<u8>,               // Dilithium подпись
}
