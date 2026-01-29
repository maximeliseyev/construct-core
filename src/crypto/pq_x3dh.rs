//! Post-quantum extensions for the X3DH protocol.
#![cfg(feature = "post-quantum")]

// ML-KEM-768 (formerly Kyber-768) public key is 1184 bytes
// ML-DSA-65 (formerly Dilithium3) signature is 3309 bytes

/// A post-quantum X3DH bundle, containing both classical and PQC keys.
pub struct PQX3DHBundle {
    // Классические ключи (для обратной совместимости)
    pub identity_public: [u8; 32],      // X25519
    pub signed_prekey_public: [u8; 32], // X25519
    pub signature: [u8; 64],            // Ed25519

    // Пост-квантовые ключи (NIST standardized names)
    pub mlkem_public_key: Vec<u8>,    // ML-KEM-768 (1184 байт)
    pub mlkem_prekey_public: Vec<u8>, // ML-KEM для prekey
    pub pq_signature: Vec<u8>,        // ML-DSA подпись
}
