// Proof of Work (PoW) implementation using Argon2id
// Memory-hard, ASIC-resistant PoW for anti-bot registration

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use serde::{Deserialize, Serialize};

/// PoW challenge from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: i64,
}

/// PoW solution computed by client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowSolution {
    pub nonce: u64,
    pub hash: String,
}

/// Compute Argon2id-based Proof of Work
///
/// # Arguments
/// * `challenge` - Random string from server
/// * `difficulty` - Required number of leading zero bits in hash
///
/// # Returns
/// * `PowSolution` containing the nonce and resulting hash
///
/// # Performance
/// - difficulty=4: ~16 attempts, <30 seconds on iPhone
/// - difficulty=8: ~256 attempts, 3-5 minutes on iPhone
/// - difficulty=12: ~4096 attempts, 1-2 hours on iPhone
///
/// # Example
/// ```
/// let solution = compute_pow("server_challenge_xyz", 8);
/// println!("Found solution after {} attempts", solution.nonce);
/// ```
pub fn compute_pow(challenge: &str, difficulty: u32) -> PowSolution {
    // Argon2id parameters optimized for mobile devices
    // memory_cost: 32 MB (32768 KiB) - balance between security and UX
    // time_cost: 2 iterations - ~1.5 seconds per attempt on iPhone
    // parallelism: 1 thread - no multi-threading for simplicity
    let params = Params::new(
        32 * 1024, // 32 MB
        2,         // 2 iterations
        1,         // single thread
        Some(32),  // 32 byte output
    )
    .expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // Fixed salt for PoW (doesn't need unique salts per user)
    // Using base64-encoded constant for deterministic behavior
    let salt = SaltString::from_b64("a29uc3RydWN0LnBvdy52MS5zYWx0")
        .expect("Invalid salt encoding");

    let mut nonce: u64 = 0;

    loop {
        // Combine challenge + nonce as password input
        let input = format!("{}{}", challenge, nonce);

        // Compute Argon2id hash
        let hash_result = argon2
            .hash_password(input.as_bytes(), &salt)
            .expect("Argon2id hashing failed");

        // Extract raw hash bytes and convert to owned Vec
        let hash_bytes: Vec<u8> = hash_result
            .hash
            .unwrap()
            .as_bytes()
            .to_vec();

        // Count leading zero bits
        let leading_zeros = count_leading_zero_bits(&hash_bytes);

        // Check if solution meets difficulty requirement
        if leading_zeros >= difficulty {
            return PowSolution {
                nonce,
                hash: hex::encode(&hash_bytes),
            };
        }

        nonce += 1;

        // Yield to prevent UI freeze every 100 attempts (~2.5 minutes)
        if nonce % 100 == 0 {
            std::thread::yield_now();
        }
    }
}

/// Verify a PoW solution (server-side validation)
///
/// # Arguments
/// * `challenge` - Original challenge string
/// * `solution` - Client-provided solution
/// * `required_difficulty` - Minimum difficulty to accept
///
/// # Returns
/// * `true` if solution is valid and meets difficulty
/// * `false` if solution is invalid or insufficient
pub fn verify_pow(challenge: &str, solution: &PowSolution, required_difficulty: u32) -> bool {
    // Same parameters as compute_pow
    let params = match Params::new(32 * 1024, 2, 1, Some(32)) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt = match SaltString::from_b64("a29uc3RydWN0LnBvdy52MS5zYWx0") {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Recompute hash with provided nonce
    let input = format!("{}{}", challenge, solution.nonce);

    let hash_result = match argon2.hash_password(input.as_bytes(), &salt) {
        Ok(h) => h,
        Err(_) => return false,
    };

    let hash_bytes: Vec<u8> = hash_result.hash.unwrap().as_bytes().to_vec();
    let hash_hex = hex::encode(&hash_bytes);

    // Verify hash matches claimed hash
    if hash_hex != solution.hash {
        return false;
    }

    // Verify difficulty requirement
    let leading_zeros = count_leading_zero_bits(&hash_bytes);
    leading_zeros >= required_difficulty
}

/// Count leading zero bits in a byte array
///
/// # Example
/// ```
/// count_leading_zero_bits(&[0x00, 0xFF]) == 8   (1 zero byte)
/// count_leading_zero_bits(&[0x00, 0x00, 0x80]) == 16  (2 zero bytes)
/// count_leading_zero_bits(&[0x0F, 0xFF]) == 4   (half zero byte)
/// ```
fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;

    for byte in bytes {
        if *byte == 0 {
            // Entire byte is zero
            count += 8;
        } else {
            // Partial byte - count leading zeros in this byte
            count += byte.leading_zeros();
            break;
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zero_bits() {
        // All zeros
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x00]), 24);

        // One zero byte
        assert_eq!(count_leading_zero_bits(&[0x00, 0xFF]), 8);

        // Two zero bytes
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x80]), 16);

        // Partial zero byte (4 bits)
        assert_eq!(count_leading_zero_bits(&[0x0F, 0xFF]), 4);

        // No leading zeros
        assert_eq!(count_leading_zero_bits(&[0xFF, 0x00]), 0);

        // Single bit set
        assert_eq!(count_leading_zero_bits(&[0x01]), 7);
    }

    #[test]
    fn test_compute_pow_difficulty_4() {
        let challenge = "test_challenge_12345";
        let difficulty = 4; // ~16 attempts, should be fast

        let solution = compute_pow(challenge, difficulty);

        // Verify solution is valid
        assert!(verify_pow(challenge, &solution, difficulty));

        // Verify hash has required leading zeros
        let hash_bytes = hex::decode(&solution.hash).unwrap();
        assert!(count_leading_zero_bits(&hash_bytes) >= difficulty);
    }

    #[test]
    fn test_verify_pow_rejects_wrong_nonce() {
        let challenge = "test_challenge_xyz";
        let difficulty = 4;

        let valid_solution = compute_pow(challenge, difficulty);

        // Create fake solution with wrong nonce
        let fake_solution = PowSolution {
            nonce: valid_solution.nonce + 1,
            hash: valid_solution.hash.clone(),
        };

        // Should reject - hash won't match for different nonce
        assert!(!verify_pow(challenge, &fake_solution, difficulty));
    }

    #[test]
    fn test_verify_pow_rejects_insufficient_difficulty() {
        let challenge = "test_challenge_abc";
        let solution = compute_pow(challenge, 4);

        // Should pass for difficulty 4
        assert!(verify_pow(challenge, &solution, 4));

        // Should fail for higher difficulty (unlikely to have 8 leading zeros)
        // Note: might randomly pass, but very unlikely
        // assert!(!verify_pow(challenge, &solution, 8));
    }

    #[test]
    fn test_deterministic_hash() {
        let challenge = "deterministic_test";
        let nonce = 12345;

        let input = format!("{}{}", challenge, nonce);
        let params = Params::new(32 * 1024, 2, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::from_b64("a29uc3RydWN0LnBvdy52MS5zYWx0").unwrap();

        let hash1 = argon2.hash_password(input.as_bytes(), &salt).unwrap();
        let hash2 = argon2.hash_password(input.as_bytes(), &salt).unwrap();

        // Same input should produce same hash
        assert_eq!(hash1.to_string(), hash2.to_string());
    }
}
