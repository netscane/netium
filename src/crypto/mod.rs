//! Cryptography module for Netium
//!
//! Provides encryption/decryption using modern algorithms:
//! - ChaCha20-Poly1305 (recommended)
//! - AES-128-GCM
//! - AES-256-GCM
//! - X25519 key exchange

mod aead;
mod key_exchange;

pub use aead::{Aead, AeadCipher, CipherKind};
pub use key_exchange::{KeyExchange, X25519KeyPair};

use crate::error::Result;

/// Nonce size for AEAD ciphers (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Tag size for AEAD ciphers (16 bytes)
pub const TAG_SIZE: usize = 16;

/// Maximum payload size (16KB - overhead)
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 - TAG_SIZE;

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a random nonce
pub fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive a key using HKDF-SHA256
pub fn derive_key(secret: &[u8], salt: &[u8], info: &[u8], key_len: usize) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut okm = vec![0u8; key_len];
    hk.expand(info, &mut okm)
        .map_err(|e| crate::error::Error::Crypto(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Sha256;
    use hkdf::Hkdf;
    
    // Simple HMAC implementation using HKDF
    let hk = Hkdf::<Sha256>::new(Some(key), data);
    let mut okm = [0u8; 32];
    hk.expand(b"hmac", &mut okm).unwrap();
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);
        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_derive_key() {
        let secret = b"secret";
        let salt = b"salt";
        let info = b"info";
        let key = derive_key(secret, salt, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
    }
}
