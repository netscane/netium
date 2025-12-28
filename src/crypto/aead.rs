//! AEAD (Authenticated Encryption with Associated Data) implementation
//!
//! Supports:
//! - ChaCha20-Poly1305
//! - AES-128-GCM
//! - AES-256-GCM

use aes_gcm::{
    aead::{Aead as AeadTrait, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{Error, Result};
use super::{NONCE_SIZE, TAG_SIZE};

/// Cipher types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl CipherKind {
    /// Get the key size for this cipher
    pub fn key_size(&self) -> usize {
        match self {
            CipherKind::ChaCha20Poly1305 => 32,
            CipherKind::Aes128Gcm => 16,
            CipherKind::Aes256Gcm => 32,
        }
    }

    /// Get the nonce size for this cipher
    pub fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    /// Get the tag size for this cipher
    pub fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

/// AEAD cipher trait
pub trait Aead: Send + Sync {
    /// Encrypt plaintext with associated data
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with associated data
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Get the cipher kind
    fn kind(&self) -> CipherKind;
}

/// AEAD cipher implementation
pub struct AeadCipher {
    kind: CipherKind,
    inner: CipherInner,
}

enum CipherInner {
    ChaCha20Poly1305(ChaCha20Poly1305),
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl AeadCipher {
    /// Create a new AEAD cipher with the given key
    pub fn new(kind: CipherKind, key: &[u8]) -> Result<Self> {
        if key.len() != kind.key_size() {
            return Err(Error::Crypto(format!(
                "Invalid key size: expected {}, got {}",
                kind.key_size(),
                key.len()
            )));
        }

        let inner = match kind {
            CipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
                CipherInner::ChaCha20Poly1305(cipher)
            }
            CipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
                CipherInner::Aes128Gcm(cipher)
            }
            CipherKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
                CipherInner::Aes256Gcm(cipher)
            }
        };

        Ok(Self { kind, inner })
    }
}

impl Aead for AeadCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(Error::Crypto(format!(
                "Invalid nonce size: expected {}, got {}",
                NONCE_SIZE,
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);

        let result = match &self.inner {
            CipherInner::ChaCha20Poly1305(cipher) => {
                if aad.is_empty() {
                    cipher.encrypt(nonce, plaintext)
                } else {
                    use aes_gcm::aead::Payload;
                    cipher.encrypt(nonce, Payload { msg: plaintext, aad })
                }
            }
            CipherInner::Aes128Gcm(cipher) => {
                if aad.is_empty() {
                    cipher.encrypt(nonce, plaintext)
                } else {
                    use aes_gcm::aead::Payload;
                    cipher.encrypt(nonce, Payload { msg: plaintext, aad })
                }
            }
            CipherInner::Aes256Gcm(cipher) => {
                if aad.is_empty() {
                    cipher.encrypt(nonce, plaintext)
                } else {
                    use aes_gcm::aead::Payload;
                    cipher.encrypt(nonce, Payload { msg: plaintext, aad })
                }
            }
        };

        result.map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(Error::Crypto(format!(
                "Invalid nonce size: expected {}, got {}",
                NONCE_SIZE,
                nonce.len()
            )));
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(Error::Crypto("Ciphertext too short".to_string()));
        }

        let nonce = Nonce::from_slice(nonce);

        let result = match &self.inner {
            CipherInner::ChaCha20Poly1305(cipher) => {
                if aad.is_empty() {
                    cipher.decrypt(nonce, ciphertext)
                } else {
                    use aes_gcm::aead::Payload;
                    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
                }
            }
            CipherInner::Aes128Gcm(cipher) => {
                if aad.is_empty() {
                    cipher.decrypt(nonce, ciphertext)
                } else {
                    use aes_gcm::aead::Payload;
                    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
                }
            }
            CipherInner::Aes256Gcm(cipher) => {
                if aad.is_empty() {
                    cipher.decrypt(nonce, ciphertext)
                } else {
                    use aes_gcm::aead::Payload;
                    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
                }
            }
        };

        result.map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))
    }

    fn kind(&self) -> CipherKind {
        self.kind
    }
}

// Implement Send + Sync for CipherInner
unsafe impl Send for CipherInner {}
unsafe impl Sync for CipherInner {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    #[test]
    fn test_chacha20_poly1305() {
        let key = random_bytes(32);
        let cipher = AeadCipher::new(CipherKind::ChaCha20Poly1305, &key).unwrap();

        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes_128_gcm() {
        let key = random_bytes(16);
        let cipher = AeadCipher::new(CipherKind::Aes128Gcm, &key).unwrap();

        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes_256_gcm() {
        let key = random_bytes(32);
        let cipher = AeadCipher::new(CipherKind::Aes256Gcm, &key).unwrap();

        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key() {
        let key1 = random_bytes(32);
        let key2 = random_bytes(32);

        let cipher1 = AeadCipher::new(CipherKind::ChaCha20Poly1305, &key1).unwrap();
        let cipher2 = AeadCipher::new(CipherKind::ChaCha20Poly1305, &key2).unwrap();

        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let ciphertext = cipher1.encrypt(&nonce, plaintext, &[]).unwrap();
        let result = cipher2.decrypt(&nonce, &ciphertext, &[]);

        assert!(result.is_err());
    }
}
