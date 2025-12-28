//! Key exchange using X25519

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand::rngs::OsRng;

use crate::error::Result;

/// Key exchange trait
pub trait KeyExchange: Send + Sync {
    /// Get the public key
    fn public_key(&self) -> &[u8];

    /// Perform key exchange with peer's public key
    fn exchange(&self, peer_public_key: &[u8]) -> Result<[u8; 32]>;
}

/// X25519 key pair for key exchange
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from an existing secret key
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public);
        *self.secret.diffie_hellman(&peer_public).as_bytes()
    }
}

impl KeyExchange for X25519KeyPair {
    fn public_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn exchange(&self, peer_public_key: &[u8]) -> Result<[u8; 32]> {
        if peer_public_key.len() != 32 {
            return Err(crate::error::Error::Crypto(
                "Invalid public key length".to_string(),
            ));
        }

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_public_key);
        Ok(self.diffie_hellman(&peer_bytes))
    }
}

/// Ephemeral X25519 key pair (for one-time use)
pub struct EphemeralX25519 {
    public: PublicKey,
    secret: Option<EphemeralSecret>,
}

impl EphemeralX25519 {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            public,
            secret: Some(secret),
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Perform key exchange (consumes the secret)
    pub fn exchange(mut self, peer_public: &[u8; 32]) -> [u8; 32] {
        let secret = self.secret.take().expect("Secret already consumed");
        let peer_public = PublicKey::from(*peer_public);
        *secret.diffie_hellman(&peer_public).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        // Alice generates her key pair
        let alice = X25519KeyPair::generate();

        // Bob generates his key pair
        let bob = X25519KeyPair::generate();

        // They exchange public keys and compute shared secret
        let alice_shared = alice.diffie_hellman(&bob.public_key_bytes());
        let bob_shared = bob.diffie_hellman(&alice.public_key_bytes());

        // Shared secrets should be identical
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let static_key = X25519KeyPair::generate();
        let ephemeral = EphemeralX25519::generate();

        let ephemeral_public = ephemeral.public_key_bytes();
        let shared1 = ephemeral.exchange(&static_key.public_key_bytes());
        let shared2 = static_key.diffie_hellman(&ephemeral_public);

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_key_exchange_trait() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.exchange(bob.public_key()).unwrap();
        let bob_shared = bob.exchange(alice.public_key()).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }
}
