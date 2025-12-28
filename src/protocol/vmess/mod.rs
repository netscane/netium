//! VMess Protocol Implementation
//!
//! VMess is the original protocol designed for V2Ray.
//! This implementation supports AEAD mode (alter_id = 0).

mod aead;
mod client;
mod server;
mod stream;

pub use client::VmessClient;
pub use server::VmessServer;

use async_trait::async_trait;
use uuid::Uuid;

use crate::common::{Metadata, Result, Stream};
use crate::protocol::ProxyProtocol;

/// VMess security types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Security {
    #[default]
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl Security {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" | "aes128gcm" => Security::Aes128Gcm,
            "chacha20-poly1305" | "chacha20poly1305" => Security::Chacha20Poly1305,
            "none" => Security::None,
            "zero" => Security::Zero,
            _ => Security::Auto,
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            Security::Auto => 0x00,      // Will be resolved to actual cipher before use
            Security::Aes128Gcm => 0x03,
            Security::Chacha20Poly1305 => 0x04,
            Security::None => 0x05,
            Security::Zero => 0x06,
        }
    }

    pub fn from_byte(b: u8) -> Self {
        match b {
            0x03 => Security::Aes128Gcm,
            0x04 => Security::Chacha20Poly1305,
            0x05 => Security::None,
            0x06 => Security::Zero,
            _ => Security::Auto,
        }
    }

    /// Resolve Auto to actual security type
    pub fn resolve(&self) -> Security {
        match self {
            Security::Auto => {
                // Prefer AES-128-GCM on x86 (has AES-NI), ChaCha20 on ARM
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    Security::Aes128Gcm
                }
                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                {
                    Security::Chacha20Poly1305
                }
            }
            _ => *self,
        }
    }
}

/// VMess protocol configuration
#[derive(Debug, Clone)]
pub struct VmessConfig {
    /// User UUID
    pub uuid: Uuid,
    /// Security type
    pub security: Security,
    /// Alter ID (must be 0 for AEAD)
    pub alter_id: u16,
}

impl Default for VmessConfig {
    fn default() -> Self {
        Self {
            uuid: Uuid::nil(),
            security: Security::Auto,
            alter_id: 0,
        }
    }
}

/// VMess protocol handler
pub struct VmessProtocol {
    config: VmessConfig,
}

impl VmessProtocol {
    pub fn new(config: VmessConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProxyProtocol for VmessProtocol {
    async fn inbound(&self, stream: Stream) -> Result<(Metadata, Stream)> {
        let server = VmessServer::new(self.config.clone());
        server.accept(stream).await
    }

    async fn outbound(&self, stream: Stream, metadata: &Metadata) -> Result<Stream> {
        let client = VmessClient::new(self.config.clone());
        client.connect(stream, metadata).await
    }

    fn name(&self) -> &'static str {
        "vmess"
    }
}
