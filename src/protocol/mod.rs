//! Proxy Protocol Layer
//!
//! Responsibilities:
//! - Authentication
//! - Target address parsing
//! - Protocol encryption/decryption
//! - Generate Metadata
//!
//! This layer handles proxy-specific protocol logic.

mod blackhole;
mod direct;
mod reject;
mod socks5;
mod http;
pub mod vmess;

pub use blackhole::BlackholeProtocol;
pub use direct::DirectProtocol;
pub use reject::RejectProtocol;
pub use socks5::Socks5Protocol;
pub use http::HttpProtocol;
pub use vmess::{VmessProtocol, VmessConfig as VmessProtocolConfig, Security as VmessSecurity};

use async_trait::async_trait;

use crate::common::{Metadata, Result, Stream};

/// Unified proxy protocol trait
///
/// All proxy protocols implement this trait for both inbound and outbound.
/// This is the core abstraction that allows protocols to be pluggable.
#[async_trait]
pub trait ProxyProtocol: Send + Sync {
    /// Handle inbound connection (server-side)
    ///
    /// Parses the incoming protocol, extracts target address,
    /// and returns Metadata + wrapped stream for data transfer.
    async fn inbound(&self, stream: Stream) -> Result<(Metadata, Stream)>;

    /// Handle outbound connection (client-side)
    ///
    /// Takes a stream and metadata, performs protocol handshake,
    /// and returns a wrapped stream ready for data transfer.
    async fn outbound(&self, stream: Stream, metadata: &Metadata) -> Result<Stream>;

    /// Get protocol name
    fn name(&self) -> &'static str;
}

/// Protocol configuration
#[derive(Debug, Clone)]
pub enum ProtocolConfig {
    /// Direct connection (no protocol)
    Direct,
    /// SOCKS5 protocol
    Socks5(Socks5Config),
    /// HTTP CONNECT protocol
    Http(HttpConfig),
    /// VMess protocol
    Vmess(VmessConfig),
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig::Direct
    }
}

/// SOCKS5 configuration
#[derive(Debug, Clone, Default)]
pub struct Socks5Config {
    /// Username for authentication (optional)
    pub username: Option<String>,
    /// Password for authentication (optional)
    pub password: Option<String>,
}

/// HTTP CONNECT configuration
#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    /// Username for authentication (optional)
    pub username: Option<String>,
    /// Password for authentication (optional)
    pub password: Option<String>,
}

/// VMess configuration
#[derive(Debug, Clone)]
pub struct VmessConfig {
    /// User UUID
    pub uuid: uuid::Uuid,
    /// Security type
    pub security: String,
    /// Alter ID (legacy, usually 0)
    pub alter_id: u16,
}

impl Default for VmessConfig {
    fn default() -> Self {
        Self {
            uuid: uuid::Uuid::nil(),
            security: "auto".to_string(),
            alter_id: 0,
        }
    }
}

/// Create a protocol from configuration
pub fn create_protocol(config: &ProtocolConfig) -> Box<dyn ProxyProtocol> {
    match config {
        ProtocolConfig::Direct => Box::new(DirectProtocol),
        ProtocolConfig::Socks5(cfg) => Box::new(Socks5Protocol::new(cfg.clone())),
        ProtocolConfig::Http(cfg) => Box::new(HttpProtocol::new(cfg.clone())),
        ProtocolConfig::Vmess(cfg) => {
            let vmess_config = vmess::VmessConfig {
                uuid: cfg.uuid,
                security: vmess::Security::from_str(&cfg.security),
                alter_id: cfg.alter_id,
            };
            Box::new(VmessProtocol::new(vmess_config))
        }
    }
}
