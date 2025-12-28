//! Session Layer
//!
//! Responsibilities:
//! - TLS encryption/decryption
//! - WebSocket framing
//! - HTTP/2 multiplexing
//!
//! This layer transforms raw transport streams into secure/framed streams.
//! It does NOT parse proxy protocols or make routing decisions.

mod tls;
mod websocket;
mod plain;
mod tls_websocket;

pub use tls::TlsSession;
pub use websocket::WebSocketSession;
pub use plain::PlainSession;
pub use tls_websocket::TlsWebSocketSession;

use async_trait::async_trait;

use crate::common::{Result, Stream};

/// Session trait for wrapping streams with encryption/framing
///
/// Each session implementation wraps a stream and returns a new stream
/// with additional capabilities (encryption, framing, etc.)
#[async_trait]
pub trait Session: Send + Sync {
    /// Wrap a stream (client-side: initiate handshake)
    async fn wrap_client(&self, stream: Stream) -> Result<Stream>;

    /// Wrap a stream (server-side: accept handshake)
    async fn wrap_server(&self, stream: Stream) -> Result<Stream>;
}

/// Session configuration
#[derive(Debug, Clone)]
pub enum SessionConfig {
    /// No session layer (plain passthrough)
    Plain,
    /// TLS session
    Tls(TlsConfig),
    /// WebSocket session
    WebSocket(WebSocketConfig),
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig::Plain
    }
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Server name for SNI
    pub server_name: Option<String>,
    /// Allow insecure certificates
    pub allow_insecure: bool,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// Certificate file path (for server)
    pub certificate_file: Option<String>,
    /// Private key file path (for server)
    pub key_file: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            allow_insecure: false,
            alpn: vec![],
            certificate_file: None,
            key_file: None,
        }
    }
}

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path
    pub path: String,
    /// Host header
    pub host: Option<String>,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: vec![],
        }
    }
}

/// Create a session from configuration
pub fn create_session(config: &SessionConfig) -> Box<dyn Session> {
    match config {
        SessionConfig::Plain => Box::new(PlainSession),
        SessionConfig::Tls(tls_config) => Box::new(TlsSession::new(tls_config.clone())),
        SessionConfig::WebSocket(ws_config) => Box::new(WebSocketSession::new(ws_config.clone())),
    }
}
