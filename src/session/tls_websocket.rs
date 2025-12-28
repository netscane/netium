//! Combined TLS + WebSocket Session
//!
//! This session wraps a stream with TLS first, then WebSocket framing.

use async_trait::async_trait;
use tracing::debug;

use super::{Session, TlsConfig, TlsSession, WebSocketConfig, WebSocketSession};
use crate::common::{Result, Stream};

/// Combined TLS + WebSocket session
///
/// Applies TLS encryption first, then WebSocket framing on top.
pub struct TlsWebSocketSession {
    tls_session: TlsSession,
    ws_session: WebSocketSession,
}

impl TlsWebSocketSession {
    pub fn new(tls_config: TlsConfig, ws_config: WebSocketConfig) -> Self {
        Self {
            tls_session: TlsSession::new(tls_config),
            ws_session: WebSocketSession::new(ws_config),
        }
    }
}

#[async_trait]
impl Session for TlsWebSocketSession {
    async fn wrap_client(&self, stream: Stream) -> Result<Stream> {
        debug!("TLS+WebSocket: Starting TLS handshake");
        let tls_stream = self.tls_session.wrap_client(stream).await?;
        
        debug!("TLS+WebSocket: Starting WebSocket handshake");
        let ws_stream = self.ws_session.wrap_client(tls_stream).await?;
        
        debug!("TLS+WebSocket: Connection established");
        Ok(ws_stream)
    }

    async fn wrap_server(&self, stream: Stream) -> Result<Stream> {
        debug!("TLS+WebSocket: Accepting TLS connection");
        let tls_stream = self.tls_session.wrap_server(stream).await?;
        
        debug!("TLS+WebSocket: Accepting WebSocket connection");
        let ws_stream = self.ws_session.wrap_server(tls_stream).await?;
        
        debug!("TLS+WebSocket: Connection established");
        Ok(ws_stream)
    }
}
