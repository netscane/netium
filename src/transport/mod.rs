//! Transport Layer
//!
//! The transport layer handles connection establishment and stream wrapping:
//!
//! - **Transport**: Establishes raw connections (TCP, UDP)
//! - **StreamLayer**: Wraps streams with additional functionality (TLS, WebSocket)
//!
//! Architecture:
//! ```text
//! TCP/UDP (Transport)
//!     ↓
//! TLS/WebSocket (StreamLayer)
//!     ↓
//! Protocol Layer
//! ```

mod tcp;
mod udp;
mod tls;
mod websocket;
mod pool;
mod null;

pub use tcp::TcpTransport;
pub use udp::{Datagram, UdpDatagram, UdpTransport};
pub use tls::{TlsConfig, TlsWrapper};
pub use websocket::{WebSocketConfig, WebSocketWrapper};
pub use pool::{ConnectionPool, PoolConfig, PoolStats};
pub use null::{BlackholeTransport, RejectTransport};

use std::sync::Arc;

use async_trait::async_trait;

use crate::common::{Address, Result, Stream};

/// Transport trait for establishing raw connections
///
/// Implementations handle connection establishment only,
/// not encryption or protocol handling.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to a remote address
    async fn connect(&self, addr: &Address) -> Result<Stream>;

    /// Create a listener bound to an address
    async fn bind(&self, addr: &Address) -> Result<Box<dyn Listener>>;
}

/// Listener trait for accepting incoming connections
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept a new connection
    async fn accept(&self) -> Result<(Stream, Address)>;

    /// Get the local bound address
    fn local_addr(&self) -> Result<Address>;

    /// Close the listener
    async fn close(&self) -> Result<()>;
}

/// StreamLayer trait for wrapping streams with additional functionality.
///
/// Used for TLS encryption and WebSocket framing.
/// This is the internal unified abstraction for Stream → Stream transformations.
#[async_trait]
pub trait StreamLayer: Send + Sync {
    /// Wrap a stream (client-side: initiate handshake)
    async fn wrap_client(&self, stream: Stream) -> Result<Stream>;

    /// Wrap a stream (server-side: accept handshake)
    async fn wrap_server(&self, stream: Stream) -> Result<Stream>;
}

/// A composable stream layer that chains multiple layers.
pub struct ChainedLayer {
    layers: Vec<Arc<dyn StreamLayer>>,
}

impl ChainedLayer {
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
        }
    }

    pub fn push(mut self, layer: Arc<dyn StreamLayer>) -> Self {
        self.layers.push(layer);
        self
    }
}

impl Default for ChainedLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StreamLayer for ChainedLayer {
    async fn wrap_client(&self, mut stream: Stream) -> Result<Stream> {
        for layer in &self.layers {
            stream = layer.wrap_client(stream).await?;
        }
        Ok(stream)
    }

    async fn wrap_server(&self, mut stream: Stream) -> Result<Stream> {
        for layer in &self.layers {
            stream = layer.wrap_server(stream).await?;
        }
        Ok(stream)
    }
}

/// Plain layer that does nothing (passthrough).
pub struct PlainLayer;

#[async_trait]
impl StreamLayer for PlainLayer {
    async fn wrap_client(&self, stream: Stream) -> Result<Stream> {
        Ok(stream)
    }

    async fn wrap_server(&self, stream: Stream) -> Result<Stream> {
        Ok(stream)
    }
}
