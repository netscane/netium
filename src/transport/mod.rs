//! Transport Layer
//!
//! Responsibilities:
//! - Establish lowest-level connections (TCP, UDP, QUIC)
//! - NO encryption, NO protocol parsing, NO content inspection
//!
//! This layer ONLY deals with raw byte transport.

mod tcp;
mod udp;

pub use tcp::TcpTransport;
pub use udp::UdpTransport;

use async_trait::async_trait;

use crate::common::{Address, Result, Stream};

/// Transport trait for establishing raw connections
///
/// Implementations should ONLY handle connection establishment,
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
