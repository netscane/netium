//! Blackhole Protocol - drops all connections
//!
//! Used to block unwanted traffic by silently dropping connections.
//! The actual blocking is done at the dispatcher layer - this protocol
//! is just a marker that tells the dispatcher to drop the connection.

use async_trait::async_trait;

use crate::common::{Metadata, Result, Stream};
use crate::error::Error;

use super::ProxyProtocol;

/// Blackhole protocol handler - drops all connections
/// 
/// This is a marker protocol. The dispatcher checks for this protocol
/// and drops connections before attempting to connect to any target.
pub struct BlackholeProtocol;

impl BlackholeProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BlackholeProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProxyProtocol for BlackholeProtocol {
    async fn inbound(&self, _stream: Stream) -> Result<(Metadata, Stream)> {
        // Blackhole cannot be used as inbound
        Err(Error::Protocol("Blackhole cannot be used as inbound".into()))
    }

    async fn outbound(&self, _stream: Stream, _metadata: &Metadata) -> Result<Stream> {
        // This should never be called - dispatcher handles blackhole specially
        Err(Error::Protocol("Blackhole outbound should not be called".into()))
    }

    fn name(&self) -> &'static str {
        "blackhole"
    }
}
