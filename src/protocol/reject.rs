//! Reject Protocol - immediately closes connections
//!
//! Used to block traffic by immediately closing the connection.
//! Unlike blackhole (which hangs), reject closes instantly.

use async_trait::async_trait;

use crate::common::{Metadata, Result, Stream};
use crate::error::Error;

use super::ProxyProtocol;

/// Reject protocol handler - immediately closes connections
/// 
/// This is a marker protocol. The dispatcher checks for this protocol
/// and immediately closes connections without any delay.
pub struct RejectProtocol;

impl RejectProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RejectProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProxyProtocol for RejectProtocol {
    async fn inbound(&self, _stream: Stream) -> Result<(Metadata, Stream)> {
        Err(Error::Protocol("Reject cannot be used as inbound".into()))
    }

    async fn outbound(&self, _stream: Stream, _metadata: &Metadata) -> Result<Stream> {
        // This should never be called - dispatcher handles reject specially
        Err(Error::Protocol("Reject outbound should not be called".into()))
    }

    fn name(&self) -> &'static str {
        "reject"
    }
}
