//! Direct Protocol - passthrough without any protocol handling

use async_trait::async_trait;

use crate::common::{Metadata, Result, Stream};

use super::ProxyProtocol;

/// Direct protocol - no-op passthrough
///
/// Used for direct connections that don't need any protocol handling.
pub struct DirectProtocol;

#[async_trait]
impl ProxyProtocol for DirectProtocol {
    async fn inbound(&self, stream: Stream) -> Result<(Metadata, Stream)> {
        // Direct protocol doesn't parse anything
        // Return empty metadata (destination should be set by caller)
        Ok((Metadata::default().with_protocol("direct"), stream))
    }

    async fn outbound(&self, stream: Stream, _metadata: &Metadata) -> Result<Stream> {
        // Direct protocol doesn't add any wrapping
        Ok(stream)
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}
