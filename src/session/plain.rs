//! Plain session - no-op passthrough

use async_trait::async_trait;

use crate::common::{Result, Stream};

use super::Session;

/// Plain session that passes through without modification
pub struct PlainSession;

#[async_trait]
impl Session for PlainSession {
    async fn wrap_client(&self, stream: Stream) -> Result<Stream> {
        Ok(stream)
    }

    async fn wrap_server(&self, stream: Stream) -> Result<Stream> {
        Ok(stream)
    }
}
