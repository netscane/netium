//! Dispatcher - Core Execution Flow
//!
//! The dispatcher is the heart of the proxy system.
//! It handles the flow: inbound → router → outbound
//!
//! Each connection is handled in a separate tokio task.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, trace};

use crate::common::{Metadata, Result, Stream};
use crate::error::Error;
use crate::router::Router;

use super::stack::OutboundStack;

/// Dispatcher handles the core proxy flow
pub struct Dispatcher {
    /// Router for selecting outbound
    router: Arc<dyn Router>,
    /// Available outbound stacks
    outbounds: HashMap<String, Arc<OutboundStack>>,
}

impl Dispatcher {
    pub fn new(router: Arc<dyn Router>, outbounds: HashMap<String, Arc<OutboundStack>>) -> Self {
        Self { router, outbounds }
    }

    /// Dispatch a connection
    ///
    /// This is the core function that:
    /// 1. Uses router to select outbound
    /// 2. Connects via outbound stack
    /// 3. Relays data bidirectionally
    pub async fn dispatch(&self, metadata: Metadata, inbound_stream: Stream) -> Result<()> {
        let start = Instant::now();

        // 1. Select outbound
        let outbound_tag = self.router.select(&metadata);
        debug!(
            "[{}] Routing {} -> {} via {}",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        // 2. Get outbound stack
        let outbound = self
            .outbounds
            .get(outbound_tag)
            .ok_or_else(|| Error::Config(format!("Unknown outbound: {}", outbound_tag)))?;

        // 3. Connect to target
        let outbound_stream = outbound.connect(&metadata).await?;

        info!(
            "[{}] {} -> {} via [{}]",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        // 4. Relay data
        let (up, down) = relay(inbound_stream, outbound_stream).await?;

        let elapsed = start.elapsed();
        info!(
            "[{}] Connection closed: {} -> {} (up: {} bytes, down: {} bytes, duration: {:?})",
            metadata.inbound_tag, metadata.source, metadata.destination, up, down, elapsed
        );

        Ok(())
    }
}

/// Relay data bidirectionally between two streams
/// Returns (bytes_uploaded, bytes_downloaded)
async fn relay(inbound: Stream, outbound: Stream) -> Result<(u64, u64)> {
    let (mut in_read, mut in_write) = tokio::io::split(inbound);
    let (mut out_read, mut out_write) = tokio::io::split(outbound);

    let client_to_server = async {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = in_read.read(&mut buf).await?;
            if n == 0 {
                trace!("Client -> Server: EOF");
                break;
            }
            out_write.write_all(&buf[..n]).await?;
            out_write.flush().await?;
            total += n as u64;
            trace!("Client -> Server: {} bytes (total: {})", n, total);
        }
        out_write.shutdown().await?;
        Ok::<_, std::io::Error>(total)
    };

    let server_to_client = async {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = out_read.read(&mut buf).await?;
            if n == 0 {
                trace!("Server -> Client: EOF");
                break;
            }
            in_write.write_all(&buf[..n]).await?;
            in_write.flush().await?;
            total += n as u64;
            trace!("Server -> Client: {} bytes (total: {})", n, total);
        }
        in_write.shutdown().await?;
        Ok::<_, std::io::Error>(total)
    };

    // Run both directions concurrently
    let (up_result, down_result) = tokio::join!(client_to_server, server_to_client);

    let up = up_result.unwrap_or_else(|e| {
        debug!("Client to server relay error: {}", e);
        0
    });
    let down = down_result.unwrap_or_else(|e| {
        debug!("Server to client relay error: {}", e);
        0
    });

    Ok((up, down))
}

/// Copy data from reader to writer
async fn copy_bidirectional(
    mut inbound: Stream,
    mut outbound: Stream,
) -> Result<(u64, u64)> {
    let result = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(result)
}
