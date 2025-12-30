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
use tracing::{debug, info, trace};

use crate::common::{Metadata, Result, Stream};
use crate::error::Error;
use crate::router::Router;

use super::metrics::{
    ConnectionMetrics, TRAFFIC_BYTES_DOWNLOADED, TRAFFIC_BYTES_UPLOADED,
    OUTBOUND_BYTES_DOWNLOADED, OUTBOUND_BYTES_UPLOADED,
};
use super::stack::OutboundStack;
use super::stats_api::{DispatcherStats, OutboundStats};

/// Dispatcher handles the core proxy flow
pub struct Dispatcher {
    /// Router for selecting outbound
    router: Arc<dyn Router>,
    /// Available outbound stacks
    outbounds: HashMap<String, Arc<OutboundStack>>,
    /// Dispatcher statistics
    stats: Option<Arc<DispatcherStats>>,
    /// Per-outbound statistics
    outbound_stats: Option<Arc<HashMap<String, Arc<OutboundStats>>>>,
}

impl Dispatcher {
    pub fn new(router: Arc<dyn Router>, outbounds: HashMap<String, Arc<OutboundStack>>) -> Self {
        Self { 
            router, 
            outbounds,
            stats: None,
            outbound_stats: None,
        }
    }

    /// Set dispatcher statistics collector
    pub fn with_stats(mut self, stats: Arc<DispatcherStats>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Set per-outbound statistics
    pub fn with_outbound_stats(mut self, outbound_stats: Arc<HashMap<String, Arc<OutboundStats>>>) -> Self {
        self.outbound_stats = Some(outbound_stats);
        self
    }

    /// Dispatch a connection
    ///
    /// This is the core function that:
    /// 1. Uses router to select outbound
    /// 2. Connects via outbound stack
    /// 3. Relays data bidirectionally with metering
    pub async fn dispatch(&self, metadata: Metadata, inbound_stream: Stream) -> Result<()> {
        let start = Instant::now();

        // Record connection start
        if let Some(stats) = &self.stats {
            stats.connection_start();
        }

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

        // Get outbound stats if available
        let outbound_stat = self.outbound_stats.as_ref()
            .and_then(|m| m.get(outbound_tag).cloned());

        // Record outbound connection start
        if let Some(stat) = &outbound_stat {
            stat.connection_start();
        }

        // Create connection metrics for duration tracking
        let conn_metrics = ConnectionMetrics::new(outbound_tag);

        // 3. Connect to target
        let outbound_stream = match outbound.connect(&metadata).await {
            Ok(stream) => stream,
            Err(e) => {
                // Record failure
                if let Some(stats) = &self.stats {
                    stats.connection_failed();
                }
                if let Some(stat) = &outbound_stat {
                    stat.dec_active();
                }
                return Err(e);
            }
        };

        info!(
            "[{}] {} -> {} via [{}]",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        // 4. Relay data with prometheus metrics
        let (up, down) = relay_with_metrics(
            inbound_stream,
            outbound_stream,
            outbound_tag,
        ).await?;

        // Record connection completion with duration
        conn_metrics.record_completion();

        // Record connection end
        if let Some(stats) = &self.stats {
            stats.connection_end(up, down);
        }
        if let Some(stat) = &outbound_stat {
            stat.connection_end(up, down);
        }

        let elapsed = start.elapsed();
        info!(
            "[{}] Connection closed: {} -> {} (up: {} bytes, down: {} bytes, duration: {:?})",
            metadata.inbound_tag, metadata.source, metadata.destination, up, down, elapsed
        );

        Ok(())
    }
}

/// Relay data bidirectionally with Prometheus metrics
/// Returns (bytes_uploaded, bytes_downloaded)
async fn relay_with_metrics(
    inbound: Stream,
    outbound: Stream,
    outbound_tag: &str,
) -> Result<(u64, u64)> {
    let (mut in_read, mut in_write) = tokio::io::split(inbound);
    let (mut out_read, mut out_write) = tokio::io::split(outbound);

    let outbound_tag_up = outbound_tag.to_string();
    let outbound_tag_down = outbound_tag.to_string();

    let client_to_server = async move {
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
            
            // Record to prometheus metrics
            TRAFFIC_BYTES_UPLOADED.inc_by(n as u64);
            OUTBOUND_BYTES_UPLOADED.with_label_values(&[&outbound_tag_up]).inc_by(n as u64);
            
            trace!("Client -> Server: {} bytes (total: {})", n, total);
        }
        out_write.shutdown().await?;
        Ok::<_, std::io::Error>(total)
    };

    let server_to_client = async move {
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
            
            // Record to prometheus metrics
            TRAFFIC_BYTES_DOWNLOADED.inc_by(n as u64);
            OUTBOUND_BYTES_DOWNLOADED.with_label_values(&[&outbound_tag_down]).inc_by(n as u64);
            
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
