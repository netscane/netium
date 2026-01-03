//! Dispatcher - Core Execution Flow
//!
//! The dispatcher is the heart of the proxy system.
//! It handles the flow: inbound → router → outbound
//!
//! Architecture:
//! ```text
//! InboundPipeline.process() → (Metadata, Stream)
//!                                  ↓
//!                         Router.select(Metadata)
//!                                  ↓
//!                         Outbound.connect()
//!                                  ↓
//!                         Bidirectional Relay
//! ```
//!
//! Each connection is handled in a separate tokio task.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::common::{Metadata, Result, Stream};
use crate::error::Error;
use crate::router::Router;

use super::metrics::{
    ConnectionMetrics, OUTBOUND_BYTES_DOWNLOADED, OUTBOUND_BYTES_UPLOADED,
    TRAFFIC_BYTES_DOWNLOADED, TRAFFIC_BYTES_UPLOADED,
};
use super::runtime::Outbound;
use super::stats_api::{DispatcherStats, OutboundStats};

// ============================================================================
// Constants
// ============================================================================

/// Relay buffer size (32KB)
const RELAY_BUFFER_SIZE: usize = 32 * 1024;

// ============================================================================
// Dispatcher
// ============================================================================

/// Dispatcher handles the core proxy flow
///
/// Responsibilities:
/// - Execute inbound pipeline
/// - Call Router to select outbound
/// - Build and execute outbound pipeline
/// - Perform bidirectional stream relay
///
/// The Dispatcher is protocol-agnostic - it only works with Stream and Metadata.
pub struct Dispatcher {
    router: Arc<dyn Router>,
    outbounds: HashMap<String, Arc<Outbound>>,
    stats: Option<Arc<DispatcherStats>>,
    outbound_stats: Option<Arc<HashMap<String, Arc<OutboundStats>>>>,
}

impl Dispatcher {
    pub fn new(router: Arc<dyn Router>, outbounds: HashMap<String, Arc<Outbound>>) -> Self {
        Self {
            router,
            outbounds,
            stats: None,
            outbound_stats: None,
        }
    }

    pub fn with_stats(mut self, stats: Arc<DispatcherStats>) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_outbound_stats(
        mut self,
        outbound_stats: Arc<HashMap<String, Arc<OutboundStats>>>,
    ) -> Self {
        self.outbound_stats = Some(outbound_stats);
        self
    }

    /// Dispatch a connection through router to appropriate outbound
    ///
    /// This is the main entry point for connection handling.
    /// Flow: Router.select() → Outbound.connect() → Relay
    pub async fn dispatch(&self, metadata: Metadata, inbound_stream: Stream) -> Result<()> {
        let start = Instant::now();

        if let Some(stats) = &self.stats {
            stats.connection_start();
        }

        // Step 1: Router selects outbound (pure function, no IO)
        let outbound_tag = self.router.select(&metadata);
        let outbound = self
            .outbounds
            .get(outbound_tag)
            .ok_or_else(|| Error::Config(format!("Unknown outbound: {}", outbound_tag)))?;

        let outbound_stat = self
            .outbound_stats
            .as_ref()
            .and_then(|m| m.get(outbound_tag).cloned());

        if let Some(stat) = &outbound_stat {
            stat.connection_start();
        }

        // Step 2: Connect and relay (Transport handles blackhole/reject)
        self.handle_relay(
            &metadata,
            inbound_stream,
            outbound,
            outbound_tag,
            outbound_stat,
            start,
        )
        .await
    }

    /// Handle relay: connect to outbound and relay data
    async fn handle_relay(
        &self,
        metadata: &Metadata,
        inbound_stream: Stream,
        outbound: &Arc<Outbound>,
        outbound_tag: &str,
        outbound_stat: Option<Arc<OutboundStats>>,
        start: Instant,
    ) -> Result<()> {
        debug!(
            "[{}] Routing {} -> {} via {}",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        let conn_metrics = ConnectionMetrics::new(outbound_tag);

        // Transport.connect() → Pipeline.process()
        let outbound_stream = match outbound.connect(metadata).await {
            Ok(stream) => stream,
            Err(e) => {
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

        // Bidirectional relay
        let (up, down) = relay_with_metrics(inbound_stream, outbound_stream, outbound_tag).await?;

        conn_metrics.record_completion();
        self.record_connection_end(up, down, &outbound_stat);

        info!(
            "[{}] Closed: {} -> {} (↑{} ↓{} {:?})",
            metadata.inbound_tag,
            metadata.source,
            metadata.destination,
            format_bytes(up),
            format_bytes(down),
            start.elapsed()
        );

        Ok(())
    }

    fn record_connection_end(
        &self,
        up: u64,
        down: u64,
        outbound_stat: &Option<Arc<OutboundStats>>,
    ) {
        if let Some(stats) = &self.stats {
            stats.connection_end(up, down);
        }
        if let Some(stat) = outbound_stat {
            stat.connection_end(up, down);
        }
    }
}

// ============================================================================
// Relay Implementation
// ============================================================================

/// Relay data bidirectionally with Prometheus metrics
async fn relay_with_metrics(
    inbound: Stream,
    outbound: Stream,
    outbound_tag: &str,
) -> Result<(u64, u64)> {
    let (mut in_read, mut in_write) = tokio::io::split(inbound);
    let (mut out_read, mut out_write) = tokio::io::split(outbound);

    let tag_up = outbound_tag.to_string();
    let tag_down = outbound_tag.to_string();

    // Upload: client → server
    let upload = async move {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        let mut total: u64 = 0;

        loop {
            let n = match in_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            if out_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
            if out_write.flush().await.is_err() {
                break;
            }

            total += n as u64;
            TRAFFIC_BYTES_UPLOADED.inc_by(n as u64);
            OUTBOUND_BYTES_UPLOADED
                .with_label_values(&[&tag_up])
                .inc_by(n as u64);
        }

        let _ = out_write.shutdown().await;
        total
    };

    // Download: server → client
    let download = async move {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        let mut total: u64 = 0;

        loop {
            let n = match out_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            if in_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
            if in_write.flush().await.is_err() {
                break;
            }

            total += n as u64;
            TRAFFIC_BYTES_DOWNLOADED.inc_by(n as u64);
            OUTBOUND_BYTES_DOWNLOADED
                .with_label_values(&[&tag_down])
                .inc_by(n as u64);
        }

        let _ = in_write.shutdown().await;
        total
    };

    let (up, down) = tokio::join!(upload, download);
    Ok((up, down))
}

// ============================================================================
// Utilities
// ============================================================================

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}
