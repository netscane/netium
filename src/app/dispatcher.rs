//! Dispatcher - Core Execution Flow
//!
//! The dispatcher is the heart of the proxy system.
//! It handles the flow: inbound → router → outbound
//!
//! Each connection is handled in a separate tokio task.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::common::{Metadata, Result, Stream};
use crate::error::Error;
use crate::router::Router;

use super::metrics::{
    ConnectionMetrics, OUTBOUND_BYTES_DOWNLOADED, OUTBOUND_BYTES_UPLOADED,
    TRAFFIC_BYTES_DOWNLOADED, TRAFFIC_BYTES_UPLOADED,
};
use super::stack::OutboundStack;
use super::stats_api::{DispatcherStats, OutboundStats};

/// Blackhole timeout duration (5 minutes)
const BLACKHOLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Dispatcher handles the core proxy flow
pub struct Dispatcher {
    router: Arc<dyn Router>,
    outbounds: HashMap<String, Arc<OutboundStack>>,
    stats: Option<Arc<DispatcherStats>>,
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
    pub async fn dispatch(&self, metadata: Metadata, inbound_stream: Stream) -> Result<()> {
        let start = Instant::now();

        if let Some(stats) = &self.stats {
            stats.connection_start();
        }

        // Select and get outbound
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

        // Handle special protocols - no outbound connection needed
        match outbound.protocol.name() {
            "blackhole" => {
                return self
                    .handle_blackhole(&metadata, inbound_stream, outbound_tag, outbound_stat)
                    .await;
            }
            "reject" => {
                return self
                    .handle_reject(&metadata, outbound_tag, outbound_stat)
                    .await;
            }
            _ => {}
        }

        // Normal flow: connect and relay
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

    /// Handle reject: immediately close connection
    async fn handle_reject(
        &self,
        metadata: &Metadata,
        outbound_tag: &str,
        outbound_stat: Option<Arc<OutboundStats>>,
    ) -> Result<()> {
        info!(
            "[{}] {} -> {} rejected by [{}]",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        // Connection is dropped immediately (inbound_stream not passed here)
        self.record_connection_end(0, 0, &outbound_stat);
        Ok(())
    }

    /// Handle blackhole: keep connection open but never respond
    async fn handle_blackhole(
        &self,
        metadata: &Metadata,
        mut stream: Stream,
        outbound_tag: &str,
        outbound_stat: Option<Arc<OutboundStats>>,
    ) -> Result<()> {
        info!(
            "[{}] {} -> {} entering blackhole [{}]",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        // Read until client disconnects or timeout
        let mut buf = [0u8; 1024];
        let result = tokio::time::timeout(BLACKHOLE_TIMEOUT, async {
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue, // Silently discard
                }
            }
        })
        .await;

        debug!(
            "[{}] {} -> {} blackhole ended ({})",
            metadata.inbound_tag,
            metadata.source,
            metadata.destination,
            if result.is_ok() { "client disconnected" } else { "timeout" }
        );

        self.record_connection_end(0, 0, &outbound_stat);
        Ok(())
    }

    /// Handle normal relay: connect to outbound and relay data
    async fn handle_relay(
        &self,
        metadata: &Metadata,
        inbound_stream: Stream,
        outbound: &Arc<OutboundStack>,
        outbound_tag: &str,
        outbound_stat: Option<Arc<OutboundStats>>,
        start: Instant,
    ) -> Result<()> {
        debug!(
            "[{}] Routing {} -> {} via {}",
            metadata.inbound_tag, metadata.source, metadata.destination, outbound_tag
        );

        let conn_metrics = ConnectionMetrics::new(outbound_tag);

        // Connect to target
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

        // Relay data
        let (up, down) = relay_with_metrics(inbound_stream, outbound_stream, outbound_tag).await?;

        conn_metrics.record_completion();
        self.record_connection_end(up, down, &outbound_stat);

        info!(
            "[{}] Connection closed: {} -> {} (up: {} bytes, down: {} bytes, duration: {:?})",
            metadata.inbound_tag,
            metadata.source,
            metadata.destination,
            up,
            down,
            start.elapsed()
        );

        Ok(())
    }

    fn record_connection_end(&self, up: u64, down: u64, outbound_stat: &Option<Arc<OutboundStats>>) {
        if let Some(stats) = &self.stats {
            stats.connection_end(up, down);
        }
        if let Some(stat) = outbound_stat {
            stat.connection_end(up, down);
        }
    }
}

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

    let client_to_server = async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = in_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            out_write.write_all(&buf[..n]).await?;
            out_write.flush().await?;
            total += n as u64;
            TRAFFIC_BYTES_UPLOADED.inc_by(n as u64);
            OUTBOUND_BYTES_UPLOADED
                .with_label_values(&[&tag_up])
                .inc_by(n as u64);
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
                break;
            }
            in_write.write_all(&buf[..n]).await?;
            in_write.flush().await?;
            total += n as u64;
            TRAFFIC_BYTES_DOWNLOADED.inc_by(n as u64);
            OUTBOUND_BYTES_DOWNLOADED
                .with_label_values(&[&tag_down])
                .inc_by(n as u64);
        }
        in_write.shutdown().await?;
        Ok::<_, std::io::Error>(total)
    };

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
