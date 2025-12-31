//! Prometheus metrics HTTP endpoint
//!
//! Provides /metrics endpoint for Prometheus scraping.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    http::header::CONTENT_TYPE,
    response::IntoResponse,
    routing::get,
    Router,
};
use prometheus::{Encoder, TextEncoder};
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::metrics::{
    init_metrics,
    DISPATCHER_CONNECTIONS_ACTIVE, DISPATCHER_CONNECTIONS_FAILED, DISPATCHER_CONNECTIONS_TOTAL,
    INBOUND_BYTES_DOWNLOADED, INBOUND_BYTES_UPLOADED, INBOUND_CONNECTIONS_ACTIVE,
    INBOUND_CONNECTIONS_TOTAL, OUTBOUND_BYTES_DOWNLOADED, OUTBOUND_BYTES_UPLOADED,
    OUTBOUND_CONNECTIONS_ACTIVE, OUTBOUND_CONNECTIONS_TOTAL, REGISTRY,
    TRAFFIC_BYTES_DOWNLOADED, TRAFFIC_BYTES_UPLOADED,
};

/// Global statistics collector
#[derive(Clone)]
pub struct StatsCollector {
    /// Inbound tags
    inbound_tags: Vec<String>,
    /// Outbound tags
    outbound_tags: Vec<String>,
}

/// Dispatcher-level statistics (wrapper for prometheus metrics)
#[derive(Default)]
pub struct DispatcherStats;

impl DispatcherStats {
    pub fn new() -> Self {
        Self
    }

    pub fn connection_start(&self) {
        DISPATCHER_CONNECTIONS_TOTAL.inc();
        DISPATCHER_CONNECTIONS_ACTIVE.inc();
    }

    pub fn connection_end(&self, uploaded: u64, downloaded: u64) {
        DISPATCHER_CONNECTIONS_ACTIVE.dec();
        TRAFFIC_BYTES_UPLOADED.inc_by(uploaded);
        TRAFFIC_BYTES_DOWNLOADED.inc_by(downloaded);
    }

    pub fn connection_failed(&self) {
        DISPATCHER_CONNECTIONS_ACTIVE.dec();
        DISPATCHER_CONNECTIONS_FAILED.inc();
    }
}

/// Per-inbound statistics (wrapper for prometheus metrics)
pub struct InboundStats {
    tag: String,
}

impl InboundStats {
    pub fn new(tag: &str) -> Self {
        // Pre-initialize the label to ensure it appears in metrics
        INBOUND_CONNECTIONS_TOTAL.with_label_values(&[tag]).inc_by(0);
        INBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).set(0);
        INBOUND_BYTES_UPLOADED.with_label_values(&[tag]).inc_by(0);
        INBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).inc_by(0);
        
        Self { tag: tag.to_string() }
    }

    pub fn connection_accepted(&self) {
        INBOUND_CONNECTIONS_TOTAL.with_label_values(&[&self.tag]).inc();
        INBOUND_CONNECTIONS_ACTIVE.with_label_values(&[&self.tag]).inc();
    }

    pub fn connection_closed(&self) {
        INBOUND_CONNECTIONS_ACTIVE.with_label_values(&[&self.tag]).dec();
    }

    #[allow(dead_code)]
    pub fn record_traffic(&self, uploaded: u64, downloaded: u64) {
        INBOUND_BYTES_UPLOADED.with_label_values(&[&self.tag]).inc_by(uploaded);
        INBOUND_BYTES_DOWNLOADED.with_label_values(&[&self.tag]).inc_by(downloaded);
    }
}

/// Per-outbound statistics (wrapper for prometheus metrics)
pub struct OutboundStats {
    tag: String,
}

impl OutboundStats {
    pub fn new(tag: &str) -> Self {
        // Pre-initialize the label to ensure it appears in metrics
        OUTBOUND_CONNECTIONS_TOTAL.with_label_values(&[tag]).inc_by(0);
        OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).set(0);
        OUTBOUND_BYTES_UPLOADED.with_label_values(&[tag]).inc_by(0);
        OUTBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).inc_by(0);
        
        Self { tag: tag.to_string() }
    }

    pub fn connection_start(&self) {
        OUTBOUND_CONNECTIONS_TOTAL.with_label_values(&[&self.tag]).inc();
        OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[&self.tag]).inc();
    }

    pub fn connection_end(&self, uploaded: u64, downloaded: u64) {
        OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[&self.tag]).dec();
        OUTBOUND_BYTES_UPLOADED.with_label_values(&[&self.tag]).inc_by(uploaded);
        OUTBOUND_BYTES_DOWNLOADED.with_label_values(&[&self.tag]).inc_by(downloaded);
    }

    pub fn dec_active(&self) {
        OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[&self.tag]).dec();
    }
}

impl StatsCollector {
    pub fn new(
        _router: Arc<dyn crate::router::Router>,
        inbound_tags: Vec<String>,
        outbound_tags: Vec<String>,
    ) -> Self {
        // Initialize prometheus metrics
        init_metrics();

        // Pre-initialize all inbound/outbound labels
        for tag in &inbound_tags {
            InboundStats::new(tag);
        }
        for tag in &outbound_tags {
            OutboundStats::new(tag);
        }

        Self {
            inbound_tags,
            outbound_tags,
        }
    }

    pub fn dispatcher_stats(&self) -> Arc<DispatcherStats> {
        Arc::new(DispatcherStats::new())
    }

    pub fn get_inbound_stats(&self, tag: &str) -> Option<Arc<InboundStats>> {
        if self.inbound_tags.contains(&tag.to_string()) {
            Some(Arc::new(InboundStats::new(tag)))
        } else {
            None
        }
    }

    pub fn get_outbound_stats(&self, tag: &str) -> Option<Arc<OutboundStats>> {
        if self.outbound_tags.contains(&tag.to_string()) {
            Some(Arc::new(OutboundStats::new(tag)))
        } else {
            None
        }
    }
}

/// Prometheus metrics endpoint
async fn get_metrics() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        buffer,
    )
}

/// Build the API router (metrics only)
pub fn build_api_router() -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
}

/// Start the metrics server
pub async fn start_api_server(
    addr: SocketAddr,
    _collector: StatsCollector,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let app = build_api_router();

    info!("Prometheus metrics server listening on http://{}/metrics", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind metrics server to {}: {}", addr, e);
            return;
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            info!("Metrics server shutting down");
        })
        .await
        .unwrap_or_else(|e| {
            warn!("Metrics server error: {}", e);
        });
}
