//! HTTP API for runtime statistics
//!
//! Provides REST endpoints to query statistics for each layer:
//! - /metrics - Prometheus metrics endpoint
//! - /api/stats - JSON overview of all statistics
//! - /api/stats/dispatcher - Dispatcher stats
//! - /api/stats/router - Router stats
//! - /api/stats/inbounds - Per-inbound stats
//! - /api/stats/outbounds - Per-outbound stats

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::header::CONTENT_TYPE,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use prometheus::{Encoder, TextEncoder};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::router::RuleRouter;

use super::metrics::{
    format_bytes, init_metrics,
    DISPATCHER_CONNECTIONS_ACTIVE, DISPATCHER_CONNECTIONS_FAILED, DISPATCHER_CONNECTIONS_TOTAL,
    INBOUND_BYTES_DOWNLOADED, INBOUND_BYTES_UPLOADED, INBOUND_CONNECTIONS_ACTIVE,
    INBOUND_CONNECTIONS_TOTAL, OUTBOUND_BYTES_DOWNLOADED, OUTBOUND_BYTES_UPLOADED,
    OUTBOUND_CONNECTIONS_ACTIVE, OUTBOUND_CONNECTIONS_TOTAL, REGISTRY,
    TRAFFIC_BYTES_DOWNLOADED, TRAFFIC_BYTES_UPLOADED,
};

/// Global statistics collector
#[derive(Clone)]
pub struct StatsCollector {
    /// Router reference for routing stats
    router: Arc<dyn crate::router::Router>,
    /// Inbound tags
    inbound_tags: Vec<String>,
    /// Outbound tags
    outbound_tags: Vec<String>,
    /// Server start time
    start_time: std::time::Instant,
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
        router: Arc<dyn crate::router::Router>,
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
            router,
            inbound_tags,
            outbound_tags,
            start_time: std::time::Instant::now(),
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

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

// === API Response Types ===

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct OverviewStats {
    uptime_secs: u64,
    dispatcher: DispatcherStatsResponse,
    traffic: TrafficStatsResponse,
    router: RouterStatsResponse,
    inbounds: Vec<InboundStatsResponse>,
    outbounds: Vec<OutboundStatsResponse>,
}

#[derive(Serialize)]
struct DispatcherStatsResponse {
    total_connections: u64,
    active_connections: i64,
    failed_connections: u64,
}

#[derive(Serialize)]
struct TrafficStatsResponse {
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    uploaded_human: String,
    downloaded_human: String,
}

#[derive(Serialize)]
struct RouterStatsResponse {
    total_hits: u64,
    rules: Vec<RuleStatResponse>,
}

#[derive(Serialize)]
struct RuleStatResponse {
    rule: String,
    hits: u64,
    percent: f64,
}

#[derive(Serialize)]
struct InboundStatsResponse {
    tag: String,
    connections: u64,
    active: i64,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    uploaded_human: String,
    downloaded_human: String,
}

#[derive(Serialize)]
struct OutboundStatsResponse {
    tag: String,
    connections: u64,
    active: i64,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    uploaded_human: String,
    downloaded_human: String,
}

// === API Handlers ===

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

async fn get_overview(State(collector): State<StatsCollector>) -> impl IntoResponse {
    let uptime = collector.uptime_secs();

    // Dispatcher stats from prometheus
    let dispatcher = DispatcherStatsResponse {
        total_connections: DISPATCHER_CONNECTIONS_TOTAL.get(),
        active_connections: DISPATCHER_CONNECTIONS_ACTIVE.get(),
        failed_connections: DISPATCHER_CONNECTIONS_FAILED.get(),
    };

    // Traffic stats
    let uploaded = TRAFFIC_BYTES_UPLOADED.get();
    let downloaded = TRAFFIC_BYTES_DOWNLOADED.get();
    let traffic = TrafficStatsResponse {
        bytes_uploaded: uploaded,
        bytes_downloaded: downloaded,
        uploaded_human: format_bytes(uploaded),
        downloaded_human: format_bytes(downloaded),
    };

    // Router stats
    let router_stats = get_router_stats(&collector.router);

    // Inbound stats
    let inbounds: Vec<InboundStatsResponse> = collector
        .inbound_tags
        .iter()
        .map(|tag| {
            let uploaded = INBOUND_BYTES_UPLOADED.with_label_values(&[tag]).get();
            let downloaded = INBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).get();
            InboundStatsResponse {
                tag: tag.clone(),
                connections: INBOUND_CONNECTIONS_TOTAL.with_label_values(&[tag]).get(),
                active: INBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).get(),
                bytes_uploaded: uploaded,
                bytes_downloaded: downloaded,
                uploaded_human: format_bytes(uploaded),
                downloaded_human: format_bytes(downloaded),
            }
        })
        .collect();

    // Outbound stats
    let outbounds: Vec<OutboundStatsResponse> = collector
        .outbound_tags
        .iter()
        .map(|tag| {
            let uploaded = OUTBOUND_BYTES_UPLOADED.with_label_values(&[tag]).get();
            let downloaded = OUTBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).get();
            OutboundStatsResponse {
                tag: tag.clone(),
                connections: OUTBOUND_CONNECTIONS_TOTAL.with_label_values(&[tag]).get(),
                active: OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).get(),
                bytes_uploaded: uploaded,
                bytes_downloaded: downloaded,
                uploaded_human: format_bytes(uploaded),
                downloaded_human: format_bytes(downloaded),
            }
        })
        .collect();

    let overview = OverviewStats {
        uptime_secs: uptime,
        dispatcher,
        traffic,
        router: router_stats,
        inbounds,
        outbounds,
    };

    Json(ApiResponse {
        success: true,
        data: overview,
    })
}

async fn get_dispatcher_stats_handler() -> impl IntoResponse {
    let stats = DispatcherStatsResponse {
        total_connections: DISPATCHER_CONNECTIONS_TOTAL.get(),
        active_connections: DISPATCHER_CONNECTIONS_ACTIVE.get(),
        failed_connections: DISPATCHER_CONNECTIONS_FAILED.get(),
    };

    Json(ApiResponse {
        success: true,
        data: stats,
    })
}

async fn get_router_stats_handler(State(collector): State<StatsCollector>) -> impl IntoResponse {
    let stats = get_router_stats(&collector.router);
    Json(ApiResponse {
        success: true,
        data: stats,
    })
}

async fn get_inbound_stats_handler(State(collector): State<StatsCollector>) -> impl IntoResponse {
    let inbounds: Vec<InboundStatsResponse> = collector
        .inbound_tags
        .iter()
        .map(|tag| {
            let uploaded = INBOUND_BYTES_UPLOADED.with_label_values(&[tag]).get();
            let downloaded = INBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).get();
            InboundStatsResponse {
                tag: tag.clone(),
                connections: INBOUND_CONNECTIONS_TOTAL.with_label_values(&[tag]).get(),
                active: INBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).get(),
                bytes_uploaded: uploaded,
                bytes_downloaded: downloaded,
                uploaded_human: format_bytes(uploaded),
                downloaded_human: format_bytes(downloaded),
            }
        })
        .collect();

    Json(ApiResponse {
        success: true,
        data: inbounds,
    })
}

async fn get_outbound_stats_handler(State(collector): State<StatsCollector>) -> impl IntoResponse {
    let outbounds: Vec<OutboundStatsResponse> = collector
        .outbound_tags
        .iter()
        .map(|tag| {
            let uploaded = OUTBOUND_BYTES_UPLOADED.with_label_values(&[tag]).get();
            let downloaded = OUTBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).get();
            OutboundStatsResponse {
                tag: tag.clone(),
                connections: OUTBOUND_CONNECTIONS_TOTAL.with_label_values(&[tag]).get(),
                active: OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).get(),
                bytes_uploaded: uploaded,
                bytes_downloaded: downloaded,
                uploaded_human: format_bytes(uploaded),
                downloaded_human: format_bytes(downloaded),
            }
        })
        .collect();

    Json(ApiResponse {
        success: true,
        data: outbounds,
    })
}

fn get_router_stats(router: &Arc<dyn crate::router::Router>) -> RouterStatsResponse {
    if let Some(rule_router) = router.as_any().downcast_ref::<RuleRouter>() {
        let stats = rule_router.get_stats();
        let total = rule_router.total_hits();
        RouterStatsResponse {
            total_hits: total,
            rules: stats
                .into_iter()
                .map(|s| RuleStatResponse {
                    rule: s.rule_desc,
                    hits: s.hits,
                    percent: s.percent,
                })
                .collect(),
        }
    } else {
        RouterStatsResponse {
            total_hits: 0,
            rules: vec![],
        }
    }
}

/// Build the API router
pub fn build_api_router(collector: StatsCollector) -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/api/stats", get(get_overview))
        .route("/api/stats/dispatcher", get(get_dispatcher_stats_handler))
        .route("/api/stats/router", get(get_router_stats_handler))
        .route("/api/stats/inbounds", get(get_inbound_stats_handler))
        .route("/api/stats/outbounds", get(get_outbound_stats_handler))
        .with_state(collector)
}

/// Start the stats API server
pub async fn start_api_server(
    addr: SocketAddr,
    collector: StatsCollector,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let app = build_api_router(collector);

    info!("Stats API server listening on http://{}", addr);
    info!("Prometheus metrics available at http://{}/metrics", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind stats API server to {}: {}", addr, e);
            return;
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            info!("Stats API server shutting down");
        })
        .await
        .unwrap_or_else(|e| {
            warn!("Stats API server error: {}", e);
        });
}
