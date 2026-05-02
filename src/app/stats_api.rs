//! Prometheus metrics HTTP endpoint
//!
//! Provides /metrics endpoint for Prometheus scraping.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use prometheus::{Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::route::{
    DynamicRuleInput, DynamicRuleManager, DynamicRuleUpdate,
    static_route::StaticRouter,
};
use crate::route::log::{FallbackDestinationLog, SlowQueryLog};
use crate::route::log::{FallbackDestination, SlowQuery};

use super::metrics::{
    init_metrics, DISPATCHER_CONNECTIONS_ACTIVE, DISPATCHER_CONNECTIONS_FAILED,
    DISPATCHER_CONNECTIONS_TOTAL, INBOUND_BYTES_DOWNLOADED, INBOUND_BYTES_UPLOADED,
    INBOUND_CONNECTIONS_ACTIVE, INBOUND_CONNECTIONS_TOTAL, OUTBOUND_BYTES_DOWNLOADED,
    OUTBOUND_BYTES_UPLOADED, OUTBOUND_CONNECTIONS_ACTIVE, OUTBOUND_CONNECTIONS_TOTAL, REGISTRY,
};

/// Global statistics collector
#[derive(Clone)]
pub struct StatsCollector {
    static_router: Arc<StaticRouter>,
    slow_query_log: Arc<SlowQueryLog>,
    fallback_log: Arc<FallbackDestinationLog>,
    dynamic_rules: Option<Arc<DynamicRuleManager>>,
    inbound_tags: Vec<String>,
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

    pub fn connection_end(&self, _uploaded: u64, _downloaded: u64) {
        DISPATCHER_CONNECTIONS_ACTIVE.dec();
        // Note: traffic bytes are already counted in relay_with_metrics() loop.
        // Do NOT double-count here.
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
        INBOUND_CONNECTIONS_TOTAL
            .with_label_values(&[tag])
            .inc_by(0);
        INBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).set(0);
        INBOUND_BYTES_UPLOADED.with_label_values(&[tag]).inc_by(0);
        INBOUND_BYTES_DOWNLOADED.with_label_values(&[tag]).inc_by(0);

        Self {
            tag: tag.to_string(),
        }
    }

    pub fn connection_accepted(&self) {
        INBOUND_CONNECTIONS_TOTAL
            .with_label_values(&[&self.tag])
            .inc();
        INBOUND_CONNECTIONS_ACTIVE
            .with_label_values(&[&self.tag])
            .inc();
    }

    pub fn connection_closed(&self) {
        INBOUND_CONNECTIONS_ACTIVE
            .with_label_values(&[&self.tag])
            .dec();
    }

    #[allow(dead_code)]
    pub fn record_traffic(&self, uploaded: u64, downloaded: u64) {
        INBOUND_BYTES_UPLOADED
            .with_label_values(&[&self.tag])
            .inc_by(uploaded);
        INBOUND_BYTES_DOWNLOADED
            .with_label_values(&[&self.tag])
            .inc_by(downloaded);
    }
}

/// Per-outbound statistics (wrapper for prometheus metrics)
pub struct OutboundStats {
    tag: String,
}

impl OutboundStats {
    pub fn new(tag: &str) -> Self {
        // Pre-initialize the label to ensure it appears in metrics
        OUTBOUND_CONNECTIONS_TOTAL
            .with_label_values(&[tag])
            .inc_by(0);
        OUTBOUND_CONNECTIONS_ACTIVE.with_label_values(&[tag]).set(0);
        OUTBOUND_BYTES_UPLOADED.with_label_values(&[tag]).inc_by(0);
        OUTBOUND_BYTES_DOWNLOADED
            .with_label_values(&[tag])
            .inc_by(0);

        Self {
            tag: tag.to_string(),
        }
    }

    pub fn connection_start(&self) {
        OUTBOUND_CONNECTIONS_TOTAL
            .with_label_values(&[&self.tag])
            .inc();
        OUTBOUND_CONNECTIONS_ACTIVE
            .with_label_values(&[&self.tag])
            .inc();
    }

    pub fn connection_end(&self, uploaded: u64, downloaded: u64) {
        OUTBOUND_CONNECTIONS_ACTIVE
            .with_label_values(&[&self.tag])
            .dec();
        OUTBOUND_BYTES_UPLOADED
            .with_label_values(&[&self.tag])
            .inc_by(uploaded);
        OUTBOUND_BYTES_DOWNLOADED
            .with_label_values(&[&self.tag])
            .inc_by(downloaded);
    }

    pub fn dec_active(&self) {
        OUTBOUND_CONNECTIONS_ACTIVE
            .with_label_values(&[&self.tag])
            .dec();
    }
}

impl StatsCollector {
    pub fn new(
        static_router: Arc<StaticRouter>,
        slow_query_log: Arc<SlowQueryLog>,
        fallback_log: Arc<FallbackDestinationLog>,
        dynamic_rules: Option<Arc<DynamicRuleManager>>,
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
            static_router,
            slow_query_log,
            fallback_log,
            dynamic_rules,
            inbound_tags,
            outbound_tags,
        }
    }

    pub fn dispatcher_stats(&self) -> Arc<DispatcherStats> {
        Arc::new(DispatcherStats::new())
    }

    /// Export router rule stats to Prometheus.
    /// Called on each /metrics scrape, NOT on each routing decision.
    pub fn export_router_stats(&self) {
        self.static_router.export_to_prometheus();
    }

    /// Get slow query log entries.
    pub fn get_slow_queries(&self) -> Vec<SlowQuery> {
        self.slow_query_log.snapshot()
    }

    /// Clear the slow query log.
    pub fn clear_slow_queries(&self) {
        self.slow_query_log.clear();
    }

    /// Get deduplicated fallback destinations.
    pub fn get_fallback_destinations(&self) -> Vec<FallbackDestination> {
        self.fallback_log.snapshot()
    }

    /// Remove a single fallback destination entry.
    pub fn remove_fallback_destination(&self, destination: &str) {
        self.fallback_log.remove(destination);
    }

    /// Clear fallback destinations.
    pub fn clear_fallback_destinations(&self) {
        self.fallback_log.clear();
    }

    pub fn dynamic_rules(&self) -> Option<Arc<DynamicRuleManager>> {
        self.dynamic_rules.clone()
    }

    pub fn outbound_tags(&self) -> Vec<String> {
        self.outbound_tags.clone()
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

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    message: String,
    data: T,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        message: "OK".to_string(),
        data,
    })
}

fn api_error(message: impl Into<String>) -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            success: false,
            message: message.into(),
            data: json!(null),
        }),
    )
}

fn dynamic_manager(
    collector: &StatsCollector,
) -> std::result::Result<Arc<DynamicRuleManager>, (StatusCode, Json<ApiResponse<serde_json::Value>>)>
{
    collector
        .dynamic_rules()
        .ok_or_else(|| api_error("dynamic routing is not enabled"))
}

#[derive(Debug, Deserialize)]
struct RemoveRuleRequest {
    id: String,
}

#[derive(Debug, Deserialize)]
struct EnableRuleRequest {
    id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct FromObservationRequest {
    destination: String,
    outbound: String,
}

/// Prometheus metrics endpoint
async fn get_metrics(State(collector): State<StatsCollector>) -> impl IntoResponse {
    // Export router stats to Prometheus gauges before scraping
    collector.export_router_stats();

    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        buffer,
    )
}

/// Slow query log endpoint — returns recent slow routing decisions as JSON.
async fn get_slow_queries(State(collector): State<StatsCollector>) -> impl IntoResponse {
    let queries = collector.get_slow_queries();
    axum::Json(queries)
}

/// Clear slow query log.
async fn delete_slow_queries(State(collector): State<StatsCollector>) -> impl IntoResponse {
    collector.clear_slow_queries();
    "OK"
}

async fn get_observations(State(collector): State<StatsCollector>) -> impl IntoResponse {
    ok(collector.get_fallback_destinations())
}

async fn clear_observations(State(collector): State<StatsCollector>) -> impl IntoResponse {
    collector.clear_fallback_destinations();
    ok(json!({}))
}

async fn get_outbounds(State(collector): State<StatsCollector>) -> impl IntoResponse {
    ok(collector.outbound_tags())
}

async fn get_rules(State(collector): State<StatsCollector>) -> impl IntoResponse {
    match dynamic_manager(&collector) {
        Ok(manager) => ok(manager.list()).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn add_rule(
    State(collector): State<StatsCollector>,
    Json(input): Json<DynamicRuleInput>,
) -> impl IntoResponse {
    match dynamic_manager(&collector)
        .and_then(|manager| manager.add(input).map_err(|e| api_error(e.to_string())))
    {
        Ok(route) => ok(route).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn edit_rule(
    State(collector): State<StatsCollector>,
    Json(input): Json<DynamicRuleUpdate>,
) -> impl IntoResponse {
    match dynamic_manager(&collector)
        .and_then(|manager| manager.update(input).map_err(|e| api_error(e.to_string())))
    {
        Ok(route) => ok(route).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn remove_rule(
    State(collector): State<StatsCollector>,
    Json(input): Json<RemoveRuleRequest>,
) -> impl IntoResponse {
    match dynamic_manager(&collector).and_then(|manager| {
        manager
            .remove(&input.id)
            .map_err(|e| api_error(e.to_string()))
    }) {
        Ok(()) => ok(json!({})).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn enable_rule(
    State(collector): State<StatsCollector>,
    Json(input): Json<EnableRuleRequest>,
) -> impl IntoResponse {
    match dynamic_manager(&collector).and_then(|manager| {
        manager
            .set_enabled(&input.id, input.enabled)
            .map_err(|e| api_error(e.to_string()))
    }) {
        Ok(route) => ok(route).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn reload_rules(State(collector): State<StatsCollector>) -> impl IntoResponse {
    match dynamic_manager(&collector)
        .and_then(|manager| manager.reload().map_err(|e| api_error(e.to_string())))
    {
        Ok(rules) => ok(rules).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn rule_from_observation(
    State(collector): State<StatsCollector>,
    Json(input): Json<FromObservationRequest>,
) -> impl IntoResponse {
    let (pattern, port) = split_destination(&input.destination);
    let match_type = if pattern.parse::<std::net::IpAddr>().is_ok() {
        crate::route::DynamicRuleMatchType::Ip
    } else {
        crate::route::DynamicRuleMatchType::Domain
    };

    let route = DynamicRuleInput {
        enabled: Some(true),
        match_type,
        pattern,
        port,
        outbound: input.outbound,
        priority: Some(100),
        comment: Some("from observation".to_string()),
    };

    match dynamic_manager(&collector)
        .and_then(|manager| manager.add(route).map_err(|e| api_error(e.to_string())))
    {
        Ok(route) => {
            collector.remove_fallback_destination(&input.destination);
            ok(route).into_response()
        }
        Err(err) => err.into_response(),
    }
}

async fn serve_ui() -> impl IntoResponse {
    Html(include_str!("../ui/index.html"))
}

/// Build the API router (metrics only)
pub fn build_api_router(collector: StatsCollector) -> Router {
    Router::new()
        .route("/ui", get(serve_ui))
        .route("/metrics", get(get_metrics))
        .route("/api/outbounds", get(get_outbounds))
        .route("/api/rules", get(get_rules))
        .route("/api/rules/add", post(add_rule))
        .route("/api/rules/edit", post(edit_rule))
        .route("/api/rules/remove", post(remove_rule))
        .route("/api/rules/enable", post(enable_rule))
        .route("/api/rules/reload", post(reload_rules))
        .route("/api/rules/from-observation", post(rule_from_observation))
        .route("/api/observations", get(get_observations))
        .route("/api/observations/clear", post(clear_observations))
        .route(
            "/slow-queries",
            get(get_slow_queries).delete(delete_slow_queries),
        )
        .with_state(collector)
}

fn split_destination(destination: &str) -> (String, Option<u16>) {
    if let Some((host, port)) = destination.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.trim_matches(['[', ']']).to_string(), Some(port));
        }
    }
    (destination.to_string(), None)
}

/// Start the metrics server
pub async fn start_api_server(
    addr: SocketAddr,
    collector: StatsCollector,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let app = build_api_router(collector);

    info!(
        "Prometheus metrics server listening on http://{}/metrics",
        addr
    );

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
