//! Prometheus-based metrics module
//!
//! Provides metrics collection using Prometheus client library.
//! All metrics are automatically exposed via /metrics endpoint.

use lazy_static::lazy_static;
use prometheus::{
    GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry,
};

lazy_static! {
    /// Global Prometheus registry
    pub static ref REGISTRY: Registry = Registry::new();

    // === Dispatcher Metrics ===
    
    /// Total connections handled by dispatcher
    pub static ref DISPATCHER_CONNECTIONS_TOTAL: IntCounter = IntCounter::new(
        "netium_dispatcher_connections_total",
        "Total number of connections handled by dispatcher"
    ).unwrap();
    
    /// Currently active connections
    pub static ref DISPATCHER_CONNECTIONS_ACTIVE: IntGauge = IntGauge::new(
        "netium_dispatcher_connections_active",
        "Number of currently active connections"
    ).unwrap();
    
    /// Failed connections
    pub static ref DISPATCHER_CONNECTIONS_FAILED: IntCounter = IntCounter::new(
        "netium_dispatcher_connections_failed",
        "Total number of failed connections"
    ).unwrap();

    // === Traffic Metrics ===
    
    /// Total bytes uploaded (global)
    pub static ref TRAFFIC_BYTES_UPLOADED: IntCounter = IntCounter::new(
        "netium_traffic_bytes_uploaded_total",
        "Total bytes uploaded"
    ).unwrap();
    
    /// Total bytes downloaded (global)
    pub static ref TRAFFIC_BYTES_DOWNLOADED: IntCounter = IntCounter::new(
        "netium_traffic_bytes_downloaded_total",
        "Total bytes downloaded"
    ).unwrap();

    // === Inbound Metrics ===
    
    /// Connections per inbound
    pub static ref INBOUND_CONNECTIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_inbound_connections_total", "Total connections per inbound"),
        &["tag"]
    ).unwrap();
    
    /// Active connections per inbound
    pub static ref INBOUND_CONNECTIONS_ACTIVE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("netium_inbound_connections_active", "Active connections per inbound"),
        &["tag"]
    ).unwrap();
    
    /// Bytes uploaded per inbound
    pub static ref INBOUND_BYTES_UPLOADED: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_inbound_bytes_uploaded_total", "Bytes uploaded per inbound"),
        &["tag"]
    ).unwrap();
    
    /// Bytes downloaded per inbound
    pub static ref INBOUND_BYTES_DOWNLOADED: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_inbound_bytes_downloaded_total", "Bytes downloaded per inbound"),
        &["tag"]
    ).unwrap();

    // === Outbound Metrics ===
    
    /// Connections per outbound
    pub static ref OUTBOUND_CONNECTIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_outbound_connections_total", "Total connections per outbound"),
        &["tag"]
    ).unwrap();
    
    /// Active connections per outbound
    pub static ref OUTBOUND_CONNECTIONS_ACTIVE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("netium_outbound_connections_active", "Active connections per outbound"),
        &["tag"]
    ).unwrap();
    
    /// Bytes uploaded per outbound
    pub static ref OUTBOUND_BYTES_UPLOADED: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_outbound_bytes_uploaded_total", "Bytes uploaded per outbound"),
        &["tag"]
    ).unwrap();
    
    /// Bytes downloaded per outbound
    pub static ref OUTBOUND_BYTES_DOWNLOADED: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_outbound_bytes_downloaded_total", "Bytes downloaded per outbound"),
        &["tag"]
    ).unwrap();

    // === Router Metrics ===
    
    /// Rule hits per rule
    pub static ref ROUTER_RULE_HITS: IntCounterVec = IntCounterVec::new(
        Opts::new("netium_router_rule_hits_total", "Number of times each routing rule was matched"),
        &["rule"]
    ).unwrap();
    
    /// Total routing decisions
    pub static ref ROUTER_DECISIONS_TOTAL: IntCounter = IntCounter::new(
        "netium_router_decisions_total",
        "Total number of routing decisions made"
    ).unwrap();

    /// Rule match duration histogram (in seconds)
    pub static ref ROUTER_RULE_MATCH_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "netium_router_rule_match_duration_seconds",
            "Time spent matching each routing rule"
        ).buckets(vec![0.000001, 0.000005, 0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]),
        &["rule"]
    ).unwrap();

    /// Maximum rule match duration (in seconds)
    pub static ref ROUTER_RULE_MATCH_MAX: GaugeVec = GaugeVec::new(
        Opts::new(
            "netium_router_rule_match_max_seconds",
            "Maximum time spent matching each routing rule"
        ),
        &["rule"]
    ).unwrap();

    // === Connection Duration ===
    
    /// Connection duration histogram
    pub static ref CONNECTION_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "netium_connection_duration_seconds",
            "Connection duration in seconds"
        ).buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0]),
        &["outbound"]
    ).unwrap();
}

/// Initialize and register all metrics with the global registry
pub fn init_metrics() {
    // Dispatcher metrics
    REGISTRY.register(Box::new(DISPATCHER_CONNECTIONS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(DISPATCHER_CONNECTIONS_ACTIVE.clone())).ok();
    REGISTRY.register(Box::new(DISPATCHER_CONNECTIONS_FAILED.clone())).ok();
    
    // Traffic metrics
    REGISTRY.register(Box::new(TRAFFIC_BYTES_UPLOADED.clone())).ok();
    REGISTRY.register(Box::new(TRAFFIC_BYTES_DOWNLOADED.clone())).ok();
    
    // Inbound metrics
    REGISTRY.register(Box::new(INBOUND_CONNECTIONS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(INBOUND_CONNECTIONS_ACTIVE.clone())).ok();
    REGISTRY.register(Box::new(INBOUND_BYTES_UPLOADED.clone())).ok();
    REGISTRY.register(Box::new(INBOUND_BYTES_DOWNLOADED.clone())).ok();
    
    // Outbound metrics
    REGISTRY.register(Box::new(OUTBOUND_CONNECTIONS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(OUTBOUND_CONNECTIONS_ACTIVE.clone())).ok();
    REGISTRY.register(Box::new(OUTBOUND_BYTES_UPLOADED.clone())).ok();
    REGISTRY.register(Box::new(OUTBOUND_BYTES_DOWNLOADED.clone())).ok();
    
    // Router metrics
    REGISTRY.register(Box::new(ROUTER_RULE_HITS.clone())).ok();
    REGISTRY.register(Box::new(ROUTER_DECISIONS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(ROUTER_RULE_MATCH_DURATION.clone())).ok();
    REGISTRY.register(Box::new(ROUTER_RULE_MATCH_MAX.clone())).ok();
    
    // Connection duration
    REGISTRY.register(Box::new(CONNECTION_DURATION_SECONDS.clone())).ok();
}

/// Helper struct for tracking a single connection's metrics
pub struct ConnectionMetrics {
    outbound_tag: String,
    start_time: std::time::Instant,
}

impl ConnectionMetrics {
    pub fn new(outbound_tag: &str) -> Self {
        Self {
            outbound_tag: outbound_tag.to_string(),
            start_time: std::time::Instant::now(),
        }
    }

    /// Record connection completion with duration
    pub fn record_completion(&self) {
        let duration = self.start_time.elapsed().as_secs_f64();
        CONNECTION_DURATION_SECONDS
            .with_label_values(&[&self.outbound_tag])
            .observe(duration);
    }
}

/// Format bytes to human readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    const TB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format bytes per second to human readable string
pub fn format_speed(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(500.0), "500 B/s");
        assert_eq!(format_speed(1024.0), "1.00 KB/s");
        assert_eq!(format_speed(1024.0 * 1024.0), "1.00 MB/s");
    }
}
