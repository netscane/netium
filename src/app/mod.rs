//! Application Layer
//!
//! This module contains:
//! - Dispatcher: core execution flow (inbound → router → outbound)
//! - Runtime: configuration-driven pipeline construction
//! - Pipeline: stream transformation chain (StreamLayer* → Protocol)
//! - StatsApi: HTTP API for runtime statistics with Prometheus metrics

mod dispatcher;
pub mod metrics;
pub mod pipeline;
pub mod runtime;
pub mod stats_api;

pub use dispatcher::Dispatcher;
pub use pipeline::{
    InboundPipeline, InboundPipelineBuilder,
    OutboundPipeline, OutboundPipelineBuilder,
};
pub use runtime::{
    Runtime, RuntimeConfig, 
    InboundConfig, InboundSettings, UserConfig,
    OutboundConfig, OutboundSettings,
    TransportConfig, TlsSettings, WebSocketSettings,
    RoutingConfig, RouteRule,
};
pub use stats_api::{StatsCollector, DispatcherStats, InboundStats, OutboundStats};
