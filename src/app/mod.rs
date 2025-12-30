//! Application Layer
//!
//! This module contains:
//! - Dispatcher: core execution flow (inbound → router → outbound)
//! - Runtime: configuration-driven pipeline construction
//! - Stack: inbound/outbound pipeline stacks
//! - StatsApi: HTTP API for runtime statistics with Prometheus metrics

mod dispatcher;
pub mod metrics;
mod runtime;
mod stack;
pub mod stats_api;

pub use dispatcher::Dispatcher;
pub use runtime::{
    Runtime, RuntimeConfig, 
    InboundConfig, InboundSettings, UserConfig,
    OutboundConfig, OutboundSettings,
    TransportConfig, TlsSettings, WebSocketSettings,
    RoutingConfig, RouteRule,
};
pub use stack::{InboundStack, OutboundStack};
pub use stats_api::{StatsCollector, DispatcherStats, InboundStats, OutboundStats};
