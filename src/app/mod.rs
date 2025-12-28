//! Application Layer
//!
//! This module contains:
//! - Dispatcher: core execution flow (inbound → router → outbound)
//! - Runtime: configuration-driven pipeline construction
//! - Stack: inbound/outbound pipeline stacks

mod dispatcher;
mod runtime;
mod stack;

pub use dispatcher::Dispatcher;
pub use runtime::{
    Runtime, RuntimeConfig, 
    InboundConfig, InboundSettings, UserConfig,
    OutboundConfig, OutboundSettings,
    TransportConfig, TlsSettings, WebSocketSettings,
    RoutingConfig, RouteRule,
};
pub use stack::{InboundStack, OutboundStack};
