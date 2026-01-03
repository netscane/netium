//! Netium - A modern VPN/proxy tool
//!
//! # Architecture
//!
//! ```text
//! Transport: creates Stream (connect/accept)
//! Pipeline:  transforms Stream (StreamLayer* → Protocol)
//! Router:    decides next Transport
//! Dispatcher: orchestrates the flow
//! ```
//!
//! ## Data Flow
//!
//! ```text
//! Inbound:
//!   Transport.accept() → Stream → Pipeline.process() → (Metadata, Stream)
//!                                                            ↓
//!                                                     Router.select()
//!                                                            ↓
//! Outbound:
//!   Transport.connect() → Stream → Pipeline.process() → Stream
//!                                                            ↓
//!                                                     Bidirectional Relay
//! ```
//!
//! ## Key Concepts
//!
//! - **Transport**: Creates streams (TCP connect/accept, UDP, QUIC)
//! - **StreamLayer**: Transforms streams (TLS, WebSocket, HTTP)
//! - **Pipeline**: Chain of StreamLayers + Protocol
//! - **Protocol**: Proxy protocol (SOCKS5, HTTP, VMess)
//! - **Router**: Selects outbound based on Metadata
//!
//! ## Module Structure
//!
//! ```text
//! src/
//! ├── common/          # Core types: Stream, Metadata, Address
//! ├── transport/       # Transport + StreamLayer
//! ├── protocol/        # ProxyProtocol implementations
//! ├── router/          # Router implementations
//! └── app/             # Dispatcher, Runtime, Pipeline
//! ```

// Core types
pub mod common;
pub mod error;

// Layered architecture
pub mod transport;
pub mod protocol;
pub mod router;
pub mod app;

// Supporting modules
pub mod config;
pub mod crypto;
pub mod geoip;
pub mod geosite;

// Re-exports for convenience
pub use common::{Address, Metadata, Network, Stream};
pub use error::{Error, Result};
pub use config::Config;

// Architecture re-exports
pub use app::{Dispatcher, Runtime, InboundPipeline, OutboundPipeline};
pub use app::runtime::{Inbound, Outbound};
pub use protocol::ProxyProtocol;
pub use router::Router;
pub use transport::{Transport, StreamLayer};
