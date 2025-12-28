//! Netium - A modern VPN/proxy tool
//!
//! # Architecture (Layered Pipeline)
//!
//! ```text
//! Transport (TCP/UDP)
//! → Session (TLS/WebSocket/HTTP2)
//! → Proxy Protocol (VMess/VLESS/SOCKS5/HTTP)
//! → Router
//! → Proxy Protocol
//! → Session
//! → Transport
//! ```
//!
//! ## Core Principles
//!
//! - Each layer does ONE thing
//! - All layers abstracted via traits
//! - Data flows as Stream + Metadata
//! - Router only depends on Metadata, no IO
//!
//! ## Module Structure
//!
//! ```text
//! src/
//! ├── common/          # Core types: Stream, Metadata, Address
//! ├── transport/       # Transport layer: TCP, UDP
//! ├── session/         # Session layer: TLS, WebSocket
//! ├── protocol/        # Protocol layer: SOCKS5, HTTP, VMess
//! ├── router/          # Router: rule-based routing
//! └── app/             # Application: Dispatcher, Runtime, Stack
//! ```

// Core types
pub mod common;
pub mod error;

// Layered architecture
pub mod transport;
pub mod session;
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
pub use app::{Dispatcher, Runtime, InboundStack, OutboundStack};
pub use protocol::ProxyProtocol;
pub use router::Router;
pub use session::Session;
pub use transport::Transport;
