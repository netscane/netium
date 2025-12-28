//! Metadata - the unified context for routing decisions
//!
//! Router ONLY depends on Metadata, never on Stream or IO.

use super::Address;

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Default for Network {
    fn default() -> Self {
        Network::Tcp
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Tcp => write!(f, "tcp"),
            Network::Udp => write!(f, "udp"),
        }
    }
}

/// Metadata extracted from protocol decoding.
/// This is the ONLY context Router can depend on.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Source address of the connection
    pub source: Address,
    /// Destination address the client wants to reach
    pub destination: Address,
    /// Network type (TCP/UDP)
    pub network: Network,
    /// Inbound tag for routing decisions
    pub inbound_tag: String,
    /// Protocol name (vmess, vless, socks, http, direct)
    pub protocol: String,
}

impl Metadata {
    /// Create new metadata with required fields
    pub fn new(destination: Address) -> Self {
        Self {
            source: Address::unspecified(),
            destination,
            network: Network::Tcp,
            inbound_tag: String::new(),
            protocol: String::new(),
        }
    }

    /// Builder: set source address
    pub fn with_source(mut self, source: Address) -> Self {
        self.source = source;
        self
    }

    /// Builder: set network type
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Builder: set inbound tag
    pub fn with_inbound_tag(mut self, tag: impl Into<String>) -> Self {
        self.inbound_tag = tag.into();
        self
    }

    /// Builder: set protocol name
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            source: Address::unspecified(),
            destination: Address::unspecified(),
            network: Network::Tcp,
            inbound_tag: String::new(),
            protocol: String::new(),
        }
    }
}
