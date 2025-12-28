//! Address type for network connections

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Network address representation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// IP socket address (IP + port)
    Socket(SocketAddr),
    /// Domain name with port
    Domain(String, u16),
}

impl Address {
    /// Create an unspecified address (0.0.0.0:0)
    pub fn unspecified() -> Self {
        Address::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    /// Create from domain and port
    pub fn domain(domain: impl Into<String>, port: u16) -> Self {
        Address::Domain(domain.into(), port)
    }

    /// Create from socket address
    pub fn socket(addr: SocketAddr) -> Self {
        Address::Socket(addr)
    }

    /// Create from IP and port
    pub fn ip_port(ip: IpAddr, port: u16) -> Self {
        Address::Socket(SocketAddr::new(ip, port))
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        match self {
            Address::Socket(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }

    /// Get the host part as string
    pub fn host(&self) -> String {
        match self {
            Address::Socket(addr) => addr.ip().to_string(),
            Address::Domain(domain, _) => domain.clone(),
        }
    }

    /// Check if this is a domain address
    pub fn is_domain(&self) -> bool {
        matches!(self, Address::Domain(_, _))
    }

    /// Check if this is a socket address
    pub fn is_socket(&self) -> bool {
        matches!(self, Address::Socket(_))
    }

    /// Try to get as socket address (fails for domain)
    pub fn as_socket(&self) -> Option<SocketAddr> {
        match self {
            Address::Socket(addr) => Some(*addr),
            Address::Domain(_, _) => None,
        }
    }

    /// Get domain if this is a domain address
    pub fn as_domain(&self) -> Option<(&str, u16)> {
        match self {
            Address::Domain(domain, port) => Some((domain, *port)),
            Address::Socket(_) => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Socket(addr) => write!(f, "{}", addr),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Socket(addr)
    }
}

impl From<(String, u16)> for Address {
    fn from((domain, port): (String, u16)) -> Self {
        Address::Domain(domain, port)
    }
}

impl From<(&str, u16)> for Address {
    fn from((domain, port): (&str, u16)) -> Self {
        Address::Domain(domain.to_string(), port)
    }
}
