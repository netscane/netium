//! Error types for Netium

use thiserror::Error;

/// Main error type for Netium
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Timeout")]
    Timeout,

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    #[error("Operation would block")]
    WouldBlock,
}

/// Result type alias for Netium
pub type Result<T> = std::result::Result<T, Error>;
