//! Configuration module for Netium
//!
//! Supports JSON configuration similar to V2Ray

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use uuid::Uuid;

use crate::error::{Error, Result};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Log configuration
    #[serde(default)]
    pub log: LogConfig,

    /// API configuration
    #[serde(default)]
    pub api: Option<ApiConfig>,

    /// Inbound configurations
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,

    /// Outbound configurations
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,

    /// Routing rules
    #[serde(default)]
    pub routing: RoutingConfig,
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Listen address for stats API (e.g., "127.0.0.1:9090")
    pub listen: String,
}

impl Config {
    /// Load configuration from a JSON file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;
        Self::from_json(&content)
    }

    /// Parse configuration from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::Config(format!("Failed to parse config: {}", e)))
    }

    /// Create a default client configuration
    pub fn default_client() -> Self {
        Config {
            log: LogConfig::default(),
            api: None,
            inbounds: vec![
                InboundConfig {
                    tag: "socks-in".to_string(),
                    protocol: InboundProtocol::Socks,
                    listen: "0.0.0.0:1080".parse().unwrap(),
                    settings: InboundSettings::Socks(SocksInboundSettings {
                        auth: AuthType::NoAuth,
                        udp: true,
                    }),
                    transport: None,
                },
                InboundConfig {
                    tag: "http-in".to_string(),
                    protocol: InboundProtocol::Http,
                    listen: "127.0.0.1:8080".parse().unwrap(),
                    settings: InboundSettings::Http(HttpInboundSettings { auth: None }),
                    transport: None,
                },
            ],
            outbounds: vec![
                OutboundConfig {
                    tag: "direct".to_string(),
                    protocol: OutboundProtocol::Direct,
                    settings: OutboundSettings::Direct,
                    transport: None,
                },
                OutboundConfig {
                    tag: "proxy".to_string(),
                    protocol: OutboundProtocol::Vmess,
                    settings: OutboundSettings::Vmess(VmessOutboundSettings {
                        uuid: Uuid::new_v4(),
                        security: SecurityType::Auto,
                        alter_id: 0,
                    }),
                    transport: Some(TransportConfig {
                        address: Some("example.com".to_string()),
                        port: Some(443),
                        transport_type: TransportType::WebSocket,
                        ws_settings: Some(WebSocketSettings {
                            path: "/ws".to_string(),
                            headers: Default::default(),
                        }),
                        tls_settings: Some(TlsSettings {
                            enabled: true,
                            server_name: Some("example.com".to_string()),
                            allow_insecure: false,
                            certificate_file: None,
                            key_file: None,
                        }),
                        ..Default::default()
                    }),
                },
            ],
            routing: RoutingConfig::default(),
        }
    }

    /// Create a default server configuration
    pub fn default_server() -> Self {
        Config {
            log: LogConfig::default(),
            api: None,
            inbounds: vec![InboundConfig {
                tag: "vmess-in".to_string(),
                protocol: InboundProtocol::Vmess,
                listen: "0.0.0.0:443".parse().unwrap(),
                settings: InboundSettings::Vmess(VmessInboundSettings {
                    users: vec![VmessUser {
                        uuid: Uuid::new_v4(),
                        alter_id: 0,
                        email: "user@example.com".to_string(),
                    }],
                }),
                transport: Some(TransportConfig {
                    transport_type: TransportType::Tcp,
                    tls_settings: Some(TlsSettings {
                        enabled: true,
                        server_name: None,
                        allow_insecure: false,
                        certificate_file: Some("/path/to/cert.pem".to_string()),
                        key_file: Some("/path/to/key.pem".to_string()),
                    }),
                    ..Default::default()
                }),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: OutboundProtocol::Direct,
                settings: OutboundSettings::Direct,
                transport: None,
            }],
            routing: RoutingConfig::default(),
        }
    }
}

/// Log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level: debug, info, warning, error, none
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Access log file path
    pub access: Option<String>,

    /// Error log file path
    pub error: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            access: None,
            error: None,
        }
    }
}

/// Inbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    /// Unique tag for this inbound
    pub tag: String,

    /// Protocol type
    pub protocol: InboundProtocol,

    /// Listen address
    pub listen: SocketAddr,

    /// Protocol-specific settings
    pub settings: InboundSettings,

    /// Transport configuration (for TLS/WebSocket server)
    #[serde(default)]
    pub transport: Option<TransportConfig>,
}

/// Inbound protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InboundProtocol {
    Socks,
    Http,
    Vmess,
    Shadowsocks,
}

/// Inbound settings (protocol-specific)
/// Note: Order matters for untagged enums - put variants with required fields first
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InboundSettings {
    Vmess(VmessInboundSettings),      // Has required 'users' field
    Shadowsocks(ShadowsocksSettings), // Has required 'method' and 'password' fields
    Http(HttpInboundSettings),        // Has optional 'auth' field
    Socks(SocksInboundSettings),      // All fields have defaults - must be last
}

/// SOCKS5 inbound settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksInboundSettings {
    /// Authentication type
    #[serde(default)]
    pub auth: AuthType,

    /// Enable UDP support
    #[serde(default)]
    pub udp: bool,
}

/// HTTP proxy inbound settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInboundSettings {
    /// Optional authentication (username:password)
    pub auth: Option<UserPass>,
}

/// VMess inbound settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessInboundSettings {
    /// Allowed users
    pub users: Vec<VmessUser>,
}

/// VMess user configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessUser {
    /// User UUID
    pub uuid: Uuid,

    /// Alter ID (legacy, should be 0 for AEAD)
    #[serde(default)]
    pub alter_id: u16,

    /// User email (for logging)
    #[serde(default)]
    pub email: String,
}

/// Shadowsocks settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksSettings {
    /// Encryption method
    pub method: String,

    /// Password
    pub password: String,
}

/// Authentication type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    #[default]
    NoAuth,
    Password,
}

/// Username and password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPass {
    pub user: String,
    pub pass: String,
}

/// Outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// Unique tag for this outbound
    pub tag: String,

    /// Protocol type
    pub protocol: OutboundProtocol,

    /// Protocol-specific settings
    pub settings: OutboundSettings,

    /// Transport configuration
    pub transport: Option<TransportConfig>,
}

/// Outbound protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundProtocol {
    Direct,
    Vmess,
    Shadowsocks,
    Freedom,
    Blackhole,
}

/// Outbound settings (protocol-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutboundSettings {
    Direct,
    Vmess(VmessOutboundSettings),
    Shadowsocks(ShadowsocksSettings),
    Blackhole,
}

/// VMess outbound settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessOutboundSettings {
    /// User UUID
    pub uuid: Uuid,

    /// Security type
    #[serde(default)]
    pub security: SecurityType,

    /// Alter ID (legacy, should be 0)
    #[serde(default)]
    pub alter_id: u16,
}

/// Security/encryption type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityType {
    #[default]
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

/// Transport configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Server address (for outbound)
    pub address: Option<String>,

    /// Server port (for outbound)
    pub port: Option<u16>,

    /// Transport type
    #[serde(default)]
    pub transport_type: TransportType,

    /// TCP settings
    pub tcp_settings: Option<TcpSettings>,

    /// WebSocket settings
    pub ws_settings: Option<WebSocketSettings>,

    /// TLS settings
    pub tls_settings: Option<TlsSettings>,
}

/// Transport types
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    #[default]
    Tcp,
    WebSocket,
    Http2,
    Grpc,
}

/// TCP transport settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpSettings {
    /// HTTP header obfuscation
    pub header: Option<HttpHeaderConfig>,
}

/// HTTP header obfuscation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderConfig {
    /// Header type
    #[serde(rename = "type")]
    pub header_type: String,

    /// Request configuration
    pub request: Option<HttpRequestConfig>,

    /// Response configuration
    pub response: Option<HttpResponseConfig>,
}

/// HTTP request configuration for obfuscation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestConfig {
    pub version: String,
    pub method: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, Vec<String>>,
}

/// HTTP response configuration for obfuscation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseConfig {
    pub version: String,
    pub status: String,
    pub reason: String,
    pub headers: HashMap<String, Vec<String>>,
}

/// WebSocket transport settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebSocketSettings {
    /// WebSocket path
    #[serde(default = "default_ws_path")]
    pub path: String,

    /// Custom headers
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_ws_path() -> String {
    "/".to_string()
}

/// TLS settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Enable TLS
    #[serde(default)]
    pub enabled: bool,

    /// Server name for SNI (client mode)
    pub server_name: Option<String>,

    /// Allow insecure certificates (client mode)
    #[serde(default)]
    pub allow_insecure: bool,

    /// Certificate file path (server mode)
    pub certificate_file: Option<String>,

    /// Private key file path (server mode)
    pub key_file: Option<String>,
}

/// Routing configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Domain strategy
    #[serde(default)]
    pub domain_strategy: DomainStrategy,

    /// Routing rules
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

/// Domain resolution strategy
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IPIfNonMatch,
    IPOnDemand,
}

/// Routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Rule type
    #[serde(rename = "type", default = "default_rule_type")]
    pub rule_type: String,

    /// Domain patterns
    #[serde(default)]
    pub domain: Vec<String>,

    /// IP patterns
    #[serde(default)]
    pub ip: Vec<String>,

    /// Port patterns
    #[serde(default)]
    pub port: Option<String>,

    /// Source IP patterns
    #[serde(default)]
    pub source: Vec<String>,

    /// Inbound tag filter
    #[serde(default)]
    pub inbound_tag: Vec<String>,

    /// Protocol filter
    #[serde(default)]
    pub protocol: Vec<String>,

    /// Target outbound tag
    pub outbound_tag: String,
}

fn default_rule_type() -> String {
    "field".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_client_config() {
        let config = Config::default_client();
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.outbounds.len(), 2);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default_client();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.inbounds.len(), config.inbounds.len());
    }
}
