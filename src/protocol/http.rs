//! HTTP CONNECT Protocol implementation

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::common::{Address, Metadata, Result, Stream};
use crate::error::Error;

use super::{HttpConfig, ProxyProtocol};

/// HTTP CONNECT protocol handler
pub struct HttpProtocol {
    config: HttpConfig,
}

impl HttpProtocol {
    pub fn new(config: HttpConfig) -> Self {
        Self { config }
    }

    fn requires_auth(&self) -> bool {
        self.config.username.is_some() && self.config.password.is_some()
    }
}

#[async_trait]
impl ProxyProtocol for HttpProtocol {
    async fn inbound(&self, stream: Stream) -> Result<(Metadata, Stream)> {
        let mut reader = BufReader::new(stream);

        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::Protocol("Invalid HTTP request line".into()));
        }

        let method = parts[0];
        let target = parts[1];

        // Parse headers
        let mut headers = Vec::new();
        let mut auth_header = None;

        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let line = line.trim();

            if line.is_empty() {
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                if key == "proxy-authorization" {
                    auth_header = Some(value);
                } else {
                    headers.push((key, value));
                }
            }
        }

        // Check authentication
        if self.requires_auth() {
            let expected_auth = format!(
                "{}:{}",
                self.config.username.as_deref().unwrap_or(""),
                self.config.password.as_deref().unwrap_or("")
            );
            let expected_encoded = format!("Basic {}", BASE64.encode(expected_auth));

            match auth_header {
                Some(auth) if auth == expected_encoded => {}
                _ => {
                    let mut stream = reader.into_inner();
                    stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                              Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
                              \r\n",
                        )
                        .await?;
                    return Err(Error::Protocol("Authentication required".into()));
                }
            }
        }

        // Parse target address
        let address = if method.eq_ignore_ascii_case("CONNECT") {
            // CONNECT host:port
            parse_host_port(target)?
        } else {
            // GET http://host:port/path
            if let Some(url) = target.strip_prefix("http://") {
                let host_part = url.split('/').next().unwrap_or(url);
                parse_host_port(host_part)?
            } else {
                return Err(Error::Protocol(format!("Invalid target: {}", target)));
            }
        };

        let mut stream = reader.into_inner();

        // Send success response for CONNECT
        if method.eq_ignore_ascii_case("CONNECT") {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            stream.flush().await?;
        }

        let metadata = Metadata::new(address).with_protocol("http");

        Ok((metadata, stream))
    }

    async fn outbound(&self, mut stream: Stream, metadata: &Metadata) -> Result<Stream> {
        let target = metadata.destination.to_string();

        // Build CONNECT request
        let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);

        // Add authentication if configured
        if self.requires_auth() {
            let auth = format!(
                "{}:{}",
                self.config.username.as_deref().unwrap_or(""),
                self.config.password.as_deref().unwrap_or("")
            );
            let encoded = BASE64.encode(auth);
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        request.push_str("\r\n");

        stream.write_all(request.as_bytes()).await?;

        // Read response
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await?;

        let parts: Vec<&str> = response_line.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::Protocol("Invalid HTTP response".into()));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| Error::Protocol("Invalid status code".into()))?;

        if status_code != 200 {
            return Err(Error::Protocol(format!(
                "HTTP CONNECT failed: {}",
                response_line.trim()
            )));
        }

        // Skip remaining headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        Ok(reader.into_inner())
    }

    fn name(&self) -> &'static str {
        "http"
    }
}

/// Parse host:port string into Address
fn parse_host_port(s: &str) -> Result<Address> {
    // Try to parse as socket address first
    if let Ok(addr) = s.parse() {
        return Ok(Address::Socket(addr));
    }

    // Parse as host:port
    let (host, port) = if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| Error::Protocol(format!("Invalid port: {}", p)))?;
        (h.to_string(), port)
    } else {
        // Default to port 80 for HTTP
        (s.to_string(), 80)
    };

    // Remove brackets from IPv6
    let host = host.trim_start_matches('[').trim_end_matches(']');

    Ok(Address::Domain(host.to_string(), port))
}
