//! HTTP Proxy Protocol implementation
//!
//! HTTP proxy works in two modes:
//! - Forward: Proxy consumes HTTP, rewrites and forwards requests
//! - Tunnel: CONNECT method, proxy becomes transparent byte stream relay
//!
//! Both modes are unified under ProxyProtocol trait:
//! - inbound() returns (Metadata, Stream) regardless of mode
//! - The difference is whether HTTP semantics are consumed or passed through
//!
//! Architecture:
//! ```text
//! Forward Mode:  Client → [HTTP Request] → Proxy → [Rewritten Request] → Server
//! Tunnel Mode:   Client → CONNECT → Proxy → [200 OK] → Raw TCP Relay
//! ```

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::BytesMut;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tracing::debug;

use crate::common::{Address, Metadata, Result, Stream};
use crate::error::Error;

use super::{HttpConfig, ProxyProtocol};

// ============================================================================
// HTTP Protocol Types
// ============================================================================

/// HTTP proxy mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMode {
    /// Forward mode: proxy consumes and rewrites HTTP requests
    Forward,
    /// Tunnel mode: CONNECT method, transparent byte stream
    Tunnel,
}

// ============================================================================
// HTTP Protocol Handler
// ============================================================================

/// HTTP proxy protocol handler
///
/// Unified handling of both Forward and Tunnel modes:
/// - Forward: GET/POST http://... → parse, forward HTTP
/// - Tunnel: CONNECT host:port → transparent relay
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

    fn check_auth(&self, auth_header: Option<&str>) -> bool {
        if !self.requires_auth() {
            return true;
        }

        let expected = self.encode_auth();
        auth_header.map(|h| h == expected).unwrap_or(false)
    }

    fn encode_auth(&self) -> String {
        let credentials = format!(
            "{}:{}",
            self.config.username.as_deref().unwrap_or(""),
            self.config.password.as_deref().unwrap_or("")
        );
        format!("Basic {}", BASE64.encode(credentials))
    }
}

// ============================================================================
// HTTP Request Parsing
// ============================================================================

/// Parsed HTTP request
struct HttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Option<BytesMut>,
}

impl HttpRequest {
    /// Check if this is a CONNECT request (tunnel mode)
    fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
    }

    /// Get the destination address
    fn destination(&self) -> Result<Address> {
        if self.is_connect() {
            parse_host_port(&self.target)
        } else {
            self.parse_forward_target()
        }
    }

    fn parse_forward_target(&self) -> Result<Address> {
        // Absolute URI: http://host:port/path
        if let Some(url) = self.target.strip_prefix("http://") {
            let host_part = url.split('/').next().unwrap_or(url);
            return parse_host_port(host_part);
        }

        // Relative URI: /path - need Host header
        if self.target.starts_with('/') {
            if let Some((_, host)) = self.headers.iter().find(|(k, _)| k == "host") {
                return parse_host_port(host);
            }
        }

        Err(Error::Protocol(format!(
            "Cannot determine target from: {}",
            self.target
        )))
    }

    /// Get the path for forwarding (removes absolute URI prefix)
    fn forward_path(&self) -> &str {
        if let Some(url) = self.target.strip_prefix("http://") {
            if let Some(pos) = url.find('/') {
                return &url[pos..];
            }
            return "/";
        }
        &self.target
    }

    /// Get authorization header value
    fn auth_header(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == "proxy-authorization")
            .map(|(_, v)| v.as_str())
    }

    /// Reconstruct HTTP request for forwarding
    fn to_forward_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Request line with relative path
        buf.extend_from_slice(self.method.as_bytes());
        buf.extend_from_slice(b" ");
        buf.extend_from_slice(self.forward_path().as_bytes());
        buf.extend_from_slice(b" ");
        buf.extend_from_slice(self.version.as_bytes());
        buf.extend_from_slice(b"\r\n");

        // Headers (skip proxy-specific headers)
        for (key, value) in &self.headers {
            if key.starts_with("proxy-") {
                continue;
            }
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        buf.extend_from_slice(b"\r\n");

        if let Some(body) = &self.body {
            buf.extend_from_slice(body);
        }

        buf
    }
}

/// Parse HTTP request from stream
async fn parse_request(reader: &mut BufReader<Stream>) -> Result<HttpRequest> {
    let (method, target, version) = parse_request_line(reader).await?;
    let (headers, content_length) = parse_headers(reader).await?;
    let body = read_body(reader, content_length).await?;

    Ok(HttpRequest {
        method,
        target,
        version,
        headers,
        body,
    })
}

/// Parse HTTP request line
async fn parse_request_line(reader: &mut BufReader<Stream>) -> Result<(String, String, String)> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() < 3 {
        return Err(Error::Protocol("Invalid HTTP request line".into()));
    }

    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

/// Parse HTTP headers, returns headers and content-length if present
async fn parse_headers(reader: &mut BufReader<Stream>) -> Result<(Vec<(String, String)>, Option<usize>)> {
    let mut headers = Vec::new();
    let mut content_length = None;

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

            if key == "content-length" {
                content_length = value.parse().ok();
            }

            headers.push((key, value));
        }
    }

    Ok((headers, content_length))
}

/// Read HTTP body based on Content-Length
async fn read_body(reader: &mut BufReader<Stream>, content_length: Option<usize>) -> Result<Option<BytesMut>> {
    match content_length {
        Some(len) if len > 0 => {
            let mut body = BytesMut::zeroed(len);
            reader.read_exact(&mut body).await?;
            Ok(Some(body))
        }
        _ => Ok(None),
    }
}

/// Skip HTTP response headers (read until empty line)
async fn skip_response_headers(reader: &mut BufReader<Stream>) -> Result<()> {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }
    Ok(())
}

// ============================================================================
// Address Parsing
// ============================================================================

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
        (h, port)
    } else {
        (s, 80) // Default to port 80 for HTTP
    };

    // Remove brackets from IPv6
    let host = host.trim_start_matches('[').trim_end_matches(']');

    Ok(Address::Domain(host.to_string(), port))
}

// ============================================================================
// HTTP Responses
// ============================================================================

const RESPONSE_200_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESPONSE_407_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
    Connection: close\r\n\r\n";

// ============================================================================
// ProxyProtocol Implementation
// ============================================================================

#[async_trait]
impl ProxyProtocol for HttpProtocol {
    async fn inbound(&self, stream: Stream) -> Result<(Metadata, Stream)> {
        let mut reader = BufReader::new(stream);
        let request = parse_request(&mut reader).await?;

        debug!(
            "HTTP inbound: {} {} (mode: {})",
            request.method,
            request.target,
            if request.is_connect() { "tunnel" } else { "forward" }
        );

        // Check authentication
        if !self.check_auth(request.auth_header()) {
            let mut stream = reader.into_inner();
            stream.write_all(RESPONSE_407_AUTH_REQUIRED).await?;
            return Err(Error::Protocol("Authentication required".into()));
        }

        // Parse destination
        let address = request.destination()?;
        let mut stream = reader.into_inner();

        // Mode-specific handling - both return (Metadata, Stream)
        if request.is_connect() {
            // Tunnel mode: send 200, return raw stream
            stream.write_all(RESPONSE_200_ESTABLISHED).await?;
            stream.flush().await?;

            let metadata = Metadata::new(address).with_protocol("http-tunnel");
            Ok((metadata, stream))
        } else {
            // Forward mode: wrap stream with pending request data
            let forward_data = request.to_forward_bytes();
            let metadata = Metadata::new(address).with_protocol("http-forward");
            let stream = Box::new(PrependStream::new(forward_data, stream));
            Ok((metadata, stream as Stream))
        }
    }

    async fn outbound(&self, mut stream: Stream, metadata: &Metadata) -> Result<Stream> {
        // Outbound always uses CONNECT for tunneling
        let target = metadata.destination.to_string();

        // Build CONNECT request
        let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);
        if self.requires_auth() {
            request.push_str(&format!("Proxy-Authorization: {}\r\n", self.encode_auth()));
        }
        request.push_str("\r\n");

        stream.write_all(request.as_bytes()).await?;

        // Read and validate response
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await?;

        let status_code = parse_status_code(&response_line)?;
        if status_code != 200 {
            return Err(Error::Protocol(format!(
                "HTTP CONNECT failed: {}",
                response_line.trim()
            )));
        }

        skip_response_headers(&mut reader).await?;
        Ok(reader.into_inner())
    }

    fn name(&self) -> &'static str {
        "http"
    }
}

/// Parse status code from HTTP response line
fn parse_status_code(line: &str) -> Result<u16> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(Error::Protocol("Invalid HTTP response".into()));
    }
    parts[1]
        .parse()
        .map_err(|_| Error::Protocol("Invalid status code".into()))
}

// ============================================================================
// PrependStream - Stream wrapper for Forward mode
// ============================================================================

/// Stream wrapper that prepends data before the underlying stream
///
/// Used in Forward mode to inject the reconstructed HTTP request
struct PrependStream {
    prepend: BytesMut,
    inner: Stream,
}

impl PrependStream {
    fn new(prepend: BytesMut, inner: Stream) -> Self {
        Self { prepend, inner }
    }
}

impl AsyncRead for PrependStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First drain prepended data
        if !self.prepend.is_empty() {
            let to_copy = self.prepend.len().min(buf.remaining());
            buf.put_slice(&self.prepend[..to_copy]);
            let _ = self.prepend.split_to(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Then read from inner stream
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrependStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
