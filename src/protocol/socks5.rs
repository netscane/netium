//! SOCKS5 Protocol implementation
//!
//! Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password Authentication).
//!
//! Architecture:
//! - `inbound()`: Server-side - accepts client connections, parses requests
//! - `outbound()`: Client-side - connects through upstream SOCKS5 proxy

use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, Metadata, Network, Result, Stream};
use crate::error::Error;

use super::{ProxyProtocol, Socks5Config};

// ============================================================================
// SOCKS5 Protocol Constants (RFC 1928)
// ============================================================================

const SOCKS5_VERSION: u8 = 0x05;

// Authentication methods
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// Commands
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

// Address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

// ============================================================================
// SOCKS5 Protocol Handler
// ============================================================================

/// SOCKS5 protocol handler
pub struct Socks5Protocol {
    config: Socks5Config,
}

impl Socks5Protocol {
    pub fn new(config: Socks5Config) -> Self {
        Self { config }
    }

    fn requires_auth(&self) -> bool {
        self.config.username.is_some() && self.config.password.is_some()
    }
}

// ============================================================================
// Inbound Implementation (Server-side)
// ============================================================================

/// Server-side: Handle authentication negotiation
async fn server_negotiate_auth(
    stream: &mut Stream,
    requires_auth: bool,
) -> Result<u8> {
    // Read version and auth methods
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != SOCKS5_VERSION {
        return Err(Error::Protocol(format!(
            "Unsupported SOCKS version: {}",
            buf[0]
        )));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Select auth method
    let selected = if requires_auth {
        if methods.contains(&AUTH_PASSWORD) {
            AUTH_PASSWORD
        } else {
            AUTH_NO_ACCEPTABLE
        }
    } else if methods.contains(&AUTH_NONE) {
        AUTH_NONE
    } else {
        AUTH_NO_ACCEPTABLE
    };

    // Send selected method
    stream.write_all(&[SOCKS5_VERSION, selected]).await?;

    if selected == AUTH_NO_ACCEPTABLE {
        return Err(Error::Protocol("No acceptable auth method".into()));
    }

    Ok(selected)
}

/// Server-side: Verify username/password authentication (RFC 1929)
async fn server_verify_password(
    stream: &mut Stream,
    expected_user: &str,
    expected_pass: &str,
) -> Result<()> {
    // Read auth version
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;

    if ver[0] != 0x01 {
        return Err(Error::Protocol("Invalid auth version".into()));
    }

    // Read username
    let mut ulen = [0u8; 1];
    stream.read_exact(&mut ulen).await?;
    let mut username = vec![0u8; ulen[0] as usize];
    stream.read_exact(&mut username).await?;

    // Read password
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    let mut password = vec![0u8; plen[0] as usize];
    stream.read_exact(&mut password).await?;

    let username = String::from_utf8_lossy(&username);
    let password = String::from_utf8_lossy(&password);

    let auth_ok = username == expected_user && password == expected_pass;

    if auth_ok {
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(())
    } else {
        stream.write_all(&[0x01, 0x01]).await?;
        Err(Error::Protocol("Authentication failed".into()))
    }
}

/// Server-side: Read and parse SOCKS5 request
async fn server_read_request(stream: &mut Stream) -> Result<(u8, Address)> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION {
        return Err(Error::Protocol("Invalid SOCKS version in request".into()));
    }

    let cmd = header[1];
    let atyp = header[3];

    let address = read_address(stream, atyp).await?;
    Ok((cmd, address))
}

/// Read address based on address type
async fn read_address(stream: &mut Stream, atyp: u8) -> Result<Address> {
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let port = read_port(stream).await?;
            Ok(Address::Socket(SocketAddr::new(
                Ipv4Addr::from(addr).into(),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let port = read_port(stream).await?;
            let domain = String::from_utf8_lossy(&domain).to_string();
            Ok(Address::Domain(domain, port))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let port = read_port(stream).await?;
            Ok(Address::Socket(SocketAddr::new(
                Ipv6Addr::from(addr).into(),
                port,
            )))
        }
        _ => Err(Error::Protocol(format!("Unsupported address type: {}", atyp))),
    }
}

/// Read 2-byte big-endian port
async fn read_port(stream: &mut Stream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

/// Server-side: Send reply to client
async fn server_send_reply(stream: &mut Stream, rep: u8) -> Result<()> {
    let reply = [SOCKS5_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

/// Convert command byte to Network type
fn cmd_to_network(cmd: u8) -> Option<Network> {
    match cmd {
        CMD_CONNECT => Some(Network::Tcp),
        CMD_UDP_ASSOCIATE => Some(Network::Udp),
        _ => None,
    }
}

// ============================================================================
// Outbound Implementation (Client-side)
// ============================================================================

/// Client-side: Send greeting and negotiate auth
async fn client_negotiate_auth(stream: &mut Stream, auth_method: u8) -> Result<u8> {
    stream.write_all(&[SOCKS5_VERSION, 1, auth_method]).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != SOCKS5_VERSION {
        return Err(Error::Protocol("Invalid SOCKS version from server".into()));
    }

    if response[1] == AUTH_NO_ACCEPTABLE {
        return Err(Error::Protocol("Server rejected auth methods".into()));
    }

    Ok(response[1])
}

/// Client-side: Send username/password authentication
async fn client_send_password(
    stream: &mut Stream,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut auth_request = vec![0x01];
    auth_request.push(username.len() as u8);
    auth_request.extend_from_slice(username.as_bytes());
    auth_request.push(password.len() as u8);
    auth_request.extend_from_slice(password.as_bytes());

    stream.write_all(&auth_request).await?;

    let mut auth_response = [0u8; 2];
    stream.read_exact(&mut auth_response).await?;

    if auth_response[1] != 0x00 {
        return Err(Error::Protocol("Authentication failed".into()));
    }

    Ok(())
}

/// Client-side: Send connect request
async fn client_send_request(
    stream: &mut Stream,
    cmd: u8,
    address: &Address,
) -> Result<()> {
    let mut request = vec![SOCKS5_VERSION, cmd, 0x00];
    write_address(&mut request, address);
    stream.write_all(&request).await?;
    Ok(())
}

/// Write address to buffer
fn write_address(buf: &mut Vec<u8>, address: &Address) {
    match address {
        Address::Socket(addr) => match addr {
            SocketAddr::V4(v4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        Address::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// Client-side: Read and validate response
async fn client_read_response(stream: &mut Stream) -> Result<()> {
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if response[0] != SOCKS5_VERSION {
        return Err(Error::Protocol("Invalid SOCKS version in response".into()));
    }

    if response[1] != REP_SUCCESS {
        let err_msg = reply_code_to_string(response[1]);
        return Err(Error::Protocol(format!("SOCKS5 error: {}", err_msg)));
    }

    // Skip bound address
    skip_address(stream, response[3]).await?;
    Ok(())
}

/// Skip address in response (we don't need it)
async fn skip_address(stream: &mut Stream, atyp: u8) -> Result<()> {
    match atyp {
        ATYP_IPV4 => {
            let mut skip = [0u8; 6]; // 4 bytes IP + 2 bytes port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 18]; // 16 bytes IP + 2 bytes port
            stream.read_exact(&mut skip).await?;
        }
        _ => {}
    }
    Ok(())
}

/// Convert reply code to human-readable string
fn reply_code_to_string(code: u8) -> &'static str {
    match code {
        REP_SUCCESS => "Success",
        REP_GENERAL_FAILURE => "General failure",
        REP_NOT_ALLOWED => "Connection not allowed",
        REP_NETWORK_UNREACHABLE => "Network unreachable",
        REP_HOST_UNREACHABLE => "Host unreachable",
        REP_CONNECTION_REFUSED => "Connection refused",
        REP_CMD_NOT_SUPPORTED => "Command not supported",
        REP_ATYP_NOT_SUPPORTED => "Address type not supported",
        _ => "Unknown error",
    }
}

// ============================================================================
// ProxyProtocol Implementation
// ============================================================================

#[async_trait]
impl ProxyProtocol for Socks5Protocol {
    async fn inbound(&self, mut stream: Stream) -> Result<(Metadata, Stream)> {
        // Step 1: Negotiate authentication
        let selected_method = server_negotiate_auth(&mut stream, self.requires_auth()).await?;

        // Step 2: Verify password if required
        if selected_method == AUTH_PASSWORD {
            let username = self.config.username.as_deref().unwrap_or("");
            let password = self.config.password.as_deref().unwrap_or("");
            server_verify_password(&mut stream, username, password).await?;
        }

        // Step 3: Read request
        let (cmd, address) = match server_read_request(&mut stream).await {
            Ok(result) => result,
            Err(e) => {
                let _ = server_send_reply(&mut stream, REP_ATYP_NOT_SUPPORTED).await;
                return Err(e);
            }
        };

        // Step 4: Validate command
        let network = match cmd_to_network(cmd) {
            Some(n) => n,
            None => {
                server_send_reply(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
                return Err(Error::Protocol(format!("Unsupported command: {}", cmd)));
            }
        };

        // Step 5: Send success reply
        server_send_reply(&mut stream, REP_SUCCESS).await?;

        let metadata = Metadata::new(address)
            .with_network(network)
            .with_protocol("socks5");

        Ok((metadata, stream))
    }

    async fn outbound(&self, mut stream: Stream, metadata: &Metadata) -> Result<Stream> {
        // Step 1: Negotiate authentication
        let auth_method = if self.requires_auth() {
            AUTH_PASSWORD
        } else {
            AUTH_NONE
        };
        let selected = client_negotiate_auth(&mut stream, auth_method).await?;

        // Step 2: Send password if required
        if selected == AUTH_PASSWORD {
            let username = self.config.username.as_deref().unwrap_or("");
            let password = self.config.password.as_deref().unwrap_or("");
            client_send_password(&mut stream, username, password).await?;
        }

        // Step 3: Send connect request
        let cmd = match metadata.network {
            Network::Tcp => CMD_CONNECT,
            Network::Udp => CMD_UDP_ASSOCIATE,
        };
        client_send_request(&mut stream, cmd, &metadata.destination).await?;

        // Step 4: Read response
        client_read_response(&mut stream).await?;

        Ok(stream)
    }

    fn name(&self) -> &'static str {
        "socks5"
    }
}
