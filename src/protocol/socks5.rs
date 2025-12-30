//! SOCKS5 Protocol implementation

use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, Metadata, Network, Result, Stream};
use crate::error::Error;

use super::{ProxyProtocol, Socks5Config};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

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

#[async_trait]
impl ProxyProtocol for Socks5Protocol {
    async fn inbound(&self, mut stream: Stream) -> Result<(Metadata, Stream)> {
        // 1. Read version and auth methods
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

        // 2. Select auth method
        let selected_method = if self.requires_auth() {
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

        // 3. Send selected method
        stream.write_all(&[SOCKS5_VERSION, selected_method]).await?;

        if selected_method == AUTH_NO_ACCEPTABLE {
            return Err(Error::Protocol("No acceptable auth method".into()));
        }

        // 4. Handle authentication if needed
        if selected_method == AUTH_PASSWORD {
            // Read username/password auth
            let mut ver = [0u8; 1];
            stream.read_exact(&mut ver).await?;

            if ver[0] != 0x01 {
                return Err(Error::Protocol("Invalid auth version".into()));
            }

            let mut ulen = [0u8; 1];
            stream.read_exact(&mut ulen).await?;
            let mut username = vec![0u8; ulen[0] as usize];
            stream.read_exact(&mut username).await?;

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut password = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut password).await?;

            let username = String::from_utf8_lossy(&username);
            let password = String::from_utf8_lossy(&password);

            let auth_ok = self
                .config
                .username
                .as_ref()
                .map(|u| u == username.as_ref())
                .unwrap_or(false)
                && self
                    .config
                    .password
                    .as_ref()
                    .map(|p| p == password.as_ref())
                    .unwrap_or(false);

            if auth_ok {
                stream.write_all(&[0x01, 0x00]).await?;
            } else {
                stream.write_all(&[0x01, 0x01]).await?;
                return Err(Error::Protocol("Authentication failed".into()));
            }
        }

        // 5. Read request
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;

        if header[0] != SOCKS5_VERSION {
            return Err(Error::Protocol("Invalid SOCKS version in request".into()));
        }

        let cmd = header[1];
        let atyp = header[3];

        // 6. Parse address
        let address = match atyp {
            ATYP_IPV4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                Address::Socket(SocketAddr::new(Ipv4Addr::from(addr).into(), port))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                let domain = String::from_utf8_lossy(&domain).to_string();
                Address::Domain(domain, port)
            }
            ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                Address::Socket(SocketAddr::new(Ipv6Addr::from(addr).into(), port))
            }
            _ => {
                let reply = [
                    SOCKS5_VERSION,
                    REP_ATYP_NOT_SUPPORTED,
                    0x00,
                    ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
                stream.write_all(&reply).await?;
                return Err(Error::Protocol(format!(
                    "Unsupported address type: {}",
                    atyp
                )));
            }
        };

        // 7. Handle command
        let network = match cmd {
            CMD_CONNECT => Network::Tcp,
            CMD_UDP_ASSOCIATE => Network::Udp,
            CMD_BIND => {
                let reply = [
                    SOCKS5_VERSION,
                    REP_CMD_NOT_SUPPORTED,
                    0x00,
                    ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
                stream.write_all(&reply).await?;
                return Err(Error::Protocol("BIND command not supported".into()));
            }
            _ => {
                let reply = [
                    SOCKS5_VERSION,
                    REP_CMD_NOT_SUPPORTED,
                    0x00,
                    ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
                stream.write_all(&reply).await?;
                return Err(Error::Protocol(format!("Unsupported command: {}", cmd)));
            }
        };

        // 8. Send success reply (will be sent after connection is established)
        // For now, we send a placeholder reply
        let reply = [
            SOCKS5_VERSION,
            REP_SUCCESS,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        stream.write_all(&reply).await?;
        stream.flush().await?;

        let metadata = Metadata::new(address)
            .with_network(network)
            .with_protocol("socks5");

        Ok((metadata, stream))
    }

    async fn outbound(&self, mut stream: Stream, metadata: &Metadata) -> Result<Stream> {
        // 1. Send greeting
        let auth_method = if self.requires_auth() {
            AUTH_PASSWORD
        } else {
            AUTH_NONE
        };
        stream.write_all(&[SOCKS5_VERSION, 1, auth_method]).await?;

        // 2. Read server's selected method
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != SOCKS5_VERSION {
            return Err(Error::Protocol("Invalid SOCKS version from server".into()));
        }

        if response[1] == AUTH_NO_ACCEPTABLE {
            return Err(Error::Protocol("Server rejected auth methods".into()));
        }

        // 3. Handle authentication
        if response[1] == AUTH_PASSWORD {
            let username = self.config.username.as_deref().unwrap_or("");
            let password = self.config.password.as_deref().unwrap_or("");

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
        }

        // 4. Send connect request
        let cmd = match metadata.network {
            Network::Tcp => CMD_CONNECT,
            Network::Udp => CMD_UDP_ASSOCIATE,
        };

        let mut request = vec![SOCKS5_VERSION, cmd, 0x00];

        match &metadata.destination {
            Address::Socket(addr) => match addr {
                SocketAddr::V4(v4) => {
                    request.push(ATYP_IPV4);
                    request.extend_from_slice(&v4.ip().octets());
                    request.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    request.push(ATYP_IPV6);
                    request.extend_from_slice(&v6.ip().octets());
                    request.extend_from_slice(&v6.port().to_be_bytes());
                }
            },
            Address::Domain(domain, port) => {
                request.push(ATYP_DOMAIN);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
                request.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&request).await?;

        // 5. Read response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await?;

        if response[0] != SOCKS5_VERSION {
            return Err(Error::Protocol("Invalid SOCKS version in response".into()));
        }

        if response[1] != REP_SUCCESS {
            let err_msg = match response[1] {
                REP_GENERAL_FAILURE => "General failure",
                REP_NOT_ALLOWED => "Connection not allowed",
                REP_NETWORK_UNREACHABLE => "Network unreachable",
                REP_HOST_UNREACHABLE => "Host unreachable",
                REP_CONNECTION_REFUSED => "Connection refused",
                REP_CMD_NOT_SUPPORTED => "Command not supported",
                REP_ATYP_NOT_SUPPORTED => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(Error::Protocol(format!("SOCKS5 error: {}", err_msg)));
        }

        // Skip bound address
        let atyp = response[3];
        match atyp {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                stream.read_exact(&mut skip).await?;
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut skip = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut skip).await?;
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                stream.read_exact(&mut skip).await?;
            }
            _ => {}
        }

        Ok(stream)
    }

    fn name(&self) -> &'static str {
        "socks5"
    }
}
