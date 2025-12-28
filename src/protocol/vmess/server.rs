//! VMess Server Implementation

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, Metadata, Network, Result, Stream};
use crate::error::Error;

use super::aead::{
    open_aead_request_header_length, open_aead_request_header_payload, open_auth_id,
    seal_aead_response_header,
};
use super::stream::VmessStream;
use super::{Security, VmessConfig};

const VMESS_VERSION: u8 = 1;
const TIMESTAMP_TOLERANCE: i64 = 120; // 2 minutes

// Commands
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;

// Address types
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x02;
const ADDR_TYPE_IPV6: u8 = 0x03;

/// VMess server for inbound connections
pub struct VmessServer {
    config: VmessConfig,
}

impl VmessServer {
    pub fn new(config: VmessConfig) -> Self {
        Self { config }
    }

    /// Generate command key from UUID
    fn cmd_key(&self) -> [u8; 16] {
        let uuid_bytes = self.config.uuid.as_bytes();
        let mut data = Vec::with_capacity(uuid_bytes.len() + 36);
        data.extend_from_slice(uuid_bytes);
        data.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");

        let result = md5::compute(&data);
        let mut key = [0u8; 16];
        key.copy_from_slice(&result.0);
        key
    }

    /// Accept incoming VMess connection
    pub async fn accept(&self, mut stream: Stream) -> Result<(Metadata, Stream)> {
        debug!("VMess server accepting connection");

        let cmd_key = self.cmd_key();
        debug!("VMess server: cmd_key={:02x?}, uuid={}", &cmd_key, self.config.uuid);

        // Read Auth ID (16 bytes)
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;
        debug!("VMess server: auth_id={:02x?}", &auth_id);

        // Decrypt and validate Auth ID
        let timestamp = open_auth_id(&cmd_key, &auth_id)?;
        self.validate_timestamp(timestamp)?;
        debug!("VMess server: timestamp={}", timestamp);

        // Read encrypted length (18 bytes = 2 + 16 tag)
        let mut encrypted_length = [0u8; 18];
        stream.read_exact(&mut encrypted_length).await?;

        // Read connection nonce (8 bytes)
        let mut connection_nonce = [0u8; 8];
        stream.read_exact(&mut connection_nonce).await?;
        debug!("VMess server: connection_nonce={:02x?}", &connection_nonce);

        // Decrypt header length
        let header_length =
            open_aead_request_header_length(&cmd_key, &auth_id, &connection_nonce, &encrypted_length)?;
        debug!("VMess server: header_length={}", header_length);

        if header_length > 2048 {
            return Err(Error::Protocol("Header too large".into()));
        }

        // Read encrypted header payload
        let mut encrypted_payload = vec![0u8; header_length as usize + 16]; // +16 for tag
        stream.read_exact(&mut encrypted_payload).await?;

        // Decrypt header payload
        let header =
            open_aead_request_header_payload(&cmd_key, &auth_id, &connection_nonce, &encrypted_payload)?;
        debug!("VMess server: decrypted header ({} bytes)", header.len());

        // Parse header
        let (metadata, request_body_key, request_body_iv, response_header, security, options) =
            self.parse_request_header(&header)?;

        debug!(
            "VMess server: target={}, security={:?}, options=0x{:02x}",
            metadata.destination, security, options
        );

        // Calculate response keys (AEAD mode uses SHA256)
        let response_body_key = {
            let mut hasher = Sha256::new();
            hasher.update(&request_body_key);
            let result = hasher.finalize();
            let mut key = [0u8; 16];
            key.copy_from_slice(&result[..16]);
            key
        };

        let response_body_iv = {
            let mut hasher = Sha256::new();
            hasher.update(&request_body_iv);
            let result = hasher.finalize();
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&result[..16]);
            iv
        };

        // Build response header: [response_header_byte, 0, 0, 0]
        let response_data = vec![response_header, 0, 0, 0];
        let sealed_response = seal_aead_response_header(&response_body_key, &response_body_iv, &response_data)?;
        debug!("VMess server: sealed response header ({} bytes)", sealed_response.len());

        // Send response header
        stream.write_all(&sealed_response).await?;
        stream.flush().await?;
        debug!("VMess server: response header sent");

        // Create VMess stream (server side: read uses request keys, write uses response keys)
        let vmess_stream = VmessStream::server(
            stream,
            security,
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            options,
        );

        Ok((metadata, Box::new(vmess_stream)))
    }

    fn validate_timestamp(&self, timestamp: i64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Protocol(format!("Time error: {}", e)))?
            .as_secs() as i64;

        let diff = (now - timestamp).abs();
        if diff > TIMESTAMP_TOLERANCE {
            return Err(Error::Protocol(format!(
                "Timestamp out of range: diff={}s",
                diff
            )));
        }
        Ok(())
    }

    fn parse_request_header(
        &self,
        header: &[u8],
    ) -> Result<(Metadata, [u8; 16], [u8; 16], u8, Security, u8)> {
        if header.len() < 41 {
            // Minimum: 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 = 41
            return Err(Error::Protocol("Header too short".into()));
        }

        let mut pos = 0;

        // Version (1 byte)
        let version = header[pos];
        pos += 1;
        if version != VMESS_VERSION {
            return Err(Error::Protocol(format!("Unsupported version: {}", version)));
        }

        // Request Body IV (16 bytes)
        let mut request_body_iv = [0u8; 16];
        request_body_iv.copy_from_slice(&header[pos..pos + 16]);
        pos += 16;

        // Request Body Key (16 bytes)
        let mut request_body_key = [0u8; 16];
        request_body_key.copy_from_slice(&header[pos..pos + 16]);
        pos += 16;

        // Response Header (1 byte)
        let response_header = header[pos];
        pos += 1;

        // Options (1 byte)
        let options = header[pos];
        pos += 1;

        // Padding + Security (1 byte)
        let padding_security = header[pos];
        pos += 1;
        let padding_len = (padding_security >> 4) & 0x0F;
        let security_byte = padding_security & 0x0F;
        let security = Security::from_byte(security_byte);

        // Reserved (1 byte)
        pos += 1;

        // Command (1 byte)
        let command = header[pos];
        pos += 1;
        let network = match command {
            COMMAND_TCP => Network::Tcp,
            COMMAND_UDP => Network::Udp,
            _ => return Err(Error::Protocol(format!("Unknown command: {}", command))),
        };

        // Port (2 bytes)
        if pos + 2 > header.len() {
            return Err(Error::Protocol("Header truncated at port".into()));
        }
        let port = u16::from_be_bytes([header[pos], header[pos + 1]]);
        pos += 2;

        // Address type (1 byte)
        if pos >= header.len() {
            return Err(Error::Protocol("Header truncated at address type".into()));
        }
        let addr_type = header[pos];
        pos += 1;

        let address = match addr_type {
            ADDR_TYPE_IPV4 => {
                if pos + 4 > header.len() {
                    return Err(Error::Protocol("Header truncated at IPv4".into()));
                }
                let ip = Ipv4Addr::new(header[pos], header[pos + 1], header[pos + 2], header[pos + 3]);
                pos += 4;
                Address::Socket(SocketAddr::from((ip, port)))
            }
            ADDR_TYPE_IPV6 => {
                if pos + 16 > header.len() {
                    return Err(Error::Protocol("Header truncated at IPv6".into()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&header[pos..pos + 16]);
                let ip = Ipv6Addr::from(octets);
                pos += 16;
                Address::Socket(SocketAddr::from((ip, port)))
            }
            ADDR_TYPE_DOMAIN => {
                if pos >= header.len() {
                    return Err(Error::Protocol("Header truncated at domain length".into()));
                }
                let domain_len = header[pos] as usize;
                pos += 1;
                if pos + domain_len > header.len() {
                    return Err(Error::Protocol("Header truncated at domain".into()));
                }
                let domain = String::from_utf8(header[pos..pos + domain_len].to_vec())
                    .map_err(|_| Error::Protocol("Invalid domain encoding".into()))?;
                pos += domain_len;
                Address::Domain(domain, port)
            }
            _ => return Err(Error::Protocol(format!("Unknown address type: {}", addr_type))),
        };

        // Skip padding
        pos += padding_len as usize;

        // Verify FNV1a hash (4 bytes)
        if pos + 4 > header.len() {
            return Err(Error::Protocol("Header truncated at hash".into()));
        }
        let expected_hash = u32::from_be_bytes([header[pos], header[pos + 1], header[pos + 2], header[pos + 3]]);
        let actual_hash = fnv1a_hash(&header[..pos]);

        if expected_hash != actual_hash {
            return Err(Error::Protocol(format!(
                "FNV1a hash mismatch: expected=0x{:08x}, actual=0x{:08x}",
                expected_hash, actual_hash
            )));
        }

        debug!(
            "VMess header parsed: version={}, options=0x{:02x}, security={:?}, command={}, addr={}, padding={}",
            version, options, security, command, address, padding_len
        );

        let metadata = Metadata::new(address)
            .with_network(network)
            .with_protocol("vmess");

        Ok((metadata, request_body_key, request_body_iv, response_header, security, options))
    }
}

/// FNV1a 32-bit hash
fn fnv1a_hash(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 2166136261;
    const FNV_PRIME: u32 = 16777619;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
