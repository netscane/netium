//! VMess Client Implementation

use std::net::SocketAddr;

use sha2::{Sha256, Digest};
use rand::RngCore;
use tracing::debug;

use crate::common::{Address, Metadata, Network, Result, Stream};
use crate::error::Error;

use super::aead::seal_vmess_aead_header;
use super::stream::VmessStream;
use super::{Security, VmessConfig};

const VMESS_VERSION: u8 = 1;

// Request options
const REQUEST_OPTION_CHUNK_STREAM: u8 = 0x01;
const REQUEST_OPTION_CHUNK_MASKING: u8 = 0x04;
const REQUEST_OPTION_GLOBAL_PADDING: u8 = 0x08;

// Commands
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;

// Address types
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x02;
const ADDR_TYPE_IPV6: u8 = 0x03;

/// VMess client for outbound connections
pub struct VmessClient {
    config: VmessConfig,
}

impl VmessClient {
    pub fn new(config: VmessConfig) -> Self {
        Self { config }
    }

    /// Generate command key from UUID
    fn cmd_key(&self) -> [u8; 16] {
        let uuid_bytes = self.config.uuid.as_bytes();

        // cmdKey = md5(uuid + "c48619fe-8f02-49e0-b9e9-edf763e17e21")
        let mut data = Vec::with_capacity(uuid_bytes.len() + 36);
        data.extend_from_slice(uuid_bytes);
        data.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        
        let result = md5::compute(&data);
        let mut key = [0u8; 16];
        key.copy_from_slice(&result.0);
        key
    }

    /// Connect to target through VMess protocol
    pub async fn connect(&self, stream: Stream, metadata: &Metadata) -> Result<Stream> {
        debug!("VMess connecting to {}", metadata.destination);

        let cmd_key = self.cmd_key();
        debug!("VMess client: cmd_key={:02x?}, uuid={}", &cmd_key, self.config.uuid);

        // Generate random keys
        let mut request_body_key = [0u8; 16];
        let mut request_body_iv = [0u8; 16];
        let mut response_header = [0u8; 1];

        rand::thread_rng().fill_bytes(&mut request_body_key);
        rand::thread_rng().fill_bytes(&mut request_body_iv);
        rand::thread_rng().fill_bytes(&mut response_header);
        
        debug!(
            "VMess keys: body_key={:02x?}, body_iv={:02x?}, resp_header={}",
            &request_body_key[..], &request_body_iv[..], response_header[0]
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

        // Build request header
        let header = self.build_request_header(
            metadata,
            &request_body_key,
            &request_body_iv,
            response_header[0],
        )?;
        
        debug!("VMess request header ({} bytes): {:02x?}", header.len(), &header);

        // Seal header with AEAD (use cmd_key computed earlier)
        let sealed_header = seal_vmess_aead_header(&cmd_key, &header)?;

        debug!("VMess sealed header: {} bytes", sealed_header.len());

        // Wrap stream with VMess encryption
        // Header will be sent together with first payload (like v2ray's BufferedWriter)
        // Response header will be read lazily on first read
        let security = self.config.security.resolve();
        
        debug!(
            "VMess stream keys: request_key={:02x?}, request_iv={:02x?}",
            &request_body_key[..8], &request_body_iv[..8]
        );
        
        let vmess_stream = VmessStream::client(
            stream,
            security,
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            sealed_header,
            response_header[0],
        );

        // Note: Response header will be read on first read from the stream
        // This matches v2ray's behavior where request and response are handled concurrently
        debug!("VMess stream created with pending header, response will be read on first read");

        Ok(Box::new(vmess_stream))
    }

    /// Build VMess request header
    fn build_request_header(
        &self,
        metadata: &Metadata,
        request_body_key: &[u8; 16],
        request_body_iv: &[u8; 16],
        response_header: u8,
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(128);

        // Version
        buf.push(VMESS_VERSION);

        // Request Body IV (16 bytes)
        buf.extend_from_slice(request_body_iv);

        // Request Body Key (16 bytes)
        buf.extend_from_slice(request_body_key);

        // Response Header (1 byte)
        buf.push(response_header);

        // Options
        let mut options = REQUEST_OPTION_CHUNK_STREAM;
        let security = self.config.security.resolve();

        // ChunkMasking is enabled for AES-GCM, ChaCha20, and None
        if matches!(
            security,
            Security::Aes128Gcm | Security::Chacha20Poly1305 | Security::None
        ) {
            options |= REQUEST_OPTION_CHUNK_MASKING;
        }
        
        // GlobalPadding is ONLY enabled for AEAD security types (not None!)
        // See v2ray shouldEnablePadding(): only AES-GCM, ChaCha20, AUTO
        if matches!(
            security,
            Security::Aes128Gcm | Security::Chacha20Poly1305
        ) {
            options |= REQUEST_OPTION_GLOBAL_PADDING;
        }
        buf.push(options);
        
        debug!("VMess header: version={}, options=0x{:02x}, security={:?}", VMESS_VERSION, options, security);

        // Padding length (4 bits) + Security (4 bits)
        let padding_len = rand::random::<u8>() % 16;
        let security_byte = (padding_len << 4) | security.to_byte();
        buf.push(security_byte);
        
        debug!("VMess header: padding_len={}, security_byte=0x{:02x}", padding_len, security_byte);

        // Reserved (1 byte)
        buf.push(0);

        // Command
        let command = match metadata.network {
            Network::Tcp => COMMAND_TCP,
            Network::Udp => COMMAND_UDP,
        };
        buf.push(command);
        
        debug!("VMess header: command={} ({})", command, if command == 1 { "TCP" } else { "UDP" });

        // Address
        self.write_address(&mut buf, &metadata.destination)?;

        // Padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len as usize];
            rand::thread_rng().fill_bytes(&mut padding);
            buf.extend_from_slice(&padding);
        }

        // FNV1a hash (4 bytes)
        let hash = fnv1a_hash(&buf);
        buf.extend_from_slice(&hash.to_be_bytes());
        
        debug!("VMess header: fnv_hash=0x{:08x}, total_len={}", hash, buf.len());

        Ok(buf)
    }

    /// Write address in VMess format (port first, then address)
    fn write_address(&self, buf: &mut Vec<u8>, addr: &Address) -> Result<()> {
        // Port (2 bytes, big endian)
        buf.extend_from_slice(&addr.port().to_be_bytes());

        match addr {
            Address::Socket(socket_addr) => match socket_addr {
                SocketAddr::V4(v4) => {
                    buf.push(ADDR_TYPE_IPV4);
                    buf.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    buf.push(ADDR_TYPE_IPV6);
                    buf.extend_from_slice(&v6.ip().octets());
                }
            },
            Address::Domain(domain, _) => {
                buf.push(ADDR_TYPE_DOMAIN);
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > 255 {
                    return Err(Error::Protocol("Domain too long".into()));
                }
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
            }
        }

        Ok(())
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
