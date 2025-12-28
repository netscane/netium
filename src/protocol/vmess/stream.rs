//! VMess Encrypted Stream
//!
//! Implements the VMess chunk-based encryption for data transfer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use sha3::{Shake128, digest::{ExtendableOutput, Update, XofReader}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::common::Stream;

use super::aead::{open_aead_response_header, open_aead_response_payload};
use super::Security;

const MAX_CHUNK_SIZE: usize = 16 * 1024 - 1;
const TAG_SIZE: usize = 16;

// ============================================================================
// Helper macro for poll_read pattern
// ============================================================================

macro_rules! poll_read_buf {
    ($inner:expr, $cx:expr, $buf:expr, $pos:expr) => {{
        let mut temp = ReadBuf::new(&mut $buf[$pos..]);
        match Pin::new(&mut $inner).poll_read($cx, &mut temp) {
            Poll::Ready(Ok(())) => temp.filled().len(),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }};
}

// ============================================================================
// State Types
// ============================================================================

#[derive(Debug)]
enum ResponseHeaderState {
    ReadingLength { buf: [u8; 18], pos: usize },
    ReadingPayload { length: u16, buf: Vec<u8>, pos: usize },
    Done,
}

#[derive(Debug)]
enum ChunkReadState {
    ReadingLength { buf: [u8; 2], pos: usize },
    ReadingData { length: u16, padding_len: u16, buf: Vec<u8>, pos: usize },
}

// ============================================================================
// VmessStream - Unified stream for both client and server
// ============================================================================

/// VMess encrypted stream for both client and server sides.
/// 
/// - Client: reads response header first, then chunks
/// - Server: reads chunks directly (response header already sent)
pub struct VmessStream {
    inner: Stream,
    security: Security,
    use_padding: bool,

    // Write state
    write_key: [u8; 16],
    write_iv: [u8; 16],
    write_nonce_count: u16,
    write_shake: Option<ShakeMask>,
    pending_header: Option<Vec<u8>>,

    // Read state
    read_key: [u8; 16],
    read_iv: [u8; 16],
    read_nonce_count: u16,
    read_shake: Option<ShakeMask>,
    read_buf: Vec<u8>,
    read_pos: usize,

    // State machines
    response_state: ResponseHeaderState,
    chunk_state: ChunkReadState,
    expected_response: Option<u8>,
}

impl VmessStream {
    /// Create client-side stream (needs to read response header)
    pub fn client(
        inner: Stream,
        security: Security,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        pending_header: Vec<u8>,
        expected_response: u8,
    ) -> Self {
        Self {
            inner,
            security,
            use_padding: matches!(security, Security::Aes128Gcm | Security::Chacha20Poly1305),
            // Client writes with request keys
            write_key: request_key,
            write_iv: request_iv,
            write_nonce_count: 0,
            write_shake: Some(ShakeMask::new(&request_iv)),
            pending_header: Some(pending_header),
            // Client reads with response keys
            read_key: response_key,
            read_iv: response_iv,
            read_nonce_count: 0,
            read_shake: Some(ShakeMask::new(&response_iv)),
            read_buf: Vec::new(),
            read_pos: 0,
            response_state: ResponseHeaderState::ReadingLength { buf: [0u8; 18], pos: 0 },
            chunk_state: ChunkReadState::ReadingLength { buf: [0u8; 2], pos: 0 },
            expected_response: Some(expected_response),
        }
    }

    /// Create server-side stream (response header already sent)
    pub fn server(
        inner: Stream,
        security: Security,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        options: u8,
    ) -> Self {
        let use_masking = (options & 0x04) != 0;
        let use_padding = (options & 0x08) != 0;

        Self {
            inner,
            security,
            use_padding,
            // Server writes with response keys
            write_key: response_key,
            write_iv: response_iv,
            write_nonce_count: 0,
            write_shake: if use_masking { Some(ShakeMask::new(&response_iv)) } else { None },
            pending_header: None,
            // Server reads with request keys
            read_key: request_key,
            read_iv: request_iv,
            read_nonce_count: 0,
            read_shake: if use_masking { Some(ShakeMask::new(&request_iv)) } else { None },
            read_buf: Vec::new(),
            read_pos: 0,
            response_state: ResponseHeaderState::Done, // Server doesn't read response header
            chunk_state: ChunkReadState::ReadingLength { buf: [0u8; 2], pos: 0 },
            expected_response: None,
        }
    }
}

// ============================================================================
// Encryption
// ============================================================================

impl VmessStream {
    fn encrypt_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let (padding, masked_len) = self.encode_length(data.len(), true);
        let mut chunk = Vec::with_capacity(2 + data.len() + padding as usize + TAG_SIZE);
        chunk.extend_from_slice(&masked_len.to_be_bytes());

        match self.security {
            Security::Aes128Gcm => {
                let key = self.write_key;
                let ct = self.aead_encrypt::<Aes128Gcm>(&key, data)?;
                chunk.extend_from_slice(&ct);
            }
            Security::Chacha20Poly1305 => {
                let key = generate_chacha_key(&self.write_key);
                let ct = self.aead_encrypt::<ChaCha20Poly1305>(&key, data)?;
                chunk.extend_from_slice(&ct);
            }
            _ => chunk.extend_from_slice(data),
        }

        chunk.resize(chunk.len() + padding as usize, 0);
        Ok(chunk)
    }

    fn aead_encrypt<C: KeyInit + Aead>(&mut self, key: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_write_nonce();
        C::new_from_slice(key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn encode_length(&mut self, data_len: usize, is_write: bool) -> (u16, u16) {
        let shake = if is_write { &mut self.write_shake } else { &mut self.read_shake };
        match self.security {
            Security::Aes128Gcm | Security::Chacha20Poly1305 => {
                let padding = if self.use_padding {
                    shake.as_mut().map(|s| s.next_padding_len()).unwrap_or(0)
                } else {
                    0
                };
                let size = data_len as u16 + TAG_SIZE as u16 + padding;
                let masked = shake.as_mut().map(|s| size ^ s.next_mask()).unwrap_or(size);
                (padding, masked)
            }
            _ => {
                let size = data_len as u16;
                let masked = shake.as_mut().map(|s| size ^ s.next_mask()).unwrap_or(size);
                (0, masked)
            }
        }
    }

    fn next_write_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.write_nonce_count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.write_iv[2..12]);
        self.write_nonce_count = self.write_nonce_count.wrapping_add(1);
        nonce
    }
}

// ============================================================================
// Decryption
// ============================================================================

impl VmessStream {
    fn decrypt_chunk(&mut self, data: &[u8], padding: u16) -> io::Result<Vec<u8>> {
        let ct_len = data.len().saturating_sub(padding as usize);
        match self.security {
            Security::Aes128Gcm => {
                if ct_len < TAG_SIZE { return Err(io::Error::new(io::ErrorKind::InvalidData, "too short")); }
                self.aead_decrypt::<Aes128Gcm>(&self.read_key.clone(), &data[..ct_len])
            }
            Security::Chacha20Poly1305 => {
                if ct_len < TAG_SIZE { return Err(io::Error::new(io::ErrorKind::InvalidData, "too short")); }
                let key = generate_chacha_key(&self.read_key);
                self.aead_decrypt::<ChaCha20Poly1305>(&key, &data[..ct_len])
            }
            _ => Ok(data[..ct_len].to_vec()),
        }
    }

    fn aead_decrypt<C: KeyInit + Aead>(&mut self, key: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_read_nonce();
        C::new_from_slice(key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .decrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn decode_length(&mut self, buf: &[u8; 2]) -> (u16, u16) {
        let masked = u16::from_be_bytes(*buf);
        match self.security {
            Security::Aes128Gcm | Security::Chacha20Poly1305 => {
                let padding = if self.use_padding {
                    self.read_shake.as_mut().map(|s| s.next_padding_len()).unwrap_or(0)
                } else {
                    0
                };
                let length = self.read_shake.as_mut().map(|s| masked ^ s.next_mask()).unwrap_or(masked);
                (padding, length)
            }
            _ => {
                let length = self.read_shake.as_mut().map(|s| masked ^ s.next_mask()).unwrap_or(masked);
                (0, length)
            }
        }
    }

    fn next_read_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.read_nonce_count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.read_iv[2..12]);
        self.read_nonce_count = self.read_nonce_count.wrapping_add(1);
        nonce
    }
}

// ============================================================================
// AsyncRead - Response Header
// ============================================================================

impl VmessStream {
    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.response_state {
                ResponseHeaderState::Done => return Poll::Ready(Ok(())),
                
                ResponseHeaderState::ReadingLength { buf, pos } => {
                    let n = poll_read_buf!(self.inner, cx, buf, *pos);
                    if n == 0 { return Poll::Ready(Err(eof_error("response header"))); }
                    *pos += n;
                    if *pos < 18 { continue; }
                    
                    let length = open_aead_response_header(&self.read_key, &self.read_iv, buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    
                    if length > 1024 {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "header too large")));
                    }
                    
                    debug!("VMess response header length: {}", length);
                    self.response_state = ResponseHeaderState::ReadingPayload {
                        length,
                        buf: vec![0u8; length as usize + 16],
                        pos: 0,
                    };
                }
                
                ResponseHeaderState::ReadingPayload { length, buf, pos } => {
                    let expected = *length as usize + 16;
                    let n = poll_read_buf!(self.inner, cx, buf, *pos);
                    if n == 0 { return Poll::Ready(Err(eof_error("response payload"))); }
                    *pos += n;
                    if *pos < expected { continue; }
                    
                    let payload = open_aead_response_payload(&self.read_key, &self.read_iv, buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    
                    if let Some(expected_byte) = self.expected_response {
                        if payload.is_empty() || payload[0] != expected_byte {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "header mismatch")));
                        }
                    }
                    
                    debug!("VMess response header verified");
                    self.response_state = ResponseHeaderState::Done;
                }
            }
        }
    }
}

// ============================================================================
// AsyncRead - Chunk Reading
// ============================================================================

impl VmessStream {
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            match &mut self.chunk_state {
                ChunkReadState::ReadingLength { buf, pos } => {
                    let n = poll_read_buf!(self.inner, cx, buf, *pos);
                    if n == 0 && *pos == 0 { return Poll::Ready(Ok(None)); } // EOF
                    if n == 0 { return Poll::Ready(Err(eof_error("chunk length"))); }
                    *pos += n;
                    if *pos < 2 { continue; }
                    
                    let buf_copy = *buf;
                    let (padding, length) = self.decode_length(&buf_copy);
                    debug!("VMess chunk: length={}, padding={}", length, padding);
                    
                    if length == 0 { return Poll::Ready(Ok(None)); }
                    
                    self.chunk_state = ChunkReadState::ReadingData {
                        length,
                        padding_len: padding,
                        buf: vec![0u8; length as usize],
                        pos: 0,
                    };
                }
                
                ChunkReadState::ReadingData { length, padding_len, buf, pos } => {
                    let expected = *length as usize;
                    let n = poll_read_buf!(self.inner, cx, buf, *pos);
                    if n == 0 { return Poll::Ready(Err(eof_error("chunk data"))); }
                    *pos += n;
                    if *pos < expected { continue; }
                    
                    let padding = *padding_len;
                    let data = std::mem::take(buf);
                    self.chunk_state = ChunkReadState::ReadingLength { buf: [0u8; 2], pos: 0 };
                    
                    let decrypted = self.decrypt_chunk(&data, padding)?;
                    debug!("VMess decrypted {} bytes", decrypted.len());
                    return Poll::Ready(Ok(Some(decrypted)));
                }
            }
        }
    }
}

// ============================================================================
// AsyncRead Implementation
// ============================================================================

impl AsyncRead for VmessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        
        // 1. Response header
        if let Poll::Pending = this.poll_response_header(cx)? {
            return Poll::Pending;
        }

        // 2. Buffered data
        if this.read_pos < this.read_buf.len() {
            let n = copy_to_buf(&this.read_buf[this.read_pos..], buf);
            this.read_pos += n;
            return Poll::Ready(Ok(()));
        }
        this.read_buf.clear();
        this.read_pos = 0;

        // 3. Read chunk
        match this.poll_chunk(cx)? {
            Poll::Ready(Some(data)) => {
                let n = copy_to_buf(&data, buf);
                if n < data.len() {
                    this.read_buf = data;
                    this.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ============================================================================
// AsyncWrite Implementation
// ============================================================================

impl AsyncWrite for VmessStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() { return Poll::Ready(Ok(0)); }

        let this = self.get_mut();
        let size = buf.len().min(MAX_CHUNK_SIZE);
        let encrypted = this.encrypt_chunk(&buf[..size])?;

        let to_write = match this.pending_header.take() {
            Some(mut h) => { h.extend_from_slice(&encrypted); h }
            None => encrypted,
        };

        match Pin::new(&mut this.inner).poll_write(cx, &to_write) {
            Poll::Ready(Ok(n)) if n == to_write.len() => Poll::Ready(Ok(size)),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "partial write"))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let term = this.write_shake.as_mut().map(|s| s.next_mask().to_be_bytes().to_vec()).unwrap_or(vec![0, 0]);
        match Pin::new(&mut this.inner).poll_write(cx, &term) {
            Poll::Ready(Ok(_)) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn eof_error(ctx: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, format!("connection closed while reading {}", ctx))
}

fn copy_to_buf(src: &[u8], dst: &mut ReadBuf<'_>) -> usize {
    let n = src.len().min(dst.remaining());
    dst.put_slice(&src[..n]);
    n
}

struct ShakeMask {
    reader: Box<dyn XofReader + Send>,
}

impl ShakeMask {
    fn new(nonce: &[u8]) -> Self {
        let mut shake = Shake128::default();
        shake.update(nonce);
        Self { reader: Box::new(shake.finalize_xof()) }
    }

    fn next_mask(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }

    fn next_padding_len(&mut self) -> u16 {
        self.next_mask() % 64
    }
}

fn generate_chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let h1 = md5::compute(key);
    result[..16].copy_from_slice(&h1.0);
    let h2 = md5::compute(&result[..16]);
    result[16..].copy_from_slice(&h2.0);
    result
}
