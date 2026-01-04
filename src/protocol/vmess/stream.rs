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
// Incremental Buffer Reader
// ============================================================================

/// Helper for incrementally reading exact bytes from async stream.
struct BufReader<const N: usize> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> BufReader<N> {
    fn new() -> Self {
        Self { buf: [0u8; N], pos: 0 }
    }

    /// Poll read until buffer is full. Returns `Poll::Ready(Ok(()))` when complete.
    fn poll_fill(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut Stream,
    ) -> Poll<io::Result<()>> {
        while self.pos < N {
            let mut temp = ReadBuf::new(&mut self.buf[self.pos..]);
            match Pin::new(&mut *inner).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(())) => {
                    let n = temp.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(eof_error("buffer fill")));
                    }
                    self.pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Check if reading just started (for EOF detection).
    fn is_empty(&self) -> bool {
        self.pos == 0
    }

    fn data(&self) -> &[u8; N] {
        &self.buf
    }
}

/// Dynamic buffer for variable-length reads.
struct DynBufReader {
    buf: Vec<u8>,
    pos: usize,
}

impl DynBufReader {
    fn with_capacity(len: usize) -> Self {
        Self { buf: vec![0u8; len], pos: 0 }
    }

    fn poll_fill(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut Stream,
    ) -> Poll<io::Result<()>> {
        while self.pos < self.buf.len() {
            let mut temp = ReadBuf::new(&mut self.buf[self.pos..]);
            match Pin::new(&mut *inner).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(())) => {
                    let n = temp.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(eof_error("dynamic buffer fill")));
                    }
                    self.pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn take(self) -> Vec<u8> {
        self.buf
    }
}

// ============================================================================
// State Types
// ============================================================================

/// Response header reading state (client-side only).
enum ResponseHeaderState {
    ReadingLength(BufReader<18>),
    ReadingPayload(DynBufReader),
    Done,
}

/// Chunk reading state.
enum ChunkReadState {
    ReadingLength(BufReader<2>),
    ReadingData { padding: u16, reader: DynBufReader },
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
    write_ctx: CryptoContext,
    pending_header: Option<Vec<u8>>,

    // Read state
    read_ctx: CryptoContext,
    read_buf: Vec<u8>,
    read_pos: usize,

    // State machines
    response_state: ResponseHeaderState,
    chunk_state: ChunkReadState,
    expected_response: Option<u8>,
}

/// Crypto context for read/write operations.
struct CryptoContext {
    key: [u8; 16],
    iv: [u8; 16],
    nonce_count: u16,
    shake: Option<ShakeMask>,
}

impl CryptoContext {
    fn new(key: [u8; 16], iv: [u8; 16], use_masking: bool) -> Self {
        Self {
            key,
            iv,
            nonce_count: 0,
            shake: if use_masking { Some(ShakeMask::new(&iv)) } else { None },
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.nonce_count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        self.nonce_count = self.nonce_count.wrapping_add(1);
        nonce
    }

    fn next_mask(&mut self) -> u16 {
        self.shake.as_mut().map(|s| s.next_mask()).unwrap_or(0)
    }

    fn next_padding(&mut self) -> u16 {
        self.shake.as_mut().map(|s| s.next_padding_len()).unwrap_or(0)
    }
}

impl VmessStream {
    /// Create client-side stream (needs to read response header).
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
        let use_padding = matches!(security, Security::Aes128Gcm | Security::Chacha20Poly1305);
        Self {
            inner,
            security,
            use_padding,
            write_ctx: CryptoContext::new(request_key, request_iv, true),
            pending_header: Some(pending_header),
            read_ctx: CryptoContext::new(response_key, response_iv, true),
            read_buf: Vec::new(),
            read_pos: 0,
            response_state: ResponseHeaderState::ReadingLength(BufReader::new()),
            chunk_state: ChunkReadState::ReadingLength(BufReader::new()),
            expected_response: Some(expected_response),
        }
    }

    /// Create server-side stream (response header already sent).
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
            write_ctx: CryptoContext::new(response_key, response_iv, use_masking),
            pending_header: None,
            read_ctx: CryptoContext::new(request_key, request_iv, use_masking),
            read_buf: Vec::new(),
            read_pos: 0,
            response_state: ResponseHeaderState::Done,
            chunk_state: ChunkReadState::ReadingLength(BufReader::new()),
            expected_response: None,
        }
    }
}

// ============================================================================
// Encryption
// ============================================================================

impl VmessStream {
    fn encrypt_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let padding = if self.use_padding { self.write_ctx.next_padding() } else { 0 };
        let (size, tag_size) = match self.security {
            Security::Aes128Gcm | Security::Chacha20Poly1305 => {
                (data.len() as u16 + TAG_SIZE as u16 + padding, TAG_SIZE)
            }
            _ => (data.len() as u16, 0),
        };
        let masked_len = size ^ self.write_ctx.next_mask();

        let mut chunk = Vec::with_capacity(2 + data.len() + tag_size + padding as usize);
        chunk.extend_from_slice(&masked_len.to_be_bytes());

        match self.security {
            Security::Aes128Gcm => {
                let ct = self.aead_encrypt::<Aes128Gcm>(&self.write_ctx.key.clone(), data)?;
                chunk.extend_from_slice(&ct);
            }
            Security::Chacha20Poly1305 => {
                let key = generate_chacha_key(&self.write_ctx.key);
                let ct = self.aead_encrypt::<ChaCha20Poly1305>(&key, data)?;
                chunk.extend_from_slice(&ct);
            }
            _ => chunk.extend_from_slice(data),
        }

        chunk.resize(chunk.len() + padding as usize, 0);
        Ok(chunk)
    }

    fn aead_encrypt<C: KeyInit + Aead>(&mut self, key: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.write_ctx.next_nonce();
        C::new_from_slice(key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
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
                if ct_len < TAG_SIZE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "ciphertext too short"));
                }
                self.aead_decrypt::<Aes128Gcm>(&self.read_ctx.key.clone(), &data[..ct_len])
            }
            Security::Chacha20Poly1305 => {
                if ct_len < TAG_SIZE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "ciphertext too short"));
                }
                let key = generate_chacha_key(&self.read_ctx.key);
                self.aead_decrypt::<ChaCha20Poly1305>(&key, &data[..ct_len])
            }
            _ => Ok(data[..ct_len].to_vec()),
        }
    }

    fn aead_decrypt<C: KeyInit + Aead>(&mut self, key: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.read_ctx.next_nonce();
        C::new_from_slice(key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .decrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn decode_length(&mut self, buf: &[u8; 2]) -> (u16, u16) {
        let masked = u16::from_be_bytes(*buf);
        let padding = if self.use_padding { self.read_ctx.next_padding() } else { 0 };
        let length = masked ^ self.read_ctx.next_mask();
        (padding, length)
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

                ResponseHeaderState::ReadingLength(reader) => {
                    if let Poll::Pending = reader.poll_fill(cx, &mut self.inner)? {
                        return Poll::Pending;
                    }
                    let length = open_aead_response_header(
                        &self.read_ctx.key,
                        &self.read_ctx.iv,
                        reader.data(),
                    ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

                    if length > 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "response header too large",
                        )));
                    }
                    debug!("VMess response header length: {}", length);
                    self.response_state = ResponseHeaderState::ReadingPayload(
                        DynBufReader::with_capacity(length as usize + 16),
                    );
                }

                ResponseHeaderState::ReadingPayload(reader) => {
                    if let Poll::Pending = reader.poll_fill(cx, &mut self.inner)? {
                        return Poll::Pending;
                    }
                    let buf = std::mem::replace(
                        reader,
                        DynBufReader::with_capacity(0),
                    ).take();
                    let payload = open_aead_response_payload(
                        &self.read_ctx.key,
                        &self.read_ctx.iv,
                        &buf,
                    ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

                    if let Some(expected) = self.expected_response {
                        if payload.is_empty() || payload[0] != expected {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "response header mismatch",
                            )));
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
                ChunkReadState::ReadingLength(reader) => {
                    // Check for clean EOF at chunk boundary
                    if reader.is_empty() {
                        let mut peek_buf = [0u8; 1];
                        let mut temp = ReadBuf::new(&mut peek_buf);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut temp) {
                            Poll::Ready(Ok(())) if temp.filled().is_empty() => {
                                return Poll::Ready(Ok(None)); // Clean EOF
                            }
                            Poll::Ready(Ok(())) => {
                                // Got one byte, store it and continue
                                if let ChunkReadState::ReadingLength(r) = &mut self.chunk_state {
                                    r.buf[0] = peek_buf[0];
                                    r.pos = 1;
                                }
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Continue reading length bytes
                    if let ChunkReadState::ReadingLength(reader) = &mut self.chunk_state {
                        if let Poll::Pending = reader.poll_fill(cx, &mut self.inner)? {
                            return Poll::Pending;
                        }
                        let buf = *reader.data();
                        let (padding, length) = self.decode_length(&buf);
                        debug!("VMess chunk: length={}, padding={}", length, padding);

                        if length == 0 {
                            return Poll::Ready(Ok(None)); // End of stream marker
                        }

                        self.chunk_state = ChunkReadState::ReadingData {
                            padding,
                            reader: DynBufReader::with_capacity(length as usize),
                        };
                    }
                }

                ChunkReadState::ReadingData { padding, reader } => {
                    if let Poll::Pending = reader.poll_fill(cx, &mut self.inner)? {
                        return Poll::Pending;
                    }

                    let pad = *padding;
                    let data = std::mem::replace(
                        reader,
                        DynBufReader::with_capacity(0),
                    ).take();
                    self.chunk_state = ChunkReadState::ReadingLength(BufReader::new());

                    let decrypted = self.decrypt_chunk(&data, pad)?;
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        let size = buf.len().min(MAX_CHUNK_SIZE);
        let encrypted = this.encrypt_chunk(&buf[..size])?;

        let to_write = match this.pending_header.take() {
            Some(mut h) => {
                h.extend_from_slice(&encrypted);
                h
            }
            None => encrypted,
        };

        match Pin::new(&mut this.inner).poll_write(cx, &to_write) {
            Poll::Ready(Ok(n)) if n == to_write.len() => Poll::Ready(Ok(size)),
            Poll::Ready(Ok(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "partial write")))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let term = this.write_ctx.next_mask().to_be_bytes();
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
