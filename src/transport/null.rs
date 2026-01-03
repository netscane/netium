//! Null Transports - Blackhole and Reject
//!
//! Special transports that don't establish real connections:
//! - **BlackholeTransport**: Returns a stream that silently discards all data
//! - **RejectTransport**: Immediately returns an error on connect

use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use crate::common::{Address, Result, Stream};
use crate::error::Error;

use super::{Listener, Transport};

// ============================================================================
// BlackholeTransport
// ============================================================================

/// Blackhole transport - returns a stream that silently discards all data
pub struct BlackholeTransport {
    timeout: Duration,
}

impl BlackholeTransport {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes default
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Default for BlackholeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for BlackholeTransport {
    async fn connect(&self, _addr: &Address) -> Result<Stream> {
        Ok(Box::new(BlackholeStream::new(self.timeout)))
    }

    async fn bind(&self, _addr: &Address) -> Result<Box<dyn Listener>> {
        Err(Error::Config("Blackhole transport cannot bind".into()))
    }
}

/// A stream that silently discards all writes and never returns data
struct BlackholeStream {
    timeout: Pin<Box<Sleep>>,
    timed_out: bool,
}

impl BlackholeStream {
    fn new(timeout: Duration) -> Self {
        Self {
            timeout: Box::pin(tokio::time::sleep(timeout)),
            timed_out: false,
        }
    }
}

impl AsyncRead for BlackholeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.timed_out {
            return Poll::Ready(Ok(())); // EOF
        }

        // Wait for timeout, then return EOF
        match self.timeout.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.timed_out = true;
                Poll::Ready(Ok(())) // EOF after timeout
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for BlackholeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Silently discard all data
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// RejectTransport
// ============================================================================

/// Reject transport - immediately fails on connect
pub struct RejectTransport;

impl RejectTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RejectTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for RejectTransport {
    async fn connect(&self, _addr: &Address) -> Result<Stream> {
        Err(Error::Io(io::Error::new(
            ErrorKind::ConnectionRefused,
            "connection rejected",
        )))
    }

    async fn bind(&self, _addr: &Address) -> Result<Box<dyn Listener>> {
        Err(Error::Config("Reject transport cannot bind".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_blackhole_discards_writes() {
        let transport = BlackholeTransport::new();
        let mut stream = transport
            .connect(&Address::domain("example.com".to_string(), 80))
            .await
            .unwrap();

        // Writes should succeed but data is discarded
        let written = stream.write(b"hello world").await.unwrap();
        assert_eq!(written, 11);
    }

    #[tokio::test]
    async fn test_blackhole_timeout() {
        let transport = BlackholeTransport::new().with_timeout(Duration::from_millis(10));
        let mut stream = transport
            .connect(&Address::domain("example.com".to_string(), 80))
            .await
            .unwrap();

        // Read should return EOF after timeout
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[tokio::test]
    async fn test_reject_fails_immediately() {
        let transport = RejectTransport::new();
        let result = transport
            .connect(&Address::domain("example.com".to_string(), 80))
            .await;

        assert!(result.is_err());
    }
}
