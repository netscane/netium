//! Pipe - Bidirectional data channel with proper lifecycle management
//!
//! A Pipe represents a bidirectional data flow with:
//! - Independent read/write halves
//! - Automatic shutdown propagation
//! - Cancellation support
//! - Metrics integration
//!
//! This is netium's answer to V2Ray's Link, but with Rust's safety guarantees.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Notify;

use super::stream::Stream;

/// Default buffer size for relay operations (32KB)
const RELAY_BUFFER_SIZE: usize = 32 * 1024;

/// A bidirectional data pipe with lifecycle management.
///
/// Unlike a raw Stream, Pipe provides:
/// - Separate read/write control
/// - Graceful shutdown propagation (when one side closes, the other is notified)
/// - Cancellation support
pub struct Pipe {
    pub reader: PipeReader,
    pub writer: PipeWriter,
}

/// Shared state for shutdown coordination
struct PipeState {
    /// Set when read side is done (EOF or error)
    read_done: AtomicBool,
    /// Set when write side is done (shutdown or error)
    write_done: AtomicBool,
    /// Set when pipe should be cancelled
    cancelled: AtomicBool,
    /// Notify waiters when state changes
    notify: Notify,
}

impl PipeState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            read_done: AtomicBool::new(false),
            write_done: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    fn mark_read_done(&self) {
        self.read_done.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn mark_write_done(&self) {
        self.write_done.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn is_read_done(&self) -> bool {
        self.read_done.load(Ordering::SeqCst)
    }

    fn is_write_done(&self) -> bool {
        self.write_done.load(Ordering::SeqCst)
    }
}

/// Read half of a Pipe
pub struct PipeReader {
    inner: ReadHalf<Stream>,
    state: Arc<PipeState>,
}

/// Write half of a Pipe
pub struct PipeWriter {
    inner: WriteHalf<Stream>,
    state: Arc<PipeState>,
}

impl Pipe {
    /// Create a new Pipe from a Stream
    pub fn from_stream(stream: Stream) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        let state = PipeState::new();

        Self {
            reader: PipeReader {
                inner: read_half,
                state: Arc::clone(&state),
            },
            writer: PipeWriter {
                inner: write_half,
                state,
            },
        }
    }

    /// Split into reader and writer (consumes self)
    pub fn split(self) -> (PipeReader, PipeWriter) {
        (self.reader, self.writer)
    }

    /// Cancel the pipe (both sides will return errors)
    pub fn cancel(&self) {
        self.reader.state.cancel();
    }

    /// Check if pipe is cancelled
    pub fn is_cancelled(&self) -> bool {
        self.reader.state.is_cancelled()
    }
}

impl PipeReader {
    /// Check if the write side is done
    pub fn is_write_done(&self) -> bool {
        self.state.is_write_done()
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.state.is_cancelled()
    }

    /// Wait until write side is done or cancelled
    pub async fn wait_write_done(&self) {
        while !self.state.is_write_done() && !self.state.is_cancelled() {
            self.state.notify.notified().await;
        }
    }
}

impl PipeWriter {
    /// Check if the read side is done
    pub fn is_read_done(&self) -> bool {
        self.state.is_read_done()
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.state.is_cancelled()
    }

    /// Wait until read side is done or cancelled
    pub async fn wait_read_done(&self) {
        while !self.state.is_read_done() && !self.state.is_cancelled() {
            self.state.notify.notified().await;
        }
    }
}

impl AsyncRead for PipeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.state.is_cancelled() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "pipe cancelled",
            )));
        }

        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        // Mark read done on EOF (no bytes read) or error
        if let Poll::Ready(ref r) = result {
            let bytes_read = buf.filled().len() - before;
            if r.is_err() || bytes_read == 0 {
                self.state.mark_read_done();
            }
        }

        result
    }
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.state.is_cancelled() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "pipe cancelled",
            )));
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.state.is_cancelled() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "pipe cancelled",
            )));
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);

        if let Poll::Ready(_) = result {
            self.state.mark_write_done();
        }

        result
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.state.mark_read_done();
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.state.mark_write_done();
    }
}

/// Relay data between two Pipes with proper error handling and metrics
pub async fn relay(inbound: Pipe, outbound: Pipe) -> (u64, u64) {
    let (mut in_reader, mut in_writer) = inbound.split();
    let (mut out_reader, mut out_writer) = outbound.split();

    // Use tokio::select! for proper cancellation
    let upload = async {
        let mut total = 0u64;
        let mut buf = BytesMut::with_capacity(RELAY_BUFFER_SIZE);
        buf.resize(RELAY_BUFFER_SIZE, 0);

        loop {
            let n = match in_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            if out_writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
            // Flush to ensure data is sent immediately
            if out_writer.flush().await.is_err() {
                break;
            }

            total += n as u64;
        }

        // Always try to shutdown
        let _ = out_writer.shutdown().await;
        total
    };

    let download = async {
        let mut total = 0u64;
        let mut buf = BytesMut::with_capacity(RELAY_BUFFER_SIZE);
        buf.resize(RELAY_BUFFER_SIZE, 0);

        loop {
            let n = match out_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            if in_writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
            // Flush to ensure data is sent immediately
            if in_writer.flush().await.is_err() {
                break;
            }

            total += n as u64;
        }

        // Always try to shutdown
        let _ = in_writer.shutdown().await;
        total
    };

    tokio::join!(upload, download)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_pipe_cancel() {
        let (client, server) = tokio::io::duplex(1024);
        let pipe = Pipe::from_stream(Box::new(client));

        assert!(!pipe.is_cancelled());
        pipe.cancel();
        assert!(pipe.is_cancelled());

        // Reading should fail after cancel
        let (mut reader, _writer) = pipe.split();
        let mut buf = [0u8; 10];
        let result = reader.read(&mut buf).await;
        assert!(result.is_err());

        drop(server);
    }

    #[tokio::test]
    async fn test_pipe_state_propagation() {
        let (client, _server) = tokio::io::duplex(1024);
        let pipe = Pipe::from_stream(Box::new(client));
        let (reader, writer) = pipe.split();

        assert!(!reader.is_write_done());
        assert!(!writer.is_read_done());

        drop(reader);
        // After dropping reader, write side should see read_done
        assert!(writer.is_read_done());
    }
}
