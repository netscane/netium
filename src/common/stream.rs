//! Stream abstraction
//!
//! Unified stream type for all layers to operate on.
//! All layers ONLY operate on Stream, never on raw TCP/UDP.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The core stream type used throughout the application.
/// All layers operate on this unified abstraction.
pub type Stream = Box<dyn AsyncReadWrite + Unpin + Send>;

/// Boxed stream alias for clarity
pub type BoxedStream = Stream;

/// Combined trait for async read + write
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Trait for types that can be converted into a Stream
pub trait IntoStream {
    fn into_stream(self) -> Stream;
}

impl<T> IntoStream for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn into_stream(self) -> Stream {
        Box::new(self)
    }
}

/// A wrapper that combines separate read and write halves into a single stream
pub struct CombinedStream<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> CombinedStream<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R, W> AsyncRead for CombinedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for CombinedStream<R, W>
where
    R: Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
