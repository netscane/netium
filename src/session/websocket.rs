//! WebSocket Session implementation

use async_trait::async_trait;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, SinkExt, Stream as FuturesStream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    accept_async_with_config,
    client_async_with_config,
    tungstenite::{
        handshake::client::Request,
        protocol::{Message, WebSocketConfig as TungsteniteConfig},
    },
    WebSocketStream,
};
use tracing::{debug, trace};

use crate::common::{Result, Stream};
use crate::error::Error;

use super::{Session, WebSocketConfig};

/// WebSocket session for framing streams
pub struct WebSocketSession {
    config: WebSocketConfig,
}

impl WebSocketSession {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Session for WebSocketSession {
    async fn wrap_client(&self, stream: Stream) -> Result<Stream> {
        let host = self
            .config
            .host
            .clone()
            .unwrap_or_else(|| "localhost".to_string());

        let uri = format!("ws://{}{}", host, self.config.path);

        let mut request = Request::builder()
            .uri(&uri)
            .header("Host", &host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            );

        // Add custom headers
        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let request = request
            .body(())
            .map_err(|e| Error::Protocol(format!("Failed to build WebSocket request: {}", e)))?;

        let ws_config = TungsteniteConfig {
            max_message_size: Some(64 << 20), // 64 MB
            max_frame_size: Some(16 << 20),   // 16 MB
            ..Default::default()
        };

        let (ws_stream, _response) =
            client_async_with_config(request, StreamWrapper(stream), Some(ws_config))
                .await
                .map_err(|e| Error::Protocol(format!("WebSocket handshake failed: {}", e)))?;

        Ok(Box::new(WebSocketStreamWrapper::new(ws_stream)))
    }

    async fn wrap_server(&self, stream: Stream) -> Result<Stream> {
        let ws_config = TungsteniteConfig {
            max_message_size: Some(64 << 20), // 64 MB
            max_frame_size: Some(16 << 20),   // 16 MB
            ..Default::default()
        };

        debug!("WebSocket server: accepting connection on path {}", self.config.path);
        
        let ws_stream = accept_async_with_config(StreamWrapper(stream), Some(ws_config))
            .await
            .map_err(|e| Error::Protocol(format!("WebSocket handshake failed: {}", e)))?;

        debug!("WebSocket server: handshake completed");
        Ok(Box::new(WebSocketStreamWrapper::new(ws_stream)))
    }
}

/// Wrapper to make Stream work with tungstenite
struct StreamWrapper(Stream);

impl AsyncRead for StreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// Wrapper to convert WebSocketStream to AsyncRead + AsyncWrite
struct WebSocketStreamWrapper<S> {
    inner: WebSocketStream<S>,
    read_buf: Vec<u8>,
    read_pos: usize,
    closed: bool,
}

impl<S> WebSocketStreamWrapper<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            closed: false,
        }
    }
}

impl<S> AsyncRead for WebSocketStreamWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Return buffered data first
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // If already closed, return EOF
        if self.closed {
            trace!("WebSocket poll_read: already closed, returning EOF");
            return Poll::Ready(Ok(()));
        }

        // Try to read next message
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                let data = match msg {
                    Message::Binary(data) => {
                        debug!("WebSocket received binary message: {} bytes", data.len());
                        data
                    }
                    Message::Text(text) => {
                        debug!("WebSocket received text message: {} bytes", text.len());
                        text.into_bytes()
                    }
                    Message::Ping(_data) => {
                        trace!("WebSocket received ping");
                        // Ignore ping/pong, try again
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Message::Pong(_) => {
                        trace!("WebSocket received pong");
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Message::Close(frame) => {
                        debug!("WebSocket received close frame: {:?}", frame);
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Message::Frame(_) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Unexpected raw frame",
                        )));
                    }
                };

                debug!("WebSocket data first 32 bytes: {:02x?}", &data[..data.len().min(32)]);
                
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.read_buf = data;
                    self.read_pos = to_copy;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                debug!("WebSocket read error: {}", e);
                self.closed = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
            Poll::Ready(None) => {
                trace!("WebSocket stream ended");
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WebSocketStreamWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // If closed, return error
        if self.closed {
            debug!("WebSocket poll_write: connection already closed");
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "WebSocket connection closed",
            )));
        }

        // First ensure the sink is ready
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                debug!("WebSocket poll_ready error: {}", e);
                self.closed = true;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Send the data as binary message
        debug!("WebSocket sending {} bytes", buf.len());
        let msg = Message::Binary(buf.to_vec());
        match Pin::new(&mut self.inner).start_send(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => {
                debug!("WebSocket start_send error: {}", e);
                self.closed = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.closed {
            debug!("WebSocket poll_flush: already closed");
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                debug!("WebSocket poll_flush: success");
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                debug!("WebSocket poll_flush error: {}", e);
                self.closed = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // WebSocket doesn't support half-close, so we just flush and return Ok
        // The actual close will happen when the stream is dropped
        trace!("WebSocket poll_shutdown called");
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
