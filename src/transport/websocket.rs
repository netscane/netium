//! WebSocket StreamLayer implementation

use async_trait::async_trait;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream as FuturesStream};
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
use tracing::debug;

use crate::common::{Result, Stream};
use crate::error::Error;

use super::StreamLayer;

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path
    pub path: String,
    /// Host header
    pub host: Option<String>,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: vec![],
        }
    }
}

/// WebSocket wrapper for framing streams
pub struct WebSocketWrapper {
    config: WebSocketConfig,
}

impl WebSocketWrapper {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl StreamLayer for WebSocketWrapper {
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

        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let request = request
            .body(())
            .map_err(|e| Error::Protocol(format!("Failed to build WebSocket request: {}", e)))?;

        let ws_config = TungsteniteConfig {
            max_message_size: Some(64 << 20),
            max_frame_size: Some(16 << 20),
            ..Default::default()
        };

        let (ws_stream, _response) =
            client_async_with_config(request, BoxedStreamWrapper(stream), Some(ws_config))
                .await
                .map_err(|e| Error::Protocol(format!("WebSocket handshake failed: {}", e)))?;

        Ok(Box::new(WebSocketStreamWrapper::new(ws_stream)))
    }

    async fn wrap_server(&self, stream: Stream) -> Result<Stream> {
        let ws_config = TungsteniteConfig {
            max_message_size: Some(64 << 20),
            max_frame_size: Some(16 << 20),
            ..Default::default()
        };

        // Removed debug log for performance
        
        let ws_stream = accept_async_with_config(BoxedStreamWrapper(stream), Some(ws_config))
            .await
            .map_err(|e| Error::Protocol(format!("WebSocket handshake failed: {}", e)))?;

        // Removed debug log for performance
        Ok(Box::new(WebSocketStreamWrapper::new(ws_stream)))
    }
}

/// Wrapper to make boxed Stream work with tungstenite
struct BoxedStreamWrapper(Stream);

impl AsyncRead for BoxedStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedStreamWrapper {
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

        if self.closed {
            // Removed trace log for performance (hot path)
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                let data = match msg {
                    Message::Binary(data) => {
                        // Removed debug log for performance (hot path)
                        data
                    }
                    Message::Text(text) => {
                        // Removed debug log for performance (hot path)
                        text.into_bytes()
                    }
                    Message::Ping(_data) => {
                        // Removed trace log for performance (hot path)
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Message::Pong(_) => {
                        // Removed trace log for performance (hot path)
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Message::Close(frame) => {
                        // Only keep warn-level log for close frames
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

                // Removed debug log for performance (hot path - every message)
                
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
                    e,
                )))
            }
            Poll::Ready(None) => {
                // Removed trace log for performance
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
        if self.closed {
            // Removed debug log for performance (hot path)
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "WebSocket connection closed",
            )));
        }

        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                debug!("WebSocket poll_ready error: {}", e);
                self.closed = true;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Removed debug log for performance (hot path - every write)
        let msg = Message::Binary(buf.to_vec());
        match Pin::new(&mut self.inner).start_send(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => {
                debug!("WebSocket start_send error: {}", e);
                self.closed = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.closed {
            // Removed debug log for performance
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                // Removed debug log for performance (hot path)
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                debug!("WebSocket poll_flush error: {}", e);
                self.closed = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e,
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Removed trace log for performance
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
