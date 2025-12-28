//! UDP Transport implementation
//!
//! Note: UDP is connectionless, so this provides a different abstraction
//! compared to TCP. For now, we provide a basic implementation.

use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::common::{Address, Result, Stream};
use crate::error::Error;

use super::{Listener, Transport};

/// UDP transport
pub struct UdpTransport;

impl UdpTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UdpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for UdpTransport {
    async fn connect(&self, addr: &Address) -> Result<Stream> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        match addr {
            Address::Socket(socket_addr) => {
                socket.connect(socket_addr).await?;
            }
            Address::Domain(domain, port) => {
                socket.connect(format!("{}:{}", domain, port)).await?;
            }
        }

        Ok(Box::new(UdpStream::new(socket)))
    }

    async fn bind(&self, addr: &Address) -> Result<Box<dyn Listener>> {
        let socket_addr = match addr {
            Address::Socket(s) => *s,
            Address::Domain(_, _) => {
                return Err(Error::Config("Cannot bind to domain address".into()));
            }
        };

        let socket = UdpSocket::bind(socket_addr).await?;
        Ok(Box::new(UdpListener {
            socket: Arc::new(socket),
        }))
    }
}

/// UDP stream wrapper to implement AsyncRead + AsyncWrite
pub struct UdpStream {
    socket: UdpSocket,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_len: usize,
}

impl UdpStream {
    fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            read_buf: vec![0u8; 65535],
            read_pos: 0,
            read_len: 0,
        }
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, return it
        if self.read_pos < self.read_len {
            let remaining = self.read_len - self.read_pos;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Otherwise, try to receive new data
        let this = self.get_mut();
        let mut recv_buf = ReadBuf::new(&mut this.read_buf);
        match Pin::new(&this.socket).poll_recv(cx, &mut recv_buf) {
            Poll::Ready(Ok(())) => {
                this.read_len = recv_buf.filled().len();
                this.read_pos = 0;

                let to_copy = this.read_len.min(buf.remaining());
                buf.put_slice(&this.read_buf[..to_copy]);
                this.read_pos = to_copy;

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&self.socket).poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// UDP listener wrapper
struct UdpListener {
    socket: Arc<UdpSocket>,
}

#[async_trait]
impl Listener for UdpListener {
    async fn accept(&self) -> Result<(Stream, Address)> {
        // UDP doesn't have accept in the traditional sense
        // This is a simplified implementation
        let mut buf = [0u8; 1];
        let (_, addr) = self.socket.peek_from(&mut buf).await?;

        // Create a connected UDP socket for this "connection"
        let new_socket = UdpSocket::bind("0.0.0.0:0").await?;
        new_socket.connect(addr).await?;

        Ok((Box::new(UdpStream::new(new_socket)), Address::Socket(addr)))
    }

    fn local_addr(&self) -> Result<Address> {
        Ok(Address::Socket(self.socket.local_addr()?))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}
