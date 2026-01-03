//! UDP Transport implementation
//!
//! UDP is fundamentally different from TCP:
//! - Connectionless, datagram-based
//! - No stream abstraction
//! - Messages have boundaries
//!
//! We provide two abstractions:
//! - `Datagram` trait for packet-based I/O
//! - `UdpStream` for connected UDP (simulates stream for compatibility)

use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

use crate::common::{Address, Result, Stream};
use crate::error::Error;

use super::{Listener, Transport};

/// Datagram trait for packet-based I/O
///
/// This is the natural abstraction for UDP, unlike Stream.
#[async_trait]
pub trait Datagram: Send + Sync {
    /// Send a packet to the specified address
    async fn send_to(&self, buf: &[u8], target: &Address) -> Result<usize>;

    /// Receive a packet, returning data and source address
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)>;

    /// Get local bound address
    fn local_addr(&self) -> Result<Address>;
}

/// UDP socket wrapper implementing Datagram trait
pub struct UdpDatagram {
    socket: Arc<UdpSocket>,
}

impl UdpDatagram {
    pub async fn bind(addr: &Address) -> Result<Self> {
        let socket_addr: SocketAddr = match addr {
            Address::Socket(s) => *s,
            Address::Domain(host, port) => {
                tokio::net::lookup_host(format!("{}:{}", host, port))
                    .await?
                    .next()
                    .ok_or_else(|| Error::Config("Failed to resolve address".into()))?
            }
        };

        let socket = UdpSocket::bind(socket_addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

#[async_trait]
impl Datagram for UdpDatagram {
    async fn send_to(&self, buf: &[u8], target: &Address) -> Result<usize> {
        let addr: SocketAddr = match target {
            Address::Socket(s) => *s,
            Address::Domain(host, port) => {
                tokio::net::lookup_host(format!("{}:{}", host, port))
                    .await?
                    .next()
                    .ok_or_else(|| Error::Config("Failed to resolve address".into()))?
            }
        };

        Ok(self.socket.send_to(buf, addr).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        Ok((len, Address::Socket(addr)))
    }

    fn local_addr(&self) -> Result<Address> {
        Ok(Address::Socket(self.socket.local_addr()?))
    }
}

/// UDP transport - provides both Datagram and Stream interfaces
pub struct UdpTransport;

impl UdpTransport {
    pub fn new() -> Self {
        Self
    }

    /// Create a datagram socket bound to the address
    pub async fn bind_datagram(&self, addr: &Address) -> Result<UdpDatagram> {
        UdpDatagram::bind(addr).await
    }
}

impl Default for UdpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for UdpTransport {
    /// Create a "connected" UDP socket (for Stream compatibility)
    ///
    /// Note: This simulates a stream over UDP, which may not be ideal
    /// for all use cases. Prefer `bind_datagram` for true UDP semantics.
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

/// UDP stream wrapper for connected UDP sockets
///
/// Provides AsyncRead + AsyncWrite interface over connected UDP.
/// Use with caution - UDP doesn't guarantee delivery or ordering.
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
        // Return buffered data first
        if self.read_pos < self.read_len {
            let remaining = self.read_len - self.read_pos;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Receive new packet
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

/// UDP listener (simplified - UDP doesn't have true accept)
struct UdpListener {
    socket: Arc<UdpSocket>,
}

#[async_trait]
impl Listener for UdpListener {
    async fn accept(&self) -> Result<(Stream, Address)> {
        // UDP doesn't have accept - this is a simplified implementation
        // that creates a new connected socket for each "connection"
        let mut buf = [0u8; 1];
        let (_, addr) = self.socket.peek_from(&mut buf).await?;

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
