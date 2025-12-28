//! TCP Transport implementation

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};

use crate::common::{Address, Result, Stream};
use crate::error::Error;

use super::{Listener, Transport};

/// TCP transport - raw TCP connections
pub struct TcpTransport;

impl TcpTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, addr: &Address) -> Result<Stream> {
        let stream = match addr {
            Address::Socket(socket_addr) => TcpStream::connect(socket_addr).await?,
            Address::Domain(domain, port) => {
                TcpStream::connect(format!("{}:{}", domain, port)).await?
            }
        };

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true)?;

        Ok(Box::new(stream))
    }

    async fn bind(&self, addr: &Address) -> Result<Box<dyn Listener>> {
        let socket_addr = match addr {
            Address::Socket(s) => *s,
            Address::Domain(_, _) => {
                return Err(Error::Config("Cannot bind to domain address".into()));
            }
        };

        let listener = TcpListener::bind(socket_addr).await?;
        Ok(Box::new(TcpListenerWrapper { listener }))
    }
}

/// Wrapper for TcpListener to implement Listener trait
struct TcpListenerWrapper {
    listener: TcpListener,
}

#[async_trait]
impl Listener for TcpListenerWrapper {
    async fn accept(&self) -> Result<(Stream, Address)> {
        let (stream, addr) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        Ok((Box::new(stream), Address::Socket(addr)))
    }

    fn local_addr(&self) -> Result<Address> {
        Ok(Address::Socket(self.listener.local_addr()?))
    }

    async fn close(&self) -> Result<()> {
        // TcpListener doesn't have explicit close, it closes on drop
        Ok(())
    }
}
