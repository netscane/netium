//! Pipeline Stacks
//!
//! InboundStack: Transport → Session → Protocol (inbound)
//! OutboundStack: Protocol → Session → Transport (outbound)

use std::sync::Arc;

use tracing::{debug, info, trace};

use crate::common::{Address, Metadata, Result, Stream};
use crate::protocol::ProxyProtocol;
use crate::session::Session;
use crate::transport::Transport;

/// Inbound pipeline stack
///
/// Processes incoming connections:
/// Transport (accept) → Session (unwrap) → Protocol (parse)
pub struct InboundStack {
    /// Tag for this inbound
    pub tag: String,
    /// Listen address
    pub listen: Address,
    /// Transport layer
    pub transport: Arc<dyn Transport>,
    /// Session layer (optional)
    pub session: Option<Arc<dyn Session>>,
    /// Protocol layer
    pub protocol: Arc<dyn ProxyProtocol>,
}

impl InboundStack {
    pub fn new(
        tag: impl Into<String>,
        listen: Address,
        transport: Arc<dyn Transport>,
        protocol: Arc<dyn ProxyProtocol>,
    ) -> Self {
        Self {
            tag: tag.into(),
            listen,
            transport,
            session: None,
            protocol,
        }
    }

    pub fn with_session(mut self, session: Arc<dyn Session>) -> Self {
        self.session = Some(session);
        self
    }

    /// Process an incoming stream through the stack
    ///
    /// Session (server-side) → Protocol (inbound)
    pub async fn process(&self, mut stream: Stream) -> Result<(Metadata, Stream)> {
        trace!("[{}] Processing inbound connection", self.tag);

        // Apply session layer if present
        if let Some(session) = &self.session {
            debug!("[{}] Applying session layer", self.tag);
            stream = session.wrap_server(stream).await?;
        }

        // Apply protocol layer
        debug!("[{}] Parsing protocol ({})", self.tag, self.protocol.name());
        let (mut metadata, stream) = self.protocol.inbound(stream).await?;

        // Set inbound tag
        metadata.inbound_tag = self.tag.clone();

        info!(
            "[{}] Inbound: {} -> {} ({})",
            self.tag, metadata.source, metadata.destination, metadata.protocol
        );

        Ok((metadata, stream))
    }
}

/// Outbound pipeline stack
///
/// Processes outgoing connections:
/// Protocol (outbound) → Session (wrap) → Transport (connect)
pub struct OutboundStack {
    /// Tag for this outbound
    pub tag: String,
    /// Remote server address (for proxy protocols)
    pub server: Option<Address>,
    /// Transport layer
    pub transport: Arc<dyn Transport>,
    /// Session layer (optional)
    pub session: Option<Arc<dyn Session>>,
    /// Protocol layer
    pub protocol: Arc<dyn ProxyProtocol>,
}

impl OutboundStack {
    pub fn new(
        tag: impl Into<String>,
        transport: Arc<dyn Transport>,
        protocol: Arc<dyn ProxyProtocol>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server: None,
            transport,
            session: None,
            protocol,
        }
    }

    pub fn with_server(mut self, server: Address) -> Self {
        self.server = Some(server);
        self
    }

    pub fn with_session(mut self, session: Arc<dyn Session>) -> Self {
        self.session = Some(session);
        self
    }

    /// Connect to the target and return a ready stream
    ///
    /// Transport (connect) → Session (client-side) → Protocol (outbound)
    pub async fn connect(&self, metadata: &Metadata) -> Result<Stream> {
        // Determine connection target
        let target = self.server.as_ref().unwrap_or(&metadata.destination);

        debug!(
            "[{}] Connecting to {} (protocol: {})",
            self.tag, target, self.protocol.name()
        );

        // Connect via transport
        let mut stream = self.transport.connect(target).await?;
        trace!("[{}] Transport connected to {}", self.tag, target);

        // Apply session layer if present
        if let Some(session) = &self.session {
            debug!("[{}] Applying session layer", self.tag);
            stream = session.wrap_client(stream).await?;
        }

        // Apply protocol layer
        debug!("[{}] Performing protocol handshake", self.tag);
        let stream = self.protocol.outbound(stream, metadata).await?;

        info!("[{}] Outbound connected to {}", self.tag, target);

        Ok(stream)
    }
}
