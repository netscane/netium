//! Pipeline - Stream Transformation Chain
//!
//! A Pipeline processes an **already existing** Stream through a series of layers.
//! It does NOT create streams - that's Transport's job.
//!
//! ## Key Concept
//!
//! ```text
//! Transport: creates Stream (connect/accept)
//! Pipeline:  transforms Stream (StreamLayer* → Protocol)
//! ```
//!
//! ## Architecture
//!
//! ```text
//! Inbound:  Stream → [StreamLayer]* → Protocol.inbound() → (Metadata, Stream)
//! Outbound: Stream → [StreamLayer]* → Protocol.outbound() → Stream
//! ```
//!
//! ## Example
//!
//! ```ignore
//! // Inbound: TLS → WebSocket → SOCKS5
//! let inbound = InboundPipeline::builder("proxy-in")
//!     .session(TlsLayer::new(tls_config))
//!     .session(WebSocketLayer::new(ws_config))
//!     .protocol(Socks5Protocol::new())
//!     .build();
//!
//! // Process an already-accepted stream
//! let stream = transport.accept().await?;
//! let (metadata, stream) = inbound.process(stream).await?;
//! ```

use std::sync::Arc;

use tracing::{debug, info, trace};

use crate::common::{Metadata, Result, Stream};
use crate::protocol::ProxyProtocol;
use crate::transport::{ChainedLayer, StreamLayer};

// ============================================================================
// Inbound Pipeline
// ============================================================================

/// Inbound pipeline: processes incoming streams.
///
/// Flow: Stream → [StreamLayer]* → Protocol.inbound() → (Metadata, Stream)
pub struct InboundPipeline {
    tag: String,
    layer: Option<Arc<dyn StreamLayer>>,
    protocol: Arc<dyn ProxyProtocol>,
}

impl InboundPipeline {
    /// Create a new builder.
    pub fn builder(tag: impl Into<String>) -> InboundPipelineBuilder {
        InboundPipelineBuilder::new(tag)
    }

    /// Get the pipeline tag.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Get the protocol name.
    pub fn protocol_name(&self) -> &str {
        self.protocol.name()
    }

    /// Process an incoming stream through the pipeline.
    ///
    /// Applies StreamLayers (server-side), then Protocol.inbound().
    pub async fn process(&self, mut stream: Stream) -> Result<(Metadata, Stream)> {
        trace!("[{}] Processing inbound stream", self.tag);

        // Apply stream layers (TLS unwrap, WS decode, etc.)
        if let Some(layer) = &self.layer {
            debug!("[{}] Applying stream layer", self.tag);
            stream = layer.wrap_server(stream).await?;
        }

        // Parse protocol (SOCKS5/HTTP/VMess handshake)
        debug!("[{}] Parsing protocol ({})", self.tag, self.protocol.name());
        let (mut metadata, stream) = self.protocol.inbound(stream).await?;

        metadata.inbound_tag = self.tag.clone();

        info!(
            "[{}] Inbound: {} -> {} ({})",
            self.tag, metadata.source, metadata.destination, metadata.protocol
        );

        Ok((metadata, stream))
    }
}

/// Builder for InboundPipeline.
pub struct InboundPipelineBuilder {
    tag: String,
    layers: Vec<Arc<dyn StreamLayer>>,
    protocol: Option<Arc<dyn ProxyProtocol>>,
}

impl InboundPipelineBuilder {
    fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            layers: Vec::new(),
            protocol: None,
        }
    }

    /// Add a session layer (TLS, WebSocket, etc.).
    pub fn session<S: StreamLayer + 'static>(mut self, s: S) -> Self {
        self.layers.push(Arc::new(s));
        self
    }

    /// Add a session layer as Arc.
    pub fn session_arc(mut self, s: Arc<dyn StreamLayer>) -> Self {
        self.layers.push(s);
        self
    }

    /// Set the protocol layer.
    pub fn protocol<P: ProxyProtocol + 'static>(mut self, p: P) -> Self {
        self.protocol = Some(Arc::new(p));
        self
    }

    /// Set the protocol layer as Arc.
    pub fn protocol_arc(mut self, p: Arc<dyn ProxyProtocol>) -> Self {
        self.protocol = Some(p);
        self
    }

    /// Build the pipeline.
    ///
    /// # Panics
    /// Panics if protocol is not set.
    pub fn build(self) -> InboundPipeline {
        InboundPipeline {
            tag: self.tag,
            layer: build_layer_chain(self.layers),
            protocol: self.protocol.expect("protocol is required"),
        }
    }
}

// ============================================================================
// Outbound Pipeline
// ============================================================================

/// Outbound pipeline: processes outgoing streams.
///
/// Flow: Stream → [StreamLayer]* → Protocol.outbound() → Stream
pub struct OutboundPipeline {
    tag: String,
    layer: Option<Arc<dyn StreamLayer>>,
    protocol: Arc<dyn ProxyProtocol>,
}

impl OutboundPipeline {
    /// Create a new builder.
    pub fn builder(tag: impl Into<String>) -> OutboundPipelineBuilder {
        OutboundPipelineBuilder::new(tag)
    }

    /// Get the pipeline tag.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Get the protocol name.
    pub fn protocol_name(&self) -> &str {
        self.protocol.name()
    }

    /// Process an outgoing stream through the pipeline.
    ///
    /// Applies StreamLayers (client-side), then Protocol.outbound().
    pub async fn process(&self, mut stream: Stream, metadata: &Metadata) -> Result<Stream> {
        trace!("[{}] Processing outbound stream", self.tag);

        // Apply stream layers (TLS handshake, WS upgrade, etc.)
        if let Some(layer) = &self.layer {
            debug!("[{}] Applying stream layer", self.tag);
            stream = layer.wrap_client(stream).await?;
        }

        // Protocol handshake (VMess/SOCKS5 client handshake)
        debug!("[{}] Protocol handshake ({})", self.tag, self.protocol.name());
        let stream = self.protocol.outbound(stream, metadata).await?;

        info!("[{}] Outbound ready", self.tag);

        Ok(stream)
    }
}

/// Builder for OutboundPipeline.
pub struct OutboundPipelineBuilder {
    tag: String,
    layers: Vec<Arc<dyn StreamLayer>>,
    protocol: Option<Arc<dyn ProxyProtocol>>,
}

impl OutboundPipelineBuilder {
    fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            layers: Vec::new(),
            protocol: None,
        }
    }

    /// Add a session layer (TLS, WebSocket, etc.).
    pub fn session<S: StreamLayer + 'static>(mut self, s: S) -> Self {
        self.layers.push(Arc::new(s));
        self
    }

    /// Add a session layer as Arc.
    pub fn session_arc(mut self, s: Arc<dyn StreamLayer>) -> Self {
        self.layers.push(s);
        self
    }

    /// Set the protocol layer.
    pub fn protocol<P: ProxyProtocol + 'static>(mut self, p: P) -> Self {
        self.protocol = Some(Arc::new(p));
        self
    }

    /// Set the protocol layer as Arc.
    pub fn protocol_arc(mut self, p: Arc<dyn ProxyProtocol>) -> Self {
        self.protocol = Some(p);
        self
    }

    /// Build the pipeline.
    ///
    /// # Panics
    /// Panics if protocol is not set.
    pub fn build(self) -> OutboundPipeline {
        OutboundPipeline {
            tag: self.tag,
            layer: build_layer_chain(self.layers),
            protocol: self.protocol.expect("protocol is required"),
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn build_layer_chain(layers: Vec<Arc<dyn StreamLayer>>) -> Option<Arc<dyn StreamLayer>> {
    match layers.len() {
        0 => None,
        1 => Some(layers.into_iter().next().unwrap()),
        _ => {
            let mut chained = ChainedLayer::new();
            for layer in layers {
                chained = chained.push(layer);
            }
            Some(Arc::new(chained) as Arc<dyn StreamLayer>)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DirectProtocol;
    use crate::transport::PlainLayer;

    #[test]
    fn test_inbound_pipeline_builds() {
        let pipeline = InboundPipeline::builder("test")
            .protocol(DirectProtocol)
            .build();

        assert_eq!(pipeline.tag(), "test");
        assert_eq!(pipeline.protocol_name(), "direct");
    }

    #[test]
    fn test_inbound_with_session() {
        let pipeline = InboundPipeline::builder("test")
            .session(PlainLayer)
            .protocol(DirectProtocol)
            .build();

        assert!(pipeline.layer.is_some());
    }

    #[test]
    fn test_inbound_with_multiple_sessions() {
        let pipeline = InboundPipeline::builder("test")
            .session(PlainLayer)
            .session(PlainLayer)
            .protocol(DirectProtocol)
            .build();

        assert!(pipeline.layer.is_some());
    }

    #[test]
    fn test_outbound_pipeline_builds() {
        let pipeline = OutboundPipeline::builder("direct")
            .protocol(DirectProtocol)
            .build();

        assert_eq!(pipeline.tag(), "direct");
    }

    #[test]
    fn test_outbound_with_session() {
        let pipeline = OutboundPipeline::builder("proxy")
            .session(PlainLayer)
            .protocol(DirectProtocol)
            .build();

        assert!(pipeline.layer.is_some());
    }
}
