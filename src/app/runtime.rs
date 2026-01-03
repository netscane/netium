//! Runtime - Configuration-driven pipeline construction
//!
//! The runtime is responsible for:
//! - Parsing configuration
//! - Building Transport + Pipeline combinations
//! - Managing lifecycle
//!
//! ## Architecture
//!
//! ```text
//! Inbound:  Transport.accept() → Stream → Pipeline.process() → (Metadata, Stream)
//! Outbound: Transport.connect() → Stream → Pipeline.process() → Stream
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::common::{Address, Result};
use crate::protocol::{
    DirectProtocol, HttpProtocol, ProxyProtocol,
    Socks5Protocol, VmessProtocol, VmessProtocolConfig, VmessSecurity,
};
use crate::router::{Router, RuleRouter, StaticRouter};
use crate::transport::{
    BlackholeTransport, ChainedLayer, ConnectionPool, PoolConfig, RejectTransport, StreamLayer,
    TcpTransport, TlsConfig, TlsWrapper, Transport, WebSocketConfig, WebSocketWrapper,
};

use super::dispatcher::Dispatcher;
use super::pipeline::{InboundPipeline, OutboundPipeline};
use super::stats_api::{self, InboundStats, StatsCollector};

// ============================================================================
// Configuration Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub api_listen: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InboundConfig {
    pub tag: String,
    pub listen: String,
    pub protocol: String,
    pub settings: InboundSettings,
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct InboundSettings {
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone)]
pub struct UserConfig {
    pub uuid: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: String,
    pub settings: OutboundSettings,
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct OutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub security: Option<String>,
    /// Enable connection pooling (keep-alive)
    pub keep_alive: Option<bool>,
    /// Max idle connections per host (default: 6)
    pub max_idle_conns: Option<usize>,
    /// Idle timeout in seconds (default: 90)
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    pub transport_type: String,
    pub tls: Option<TlsSettings>,
    pub websocket: Option<WebSocketSettings>,
}

#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    pub allow_insecure: bool,
    pub certificate_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WebSocketSettings {
    pub path: String,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RoutingConfig {
    pub rules: Vec<RouteRule>,
    pub default_outbound: String,
}

#[derive(Debug, Clone, Default)]
pub struct RouteRule {
    pub rule_type: String,
    pub inbound_tag: Vec<String>,
    pub domain: Vec<String>,
    pub ip: Vec<String>,
    pub port: Option<String>,
    pub outbound_tag: String,
}

// ============================================================================
// Inbound / Outbound (Transport + Pipeline)
// ============================================================================

/// Inbound endpoint: Transport (accept) + Pipeline (process)
pub struct Inbound {
    pub tag: String,
    pub listen: Address,
    pub transport: Arc<dyn Transport>,
    pub pipeline: InboundPipeline,
}

/// Outbound endpoint: Transport (connect) + Pipeline (process)
pub struct Outbound {
    pub tag: String,
    pub server: Option<Address>,
    pub transport: Arc<dyn Transport>,
    pub pipeline: OutboundPipeline,
    pool: Option<Arc<ConnectionPool>>,
}

impl Outbound {
    /// Connect and process through pipeline
    pub async fn connect(&self, metadata: &crate::common::Metadata) -> Result<crate::common::Stream> {
        let target = self.server.as_ref().unwrap_or(&metadata.destination);

        // Try to get a pooled connection first
        if let Some(pool) = &self.pool {
            if let Some(stream) = pool.get(target) {
                debug!("[{}] Reusing pooled connection to {}", self.tag, target);
                return self.pipeline.process(stream, metadata).await;
            }
        }

        debug!("[{}] Connecting to {}", self.tag, target);

        // Transport creates the stream
        let stream = self.transport.connect(target).await?;

        // Pipeline transforms the stream
        self.pipeline.process(stream, metadata).await
    }

    /// Return a connection to the pool for reuse
    pub fn return_connection(&self, addr: &Address, stream: crate::common::Stream) {
        if let Some(pool) = &self.pool {
            pool.put(addr, stream);
        }
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &str {
        self.pipeline.protocol_name()
    }

    /// Check if this outbound supports connection pooling
    pub fn supports_pooling(&self) -> bool {
        self.pool.is_some()
    }
}

// ============================================================================
// Runtime
// ============================================================================

/// Runtime manages the proxy system lifecycle
pub struct Runtime {
    inbounds: Vec<Arc<Inbound>>,
    dispatcher: Arc<Dispatcher>,
    shutdown_tx: broadcast::Sender<()>,
    stats_collector: StatsCollector,
    inbound_stats: Arc<HashMap<String, Arc<InboundStats>>>,
    api_listen: Option<SocketAddr>,
}

impl Runtime {
    /// Build runtime from configuration
    pub fn from_config(config: RuntimeConfig) -> Result<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);

        let inbound_tags: Vec<String> = config.inbounds.iter().map(|i| i.tag.clone()).collect();
        let outbound_tags: Vec<String> = config.outbounds.iter().map(|o| o.tag.clone()).collect();

        // Build outbounds
        let mut outbounds = HashMap::new();
        for cfg in &config.outbounds {
            let outbound = Self::build_outbound(cfg)?;
            outbounds.insert(cfg.tag.clone(), Arc::new(outbound));
        }

        // Build router
        let router: Arc<dyn Router> = if config.routing.rules.is_empty() {
            Arc::new(StaticRouter::new(&config.routing.default_outbound))
        } else {
            let rules = config.routing.rules.iter()
                .map(|r| crate::router::rule_router::Rule {
                    rule_type: crate::router::rule_router::RuleType::from_str(&r.rule_type),
                    inbound_tag: r.inbound_tag.clone(),
                    domain: r.domain.clone(),
                    ip: r.ip.clone(),
                    port: r.port.clone(),
                    outbound_tag: r.outbound_tag.clone(),
                    ..Default::default()
                })
                .collect();
            Arc::new(
                RuleRouter::new(rules, &config.routing.default_outbound)
                    .with_geosite(crate::geosite::GeoSiteMatcher::load_default())
                    .with_geoip(crate::geoip::GeoIpMatcher::load_default())
            )
        };

        // Stats
        let stats_collector = StatsCollector::new(router.clone(), inbound_tags.clone(), outbound_tags);

        let mut inbound_stats_map = HashMap::new();
        for tag in &inbound_tags {
            if let Some(stats) = stats_collector.get_inbound_stats(tag) {
                inbound_stats_map.insert(tag.clone(), stats);
            }
        }
        let inbound_stats = Arc::new(inbound_stats_map);

        let mut outbound_stats_map = HashMap::new();
        for tag in config.outbounds.iter().map(|o| &o.tag) {
            if let Some(stats) = stats_collector.get_outbound_stats(tag) {
                outbound_stats_map.insert(tag.clone(), stats);
            }
        }

        // Dispatcher
        let dispatcher = Arc::new(
            Dispatcher::new(router.clone(), outbounds)
                .with_stats(stats_collector.dispatcher_stats())
                .with_outbound_stats(Arc::new(outbound_stats_map))
        );

        // Build inbounds
        let mut inbounds = Vec::new();
        for cfg in &config.inbounds {
            let inbound = Self::build_inbound(cfg)?;
            inbounds.push(Arc::new(inbound));
        }

        let api_listen = config.api_listen.as_ref().and_then(|s| {
            s.parse::<SocketAddr>().ok().or_else(|| {
                warn!("Invalid API listen address: {}", s);
                None
            })
        });

        Ok(Self {
            inbounds,
            dispatcher,
            shutdown_tx,
            stats_collector,
            inbound_stats,
            api_listen,
        })
    }

    fn build_inbound(config: &InboundConfig) -> Result<Inbound> {
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport::new());
        let protocol = Self::build_protocol(&config.protocol, &config.settings)?;
        let layer = config.transport.as_ref()
            .and_then(|t| Self::build_stream_layer(t).ok().flatten());

        let mut builder = InboundPipeline::builder(&config.tag);
        if let Some(l) = layer {
            builder = builder.session_arc(l);
        }
        let pipeline = builder.protocol_arc(protocol).build();

        Ok(Inbound {
            tag: config.tag.clone(),
            listen: parse_listen_address(&config.listen)?,
            transport,
            pipeline,
        })
    }

    fn build_outbound(config: &OutboundConfig) -> Result<Outbound> {
        let keep_alive = config.settings.keep_alive.unwrap_or(false);

        let transport: Arc<dyn Transport> = match config.protocol.as_str() {
            "blackhole" => Arc::new(BlackholeTransport::new()),
            "reject" => Arc::new(RejectTransport::new()),
            _ => Arc::new(TcpTransport::new()),
        };

        let pool = if keep_alive {
            let pool_config = PoolConfig {
                max_conns_per_host: config.settings.max_idle_conns.unwrap_or(6),
                idle_timeout: std::time::Duration::from_secs(
                    config.settings.idle_timeout_secs.unwrap_or(120),
                ),
                ..Default::default()
            };
            Some(Arc::new(ConnectionPool::new(pool_config)))
        } else {
            None
        };

        let protocol = Self::build_outbound_protocol(&config.protocol, &config.settings)?;
        let layer = config.transport.as_ref()
            .and_then(|t| Self::build_stream_layer(t).ok().flatten());

        let server = match (&config.settings.address, config.settings.port) {
            (Some(addr), Some(port)) => Some(Address::domain(addr.clone(), port)),
            _ => None,
        };

        let mut builder = OutboundPipeline::builder(&config.tag);
        if let Some(l) = layer {
            builder = builder.session_arc(l);
        }
        let pipeline = builder.protocol_arc(protocol).build();

        Ok(Outbound {
            tag: config.tag.clone(),
            server,
            transport,
            pipeline,
            pool,
        })
    }

    fn build_protocol(name: &str, settings: &InboundSettings) -> Result<Arc<dyn ProxyProtocol>> {
        Ok(match name {
            "socks" | "socks5" => Arc::new(Socks5Protocol::new(Default::default())),
            "http" => Arc::new(HttpProtocol::new(Default::default())),
            "vmess" => {
                let uuid = settings.users.first()
                    .and_then(|u| uuid::Uuid::parse_str(&u.uuid).ok())
                    .unwrap_or_else(uuid::Uuid::nil);
                Arc::new(VmessProtocol::new(VmessProtocolConfig {
                    uuid,
                    security: VmessSecurity::Auto,
                    alter_id: 0,
                }))
            }
            _ => Arc::new(DirectProtocol),
        })
    }

    fn build_outbound_protocol(name: &str, settings: &OutboundSettings) -> Result<Arc<dyn ProxyProtocol>> {
        Ok(match name {
            "socks" | "socks5" => Arc::new(Socks5Protocol::new(Default::default())),
            "http" => Arc::new(HttpProtocol::new(Default::default())),
            "vmess" => {
                let uuid = settings.uuid.as_ref()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .unwrap_or_else(uuid::Uuid::nil);
                let security = settings.security.as_deref()
                    .map(VmessSecurity::from_str)
                    .unwrap_or(VmessSecurity::Auto);
                Arc::new(VmessProtocol::new(VmessProtocolConfig {
                    uuid,
                    security,
                    alter_id: 0,
                }))
            }
            // direct, freedom, blackhole, reject - all use DirectProtocol
            // (blackhole/reject behavior is handled by Transport layer)
            _ => Arc::new(DirectProtocol),
        })
    }

    fn build_stream_layer(config: &TransportConfig) -> Result<Option<Arc<dyn StreamLayer>>> {
        Ok(match config.transport_type.as_str() {
            "tcp" | "" => None,
            "tls" => {
                let tls_config = config.tls.as_ref().map(|t| TlsConfig {
                    server_name: t.server_name.clone(),
                    allow_insecure: t.allow_insecure,
                    alpn: vec![],
                    certificate_file: t.certificate_file.clone(),
                    key_file: t.key_file.clone(),
                }).unwrap_or_default();
                Some(Arc::new(TlsWrapper::new(tls_config)))
            }
            "ws" | "websocket" => {
                let ws_config = config.websocket.as_ref().map(|w| WebSocketConfig {
                    path: w.path.clone(),
                    host: w.host.clone(),
                    headers: vec![],
                }).unwrap_or_default();
                Some(Arc::new(WebSocketWrapper::new(ws_config)))
            }
            "wss" => {
                let tls_config = config.tls.as_ref().map(|t| TlsConfig {
                    server_name: t.server_name.clone(),
                    allow_insecure: t.allow_insecure,
                    alpn: vec![],
                    certificate_file: t.certificate_file.clone(),
                    key_file: t.key_file.clone(),
                }).unwrap_or_default();
                let ws_config = config.websocket.as_ref().map(|w| WebSocketConfig {
                    path: w.path.clone(),
                    host: w.host.clone().or_else(|| tls_config.server_name.clone()),
                    headers: vec![],
                }).unwrap_or_default();

                let chained = ChainedLayer::new()
                    .push(Arc::new(TlsWrapper::new(tls_config)))
                    .push(Arc::new(WebSocketWrapper::new(ws_config)));
                Some(Arc::new(chained) as Arc<dyn StreamLayer>)
            }
            _ => None,
        })
    }

    /// Run the runtime
    pub async fn run(&self) -> Result<()> {
        let mut handles = Vec::new();

        for inbound in &self.inbounds {
            let inbound = inbound.clone();
            let dispatcher = self.dispatcher.clone();
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let inbound_stat = self.inbound_stats.get(&inbound.tag).cloned();

            let handle = tokio::spawn(async move {
                if let Err(e) = run_inbound(inbound, dispatcher, &mut shutdown_rx, inbound_stat).await {
                    error!("Inbound error: {}", e);
                }
            });

            handles.push(handle);
        }

        info!("Runtime started with {} inbounds", self.inbounds.len());

        let api_handle = if let Some(addr) = self.api_listen {
            let collector = self.stats_collector.clone();
            let api_shutdown_rx = self.shutdown_tx.subscribe();
            Some(tokio::spawn(async move {
                stats_api::start_api_server(addr, collector, api_shutdown_rx).await;
            }))
        } else {
            None
        };

        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        let _ = self.shutdown_tx.send(());

        for handle in handles {
            let _ = handle.await;
        }
        if let Some(handle) = api_handle {
            let _ = handle.await;
        }

        Ok(())
    }
}

// ============================================================================
// Inbound Runner
// ============================================================================

async fn run_inbound(
    inbound: Arc<Inbound>,
    dispatcher: Arc<Dispatcher>,
    shutdown_rx: &mut broadcast::Receiver<()>,
    inbound_stat: Option<Arc<InboundStats>>,
) -> Result<()> {
    // Transport creates listener
    let listener = inbound.transport.bind(&inbound.listen).await?;
    info!(
        "[{}] Listening on {} (protocol: {})",
        inbound.tag, inbound.listen, inbound.pipeline.protocol_name()
    );

    let mut conn_count: u64 = 0;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, source)) => {
                        conn_count += 1;
                        debug!("[{}] Connection #{} from {}", inbound.tag, conn_count, source);

                        if let Some(stat) = &inbound_stat {
                            stat.connection_accepted();
                        }

                        let inbound = inbound.clone();
                        let dispatcher = dispatcher.clone();
                        let inbound_stat_clone = inbound_stat.clone();
                        let conn_id = conn_count;

                        tokio::spawn(async move {
                            // Pipeline processes the stream
                            let result = async {
                                let (mut metadata, stream) = inbound.pipeline.process(stream).await?;
                                metadata.source = source.clone();
                                dispatcher.dispatch(metadata, stream).await
                            }.await;

                            if let Some(stat) = inbound_stat_clone {
                                stat.connection_closed();
                            }

                            if let Err(e) = result {
                                warn!("Connection #{} from {} error: {}", conn_id, source, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("[{}] Accept error: {}", inbound.tag, e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("[{}] Shutting down (handled {} connections)", inbound.tag, conn_count);
                break;
            }
        }
    }

    Ok(())
}

fn parse_listen_address(s: &str) -> Result<Address> {
    if let Ok(addr) = s.parse() {
        return Ok(Address::Socket(addr));
    }

    if let Some((host, port)) = s.rsplit_once(':') {
        let port: u16 = port.parse().map_err(|_| {
            crate::error::Error::Config(format!("Invalid port in address: {}", s))
        })?;
        if let Ok(ip) = host.parse() {
            return Ok(Address::Socket(std::net::SocketAddr::new(ip, port)));
        }
        return Ok(Address::Domain(host.to_string(), port));
    }

    Err(crate::error::Error::Config(format!("Invalid listen address: {}", s)))
}
