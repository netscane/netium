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
    BlackholeTransport, ChainedLayer, RejectTransport, StreamLayer,
    TcpTransport, TlsConfig, TlsWrapper, Transport, WebSocketConfig, WebSocketWrapper, MuxManager,
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
    /// Enable multiplexing (yamux)
    pub mux_enabled: Option<bool>,
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
// Config Conversion (From traits)
// ============================================================================

use crate::config::{
    Config, InboundConfig as LegacyInbound, InboundSettings as LegacyInboundSettings,
    OutboundConfig as LegacyOutbound, OutboundSettings as LegacyOutboundSettings,
    TransportConfig as LegacyTransport, TransportType,
};

impl From<&Config> for RuntimeConfig {
    fn from(config: &Config) -> Self {
        let default_outbound = config
            .outbounds
            .first()
            .map(|o| o.tag.clone())
            .unwrap_or_else(|| "direct".to_string());

        RuntimeConfig {
            inbounds: config.inbounds.iter().map(InboundConfig::from).collect(),
            outbounds: config.outbounds.iter().map(OutboundConfig::from).collect(),
            routing: RoutingConfig {
                rules: config.routing.rules.iter().map(RouteRule::from).collect(),
                default_outbound,
            },
            api_listen: config.api.as_ref().map(|a| a.listen.clone()),
        }
    }
}

impl From<&LegacyInbound> for InboundConfig {
    fn from(i: &LegacyInbound) -> Self {
        InboundConfig {
            tag: i.tag.clone(),
            listen: i.listen.to_string(),
            protocol: format!("{:?}", i.protocol).to_lowercase(),
            settings: InboundSettings::from(&i.settings),
            transport: i.transport.as_ref().map(|t| TransportConfig::from_legacy(t, true)),
        }
    }
}

impl From<&LegacyInboundSettings> for InboundSettings {
    fn from(settings: &LegacyInboundSettings) -> Self {
        match settings {
            LegacyInboundSettings::Vmess(vmess) => InboundSettings {
                users: vmess
                    .users
                    .iter()
                    .map(|u| UserConfig {
                        uuid: u.uuid.to_string(),
                        email: Some(u.email.clone()),
                    })
                    .collect(),
            },
            _ => InboundSettings::default(),
        }
    }
}

impl From<&LegacyOutbound> for OutboundConfig {
    fn from(o: &LegacyOutbound) -> Self {
        OutboundConfig {
            tag: o.tag.clone(),
            protocol: format!("{:?}", o.protocol).to_lowercase(),
            settings: OutboundSettings::from_legacy(o),
            transport: o.transport.as_ref().map(|t| TransportConfig::from_legacy(t, false)),
        }
    }
}

impl OutboundSettings {
    fn from_legacy(o: &LegacyOutbound) -> Self {
        let (address, port) = o
            .transport
            .as_ref()
            .map(|t| (t.address.clone(), t.port))
            .unwrap_or_default();

        let (uuid, security) = match &o.settings {
            LegacyOutboundSettings::Vmess(vmess) => (
                Some(vmess.uuid.to_string()),
                Some(format!("{:?}", vmess.security).to_lowercase()),
            ),
            _ => (None, None),
        };

        OutboundSettings {
            address,
            port,
            uuid,
            security,
            mux_enabled: None,
        }
    }
}

impl TransportConfig {
    fn from_legacy(t: &LegacyTransport, _is_inbound: bool) -> Self {
        let tls = t.tls_settings.as_ref().filter(|tls| tls.enabled).map(|tls| TlsSettings {
            server_name: tls.server_name.clone(),
            allow_insecure: tls.allow_insecure,
            certificate_file: tls.certificate_file.clone(),
            key_file: tls.key_file.clone(),
        });

        let websocket = if t.transport_type == TransportType::WebSocket {
            t.ws_settings.as_ref().map(|ws| WebSocketSettings {
                path: ws.path.clone(),
                host: t.tls_settings.as_ref().and_then(|tls| tls.server_name.clone()),
            })
        } else {
            None
        };

        let transport_type = match t.transport_type {
            TransportType::Tcp => {
                if tls.is_some() { "tls" } else { "tcp" }
            }
            TransportType::WebSocket => {
                if tls.is_some() { "wss" } else { "ws" }
            }
            _ => "tcp",
        };

        TransportConfig {
            transport_type: transport_type.to_string(),
            tls,
            websocket,
        }
    }
}

impl From<&crate::config::RoutingRule> for RouteRule {
    fn from(r: &crate::config::RoutingRule) -> Self {
        RouteRule {
            rule_type: r.rule_type.clone(),
            inbound_tag: r.inbound_tag.clone(),
            domain: r.domain.clone(),
            ip: r.ip.clone(),
            port: r.port.clone(),
            outbound_tag: r.outbound_tag.clone(),
        }
    }
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
    mux: Option<Arc<MuxManager>>,
}

impl Outbound {
    /// Connect and process through pipeline
    pub async fn connect(&self, metadata: &crate::common::Metadata) -> Result<crate::common::Stream> {
        let target = self.server.as_ref().unwrap_or(&metadata.destination);

        // Mux path: get a stream from mux session
        if let Some(mux) = &self.mux {
            let key = target.to_string();
            debug!("[{}] Using mux for {}", self.tag, target);
            
            let dial = || async {
                let base_stream = self.transport.connect(target).await?;
                self.pipeline.wrap_session_layer(base_stream).await
            };
            
            let mux_stream = mux.get_stream(&key, dial).await?;
            return self.pipeline.protocol_only(mux_stream, metadata).await;
        }

        // Direct connection without mux
        debug!("[{}] Connecting to {}", self.tag, target);
        let stream = self.transport.connect(target).await?;
        self.pipeline.process(stream, metadata).await
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &str {
        self.pipeline.protocol_name()
    }

    /// Check if mux is enabled
    pub fn mux_enabled(&self) -> bool {
        self.mux.is_some()
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
        let mux_enabled = config.settings.mux_enabled.unwrap_or(false);

        let transport: Arc<dyn Transport> = match config.protocol.as_str() {
            "blackhole" => Arc::new(BlackholeTransport::new()),
            "reject" => Arc::new(RejectTransport::new()),
            _ => Arc::new(TcpTransport::new()),
        };

        let mux = if mux_enabled {
            Some(Arc::new(MuxManager::new()))
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
            mux,
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
