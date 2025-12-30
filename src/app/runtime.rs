//! Runtime - Configuration-driven pipeline construction
//!
//! The runtime is responsible for:
//! - Parsing configuration
//! - Building trait objects
//! - Assembling pipeline graph
//! - Managing lifecycle

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::common::{Address, Result};
use crate::protocol::{DirectProtocol, HttpProtocol, ProxyProtocol, Socks5Protocol, VmessProtocol, VmessProtocolConfig, VmessSecurity};
use crate::router::{Router, RuleRouter, StaticRouter};
use crate::session::{Session, TlsConfig, TlsSession, TlsWebSocketSession, WebSocketConfig, WebSocketSession};
use crate::transport::{TcpTransport, Transport};

use super::dispatcher::Dispatcher;
use super::stack::{InboundStack, OutboundStack};
use super::stats_api::{self, InboundStats, StatsCollector};

/// Runtime configuration
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    /// Stats API listen address (e.g., "127.0.0.1:9090")
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

/// Runtime manages the proxy system lifecycle
pub struct Runtime {
    inbounds: Vec<Arc<InboundStack>>,
    dispatcher: Arc<Dispatcher>,
    shutdown_tx: broadcast::Sender<()>,
    /// Stats collector for API
    stats_collector: StatsCollector,
    /// Per-inbound statistics
    inbound_stats: Arc<HashMap<String, Arc<InboundStats>>>,
    /// API listen address
    api_listen: Option<SocketAddr>,
}

impl Runtime {
    /// Build runtime from configuration
    pub fn from_config(config: RuntimeConfig) -> Result<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);

        // Collect tags for stats
        let inbound_tags: Vec<String> = config.inbounds.iter().map(|i| i.tag.clone()).collect();
        let outbound_tags: Vec<String> = config.outbounds.iter().map(|o| o.tag.clone()).collect();

        // Build outbounds
        let mut outbounds = HashMap::new();
        for outbound_config in &config.outbounds {
            let stack = Self::build_outbound(outbound_config)?;
            outbounds.insert(outbound_config.tag.clone(), Arc::new(stack));
        }

        // Build router
        let router: Arc<dyn Router> = if config.routing.rules.is_empty() {
            Arc::new(StaticRouter::new(&config.routing.default_outbound))
        } else {
            let rules = config
                .routing
                .rules
                .iter()
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

        // Create stats collector
        let stats_collector = StatsCollector::new(
            router.clone(),
            inbound_tags.clone(),
            outbound_tags,
        );

        // Build per-inbound stats map
        let mut inbound_stats_map = HashMap::new();
        for tag in &inbound_tags {
            if let Some(stats) = stats_collector.get_inbound_stats(tag) {
                inbound_stats_map.insert(tag.clone(), stats);
            }
        }
        let inbound_stats = Arc::new(inbound_stats_map);

        // Build per-outbound stats map for dispatcher
        let mut outbound_stats_map = HashMap::new();
        for tag in config.outbounds.iter().map(|o| &o.tag) {
            if let Some(stats) = stats_collector.get_outbound_stats(tag) {
                outbound_stats_map.insert(tag.clone(), stats);
            }
        }

        // Build dispatcher with stats
        let dispatcher = Arc::new(
            Dispatcher::new(router.clone(), outbounds)
                .with_stats(stats_collector.dispatcher_stats())
                .with_outbound_stats(Arc::new(outbound_stats_map))
        );

        // Build inbounds
        let mut inbounds = Vec::new();
        for inbound_config in &config.inbounds {
            let stack = Self::build_inbound(inbound_config)?;
            inbounds.push(Arc::new(stack));
        }

        // Parse API listen address
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

    fn build_inbound(config: &InboundConfig) -> Result<InboundStack> {
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport::new());

        let protocol: Arc<dyn ProxyProtocol> = match config.protocol.as_str() {
            "socks" | "socks5" => Arc::new(Socks5Protocol::new(Default::default())),
            "http" => Arc::new(HttpProtocol::new(Default::default())),
            "vmess" => {
                // Parse VMess inbound settings - use first user's UUID
                let uuid = config.settings.users.first()
                    .and_then(|u| uuid::Uuid::parse_str(&u.uuid).ok())
                    .unwrap_or_else(uuid::Uuid::nil);
                let vmess_config = VmessProtocolConfig {
                    uuid,
                    security: VmessSecurity::Auto,
                    alter_id: 0,
                };
                Arc::new(VmessProtocol::new(vmess_config))
            }
            "direct" => Arc::new(DirectProtocol),
            _ => Arc::new(DirectProtocol),
        };

        let listen = parse_listen_address(&config.listen)?;

        let mut stack = InboundStack::new(&config.tag, listen, transport, protocol);

        // Add session layer if configured
        if let Some(transport_config) = &config.transport {
            if let Some(session) = Self::build_session(transport_config)? {
                stack = stack.with_session(session);
            }
        }

        Ok(stack)
    }

    fn build_outbound(config: &OutboundConfig) -> Result<OutboundStack> {
        debug!(
            "Building outbound [{}]: protocol={}, address={:?}, port={:?}, uuid={:?}",
            config.tag, config.protocol, config.settings.address, config.settings.port, config.settings.uuid
        );

        let transport: Arc<dyn Transport> = Arc::new(TcpTransport::new());

        let protocol: Arc<dyn ProxyProtocol> = match config.protocol.as_str() {
            "socks" | "socks5" => Arc::new(Socks5Protocol::new(Default::default())),
            "http" => Arc::new(HttpProtocol::new(Default::default())),
            "direct" | "freedom" => Arc::new(DirectProtocol),
            "vmess" => {
                let uuid = config.settings.uuid.as_ref()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .unwrap_or_else(uuid::Uuid::nil);
                let security = config.settings.security.as_deref()
                    .map(VmessSecurity::from_str)
                    .unwrap_or(VmessSecurity::Auto);
                
                debug!("VMess config: uuid={}, security={:?}", uuid, security);
                
                let vmess_config = VmessProtocolConfig {
                    uuid,
                    security,
                    alter_id: 0,
                };
                Arc::new(VmessProtocol::new(vmess_config))
            }
            _ => Arc::new(DirectProtocol),
        };

        let mut stack = OutboundStack::new(&config.tag, transport, protocol);

        // Set server address if configured
        if let (Some(addr), Some(port)) = (&config.settings.address, config.settings.port) {
            debug!("Setting server address: {}:{}", addr, port);
            stack = stack.with_server(Address::domain(addr.clone(), port));
        }

        // Add session layer if configured
        if let Some(transport_config) = &config.transport {
            debug!("Transport config: type={}, tls={:?}, ws={:?}", 
                transport_config.transport_type, 
                transport_config.tls.is_some(),
                transport_config.websocket.is_some()
            );
            if let Some(session) = Self::build_session(transport_config)? {
                stack = stack.with_session(session);
            }
        }

        Ok(stack)
    }

    fn build_session(config: &TransportConfig) -> Result<Option<Arc<dyn Session>>> {
        let session: Option<Arc<dyn Session>> = match config.transport_type.as_str() {
            "tcp" | "" => None,
            "tls" => {
                let tls_config = config.tls.as_ref().map(|t| TlsConfig {
                    server_name: t.server_name.clone(),
                    allow_insecure: t.allow_insecure,
                    alpn: vec![],
                    certificate_file: t.certificate_file.clone(),
                    key_file: t.key_file.clone(),
                }).unwrap_or_default();
                Some(Arc::new(TlsSession::new(tls_config)))
            }
            "ws" | "websocket" => {
                let ws_config = config.websocket.as_ref().map(|w| WebSocketConfig {
                    path: w.path.clone(),
                    host: w.host.clone(),
                    headers: vec![],
                }).unwrap_or_default();
                Some(Arc::new(WebSocketSession::new(ws_config)))
            }
            "wss" => {
                // WebSocket over TLS - need to compose both sessions
                // For now, we'll use a combined session
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
                
                debug!("Building WSS session: tls_sni={:?}, ws_path={}, ws_host={:?}",
                    tls_config.server_name, ws_config.path, ws_config.host);
                
                // Create a combined TLS + WebSocket session
                Some(Arc::new(TlsWebSocketSession::new(tls_config, ws_config)))
            }
            _ => None,
        };

        Ok(session)
    }

    /// Run the runtime
    pub async fn run(&self) -> Result<()> {
        // Start all inbound listeners
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

        // Start API server if configured
        let api_handle = if let Some(addr) = self.api_listen {
            let collector = self.stats_collector.clone();
            let api_shutdown_rx = self.shutdown_tx.subscribe();
            Some(tokio::spawn(async move {
                stats_api::start_api_server(addr, collector, api_shutdown_rx).await;
            }))
        } else {
            None
        };

        // Wait for shutdown signal (Ctrl+C)
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }
        if let Some(handle) = api_handle {
            let _ = handle.await;
        }

        Ok(())
    }
}

/// Run a single inbound listener
async fn run_inbound(
    inbound: Arc<InboundStack>,
    dispatcher: Arc<Dispatcher>,
    shutdown_rx: &mut broadcast::Receiver<()>,
    inbound_stat: Option<Arc<InboundStats>>,
) -> Result<()> {
    let listener = inbound.transport.bind(&inbound.listen).await?;
    info!(
        "[{}] Listening on {} (protocol: {})",
        inbound.tag,
        inbound.listen,
        inbound.protocol.name()
    );

    let mut conn_count: u64 = 0;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, source)) => {
                        conn_count += 1;
                        let conn_id = conn_count;
                        debug!("[{}] New connection #{} from {}", inbound.tag, conn_id, source);

                        // Record inbound connection
                        if let Some(stat) = &inbound_stat {
                            stat.connection_accepted();
                        }

                        let inbound = inbound.clone();
                        let dispatcher = dispatcher.clone();
                        let inbound_stat_clone = inbound_stat.clone();

                        tokio::spawn(async move {
                            let result = handle_connection(inbound, dispatcher, stream, source.clone()).await;
                            
                            // Record connection closed
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

/// Handle a single connection
async fn handle_connection(
    inbound: Arc<InboundStack>,
    dispatcher: Arc<Dispatcher>,
    stream: crate::common::Stream,
    source: Address,
) -> Result<()> {
    // Process through inbound stack
    let (mut metadata, stream) = inbound.process(stream).await?;
    metadata.source = source;

    // Dispatch to outbound
    dispatcher.dispatch(metadata, stream).await
}

/// Parse listen address string to Address
fn parse_listen_address(s: &str) -> Result<Address> {
    if let Ok(addr) = s.parse() {
        return Ok(Address::Socket(addr));
    }

    // Try host:port format
    if let Some((host, port)) = s.rsplit_once(':') {
        let port: u16 = port.parse().map_err(|_| {
            crate::error::Error::Config(format!("Invalid port in address: {}", s))
        })?;
        if let Ok(ip) = host.parse() {
            return Ok(Address::Socket(std::net::SocketAddr::new(ip, port)));
        }
        return Ok(Address::Domain(host.to_string(), port));
    }

    Err(crate::error::Error::Config(format!(
        "Invalid listen address: {}",
        s
    )))
}
