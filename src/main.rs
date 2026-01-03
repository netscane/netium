//! Netium - A modern VPN/proxy tool inspired by V2Ray

use std::path::PathBuf;

use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use netium::config::{Config, OutboundSettings, OutboundProtocol, TransportType, InboundSettings as ConfigInboundSettings};
use netium::error::Result;
use netium::app::{
    Runtime, RuntimeConfig, InboundConfig, OutboundConfig, RoutingConfig, RouteRule,
    OutboundSettings as RuntimeOutboundSettings, TransportConfig, TlsSettings, WebSocketSettings,
    InboundSettings, UserConfig,
};

fn main() -> Result<()> {
    let args = Args::parse();

    if args.version {
        print_version();
        return Ok(());
    }

    if let Some(config_type) = args.gen_config {
        let config = match config_type.as_str() {
            "client" => Config::default_client(),
            "server" => Config::default_server(),
            _ => {
                eprintln!("Unknown config type: {}. Use 'client' or 'server'", config_type);
                std::process::exit(1);
            }
        };
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
        return Ok(());
    }

    // Initialize logging
    let log_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Level::INFO);
    
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // Load configuration
    let config = if let Some(path) = args.config {
        Config::load(&path)?
    } else {
        info!("No config file specified, using default client config");
        Config::default_client()
    };

    info!("Netium v{} starting...", env!("CARGO_PKG_VERSION"));

    // Convert Config to RuntimeConfig
    let mut runtime_config = convert_config(&config);
    
    // Override API listen from command line, or use config file value
    if args.api_listen.is_some() {
        runtime_config.api_listen = args.api_listen;
    } else if let Some(api) = &config.api {
        runtime_config.api_listen = Some(api.listen.clone());
    }

    // Run Netium
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let runtime = Runtime::from_config(runtime_config)?;
        runtime.run().await
    })?;

    info!("Goodbye!");
    Ok(())
}

/// Convert legacy Config to RuntimeConfig
fn convert_config(config: &Config) -> RuntimeConfig {
    let inbounds = config.inbounds.iter().map(|i| {
        let transport = i.transport.as_ref().map(|t| {
            let tls = t.tls_settings.as_ref().filter(|tls| tls.enabled).map(|tls| {
                TlsSettings {
                    server_name: tls.server_name.clone(),
                    allow_insecure: tls.allow_insecure,
                    certificate_file: tls.certificate_file.clone(),
                    key_file: tls.key_file.clone(),
                }
            });

            let websocket = if t.transport_type == TransportType::WebSocket {
                t.ws_settings.as_ref().map(|ws| {
                    WebSocketSettings {
                        path: ws.path.clone(),
                        host: t.tls_settings.as_ref().and_then(|tls| tls.server_name.clone()),
                    }
                })
            } else {
                None
            };

            let transport_type = match t.transport_type {
                TransportType::Tcp => {
                    if tls.is_some() { "tls".to_string() } else { "tcp".to_string() }
                }
                TransportType::WebSocket => {
                    if tls.is_some() { "wss".to_string() } else { "ws".to_string() }
                }
                _ => "tcp".to_string(),
            };

            TransportConfig {
                transport_type,
                tls,
                websocket,
            }
        });

        // Parse inbound settings
        let settings = match &i.settings {
            ConfigInboundSettings::Vmess(vmess) => {
                InboundSettings {
                    users: vmess.users.iter().map(|u| UserConfig {
                        uuid: u.uuid.to_string(),
                        email: Some(u.email.clone()),
                    }).collect(),
                }
            }
            _ => Default::default(),
        };

        InboundConfig {
            tag: i.tag.clone(),
            listen: i.listen.to_string(),
            protocol: format!("{:?}", i.protocol).to_lowercase(),
            settings,
            transport,
        }
    }).collect();

    let outbounds = config.outbounds.iter().map(|o| {
        let (address, port, keep_alive, max_idle_conns, idle_timeout_secs) = o.transport.as_ref()
            .map(|t| (
                t.address.clone(),
                t.port,
                t.keep_alive,
                t.max_idle_conns,
                t.idle_timeout_secs,
            ))
            .unwrap_or((None, None, None, None, None));

        let (uuid, security) = match &o.settings {
            OutboundSettings::Vmess(vmess) => {
                (Some(vmess.uuid.to_string()), Some(format!("{:?}", vmess.security).to_lowercase()))
            }
            _ => (None, None),
        };

        let transport = o.transport.as_ref().map(|t| {
            let tls = t.tls_settings.as_ref().filter(|tls| tls.enabled).map(|tls| {
                TlsSettings {
                    server_name: tls.server_name.clone(),
                    allow_insecure: tls.allow_insecure,
                    certificate_file: tls.certificate_file.clone(),
                    key_file: tls.key_file.clone(),
                }
            });

            let websocket = if t.transport_type == TransportType::WebSocket {
                t.ws_settings.as_ref().map(|ws| {
                    WebSocketSettings {
                        path: ws.path.clone(),
                        host: t.tls_settings.as_ref().and_then(|tls| tls.server_name.clone()),
                    }
                })
            } else {
                None
            };

            let transport_type = match t.transport_type {
                TransportType::Tcp => {
                    if tls.is_some() { "tls".to_string() } else { "tcp".to_string() }
                }
                TransportType::WebSocket => {
                    if tls.is_some() { "wss".to_string() } else { "ws".to_string() }
                }
                _ => "tcp".to_string(),
            };

            TransportConfig {
                transport_type,
                tls,
                websocket,
            }
        });

        OutboundConfig {
            tag: o.tag.clone(),
            protocol: format!("{:?}", o.protocol).to_lowercase(),
            settings: RuntimeOutboundSettings {
                address,
                port,
                uuid,
                security,
                keep_alive,
                max_idle_conns,
                idle_timeout_secs,
            },
            transport,
        }
    }).collect();

    let default_outbound = config.outbounds.first()
        .map(|o| o.tag.clone())
        .unwrap_or_else(|| "direct".to_string());

    // Convert routing rules
    let rules = config.routing.rules.iter().map(|r| RouteRule {
        rule_type: r.rule_type.clone(),
        inbound_tag: r.inbound_tag.clone(),
        domain: r.domain.clone(),
        ip: r.ip.clone(),
        port: r.port.clone(),
        outbound_tag: r.outbound_tag.clone(),
    }).collect();

    RuntimeConfig {
        inbounds,
        outbounds,
        routing: RoutingConfig {
            rules,
            default_outbound,
        },
        api_listen: None,
    }
}

/// Command line arguments
struct Args {
    config: Option<PathBuf>,
    gen_config: Option<String>,
    version: bool,
    api_listen: Option<String>,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut config = None;
        let mut gen_config = None;
        let mut version = false;
        let mut api_listen = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-c" | "--config" => {
                    if i + 1 < args.len() {
                        config = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                }
                "--gen-config" => {
                    if i + 1 < args.len() {
                        gen_config = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "--api" => {
                    if i + 1 < args.len() {
                        api_listen = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "-v" | "--version" => version = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                arg if !arg.starts_with('-') && config.is_none() => {
                    // Positional argument: treat as config file
                    config = Some(PathBuf::from(arg));
                }
                _ => {}
            }
            i += 1;
        }

        Self { config, gen_config, version, api_listen }
    }
}

fn print_help() {
    println!(r#"Netium - A modern VPN/proxy tool

USAGE:
    netium [OPTIONS]

OPTIONS:
    -c, --config <FILE>     Path to configuration file
    --gen-config <TYPE>     Generate example config (client/server)
    --api <ADDR>            Stats API listen address (e.g., 127.0.0.1:9090)
    -v, --version           Print version information
    -h, --help              Print help information

EXAMPLES:
    netium -c config.json
    netium -c config.json --api 127.0.0.1:9090
    netium --gen-config client > client.json
    netium --gen-config server > server.json

STATS API ENDPOINTS:
    GET /metrics             Prometheus metrics (for Grafana/Prometheus)
    GET /api/stats           Overview of all statistics
    GET /api/stats/dispatcher  Dispatcher stats (connections, traffic)
    GET /api/stats/router      Router stats (rule hits)
    GET /api/stats/inbounds    Per-inbound stats
    GET /api/stats/outbounds   Per-outbound stats
"#);
}

fn print_version() {
    println!("Netium v{}", env!("CARGO_PKG_VERSION"));
    println!("A modern VPN/proxy tool inspired by V2Ray");
}
