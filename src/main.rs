//! Netium - A modern VPN/proxy tool inspired by V2Ray

use std::path::PathBuf;

use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use netium::config::Config;
use netium::error::Result;
use netium::app::{Runtime, RuntimeConfig};

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

    // Convert Config to RuntimeConfig using From trait
    let mut runtime_config = RuntimeConfig::from(&config);
    
    // Override API listen from command line
    if args.api_listen.is_some() {
        runtime_config.api_listen = args.api_listen;
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
