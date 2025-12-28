# Netium

A modern, high-performance proxy tool written in Rust, inspired by V2Ray.

## Features

- **VMess Protocol** - Full VMess protocol support with AEAD encryption
- **Multiple Transports** - TCP, WebSocket, TLS, WebSocket+TLS
- **Inbound Protocols** - SOCKS5, HTTP proxy
- **GeoIP/GeoSite Routing** - Smart traffic routing based on IP and domain rules
- **Built-in Rule Types** - Simplified routing configuration with `chinasites`, `chinaip`, `privateip`

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/user/netium.git
cd netium

# Build release version
cargo build --release

# Binary will be at target/release/netium
```

## Usage

### Client Mode

```bash
# Run with config file
./netium -c config.json

# Or specify config path
./netium --config /path/to/client.json
```

### Server Mode

```bash
./netium -c server.json
```

## Configuration

### Client Configuration Example

```json
{
    "log": {
        "level": "info"
    },
    "inbounds": [
        {
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1:1080",
            "settings": {
                "auth": "noauth",
                "udp": true
            }
        },
        {
            "tag": "http-in",
            "protocol": "http",
            "listen": "127.0.0.1:8080",
            "settings": {}
        }
    ],
    "outbounds": [
        {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "uuid": "your-uuid-here",
                "security": "auto",
                "alter_id": 0
            },
            "transport": {
                "address": "your-server.com",
                "port": 443,
                "transport_type": "websocket",
                "ws_settings": {
                    "path": "/ws"
                },
                "tls_settings": {
                    "enabled": true,
                    "server_name": "your-server.com"
                }
            }
        },
        {
            "tag": "direct",
            "protocol": "direct"
        }
    ],
    "routing": {
        "rules": [
            { "type": "chinasites", "outbound_tag": "direct" },
            { "type": "chinaip", "outbound_tag": "direct" },
            { "type": "privateip", "outbound_tag": "direct" },
            { "type": "all", "outbound_tag": "proxy" }
        ]
    }
}
```

### Routing Rule Types

| Type | Description |
|------|-------------|
| `chinasites` | Match domains in China (geosite:cn) |
| `chinaip` | Match IP addresses in China (geoip:cn) |
| `privateip` | Match private/local IP addresses (10.x, 192.168.x, 127.x, etc.) |
| `field` | Custom field-based matching (domain, ip, port) |
| `all` | Match all traffic (catch-all rule) |

### Field-based Routing

For more granular control, use `field` type with specific matchers:

```json
{
    "type": "field",
    "domain": ["google.com", "github.com"],
    "outbound_tag": "proxy"
}
```

```json
{
    "type": "field",
    "ip": ["8.8.8.8", "1.1.1.1"],
    "outbound_tag": "direct"
}
```

## GeoIP/GeoSite Data

For GeoIP and GeoSite routing to work, place the data files in one of these locations:

- `./geoip.dat` and `./geosite.dat` (current directory)
- `/usr/share/netium/geoip.dat` and `/usr/share/netium/geosite.dat`

You can download the data files from [v2ray/geoip](https://github.com/v2fly/geoip) and [v2ray/domain-list-community](https://github.com/v2fly/domain-list-community).

## Supported Protocols

### Inbound

| Protocol | Description |
|----------|-------------|
| `socks` | SOCKS5 proxy (with optional UDP support) |
| `http` | HTTP/HTTPS proxy |
| `vmess` | VMess server (for relay/transfer) |

### Outbound

| Protocol | Description |
|----------|-------------|
| `vmess` | VMess client |
| `direct` | Direct connection (bypass proxy) |

### Transport

| Type | Description |
|------|-------------|
| `tcp` | Raw TCP connection |
| `websocket` | WebSocket transport |
| `tls` | TLS encryption |
| `websocket+tls` | WebSocket over TLS |

## License

MIT License
