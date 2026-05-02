# Netium

A modern, high-performance proxy tool written in Rust, inspired by V2Ray.

## Features

- **VMess Protocol** - Full VMess protocol support with AEAD encryption
- **Multiple Transports** - TCP, WebSocket, TLS, WebSocket+TLS
- **Inbound Protocols** - SOCKS5, HTTP proxy
- **GeoIP/GeoSite Routing** - Smart traffic routing based on IP and domain rules
- **Built-in Rule Types** - Simplified routing configuration with `chinasites`, `chinaip`, `privateip`
- **Dynamic Routing** - Add/edit/remove routing rules at runtime via Web UI or API without restart
- **Middleware Chain** - Pluggable router stack: StaticRouter → DynamicRouter → fallback

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

### Stats API

Enable the stats API from the command line:

```bash
./netium -c config.json --api 127.0.0.1:9090
```

Or configure it in JSON:

```json
{
    "api": {
        "listen": "127.0.0.1:9090"
    }
}
```

Available endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/slow-queries` | Recent slow routing decisions |
| `DELETE` | `/slow-queries` | Clear slow query records |
| `GET` | `/ui` | Embedded route management page |
| `GET` | `/api/outbounds` | Available outbound tags |
| `GET` | `/api/observations` | Deduplicated fallback destinations (hitting the default outbound) |
| `POST` | `/api/observations/clear` | Clear observation records |
| `GET` | `/api/rules` | List persisted dynamic rules |
| `POST` | `/api/rules/add` | Add a dynamic rule |
| `POST` | `/api/rules/edit` | Edit a dynamic rule |
| `POST` | `/api/rules/remove` | Remove a dynamic rule |
| `POST` | `/api/rules/enable` | Enable or disable a dynamic rule |
| `POST` | `/api/rules/reload` | Reload dynamic rules from disk |
| `POST` | `/api/rules/from-observation` | Create a dynamic rule from an observed destination |

To observe destinations that fall through to the default outbound, enable dynamic
routing — unhandled destinations are automatically recorded and surfaced in `/api/observations`.
Example response:

```json
[
    {
        "destination": "example.com:443",
        "hits": 12,
        "first_seen": "2026-05-01T10:20:30.001Z",
        "last_seen": "2026-05-01T10:25:45.123Z"
    }
]
```

Click an outbound tag in the Web UI to create a dynamic rule from an observation.

### Dynamic Routes

Dynamic routes are user-managed rules evaluated after static config rules.
They are added, edited, or removed at runtime via the Web UI or API without restarting,
and persist to disk. When a destination matches a dynamic rule, its outbound overrides
whatever the static router chose. Enable them with:

```json
{
    "routing": {
        "dynamic": {
            "enabled": true,
            "file": "./dynamic_routes.json"
        },
        "rules": [
            {
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outbound_tag": "reject"
            },
            {
                "type": "chinasites",
                "outbound_tag": "direct"
            },
            {
                "type": "all",
                "label": "proxy-fallback",
                "record_destination": true,
                "outbound_tag": "proxy"
            }
        ]
    }
}
```

When `dynamic.enabled` is `true`, a `DynamicRouter` is added to the middleware chain
after the `StaticRouter`. Each dynamic rule item has its own
priority; the compiled groups are sorted ascending so higher-priority items override
lower-priority ones for the same destination.

Open `http://127.0.0.1:9090/ui` to manage rules from the embedded page.

Dynamic rules are persisted as JSON:

```json
{
    "version": 1,
    "rules": [
        {
            "id": "uuid",
            "enabled": true,
            "match_type": "domain",
            "pattern": "example.com",
            "port": null,
            "outbound": "direct",
            "priority": 100,
            "comment": "created from observation",
            "created_at": 1704067200,
            "updated_at": 1704067200
        }
    ]
}
```

Supported `match_type` values are `exact`, `domain`, `wildcard`, `regex`, `ip`, and `cidr`.

## Architecture

```
FallbackRouter           ← default outbound + records fallback destinations
  LoggingRouter          ← slow query tracking
    CompositeRouter      ← iterates router chain
      ├── StaticRouter   ← config rules (geosite/geoip/field/all)
      └── DynamicRouter  ← user-managed rules (optional)
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
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        },
        {
            "tag": "reject",
            "protocol": "reject"
        }
    ],
    "routing": {
        "dynamic": {
            "enabled": true,
            "file": "./dynamic_routes.json"
        },
        "rules": [
            { "type": "field", "domain": ["geosite:category-ads-all"], "outbound_tag": "reject" },
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
| `blackhole` | Drop connection (keeps open, simulates unresponsive server) |
| `reject` | Reject connection (immediately closes) |

### Transport

| Type | Description |
|------|-------------|
| `tcp` | Raw TCP connection |
| `websocket` | WebSocket transport |
| `tls` | TLS encryption |
| `websocket+tls` | WebSocket over TLS |

## License

MIT License
