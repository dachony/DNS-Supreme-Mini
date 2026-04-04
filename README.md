# DNS-Supreme Mini

Full-featured DNS security and filtering server packaged as a single Docker container. Designed to run on MikroTik routers (RouterOS 7.x container feature) and other resource-constrained environments.

A single-container port of [DNS-Supreme](https://github.com/dachony/DNS-supreme) using embedded SQLite instead of PostgreSQL — all features preserved.

## Features

- **DNS Server** — UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), DNS-over-QUIC (DoQ)
- **DNS Filtering** — ads, malware, tracking blocking with community blocklists
- **Service Blocking** — block entire platforms (YouTube, TikTok, Facebook, Instagram, gaming, AI, etc.)
- **Network Protection** — IP-based threat intelligence feeds with automatic updates
- **GeoIP Blocking** — block DNS responses by country using MaxMind GeoLite2
- **Zone Management** — primary/secondary zones, full record types, AXFR transfers
- **ACME Certificates** — Let's Encrypt integration with DNS-01 challenge (local + Cloudflare)
- **TLS Certificates** — self-signed generation, upload, export (PEM/DER)
- **Block Page** — custom HTML block page with logo upload, HTTPS support
- **Device Policies** — per-device/network filtering rules
- **Web UI** — Vue.js SPA dashboard with real-time updates (SSE)
- **Authentication** — JWT with MFA (TOTP + email), role-based access (admin/viewer)
- **Fail2Ban** — brute-force protection with configurable thresholds
- **Audit Logging** — track all admin actions
- **Backup & Restore** — full database backup/restore via API
- **Email Notifications** — SMTP alerts for security events
- **Prometheus Metrics** — `/api/metrics` endpoint for monitoring
- **LRU DNS Cache** — configurable size with TTL-based expiry
- **Single Container** — no external database, embedded SQLite with persistent `/data` volume

## Quick Start (Docker)

```bash
docker run -d \
  --name dns-supreme-mini \
  -p 53:53/udp -p 53:53/tcp \
  -p 80:80 -p 443:443 \
  -p 853:853/tcp -p 853:853/udp \
  -p 5380:5380 \
  -v dns-data:/data \
  dachony/dnssuprememini:latest
```

### Login

- **Web UI:** `https://<ip>:5380`
- **Default credentials:** `admin` / `admin`
- You will be prompted to change the password on first login.

### Ports

| Port | Protocol | Service |
|------|----------|---------|
| 53 | UDP/TCP | DNS |
| 80 | TCP | Block page (HTTP) |
| 443 | TCP | Block page (HTTPS) + DoH |
| 853 | TCP | DNS-over-TLS (DoT) |
| 853 | UDP | DNS-over-QUIC (DoQ) |
| 5380 | TCP | Web UI & API (HTTPS) |

## MikroTik Deployment

### Prerequisites
- RouterOS 7.4+ with container support enabled
- USB or disk storage for container image and data
- At least 128MB RAM available

### Setup

1. Enable container mode (router will reboot):
```
/system/device-mode/update container=yes
```

2. Create VETH interface and bridge:
```
/interface/veth/add name=veth-dns address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=docker
/interface/bridge/port/add interface=veth-dns bridge=docker
/ip/address/add address=172.17.0.1/24 interface=docker
```

3. Configure NAT for container internet access:
```
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24
```

4. Create mount and environment:
```
/container/mounts/add name=dns-data src=disk1/dns-data dst=/data
/container/envs/add name=dns-env key=DNS_FORWARDERS value="8.8.8.8:53,1.1.1.1:53"
```

5. Pull and add the container:
```
/container/add remote-image=dachony/dnssuprememini:latest interface=veth-dns root-dir=disk1/dns-container mounts=dns-data envlist=dns-env logging=yes
```

6. Start the container:
```
/container/start 0
```

7. Point MikroTik DNS to the container:
```
/ip/dns/set servers=172.17.0.2
```

8. Access the web UI at `https://172.17.0.2:5380` — login with `admin` / `admin`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_PORT` | `53` | DNS listener port |
| `DNS_FORWARDERS` | `8.8.8.8:53,1.1.1.1:53` | Upstream DNS servers (comma-separated) |
| `DNS_CACHE_SIZE` | `10000` | Max cache entries |
| `API_PORT` | `5380` | Web UI/API port |
| `API_HTTPS_PORT` | `53443` | API HTTPS port (alternative) |
| `DATA_DIR` | `/data` | Persistent data directory (SQLite DB, certs, backups) |
| `BLOCK_PAGE_IP` | auto-detect | IP address for block page redirects |
| `TLS_CERT_FILE` | `/data/certs/server.crt` | Custom TLS certificate path |
| `TLS_KEY_FILE` | `/data/certs/server.key` | Custom TLS key path |
| `CONFIG_FILE` | | Path to JSON config file (overrides env vars) |

## Build from Source

```bash
# Single architecture
docker build -t dns-supreme-mini .

# Multi-arch build and push (AMD64 + ARM64 + ARMv7)
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t dachony/dnssuprememini:latest --push .
```

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 DNS-Supreme Mini                     │
│                                                      │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────┐ │
│  │DNS Server │  │ Filter    │  │  LRU Cache       │ │
│  │UDP/TCP :53│──│ Engine    │──│  (configurable)  │ │
│  │DoT    :853│  │           │  └──────────────────┘ │
│  │DoH    :443│  │ Blocklists│                        │
│  │DoQ    :853│  │ Services  │  ┌──────────────────┐ │
│  └───────────┘  │ Custom    │  │  Network Protect │ │
│                 │ GeoIP     │  │  GeoIP + Feeds   │ │
│  ┌───────────┐  └───────────┘  └──────────────────┘ │
│  │ Web UI    │                                       │
│  │ API :5380 │  ┌───────────┐  ┌──────────────────┐ │
│  │ Vue.js SPA│  │Block Page │  │  SQLite          │ │
│  └───────────┘  │HTTP  :80  │  │  /data/dns.db    │ │
│                 │HTTPS :443 │  └──────────────────┘ │
│  ┌───────────┐  └───────────┘                        │
│  │ Zone Mgmt │  ┌───────────┐  ┌──────────────────┐ │
│  │ AXFR      │  │ ACME/TLS  │  │  Auth/MFA/F2B    │ │
│  └───────────┘  └───────────┘  └──────────────────┘ │
└──────────────────────────────────────────────────────┘
```

## License

MIT
