# DNS-Supreme-Mini

Lightweight DNS filtering server designed to run as a single container on MikroTik routers (RouterOS 7.x container feature).

A stripped-down version of [DNS-Supreme](https://github.com/dachony/DNS-supreme) optimized for constrained environments.

## Key Features

- **Single container** - no external database (SQLite embedded)
- **DNS filtering** - ads, malware, tracking blocking with community blocklists
- **Service blocking** - block entire services (YouTube, TikTok, Facebook, etc.)
- **LRU DNS cache** with TTL-based expiry
- **Web management UI** - dashboard, query log, blocklist management
- **REST API** - full API for automation
- **Authentication** - JWT auth, MFA (TOTP), role-based access
- **Fail2Ban** - brute-force protection
- **Block page** - custom HTML block pages
- **Multi-arch** - AMD64, ARM64 (MikroTik)
- **Low footprint** - ~30-50MB RAM, ~15MB image

## Architecture

```
┌─────────────────────────────────────────┐
│          DNS-Supreme Mini               │
│                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │DNS Server│  │Filter    │  │ Cache │ │
│  │UDP/TCP:53│──│Engine    │──│ LRU   │ │
│  └──────────┘  └──────────┘  └───────┘ │
│                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │ Web API  │  │Block Page│  │SQLite │ │
│  │ :8080    │  │ :80      │  │/data  │ │
│  └──────────┘  └──────────┘  └───────┘ │
└─────────────────────────────────────────┘
```

## Quick Start (Docker)

```bash
docker run -d \
  --name dns-mini \
  -p 53:53/udp -p 53:53/tcp \
  -p 8080:8080 \
  -p 80:80 \
  -v dns-mini-data:/data \
  ghcr.io/dachony/dns-supreme-mini:latest
```

Default login: **admin** / **admin** (change on first login)

Web UI: `http://<ip>:8080/ui/`

## Build from Source

```bash
docker build -t dns-supreme-mini .

# Multi-arch build (for MikroTik ARM64)
docker buildx build --platform linux/amd64,linux/arm64 -t dns-supreme-mini .
```

## MikroTik Deployment

### Prerequisites
- RouterOS 7.4+ with container support
- USB/disk storage for container image and data
- At least 128MB RAM available

### Setup

1. Enable container mode on MikroTik:
```
/system/device-mode/update container=yes
```
(Router will reboot)

2. Create VETH interface:
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

5. Add container:
```
/container/add remote-image=ghcr.io/dachony/dns-supreme-mini:latest \
  interface=veth-dns root-dir=disk1/dns-container \
  mounts=dns-data envlist=dns-env logging=yes
```

6. Start container:
```
/container/start 0
```

7. Set MikroTik to use the container as DNS:
```
/ip/dns/set servers=172.17.0.2
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_PORT` | `53` | DNS listener port |
| `DNS_FORWARDERS` | `8.8.8.8:53,1.1.1.1:53` | Upstream DNS servers |
| `DNS_CACHE_SIZE` | `5000` | Max cache entries |
| `API_PORT` | `8080` | Web UI/API port |
| `DATA_DIR` | `/data` | SQLite database directory |
| `BLOCK_PAGE_IP` | auto-detect | IP for block page redirects |
| `BLOCKPAGE_HTTP_PORT` | `80` | Block page HTTP port |
| `CONFIG_FILE` | | Path to JSON config file |

## API Endpoints

### Public
- `GET /api/health` - Health check
- `POST /api/auth/login` - Login

### Authenticated (viewer + admin)
- `GET /api/stats` - Dashboard statistics
- `GET /api/logs` - Query log
- `GET /api/blocklists` - List blocklists
- `GET /api/custom-blocks` - Custom block rules
- `GET /api/allowlist` - Allowlist
- `GET /api/categories` - Filter categories
- `GET /api/block-services` - Service blocking status

### Admin only
- `POST /api/blocklists` - Add blocklist
- `DELETE /api/blocklists/:name` - Remove blocklist
- `POST /api/custom-blocks` - Add custom block
- `POST /api/allowlist` - Add to allowlist
- `PUT /api/settings/forwarders` - Set DNS forwarders
- `POST /api/cache/flush` - Flush DNS cache
- `POST /api/restart` - Restart server

## Differences from DNS-Supreme

| Feature | DNS-Supreme | Mini |
|---------|------------|------|
| Database | PostgreSQL | SQLite |
| Containers | 2 (app + db) | 1 |
| DoT/DoH/DoQ | Yes | No |
| DNSSEC | Yes | No |
| Zone management | Yes | No |
| ACME certificates | Yes | No |
| Clustering | Yes | No |
| Email notifications | Yes | No |
| GeoIP blocking | Yes | No |
| Network protection | Yes | No |
| Service blocking | Yes | Yes |
| Blocklists | Yes | Yes |
| Query logging | Yes | Yes |
| Web UI | Vue.js SPA | Embedded HTML |
| Auth/MFA | Yes | Yes |
| Fail2Ban | Yes | Yes |
| Block page | Yes | Yes |
| RAM usage | ~200MB | ~30-50MB |
| Image size | ~100MB | ~15MB |

## License

MIT
