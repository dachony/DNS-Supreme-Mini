# DNS-Supreme-Mini

Lightweight DNS filtering server designed to run as a single container on MikroTik routers (RouterOS 7.x container feature).

A stripped-down version of [DNS-Supreme](https://github.com/dachony/DNS-supreme) optimized for constrained environments.

## Key Features

- Single container deployment (no external database)
- SQLite embedded database
- DNS ad/malware/tracker blocking with community blocklists
- LRU DNS cache
- Minimal web management UI
- Multi-arch support (AMD64, ARM64, ARM)
- Low memory footprint (~30-50MB RAM)

## Target Platform

- MikroTik routers with RouterOS 7.x container support
- Any Docker-capable device with limited resources

## Quick Start

```bash
docker run -d \
  --name dns-mini \
  -p 53:53/udp -p 53:53/tcp \
  -p 8080:8080 \
  -v dns-mini-data:/data \
  ghcr.io/dachony/dns-supreme-mini:latest
```

## License

MIT
