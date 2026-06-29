# BGP Blackhole

Automation tool for [Remote Triggered Black Hole (RTBH)](https://tools.ietf.org/html/rfc7999) — quickly drops DDoS traffic at the provider edge before it congests your pipe.

## How It Works

1. Your server/router announces a route to the attacked IP with a blackhole community tag to the provider
2. The provider (or upstream) redirects traffic to null on their side
3. DDoS traffic never reaches your network

```
                        ┌──────────────┐
   DDoS Traffic ───────▶│   Provider   │──────▶ dropped at provider edge
                        │  (upstream)  │
                        └──────┬───────┘
                               │ BGP announce
                               │ community: 65535:666
                        ┌──────┴───────┐
                        │  Your Router │──────▶ null route (ip route x.x.x.x Null0)
                        │  (edge)      │
                        └──────────────┘
```

## Features

- **Auto-detect public IP** — from Linux routing table, `hostname -I`, or cloud metadata (AWS)
- **Multiple backends** — dry_run (testing), Cisco IOS (SSH), FRRouting, BIRD
- **Config via YAML/JSON** or environment variables
- **Systemd integration** — per-IP service templates for automated blackhole management
- **Safety checks** — prevents blackholing BGP neighbors, 0.0.0.0, loopback, etc.

## Quick Start

```bash
git clone https://github.com/USERNAME/bgp-blackhole.git
cd bgp-blackhole

# 1. Copy and edit config
cp config.yaml.example config.yaml
nano config.yaml

# 2. Check auto-detected IP
./bgp-blackhole.py detect

# 3. Dry run (default backend)
./bgp-blackhole.py blackhole

# 4. Switch backend and apply
BGP_BLACKHOLE_BACKEND=frr ./bgp-blackhole.py blackhole --force
```

## Usage

```
./bgp-blackhole.py blackhole [IP]           # blackhole an IP
./bgp-blackhole.py unblackhole [IP]         # remove blackhole
./bgp-blackhole.py status [IP]              # check BGP status
./bgp-blackhole.py detect                   # show auto-detected IP
```

### Options

| Flag | Description |
|------|-------------|
| `--backend` | Backend: `dry_run`, `cisco_ios`, `frr`, `bird` |
| `-c, --config` | Path to config file |
| `-f, --force` | Skip confirmation prompt |
| `--allow-private` | Allow blackholing private IPs |
| `--community` | BGP community (e.g. `65535:666`) |
| `--neighbor` | BGP neighbor IP for `clear ip bgp ... soft out` |
| `-i, --interface` | Preferred interface for IP detection |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `BGP_BLACKHOLE_BACKEND` | Backend selection |
| `BGP_BLACKHOLE_ASN` | Your ASN |
| `BGP_BLACKHOLE_NEIGHBOR` | BGP neighbor IP |
| `BGP_BLACKHOLE_COMMUNITY` | RTBH community tag |
| `BGP_BLACKHOLE_CISCO_HOST` | Cisco SSH host |
| `BGP_BLACKHOLE_CISCO_USER` | Cisco SSH username |
| `BGP_BLACKHOLE_CISCO_PASS` | Cisco SSH password |

## Backends

### dry_run (default)

Prints commands without executing. Useful for testing and understanding what would happen.

```bash
./bgp-blackhole.py blackhole 203.0.113.5
# [DRY-RUN] Create blackhole for 203.0.113.5/32
#   ip route 203.0.113.5 255.255.255.255 Null0
#   router bgp 65001
#   network 203.0.113.5 mask 255.255.255.255
```

### cisco_ios

Manages Cisco IOS routers via SSH (requires `paramiko`).

```bash
pip install paramiko
BGP_BLACKHOLE_BACKEND=cisco_ios ./bgp-blackhole.py blackhole 203.0.113.5
```

### frr

Manages FRRouting via `vtysh` (local).

```bash
BGP_BLACKHOLE_BACKEND=frr ./bgp-blackhole.py blackhole 203.0.113.5
```

### bird

Manages BIRD by writing to a config file and reloading (local).

```bash
BGP_BLACKHOLE_BACKEND=bird ./bgp-blackhole.py blackhole 203.0.113.5
```

## Systemd Integration

Use per-IP service templates for automated management:

```bash
# Install the service template
cp systemd/bgp-blackhole@.service /etc/systemd/system/
systemctl daemon-reload

# Blackhole an IP
systemctl start bgp-blackhole@203.0.113.5.service

# Remove blackhole
systemctl stop bgp-blackhole@203.0.113.5.service
```

See [systemd/README.md](systemd/README.md) for details.

## Emergency Trigger Script

For quick blackholing during an active DDoS attack:

```bash
# Blackhole detected IP
./trigger.sh blackhole

# Blackhole specific IP
./trigger.sh blackhole 203.0.113.5

# Remove blackhole
./trigger.sh unblackhole 203.0.113.5
```

## Configuration

The tool looks for config in this order:

1. `./bgp-blackhole.yaml` or `./bgp-blackhole.json`
2. `~/.bgp-blackhole.yaml` or `~/.bgp-blackhole.json`
3. `/etc/bgp-blackhole.yaml` or `/etc/bgp-blackhole.json`

See [config.yaml.example](config.yaml.example) for all options.

## Dependencies

- **Python 3.6+** (no external deps for dry_run/frr/bird backends)
- **paramiko** (only for cisco_ios backend: `pip install paramiko`)
- **PyYAML** (optional, for YAML config files: `pip install pyyaml`)

## Provider RTBH Community

You must obtain the correct RTBH community value from your provider. Common values:

| Community | Description |
|-----------|-------------|
| `65535:666` | "Traditional" value (not a standard!) |
| Provider-specific | Check your provider's documentation |

RFC 7999 defines the standard, but each provider may use different community values.

## License

MIT
