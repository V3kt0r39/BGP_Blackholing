# systemd: BGP Blackhole Service

A template systemd service unit for managing per-IP blackholes via systemd.

## Installation

```bash
cp systemd/bgp-blackhole@.service /etc/systemd/system/
systemctl daemon-reload
```

## Usage

```bash
# Blackhole an IP (starts the service)
systemctl start bgp-blackhole@203.0.113.5.service

# Remove blackhole (stops the service)
systemctl stop bgp-blackhole@203.0.113.5.service

# Check status
systemctl status bgp-blackhole@203.0.113.5.service
```

## How It Works

- `systemctl start` runs the blackhole command (adds Null0 route + BGP announcement)
- `systemctl stop` runs the unblackhole command (removes the route)
- `RemainAfterExit=yes` keeps the service in "active" state after start, so `stop` can clean up

## Notes

- The service uses `--force` to skip interactive confirmation
- Make sure `/etc/bgp-blackhole.yaml` exists and is configured before use
- The `%i` systemd specifier is the IP address passed as the instance name
