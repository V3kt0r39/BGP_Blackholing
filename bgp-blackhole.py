#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bgp-blackhole.py

BGP Remote Triggered Black Hole (RTBH) automation tool.
Drops DDoS traffic at provider edge before it congests your pipe.

Backends:
    dry_run   — print commands only (for testing)
    cisco_ios — manage Cisco IOS via SSH (requires paramiko)
    frr       — manage FRRouting via vtysh (local)
    bird      — manage BIRD via config file (local)

Usage:
    ./bgp-blackhole.py blackhole [IP]           — blackhole an IP
    ./bgp-blackhole.py unblackhole [IP]         — remove blackhole
    ./bgp-blackhole.py status [IP]              — check BGP status
    ./bgp-blackhole.py detect                   — show auto-detected IP
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# --- optional deps ------------------------------------------------------------
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# --- constants ----------------------------------------------------------------
CONFIG_PATHS = [
    "./bgp-blackhole.yaml",
    "./bgp-blackhole.json",
    "~/.bgp-blackhole.yaml",
    "~/.bgp-blackhole.json",
    "/etc/bgp-blackhole.yaml",
    "/etc/bgp-blackhole.json",
]

DEFAULTS = {
    "backend": "dry_run",
    "asn": 65001,
    "neighbor": None,
    "community": "65535:666",
    "auto_detect": True,
    "allow_private": False,
    "preferred_interface": None,
    "confirm": True,
    "cisco": {
        "host": None,
        "username": None,
        "password": None,
        "enable_password": None,
        "timeout": 30,
    },
    "frr": {
        "vtysh": "/usr/bin/vtysh",
    },
    "bird": {
        "routes_file": "/etc/bird/blackhole-routes.conf",
        "reload_cmd": "/usr/sbin/birdc configure",
    },
}

# --- logging ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("bgp-blackhole")


# --- config -------------------------------------------------------------------
def load_config():
    cfg = dict(DEFAULTS)

    env_map = {
        "BGP_BLACKHOLE_BACKEND": ("backend", str),
        "BGP_BLACKHOLE_ASN": ("asn", int),
        "BGP_BLACKHOLE_NEIGHBOR": ("neighbor", str),
        "BGP_BLACKHOLE_COMMUNITY": ("community", str),
        "BGP_BLACKHOLE_CISCO_HOST": ("cisco", "host"),
        "BGP_BLACKHOLE_CISCO_USER": ("cisco", "username"),
        "BGP_BLACKHOLE_CISCO_PASS": ("cisco", "password"),
    }
    for env, path in env_map.items():
        val = os.getenv(env)
        if not val:
            continue
        if isinstance(path, tuple):
            section, key = path[0], path[1]
            cfg.setdefault(section, {})
            cfg[section][key] = path[2](val) if len(path) > 2 else val
        else:
            cfg[path] = val

    for p in CONFIG_PATHS:
        p = Path(p).expanduser()
        if not p.exists():
            continue
        try:
            raw = p.read_text()
            if p.suffix in (".yaml", ".yml") and HAS_YAML:
                loaded = yaml.safe_load(raw) or {}
            else:
                loaded = json.loads(raw)
            cfg = deep_merge(cfg, loaded)
            log.info("Loaded config: %s", p)
            break
        except Exception as exc:
            log.warning("Failed to load %s: %s", p, exc)

    return cfg


def deep_merge(base, override):
    result = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and k in result and isinstance(result[k], dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# --- IP detection -------------------------------------------------------------
def detect_public_ip(preferred_iface=None, allow_private=False):
    """Detect public IPv4 of the current server."""
    candidates = []

    # 1. via ip route + ip addr (Linux)
    try:
        out = subprocess.check_output(
            ["ip", "-j", "route", "get", "1.1.1.1"], text=True
        )
        route_info = json.loads(out)
        iface = None
        if isinstance(route_info, list) and route_info:
            iface = route_info[0].get("dev")
        if preferred_iface:
            iface = preferred_iface

        out = subprocess.check_output(["ip", "-j", "addr", "show", iface or "eth0"], text=True)
        addrs = json.loads(out)
        for item in addrs:
            for addr_info in item.get("addr_info", []):
                if addr_info.get("family") == "inet":
                    candidates.append(addr_info.get("local"))
    except Exception:
        pass

    # 2. fallback: hostname -I
    if not candidates:
        try:
            out = subprocess.check_output(["hostname", "-I"], text=True).strip()
            candidates = out.split()
        except Exception:
            pass

    # 3. cloud metadata (AWS)
    if not candidates:
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/public-ipv4",
                timeout=2,
            )
            with urllib.request.urlopen(req) as resp:
                candidates.append(resp.read().decode().strip())
        except Exception:
            pass

    # filtering
    for c in candidates:
        try:
            ip = ipaddress.ip_address(c)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast:
                continue
            if ip.is_private and not allow_private:
                continue
            return str(ip)
        except ValueError:
            continue

    return None


def validate_ip(ip_str, allow_private=False):
    ip = ipaddress.ip_address(ip_str)
    if ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise ValueError(f"IP {ip_str} is not suitable for blackhole")
    if ip.is_private and not allow_private:
        raise ValueError(
            f"IP {ip_str} is private. Use --allow-private or set allow_private: true"
        )
    return str(ip)


# --- backends -----------------------------------------------------------------
class DryRunBackend:
    name = "dry_run"

    def __init__(self, cfg):
        self.cfg = cfg

    def blackhole(self, ip, mask=None):
        log.info("[DRY-RUN] Create blackhole for %s/%s", ip, mask or "32")
        log.info("[DRY-RUN] Community: %s", self.cfg.get("community"))
        log.info("[DRY-RUN] Cisco commands:")
        print(f"  ip route {ip} {mask or '255.255.255.255'} Null0")
        print(f"  router bgp {self.cfg['asn']}")
        print(f"  network {ip} mask {mask or '255.255.255.255'}")
        print(f"  end")
        print(f"  clear ip bgp {self.cfg['neighbor']} soft out")

    def unblackhole(self, ip, mask=None):
        log.info("[DRY-RUN] Remove blackhole for %s/%s", ip, mask or "32")
        print(f"  no ip route {ip} {mask or '255.255.255.255'} Null0")
        print(f"  router bgp {self.cfg['asn']}")
        print(f"  no network {ip} mask {mask or '255.255.255.255'}")
        print(f"  end")
        print(f"  clear ip bgp {self.cfg['neighbor']} soft out")

    def status(self, ip):
        log.info("[DRY-RUN] Check: show bgp ipv4 unicast %s", ip)


class CiscoIOSBackend:
    name = "cisco_ios"

    def __init__(self, cfg):
        self.cfg = cfg
        self.cisco = cfg.get("cisco", {})
        if not HAS_PARAMIKO:
            sys.exit("ERROR: backend 'cisco_ios' requires paramiko: pip install paramiko")
        for k in ("host", "username", "password"):
            if not self.cisco.get(k):
                sys.exit(f"ERROR: cisco.{k} is not set in config")

    def _connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.cisco["host"],
            username=self.cisco["username"],
            password=self.cisco["password"],
            timeout=self.cisco.get("timeout", 30),
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def _exec(self, client, commands):
        shell = client.invoke_shell()
        time.sleep(0.5)
        enable_pass = self.cisco.get("enable_password")
        if enable_pass:
            shell.send("enable\n")
            time.sleep(0.3)
            shell.send(enable_pass + "\n")
            time.sleep(0.3)
        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(0.3)
        time.sleep(1)
        output = shell.recv(65535).decode("utf-8", errors="ignore")
        shell.close()
        return output

    def blackhole(self, ip, mask=None):
        mask = mask or "255.255.255.255"
        neighbor = self.cfg.get("neighbor")
        commands = [
            "conf t",
            f"ip route {ip} {mask} Null0",
            f"router bgp {self.cfg['asn']}",
            f"network {ip} mask {mask}",
            "end",
        ]
        if neighbor:
            commands.append(f"clear ip bgp {neighbor} soft out")
        log.info("Applying blackhole on Cisco IOS (%s)...", self.cisco["host"])
        client = self._connect()
        try:
            out = self._exec(client, commands)
            log.info("Output:\n%s", out)
        finally:
            client.close()

    def unblackhole(self, ip, mask=None):
        mask = mask or "255.255.255.255"
        neighbor = self.cfg.get("neighbor")
        commands = [
            "conf t",
            f"no ip route {ip} {mask} Null0",
            f"router bgp {self.cfg['asn']}",
            f"no network {ip} mask {mask}",
            "end",
        ]
        if neighbor:
            commands.append(f"clear ip bgp {neighbor} soft out")
        log.info("Removing blackhole on Cisco IOS (%s)...", self.cisco["host"])
        client = self._connect()
        try:
            out = self._exec(client, commands)
            log.info("Output:\n%s", out)
        finally:
            client.close()

    def status(self, ip):
        commands = [
            f"show bgp ipv4 unicast {ip}",
            f"show ip route {ip}",
        ]
        client = self._connect()
        try:
            out = self._exec(client, commands)
            print(out)
        finally:
            client.close()


class FRRBackend:
    name = "frr"

    def __init__(self, cfg):
        self.cfg = cfg
        self.vtysh = cfg.get("frr", {}).get("vtysh", "/usr/bin/vtysh")

    def _run(self, commands):
        cmd = [self.vtysh, "-c", "conf t"]
        for c in commands:
            cmd += ["-c", c]
        cmd += ["-c", "end"]
        log.info("Running: %s", " ".join(cmd))
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        return out

    def blackhole(self, ip, mask=None):
        prefix = f"{ip}/{mask}" if mask else f"{ip}/32"
        neighbor = self.cfg.get("neighbor")
        commands = [
            f"ip route {prefix} blackhole",
            f"router bgp {self.cfg['asn']}",
            f"network {prefix}",
        ]
        out = self._run(commands)
        log.info(out)
        if neighbor:
            subprocess.run([self.vtysh, "-c", f"clear ip bgp {neighbor} soft out"], check=False)

    def unblackhole(self, ip, mask=None):
        prefix = f"{ip}/{mask}" if mask else f"{ip}/32"
        neighbor = self.cfg.get("neighbor")
        commands = [
            f"no ip route {prefix} blackhole",
            f"router bgp {self.cfg['asn']}",
            f"no network {prefix}",
        ]
        out = self._run(commands)
        log.info(out)
        if neighbor:
            subprocess.run([self.vtysh, "-c", f"clear ip bgp {neighbor} soft out"], check=False)

    def status(self, ip):
        prefix = f"{ip}/32"
        out = subprocess.check_output([self.vtysh, "-c", f"show bgp ipv4 unicast {prefix}"], text=True)
        print(out)


class BIRDBackend:
    name = "bird"

    def __init__(self, cfg):
        self.cfg = cfg
        self.routes_file = Path(cfg.get("bird", {}).get("routes_file", "/etc/bird/blackhole-routes.conf"))
        self.reload_cmd = cfg.get("bird", {}).get("reload_cmd", "/usr/sbin/birdc configure")

    def _read_routes(self):
        if not self.routes_file.exists():
            return []
        lines = self.routes_file.read_text().splitlines()
        routes = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        return routes

    def _write_routes(self, routes):
        header = (
            "# AUTO-GENERATED by bgp-blackhole.py\n"
            "# DO NOT EDIT MANUALLY\n"
            'protocol static blackhole_static {\n    ipv4;\n'
        )
        body = "".join(f"    {r}\n" for r in routes)
        footer = "}"
        self.routes_file.write_text(header + body + footer)
        log.info("Reloading BIRD: %s", self.reload_cmd)
        subprocess.run(self.reload_cmd, shell=True, check=False)

    def blackhole(self, ip, mask=None):
        prefix = f"{ip}/{mask}" if mask else f"{ip}/32"
        route_line = f"route {prefix} reject;"
        routes = self._read_routes()
        if route_line in routes:
            log.warning("Route already exists")
            return
        routes.append(route_line)
        self._write_routes(routes)

    def unblackhole(self, ip, mask=None):
        prefix = f"{ip}/{mask}" if mask else f"{ip}/32"
        route_line = f"route {prefix} reject;"
        routes = self._read_routes()
        if route_line not in routes:
            log.warning("Route not found")
            return
        routes.remove(route_line)
        self._write_routes(routes)

    def status(self, ip):
        prefix = f"{ip}/32"
        routes = self._read_routes()
        match = any(prefix in r for r in routes)
        print(f"BIRD blackhole_static: {'ACTIVE' if match else 'NOT FOUND'} for {prefix}")


BACKENDS = {
    "dry_run": DryRunBackend,
    "cisco_ios": CiscoIOSBackend,
    "frr": FRRBackend,
    "bird": BIRDBackend,
}


# --- CLI ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="BGP Blackhole automation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s blackhole                  # auto-detect IP and blackhole it
  %(prog)s blackhole 203.0.113.5      # specify IP explicitly
  %(prog)s unblackhole 203.0.113.5    # remove blackhole
  %(prog)s status 203.0.113.5         # check status in BGP
  %(prog)s detect                     # show auto-detected IP
        """,
    )
    parser.add_argument("action", choices=["blackhole", "unblackhole", "status", "detect"])
    parser.add_argument("ip", nargs="?", help="IP address (if omitted — auto-detect)")
    parser.add_argument("--backend", choices=list(BACKENDS.keys()), help="Backend")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--force", "-f", action="store_true", help="Skip confirmation")
    parser.add_argument("--allow-private", action="store_true", help="Allow private IPs")
    parser.add_argument("--community", help="BGP community (e.g. 65535:666)")
    parser.add_argument("--neighbor", help="BGP neighbor IP for clear/soft-reconfig")
    parser.add_argument("--interface", "-i", help="Preferred interface for auto-detection")

    args = parser.parse_args()

    cfg = load_config()
    if args.config:
        cfg = deep_merge(cfg, json.loads(Path(args.config).read_text()))

    # CLI overrides
    if args.backend:
        cfg["backend"] = args.backend
    if args.community:
        cfg["community"] = args.community
    if args.neighbor:
        cfg["neighbor"] = args.neighbor
    if args.allow_private:
        cfg["allow_private"] = True
    if args.interface:
        cfg["preferred_interface"] = args.interface

    backend_cls = BACKENDS.get(cfg["backend"])
    if not backend_cls:
        sys.exit(f"Unknown backend: {cfg['backend']}")

    # detect IP
    if args.action == "detect":
        ip = detect_public_ip(cfg.get("preferred_interface"), cfg.get("allow_private", False))
        if ip:
            print(ip)
            sys.exit(0)
        else:
            print("Failed to detect public IP", file=sys.stderr)
            sys.exit(1)

    ip = args.ip
    if not ip:
        if not cfg.get("auto_detect"):
            sys.exit("IP not specified and auto_detect is disabled")
        ip = detect_public_ip(cfg.get("preferred_interface"), cfg.get("allow_private", False))
        if not ip:
            sys.exit(
                "Failed to auto-detect public IP. Specify it explicitly or use --allow-private."
            )

    try:
        ip = validate_ip(ip, cfg.get("allow_private", False))
    except ValueError as exc:
        sys.exit(f"IP validation error: {exc}")

    # safety checks
    if ip in ("0.0.0.0", "::"):
        sys.exit("Blackhole for 0.0.0.0 is not allowed")
    neighbor = cfg.get("neighbor")
    if neighbor and ip == neighbor:
        sys.exit("Cannot blackhole BGP neighbor IP")

    # confirmation
    if cfg.get("confirm", True) and not args.force and args.action in ("blackhole", "unblackhole"):
        action_text = "blackhole" if args.action == "blackhole" else "remove blackhole from"
        ans = input(f"Are you sure you want to {action_text} {ip}? [y/N]: ")
        if ans.lower() not in ("y", "yes"):
            print("Cancelled")
            sys.exit(0)

    backend = backend_cls(cfg)

    if args.action == "blackhole":
        backend.blackhole(ip)
        log.info("Done. Check: ./bgp-blackhole.py status %s", ip)
    elif args.action == "unblackhole":
        backend.unblackhole(ip)
    elif args.action == "status":
        backend.status(ip)


if __name__ == "__main__":
    main()
