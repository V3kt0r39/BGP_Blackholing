#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT_DIR}/bgp-blackhole.py"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <blackhole|unblackhole|status|detect> [IP]"
    echo ""
    echo "Emergency blackhole trigger script."
    echo ""
    echo "Examples:"
    echo "  $0 blackhole            # auto-detect IP and blackhole it"
    echo "  $0 blackhole 1.2.3.4    # blackhole specific IP"
    echo "  $0 unblackhole 1.2.3.4  # remove blackhole"
    echo ""
    echo "Environment variables:"
    echo "  BGP_BLACKHOLE_BACKEND    Backend to use (dry_run, cisco_ios, frr, bird)"
    echo "  BGP_BLACKHOLE_NEIGHBOR   BGP neighbor IP"
    exit 1
fi

exec python3 "$SCRIPT" --force "$@"
