#!/usr/bin/env bash
# Launch the mitmproxy capture agent. Run with no arguments for a
# regular HTTP proxy on :8080; extra flags pass through (e.g. --mode wireguard,
# --label, --listen-port). Args after `--` are forwarded to mitmdump.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --project "$HERE/capture_mitmproxy" trafficdeck-capture-mitmproxy "$@"
