#!/usr/bin/env bash
# Launch the TrafficDeck TUI. Connects to the gateway at $GATEWAY_ADDR
# (default 127.0.0.1:7331); any extra args pass through. Run from anywhere.
#
# Needs the gRPC stubs generated once (`mise run gen`) and the gateway running.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The viewer is a non-package uv project (package = false), so run the module with the
# project dir as cwd rather than via a console script.
exec uv run --directory "$HERE" python -m traffic_viewer.app "$@"
