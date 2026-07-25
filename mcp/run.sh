#!/usr/bin/env bash
# Launch the trafficdeck-mcp server. Exposes recorded sessions over the Model Context
# Protocol, backed by the gateway at $GATEWAY_ADDR (default 127.0.0.1:7331). Point your
# MCP client at this command; any extra args pass through. Run from anywhere.
#
# Transport via $MCP_TRANSPORT: streamable-http (default), sse, or stdio. The HTTP
# transports bind $MCP_HOST:$MCP_PORT (default 127.0.0.1:8765) and serve at /mcp; set
# MCP_TRANSPORT=stdio to speak the protocol over stdin/stdout instead.
#
# Read-only by default: set $MCP_READONLY=0 to also expose the mutating rename_session /
# set_session_group tools.
#
# Needs the gRPC stubs generated once (`mise run gen`) and the gateway running.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# trafficdeck-mcp is a non-package uv project (package = false), so run the module with
# the project dir as cwd rather than via a console script.
exec uv run --directory "$HERE" python -m traffic_mcp.server "$@"
