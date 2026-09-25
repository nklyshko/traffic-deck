#!/usr/bin/env bash
# Launch the macOS per-process (PKTAP) Chrome capture.
#
#   ./capture-pktap.sh                  start the source the gateway dials, and leave it up
#   ./capture-pktap.sh --label demo     one interactive capture instead (any flag does this)
#
# Serving is the default because that is what this tool is for: the module is started once
# and left running, while captures come and go from the viewer. Passing any argument means
# you are configuring a one-shot capture, so it falls through to that. See capture_pktap/cli.py.
#
# PKTAP creates its capture interface with a privileged ioctl, so unlike the dumpcap tools
# this needs root — Wireshark's ChmodBPF does not cover it. Rather than failing we re-exec
# under sudo, so there is one password (or Touch ID) prompt and nothing else to remember.
# The browser is still launched as you, never as root.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "capture-pktap: PKTAP is macOS-only — use ./capture-chrome.sh here" >&2
  exit 1
fi

args=("$@")
if [[ ${#args[@]} -eq 0 ]]; then
  args=(serve)
fi

# `serve` with no --control takes the address from the installed manifest, so the port
# lives in exactly one place and the command the user types stays short. Resolved here,
# before the sudo re-exec, so $HOME is still theirs and not root's.
if [[ "${args[0]}" == "serve" && " ${args[*]} " != *" --control "* ]]; then
  manifest="${TRAFFIC_DECK_HOME:-$HOME/.traffic-deck}/plugins/pktap.toml"
  if [[ ! -f "$manifest" ]]; then
    echo "capture-pktap: no module manifest at $manifest" >&2
    echo "  run 'make install-pktap' first, or pass --control host:port explicitly" >&2
    exit 1
  fi
  addr="$(sed -n 's/^[[:space:]]*addr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -1)"
  if [[ -z "$addr" ]]; then
    echo "capture-pktap: no [control] addr in $manifest — re-run 'make install-pktap'" >&2
    exit 1
  fi
  echo "serving on $addr (from $manifest)" >&2
  args+=(--control "$addr")
fi

# Re-exec under sudo, preserving the invoking user's identity: SUDO_UID/SUDO_GID are how
# the tool knows who to launch the browser as and whose home to resolve profiles against.
if [[ "$(id -u)" != "0" ]]; then
  echo "pktap needs root to create its capture interface — re-running under sudo …" >&2
  exec sudo -- "$0" "${args[@]}"
fi

exec uv run --project "$HERE/capture_pktap" trafficdeck-capture-pktap "${args[@]}"
