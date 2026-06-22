#!/usr/bin/env bash
# Launch the Chrome live-capture tool (plan §7.2). Run with no arguments for a
# default local capture; any extra flags pass through (e.g. --label, --url,
# --duration, --profile-dir). See capture_chrome/capture_chrome/cli.py for all flags.
#
# dumpcap needs capture permission: on Linux be in the `wireshark` group (or wrap
# this in `sg wireshark -c '…'`); on macOS use Wireshark's ChmodBPF.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --project "$HERE/capture_chrome" capture-chrome "$@"
