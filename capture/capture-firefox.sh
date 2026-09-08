#!/usr/bin/env bash
# Launch the Firefox live-capture tool. Run with no arguments for the
# interactive flow (pick Firefox binary + profile); any extra flags pass through
# (e.g. --label, --url, --duration). See capture_firefox/capture_firefox/cli.py.
#
# dumpcap needs the `wireshark` group active. If it isn't runnable right now but we're
# a member of that group on paper (e.g. added but not re-logged-in), re-exec the whole
# command under `sg wireshark` so capture works without a manual wrapper. On macOS use
# Wireshark's ChmodBPF instead (no `sg`).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${CAPTURE_FIREFOX_SG:-}" != "1" ]] \
   && ! dumpcap -v >/dev/null 2>&1 \
   && command -v sg >/dev/null 2>&1 \
   && getent group wireshark 2>/dev/null | grep -qw "$(id -un)"; then
  echo "activating 'wireshark' group for dumpcap (sg wireshark) …" >&2
  export CAPTURE_FIREFOX_SG=1
  exec sg wireshark -c "$(printf '%q ' "$0" "$@")"
fi

exec uv run --project "$HERE/capture_firefox" trafficdeck-capture-firefox "$@"
