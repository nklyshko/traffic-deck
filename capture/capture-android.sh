#!/usr/bin/env bash
# Launch the Android per-app capture tool. Run with no arguments for the
# interactive flow (pick target / emulator / root / frida version / app / scripts);
# extra flags pass through (e.g. --gateway, --duration, --all-apps).
#
# Needs the Android SDK on PATH (adb/emulator) and a rooted target. For the
# non-interactive flow use: python -m capture_android.headless --package <pkg> …
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --project "$HERE/capture_android" trafficdeck-capture-android "$@"
