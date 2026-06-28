#!/usr/bin/env bash
# Drive HttpsProbe programmatically (via `am start`) to generate HTTPS traffic for
# Android capture tests — no UI interaction needed.
#
#   ./probe.sh [--serial <s>] <url> [GET|POST] [body] [times]
#   ./probe.sh [--serial <s>] --suite     # fire a built-in sequence of requests
#
# Confirm requests fired:  adb [-s <s>] logcat -s HttpsProbe
set -euo pipefail

ADB=${ADB:-adb}
SERIAL_ARGS=()
if [[ "${1:-}" == "--serial" ]]; then SERIAL_ARGS=(-s "$2"); shift 2; fi

COMP=com.example.httpsprobe/.MainActivity

fire() {  # url [method] [body] [times]
    "$ADB" "${SERIAL_ARGS[@]}" shell am start -n "$COMP" \
        --es url "$1" --es method "${2:-GET}" --es body "${3:-}" --ei times "${4:-1}" \
        >/dev/null
    echo "→ ${2:-GET} $1${4:+ ×$4}"
}

if [[ "${1:-}" == "--suite" ]]; then
    fire https://example.com
    sleep 1; fire https://httpbin.org/get GET "" 2
    sleep 1; fire https://httpbin.org/post POST '{"hello":"world"}'
    sleep 1; fire https://httpbin.org/redirect/2
    echo "fired test suite — check the capture / TUI for the flows"
else
    fire "${1:?usage: probe.sh [--serial <s>] <url> [GET|POST] [body] [times]}" \
        "${2:-GET}" "${3:-}" "${4:-1}"
fi
