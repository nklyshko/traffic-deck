# capture-tools

Independent capture apps that feed the traffic-gateway, each its own Python project
with its own dependencies, over a shared SDK:

| Project | Command | Extra deps | What |
|---|---|---|---|
| [`capture_sdk/`](capture_sdk/) | — (library) | grpcio, protobuf | gRPC stubs (`capture_sdk.proto`), `UploadCapture` streaming, platform discovery |
| [`capture_chrome/`](capture_chrome/) | `capture-chrome` | — | live Chrome capture (dumpcap + `SSLKEYLOGFILE`) |
| [`capture_mitmproxy/`](capture_mitmproxy/) | `capture-mitmproxy` | mitmproxy | mitmproxy addon → `PushFlows` (any device, incl. WireGuard) |
| [`capture_android/`](capture_android/) | `capture-android` | frida | per-app capture from a rooted emulator/device (interactive) |

Each app is a separate uv project that depends on `capture_sdk` via an editable path
source, so they don't share a venv — installing `capture_chrome` pulls neither
`mitmproxy` nor `frida`. Every command runs with no required arguments:

```sh
uv run --project capture-tools/capture_chrome     capture-chrome
uv run --project capture-tools/capture_mitmproxy  capture-mitmproxy
uv run --project capture-tools/capture_android    capture-android
```

The non-interactive Android flow is `python -m capture_android.headless` (takes
`--package …`). Regenerate the shared gRPC stubs with `mise run gen` (they land in
`capture_sdk/capture_sdk/gen/`, gitignored).
