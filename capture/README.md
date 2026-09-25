# TrafficDeck — capture tools

Independent capture apps that feed the TrafficDeck gateway, each its own Python project
with its own dependencies, over a shared SDK:

| Project | Command | Extra deps | What |
|---|---|---|---|
| [`capture_sdk/`](capture_sdk/) | — (library) | grpcio, protobuf, questionary | gRPC stubs (`capture_sdk.proto`), `UploadCapture` streaming, interactive prompts, viewer hints declared at `OpenSession` (`capture_sdk.viewer`) |
| [`capture_chrome/`](capture_chrome/) | `trafficdeck-capture-chrome` | — | live Chrome capture (dumpcap + `SSLKEYLOGFILE`) |
| [`capture_firefox/`](capture_firefox/) | `trafficdeck-capture-firefox` | — | live Firefox capture (dumpcap + `SSLKEYLOGFILE`) |
| [`capture_mitmproxy/`](capture_mitmproxy/) | `trafficdeck-capture-mitmproxy` | mitmproxy | mitmproxy addon → `PushFlows` (any device, incl. WireGuard) |
| [`capture_android/`](capture_android/) | `trafficdeck-capture-android` | frida | per-app capture from a rooted emulator/device (interactive) |
| [`capture_pktap/`](capture_pktap/) | `trafficdeck-capture-pktap` | — | per-process Chrome capture on macOS (PKTAP + `SSLKEYLOGFILE`); needs root |

Each app is a separate uv project that depends on `capture_sdk` via an editable path
source, so they don't share a venv — installing `capture_chrome` pulls neither
`mitmproxy` nor `frida`. Every command runs with no required arguments. (`capture_pktap`
is the one app that also depends on another: it is `capture_chrome`'s runner with the
capture command and the browser launch swapped, so it inherits the binary discovery,
profile pickers and remembered defaults rather than restating them.)

The simplest way to launch is the wrapper scripts (run from anywhere; no arguments
needed — `trafficdeck-capture-android` starts interactively; extra flags pass through):

```sh
./capture-chrome.sh
./capture-firefox.sh
./capture-mitmproxy.sh
./capture-android.sh
./capture-pktap.sh          # macOS only; serves the module, self-sudos
```

Equivalently, via uv directly:

```sh
uv run --project capture/capture_chrome     trafficdeck-capture-chrome
uv run --project capture/capture_firefox    trafficdeck-capture-firefox
uv run --project capture/capture_mitmproxy  trafficdeck-capture-mitmproxy
uv run --project capture/capture_android    trafficdeck-capture-android
sudo uv run --project capture/capture_pktap trafficdeck-capture-pktap serve
```

The non-interactive Android flow is `python -m capture_android.headless` (takes
`--package …`). Regenerate the shared gRPC stubs with `mise run gen` (they land in
`capture_sdk/capture_sdk/gen/`, gitignored).
