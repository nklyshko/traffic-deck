# HttpsProbe — Android capture test app

A tiny Android app used to exercise the Android capture tools end-to-end. Enter a URL,
pick GET/POST, optionally a body, and fire HTTPS requests — or drive it programmatically
for scripted capture tests.

Two request engines, both over the platform Conscrypt TLS stack (so the capture's frida
TLS-keylog hook sees real, decryptable HTTPS): the default **OkHttp** engine negotiates
**HTTP/2** via ALPN (to exercise the gateway's live HTTP/2 decode), and the framework
**`HttpURLConnection`** engine speaks HTTP/1.1 — select it with `--es engine urlconn`
(or `&engine=urlconn` in a deeplink). Package: `com.example.httpsprobe`.

```
┌───────────────────────────────┐
│ URL: [ https://example.com   ] │
│ Method: (•GET) ( POST)         │
│ body (optional) [           ]  │
│ [ Send request ]               │
│ [example.com][httpbin GET]…    │   ← quick presets
│ 200 OK  1256B  342ms           │
│ <response body preview…>       │
└───────────────────────────────┘
```

## Build & install

Needs the Android SDK and the `android-34` platform. **Easiest: open this folder in
Android Studio and Run** — it provisions Gradle, the wrapper, and any missing SDK bits
automatically.

From the CLI you need Gradle 8.7+ (this repo has no system Gradle yet) and the platform:

```sh
sdkmanager "platforms;android-34"          # if not already installed
cd capture/testapp/httpsprobe
gradle wrapper --gradle-version 8.7        # one-time, creates ./gradlew
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

(`compileSdk`/`targetSdk` are 34 to match the API-34 emulator; `minSdk` 24 covers the
API-29 phone. Bump them if you'd rather build against your installed `android-36`.)

## Drive it programmatically

For scripted capture tests, fire requests without touching the UI. The app is
`singleTop`, so repeated launches re-fire in the same instance.

```sh
# intent extras (no URL-encoding needed) — url / method / body / times / engine
adb shell am start -n com.example.httpsprobe/.MainActivity \
  --es url https://example.com --es method POST --es body '{"k":1}' --ei times 3

# force HTTP/2 (default OkHttp engine, h2 via ALPN) against an h2 server
adb shell am start -a android.intent.action.VIEW -d 'https://www.google.com/generate_204'
# force HTTP/1.1 (framework HttpURLConnection)
adb shell am start -n com.example.httpsprobe/.MainActivity \
  --es url https://example.com --es engine urlconn

# a plain http(s) link → GET it (this is what `capture-android --url` does)
adb shell am start -a android.intent.action.VIEW -d 'https://example.com'

# custom deeplink with method/body/times (url-encode the url= value)
adb shell am start -a android.intent.action.VIEW \
  -d 'httpsprobe://request?url=https%3A%2F%2Fexample.com&method=GET&times=2'
```

Every request logs a marker, so a test can confirm it fired/completed:

```sh
adb logcat -s HttpsProbe        # e.g. "GET https://example.com -> 200 1256B 342ms"
```

### `probe.sh` — one-shot / suite driver

```sh
./probe.sh https://example.com            # single GET
./probe.sh https://httpbin.org/post POST '{"a":1}'
./probe.sh --serial emulator-5554 --suite # a built-in sequence of varied requests
```

## Use with the capture

```sh
# 1. start a capture targeting this app (interactive picker, or headless):
uv run --project capture/capture_android python -m capture_android.headless \
  --serial emulator-5554 --package com.example.httpsprobe

# 2. generate traffic, then watch the decoded flows in the TUI:
capture/testapp/httpsprobe/probe.sh --serial emulator-5554 --suite
```
