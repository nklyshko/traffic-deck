"""capture_android — per-app Android capture. Run `trafficdeck-capture-android`.

`trafficdeck-capture-android` is the interactive front-end ([cli][capture_android.cli]); it never
imports frida and launches the actual capture under a device-matched frida via
`uv run --with frida==<ver>`. The non-interactive flow is
[headless][capture_android.headless] (`python -m capture_android.headless`).
"""
