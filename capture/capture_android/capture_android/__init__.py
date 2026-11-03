"""capture_android — per-app Android capture. Run `trafficdeck-capture-android`.

`trafficdeck-capture-android` is the interactive front-end ([cli][capture_android.cli]); it never
imports frida and launches the actual capture under a device-matched frida: from a checkout
via `uv run --with frida==<ver>`, from an install in that version's venv
([frida_env][capture_android.frida_env]). The non-interactive flow is
[headless][capture_android.headless] (`python -m capture_android.headless`).
"""
