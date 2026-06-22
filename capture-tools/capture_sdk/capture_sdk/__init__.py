"""capture_sdk — shared library for the capture tools.

Holds what every capture app needs and nothing tool-specific: the generated gRPC
stubs ([proto][capture_sdk.proto]), the `UploadCapture` streaming helper
([upload][capture_sdk.upload]), and cross-platform discovery of Chrome / dumpcap /
the capture interface ([platform][capture_sdk.platform]). The per-tool apps
(`capture_chrome`, `capture_mitmproxy`, `capture_android`) depend on this package and
carry only their own heavy deps (mitmproxy, frida).
"""
