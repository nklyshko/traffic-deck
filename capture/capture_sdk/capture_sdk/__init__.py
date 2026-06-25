"""capture_sdk — shared library for the capture tools.

Holds what every capture app needs and nothing tool-specific: the generated gRPC
stubs ([proto][capture_sdk.proto]), the `UploadCapture` streaming helper
([upload][capture_sdk.upload]), and interactive terminal prompts
([prompt][capture_sdk.prompt]). The per-tool apps (`capture_chrome`,
`capture_mitmproxy`, `capture_android`) depend on this package and carry their own
tool-specific code and heavy deps (mitmproxy, frida, Chrome/dumpcap discovery).
"""
