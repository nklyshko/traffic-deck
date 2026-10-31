"""capture_sdk — shared library for the capture tools.

Holds what more than one capture app needs and nothing tool-specific: the generated
gRPC stubs ([proto][capture_sdk.proto]), the `UploadCapture` streaming helper
([upload][capture_sdk.upload]), the dumpcap + key-log capture engine
([livecapture][capture_sdk.livecapture]), the `CaptureSourceService` serve harness
([source][capture_sdk.source]), and interactive terminal prompts
([prompt][capture_sdk.prompt]). The per-tool apps (`capture_chrome`, `capture_firefox`,
`capture_mitmproxy`, `capture_android`, `capture_pktap`) depend on this package and carry
their own tool-specific code and heavy deps (mitmproxy, frida, browser discovery).
"""
