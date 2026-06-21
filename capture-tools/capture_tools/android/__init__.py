"""Android capture agent (plan §7, Phase 7).

Drives a rooted emulator/device over adb: pushes/starts frida-server, spawns the
target app under Frida to dump TLS secrets (NSS key.log), and captures *only that
app's* packets via UID→NFLOG tcpdump streamed over adb. Both artifacts stream to the
gateway over the existing UploadCapture pipeline (same as the Chrome tool).
"""
