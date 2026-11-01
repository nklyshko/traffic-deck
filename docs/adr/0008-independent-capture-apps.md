# 0008 — Capture tools are independent apps over a shared SDK

Status: accepted. The editable path dependency is the dev setup; an installed copy builds wheels
into per-component venvs ([0017](0017-frozen-install.md)). The proto stubs have since moved out of
`capture_sdk` into `trafficdeck-proto`, which the TUI and MCP server share with it.

## Context

The capture tools have very different, heavy dependencies: `capture_mitmproxy` needs
`mitmproxy`, `capture_android` needs `frida`, while `capture_chrome` needs neither. As a
single package they all pulled every dependency, and the tools weren't independently
installable.

## Decision

Split capture into independent projects sharing a light `capture_sdk` (proto
stubs, the upload-streaming helper, interactive prompts) — tool-specific code (e.g.
Chrome/dumpcap discovery) stays in the owning app:

- `capture_sdk` (deps: `trafficdeck-proto`, `grpcio`, `protobuf`, `questionary`) — the shared library.
- `capture_chrome`, `capture_mitmproxy`, `capture_android` — one app each, depending on
  `capture_sdk` via an editable **path dependency** and adding only its own heavy deps.

Each app is its own `uv` project with its own virtualenv (path dependency, not a
shared-venv workspace, which is what actually isolates the dependency sets). Each exposes
a console-script entry point and runs with no required arguments (interactive by
default).

## Consequences

- Installing one tool no longer pulls the others' heavy dependencies.
- The shared gRPC/upload code lives in one place (`capture_sdk`).
- More `pyproject.toml`/lockfiles to maintain, and `capture_sdk` is consumed as a path
  dependency rather than a published package — fine for an in-repo toolset.
