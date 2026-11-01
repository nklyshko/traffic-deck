# Build/run helpers for the TrafficDeck gateway. The toolchain is mise-managed (`go`,
# `buf`, …); run `mise install` once if it's missing. The generated gRPC stubs are
# committed, so `make build` needs only the Go toolchain — regenerate with `make gen`
# after editing proto/.
#
#   make            build the gateway and web viewer -> ./trafficdeck ./trafficdeck-web
#   make run        build + run the gateway server
#   make test       run gateway and web viewer tests
#   make gen        regenerate all stubs (Go + Python) via mise
#   make clean      remove the built binary
#
#   make install         freeze this tree into a self-contained prefix (ADR-0017)
#   make install-pktap   enrol the macOS per-process capture module (writes a manifest)

GO          ?= go
GATEWAY_DIR := gateway
GATEWAY_BIN := trafficdeck
WEB_DIR     := web
WEB_BIN     := trafficdeck-web

# Where the gateway looks for plugin manifests — mirrors config.Home().
TD_HOME     ?= $(if $(TRAFFIC_DECK_HOME),$(TRAFFIC_DECK_HOME),$(HOME)/.traffic-deck)
# Address the pktap source serves on, and the gateway dials. Override to move it:
#   make install-pktap PKTAP_ADDR=127.0.0.1:7099
PKTAP_ADDR  ?= 127.0.0.1:7071
# How to start that source: the installed copy when there is one, so enrolling doesn't tie an
# installed gateway to this checkout.
PKTAP_INSTALLED := $(or $(PREFIX),$(HOME)/.local/share/trafficdeck)/libexec/trafficdeck-capture-pktap
PKTAP_CMD   ?= $(if $(wildcard $(PKTAP_INSTALLED)),trafficdeck pktap,$(CURDIR)/capture/capture-pktap.sh)

.PHONY: build web-ui run test vet gen clean help install install-pktap

build: web-ui ## build the gateway and web viewer binaries
	@echo "==> building $(GATEWAY_BIN) (a first build can take minutes)"
	@cd $(GATEWAY_DIR) && $(GO) build -o ../$(GATEWAY_BIN) ./cmd/gateway
	@echo "==> building $(WEB_BIN)"
	@cd $(WEB_DIR) && $(GO) build -o ../$(WEB_BIN) .
	@echo "==> done: ./$(GATEWAY_BIN) ./$(WEB_BIN)"

# Node is needed only to change the UI: without it the binary embeds a page saying so, and
# gateway work isn't blocked. `make install` is stricter, since a frozen stub would be silent.
web-ui: ## build the SPA bundle embedded in the web viewer
	@if command -v npm >/dev/null; then \
		echo "==> installing web UI dependencies"; \
		cd $(WEB_DIR)/ui && npm ci --silent && \
		echo "==> building the web UI" && npm run --silent build; \
	else \
		echo "web-ui: npm not found, trafficdeck-web will serve a stub page" >&2; \
	fi

run: build ## build, then run the gateway server
	./$(GATEWAY_BIN) serve

test: ## run the gateway and web viewer test suites
	cd $(GATEWAY_DIR) && $(GO) test ./...
	cd $(WEB_DIR) && $(GO) test ./...

vet: ## go vet the gateway and web viewer
	cd $(GATEWAY_DIR) && $(GO) vet ./...
	cd $(WEB_DIR) && $(GO) vet ./...

gen: ## regenerate all stubs (Go + Python) after editing proto/
	mise run gen

clean: ## remove the built binaries
	rm -f $(GATEWAY_BIN) $(WEB_BIN)

# PREFIX, BINDIR, COMPONENTS, VIEWER and INSTALL_PYTHON (default 3.12.13) pass through the
# environment; ALLOW_DIRTY=1 installs a tree with uncommitted changes and records that it did.
install: ## freeze this tree into ~/.local/share/trafficdeck
	./scripts/install.sh

# The pktap source is the one capture tool the gateway cannot spawn: PKTAP creates its
# interface with a privileged ioctl, and sources are spawned unprivileged with no
# controlling terminal, so there is nowhere to answer a sudo prompt. It enrols as a
# dial-only module instead — a manifest with a [control] block and no [[process]] entries,
# so the gateway dials an address you serve yourself under sudo. Hence a manifest, not an
# entry in the gateway's built-in source list.
install-pktap: ## enrol the macOS per-process (PKTAP) capture module
	@[ "$$(uname -s)" = "Darwin" ] || { \
		echo "install-pktap: PKTAP is macOS-only — nothing to install here" >&2; exit 1; }
	@mkdir -p "$(TD_HOME)/plugins"
	@printf '%s\n' \
		'# Per-process Chrome capture on macOS (PKTAP). Written by `make install-pktap`;' \
		'# paths are absolute and machine-specific, so re-run that after moving the repo.' \
		'#' \
		'# No [[process]] block on purpose: PKTAP needs root, and the gateway spawns sources' \
		'# with no controlling terminal, so it could never answer a sudo prompt. Start the' \
		'# source yourself and leave it up; the gateway only dials it:' \
		'#' \
		'#   $(PKTAP_CMD)' \
		'name = "pktap"' \
		'' \
		'[control]' \
		'addr   = "$(PKTAP_ADDR)"' \
		'source = "chrome-pktap"' \
		'label  = "Chrome (per-process)"' \
		> "$(TD_HOME)/plugins/pktap.toml"
	@echo "wrote $(TD_HOME)/plugins/pktap.toml"
	@echo
	@echo "next:"
	@echo "  1. $(PKTAP_CMD)            # prompts for sudo"
	@echo "  2. restart the gateway (manifests are read at startup)"
	@echo "  3. pick 'Chrome (per-process)' in the source list"
	@echo
	@echo "uninstall: rm $(TD_HOME)/plugins/pktap.toml"

help: ## list targets
	@grep -hE '^[a-z][a-z-]*:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
