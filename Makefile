# Build/run helpers for the TrafficDeck gateway. The toolchain is mise-managed (`go`,
# `buf`, …); run `mise install` once if it's missing. The generated gRPC stubs are
# committed, so `make build` needs only the Go toolchain — regenerate with `make gen`
# after editing proto/.
#
#   make            build the gateway -> ./trafficdeck
#   make run        build + run the gateway server
#   make test       run gateway tests
#   make gen        regenerate all stubs (Go + Python) via mise
#   make clean      remove the built binary
#
#   make install-pktap   enrol the macOS per-process capture module (writes a manifest)

GO          ?= go
GATEWAY_DIR := gateway
GATEWAY_BIN := trafficdeck

# Where the gateway looks for plugin manifests — mirrors config.Home().
TD_HOME     ?= $(if $(TRAFFIC_DECK_HOME),$(TRAFFIC_DECK_HOME),$(HOME)/.traffic-deck)
# Address the pktap source serves on, and the gateway dials. Override to move it:
#   make install-pktap PKTAP_ADDR=127.0.0.1:7099
PKTAP_ADDR  ?= 127.0.0.1:7071

.PHONY: build run test vet gen clean help install-pktap

build: ## build the gateway binary -> ./trafficdeck
	cd $(GATEWAY_DIR) && $(GO) build -o ../$(GATEWAY_BIN) ./cmd/gateway

run: build ## build, then run the gateway server
	./$(GATEWAY_BIN) serve

test: ## run the gateway test suite
	cd $(GATEWAY_DIR) && $(GO) test ./...

vet: ## go vet the gateway
	cd $(GATEWAY_DIR) && $(GO) vet ./...

gen: ## regenerate all stubs (Go + Python) after editing proto/
	mise run gen

clean: ## remove the built binary
	rm -f $(GATEWAY_BIN)

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
		'#   $(CURDIR)/capture/capture-pktap.sh' \
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
	@echo "  1. $(CURDIR)/capture/capture-pktap.sh            # prompts for sudo"
	@echo "  2. restart the gateway (manifests are read at startup)"
	@echo "  3. pick 'Chrome (per-process)' in the source list"
	@echo
	@echo "uninstall: rm $(TD_HOME)/plugins/pktap.toml"

help: ## list targets
	@grep -hE '^[a-z][a-z-]*:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
