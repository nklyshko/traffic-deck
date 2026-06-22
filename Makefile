# Build/run helpers for the traffic-gateway. The toolchain is mise-managed, so `go`
# (and `uv`/`buf`) come from mise; run `mise install` once if they're missing.
#
#   make            build the gateway -> ./gateway
#   make run        build + run the gateway server
#   make test       run gateway tests
#   make gen        regenerate gRPC stubs (Go + Python)
#   make clean      remove the built binary

GO          ?= go
GATEWAY_DIR := traffic-gateway
GATEWAY_BIN := gateway

.PHONY: build run test vet clean gen help

build: ## build the gateway binary -> ./gateway
	cd $(GATEWAY_DIR) && $(GO) build -o ../$(GATEWAY_BIN) ./cmd/gateway

run: build ## build, then run the gateway server
	./$(GATEWAY_BIN) serve

test: ## run the gateway test suite
	cd $(GATEWAY_DIR) && $(GO) test ./...

vet: ## go vet the gateway
	cd $(GATEWAY_DIR) && $(GO) vet ./...

gen: ## regenerate gRPC stubs (delegates to `mise run gen`)
	mise run gen

clean: ## remove the built binary
	rm -f $(GATEWAY_BIN)

help: ## list targets
	@grep -hE '^[a-z]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
