# Build/run helpers for the traffic-gateway. The toolchain is mise-managed (`go`,
# `buf`, …); run `mise install` once if it's missing. The generated gRPC stubs are
# committed, so `make build` needs only the Go toolchain — regenerate with `make gen`
# after editing proto/.
#
#   make            build the gateway -> ./gateway
#   make run        build + run the gateway server
#   make test       run gateway tests
#   make gen        regenerate all stubs (Go + Python) via mise
#   make clean      remove the built binary

GO          ?= go
GATEWAY_DIR := traffic-gateway
GATEWAY_BIN := gateway

.PHONY: build run test vet gen clean help

build: ## build the gateway binary -> ./gateway
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

help: ## list targets
	@grep -hE '^[a-z]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
