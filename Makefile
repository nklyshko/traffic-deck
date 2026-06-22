# Build/run helpers for the traffic-gateway. The toolchain is mise-managed, so `go`,
# `buf`, and the protoc-gen-go plugins come from mise; run `mise install` once if
# they're missing.
#
#   make            build the gateway -> ./gateway (generating Go stubs if needed)
#   make run        build + run the gateway server
#   make test       run gateway tests
#   make proto      (re)generate the Go gRPC stubs
#   make gen        regenerate all stubs (Go + Python) via mise
#   make clean      remove the built binary

GO          ?= go
BUF         ?= buf
GATEWAY_DIR := traffic-gateway
GATEWAY_BIN := gateway
# The generated gRPC stubs are gitignored, so a fresh checkout must generate them
# before building. Use one emitted file as the make marker for the whole set.
GEN_STUB    := $(GATEWAY_DIR)/gen/traffic/v1/viewer.pb.go
PROTOS      := $(wildcard proto/traffic/v1/*.proto)

.PHONY: build run test vet proto gen clean help

build: $(GEN_STUB) ## build the gateway binary -> ./gateway
	cd $(GATEWAY_DIR) && $(GO) build -o ../$(GATEWAY_BIN) ./cmd/gateway

# (Re)generate the Go stubs when the proto contract or buf config changes, or when
# they're missing (e.g. a fresh clone). `buf generate proto` writes to traffic-gateway/gen.
$(GEN_STUB): buf.gen.yaml proto/buf.yaml $(PROTOS)
	$(BUF) generate proto

proto: $(GEN_STUB) ## (re)generate the Go gRPC stubs

run: build ## build, then run the gateway server
	./$(GATEWAY_BIN) serve

test: $(GEN_STUB) ## run the gateway test suite
	cd $(GATEWAY_DIR) && $(GO) test ./...

vet: $(GEN_STUB) ## go vet the gateway
	cd $(GATEWAY_DIR) && $(GO) vet ./...

gen: ## regenerate all stubs (Go + Python) via mise
	mise run gen

clean: ## remove the built binary
	rm -f $(GATEWAY_BIN)

help: ## list targets
	@grep -hE '^[a-z]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
