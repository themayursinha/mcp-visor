.PHONY: build test bench vet demo demo-ui demo-ui-tailscale clean fmt lint setup-hooks

GOPATH ?= $(shell go env GOPATH)
GO ?= go

build:
	$(GO) build ./cmd/mcp-visor/

test:
	$(GO) test ./... -count=1 -timeout 120s

bench:
	$(GO) test -bench=. -benchmem -count=1 -timeout 120s ./internal/...

vet:
	$(GO) vet ./...

demo:
	$(GO) run ./examples/demo-runner/

demo-ui:
	$(GO) run ./examples/demo-runner/ -ui

demo-ui-tailscale:
	@test -n "$(TAILSCALE_BIND_ADDRESS)" || (echo "Set TAILSCALE_BIND_ADDRESS to a Tailscale CGNAT address in 100.64.0.0/10"; exit 1)
	$(GO) run ./examples/demo-runner/ -ui -ui-addr $(TAILSCALE_BIND_ADDRESS):9092

fmt:
	$(GO) fmt ./...

setup-hooks:
	ln -sf ../../scripts/pre-commit .git/hooks/pre-commit

clean:
	rm -f mcp-visor
	rm -f coverage.out

coverage:
	$(GO) test ./... -coverprofile=coverage.out -count=1
	$(GO) tool cover -func=coverage.out
