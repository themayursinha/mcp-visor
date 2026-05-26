.PHONY: build test bench vet demo clean fmt lint setup-hooks

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
