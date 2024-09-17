.PHONY: test install-lint checks build dist

export GOOS=wasip1
export GOARCH=wasm
export GOLANGCI_LINT_VERSION=v1.59.1

default: test checks build

test:
	go test -v -cover ./...

build:
	@go build -o plugin.wasm .

install-lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin ${GOLANGCI_LINT_VERSION}

checks:
	golangci-lint run

dist: build
	cp plugin.wasm dist/traefik-oidc-wasm
	cp .traefik.yml dist/traefik-oidc-wasm