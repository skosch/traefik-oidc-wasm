.PHONY: test checks build dist

export GOOS=wasip1
export GOARCH=wasm

default: test checks build

test:
	go test -v -cover ./...

build:
	@go build -o plugin.wasm .

checks:
	golangci-lint run

dist: build
	cp plugin.wasm dist/traefik-oidc-wasm
	cp .traefik.yml dist/traefik-oidc-wasm