.DEFAULT_GOAL := test

GO ?= go

.PHONY: test vet vuln security build docker-build

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

vuln:
	govulncheck ./...

security:
	gosec ./...
	gitleaks git --redact --no-banner

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o bin/shortlinks ./cmd/shortlinks

docker-build:
	docker build --pull --tag shortlinks:local .
