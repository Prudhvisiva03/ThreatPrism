# ThreatPrism Makefile

BINARY      := threatprism
PKG         := github.com/threatprism/threatprism
CMD         := ./cmd/threatprism
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X '$(PKG)/internal/buildinfo.Version=$(VERSION)' \
	-X '$(PKG)/internal/buildinfo.Commit=$(COMMIT)' \
	-X '$(PKG)/internal/buildinfo.Date=$(DATE)'

.PHONY: all build run tidy test test-race lint fmt vet clean install cross

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD)

run: build
	./bin/$(BINARY)

install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

tidy:
	go mod tidy

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint: fmt vet

clean:
	rm -rf bin dist

# Cross-platform release builds
cross:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64      $(CMD)
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64     $(CMD)
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64     $(CMD)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe $(CMD)
