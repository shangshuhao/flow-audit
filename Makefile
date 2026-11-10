SHELL := /bin/sh

BINARY := flowaudit
VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X flowaudit/internal/version.Version=$(VERSION) \
	-X flowaudit/internal/version.Commit=$(COMMIT) \
	-X flowaudit/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: build build-linux test lint clean

build:
	GO111MODULE=on CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/flowaudit

build-linux:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/flowaudit

test:
	GO111MODULE=on CGO_ENABLED=0 go test ./...

lint:
	GO111MODULE=on golangci-lint run ./...

clean:
	rm -rf bin dist
