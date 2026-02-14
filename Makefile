VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -s -w \
	-X github.com/peg/rampart/internal/build.Version=$(VERSION) \
	-X github.com/peg/rampart/internal/build.Commit=$(COMMIT) \
	-X github.com/peg/rampart/internal/build.Date=$(DATE)

.PHONY: build test vet clean linux

build:
	go build -ldflags "$(LDFLAGS)" -o rampart ./cmd/rampart

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o rampart-linux ./cmd/rampart

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f rampart rampart-linux
