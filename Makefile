VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -s -w \
	-X github.com/peg/rampart/internal/build.versionFromLDFlags=$(VERSION) \
	-X github.com/peg/rampart/internal/build.Commit=$(COMMIT) \
	-X github.com/peg/rampart/internal/build.Date=$(DATE)

.PHONY: build test vet clean linux lab-runner-test lab-e2e security-assurance

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

lab-runner-test:
	scripts/lab/test-run-e2e.sh

lab-e2e:
	scripts/lab/run-e2e.sh --sha "$$(git rev-parse HEAD)" --suite e2e --no-fetch

security-assurance:
	scripts/security-assurance.sh
