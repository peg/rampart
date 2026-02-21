---
title: Contributing
description: "Contribute to Rampart with a clean workflow for issues, branches, tests, and pull requests. Learn how to ship secure AI agent guardrail improvements fast."
---

# Contributing

Contributions are welcome! Please open an issue first for anything beyond small fixes — we want to discuss the approach before you invest time.

## Getting Started

```bash
git clone https://github.com/peg/rampart.git
cd rampart
go test ./...
```

Requires Go 1.24+.

## Workflow

All work goes through the `staging` branch:

1. Fork the repo
2. Create a feature branch from `staging`
3. Make your changes
4. Run tests: `go test ./...`
5. Open a PR targeting `staging`

PRs to `main` require one approving review.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep the policy engine hot path allocation-free
- New interceptors go in `internal/intercept/`
- New CLI commands go in `cmd/rampart/cli/`

## Testing

```bash
# All tests
go test ./...

# With race detection
go test -race ./...

# Specific package
go test ./internal/engine/...
```

## Security

If you've found a security vulnerability, **do not** open a public issue. Email [rampartsec@pm.me](mailto:rampartsec@pm.me) instead.

## License

By contributing, you agree that your contributions will be licensed under [Apache 2.0](https://github.com/peg/rampart/blob/main/LICENSE).
