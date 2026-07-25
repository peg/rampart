#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

go test ./internal/assurance ./internal/engine ./internal/intercept ./internal/approval ./internal/token ./internal/signing
python3 -m unittest internal/plugin/hermes/test_hermes_plugin.py

node internal/plugin/openclaw/smoke-test.mjs
node internal/plugin/openclaw/tool-alias-test.mjs
node internal/plugin/openclaw/provider-surface-replay.mjs
node internal/plugin/openclaw/approval-regression.mjs
node internal/plugin/openclaw/degraded-mode-test.mjs
