# Task: Fix setup panic, doc errors, and TOCTOU mutex

## 1. Panic fix — setup_openclaw_plugin.go
Find the line with strings.Fields(version)[0] (no length guard). Fix:
  fields := strings.Fields(version)
  if len(fields) > 0 { version = fields[0] }
Commit: "fix: guard strings.Fields empty slice in setup OpenClaw plugin"

## 2. Docs — approval timeout defaults wrong
Find in README.md and docs-site/reference/cli-commands.md where it says approval timeout is "1 hour" or "5m".
The actual default in store.go is 2 minutes. Update docs to say "2 minutes".
Commit: "docs: fix approval timeout default (2m not 1h/5m)"

## 3. Docs — remove stale require_approval from API-REFERENCE.md
In docs/API-REFERENCE.md around line 59, "require_approval" is listed as a valid decision value.
It was removed in v0.9.9, replaced by "ask". Remove it and note "ask" is correct.
Commit: "docs: remove stale require_approval from API-REFERENCE, use ask"

## 4. Docs — action:log deprecation
Search docs/ and docs-site/ for examples using "action: log" not noted as deprecated.
Add comment noting it was renamed to "action: watch" in v0.9.x.
Commit: "docs: note action:log renamed to action:watch in examples"

## 5. TOCTOU mutex in learn_handlers.go
In internal/proxy/learn_handlers.go the read-modify-write on user-overrides.yaml is unprotected.
Add a sync.Mutex to serialize concurrent writes. Same for rules deletion handler.
Commit: "fix: serialize user-overrides.yaml writes with mutex to prevent lost updates"

## Finish
- Run: go test ./...
- Run: git push origin fix/setup-panic-and-docs
- Run: openclaw system event --text "Setup/docs/mutex fixes done — fix/setup-panic-and-docs pushed" --mode now
