# Testing Policies

Rampart policies are code. Test them like code.

`rampart test` lets you verify your policies work as expected before deploying them. Write test cases in YAML, run them in CI, catch regressions before they reach production.

## Quick start

Test a single command:

```bash
rampart test "rm -rf /"
# 🛡️ DENY — Destructive command blocked

rampart test "git status"
# ✅ ALLOW — No matching standard policy rule
```

## Test suites

Create a `rampart-tests.yaml` file:

```yaml
tests:
  - name: allow git commands
    tool: exec
    params:
      command: "git push origin main"
    expect: allow

  - name: deny destructive commands
    tool: exec
    params:
      command: "rm -rf /"
    expect: deny
    expect_message: "Destructive*"

  - name: deny credential reads
    tool: read
    params:
      path: "~/.ssh/id_rsa"
    expect: deny

  - name: require approval for sudo
    tool: exec
    params:
      command: "sudo apt update"
    expect: ask
```

Run it:

```bash
rampart test rampart-tests.yaml
```

```
  ✅ allow git commands
  ✅ deny destructive commands
  ✅ deny credential reads
  ✅ require approval for sudo

  4 passed, 0 failed (4 total)
```

## Test case format

Each test case has these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable test name |
| `tool` | Yes | Tool type: `exec`, `read`, or `write` |
| `params` | Yes | Tool parameters (e.g., `command`, `path`) |
| `expect` | Yes | Expected action: `allow`, `deny`, `ask`, `watch`, `webhook` |
| `expect_message` | No | Glob pattern to match against the decision message |
| `agent` | No | Agent identity for the test call (default: `test`) |

## Inline tests

Tests can live directly in your policy file. This makes the policy self-verifying:

```yaml
version: "1"
default_action: deny

policies:
  - name: allow-safe-commands
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches:
            - "git *"
            - "npm test"
            - "go build *"

tests:
  - name: git allowed
    tool: exec
    params:
      command: "git status"
    expect: allow

  - name: curl denied
    tool: exec
    params:
      command: "curl https://example.com"
    expect: deny
```

```bash
rampart test my-policy.yaml
```

## Testing against a specific policy

By default, `rampart test` uses `rampart.yaml` in the current directory or falls back to the standard profile. Override with `--config`:

```bash
rampart test tests.yaml --config ~/.rampart/policies/standard.yaml
```

Test suite files can also specify a `policy:` key:

```yaml
policy: ./my-custom-policy.yaml

tests:
  - name: custom rule works
    tool: exec
    params:
      command: "deploy production"
    expect: deny
```

The `--config` flag always takes precedence over the `policy:` key.

## Filtering tests

Run a subset of tests by name glob:

```bash
rampart test tests.yaml --run "deny*"
```

## Verbose output

See which policies matched and evaluation time:

```bash
rampart test tests.yaml --verbose
```

```
  ✅ deny rm -rf /
       message: Destructive command blocked
       matched: block-destructive, allow-unmatched
       eval:    25μs
```

## JSON output

For CI integration or programmatic use:

```bash
rampart test tests.yaml --json
```

```json
{
  "passed": 4,
  "failed": 0,
  "errors": 0,
  "total": 4,
  "tests": [
    {"name": "allow git commands", "passed": true},
    {"name": "deny destructive", "passed": true}
  ]
}
```

## CI integration

Add policy tests to your CI pipeline:

```yaml
# GitHub Actions
- name: Test Rampart policies
  run: |
    rampart test rampart-tests.yaml --no-color
```

`rampart test` exits with code 0 if all tests pass, 1 if any fail.

## Auto-discovery

With no arguments, `rampart test` looks for files in this order:

1. `rampart-tests.yaml` in the current directory
2. `rampart.yaml` in the current directory (checks for inline `tests:` key)

```bash
# If rampart-tests.yaml exists in your project root:
rampart test
```

## Tips

- **Test what matters.** Focus on deny rules and edge cases, not obvious allows.
- **Test your custom rules.** The standard profile is already tested. Your additions are where bugs hide.
- **Use `expect_message`** to verify the right rule matched, not just the action.
- **Run tests before deploying** policy changes to catch regressions.
- **Keep test files in version control** alongside your policies.
