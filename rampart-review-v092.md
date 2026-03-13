# Rampart v0.9.2 Staging Review

Reviewed branch: `staging`  
Scope requested: `cmd/rampart/cli/`, `internal/proxy/`, `internal/engine/`, `docs/index.html`, `policies/standard.yaml`

I did not try to exhaustively fuzz or run the full test suite. Findings below are from targeted code review of the requested areas.

## 1. Codebase

### Critical

1. `serve --background` leaks the full admin token into a world-readable log file.
   - `cmd/rampart/cli/serve.go:100-124` opens `~/.rampart/serve.log` with mode `0644` and redirects both stdout and stderr into it.
   - `cmd/rampart/cli/serve.go:403-416` prints `Full token : <token>` to stderr.
   - Result: any local user who can read `~/.rampart/serve.log` gets the admin bearer token and full control of the policy runtime.
   - This is a direct credential disclosure in the default operational path of a security product.

2. Agent-scoped tokens can read global approvals, audit logs, policy summaries, and runtime status for all agents.
   - Read endpoints use `checkAuth`, not `checkAdminAuth`: `internal/proxy/approval_handlers.go:99-206`, `internal/proxy/audit_handlers.go:37-154`, `internal/proxy/audit_handlers.go:156-270`, `internal/proxy/eval_handlers.go:443-500`, `internal/proxy/rules_handlers.go:39-93`, `internal/proxy/server.go:356-363`.
   - `checkAuth` accepts any valid agent token: `internal/proxy/server.go:424-432`.
   - Impact:
     - `GET /v1/approvals` exposes pending commands/messages/run IDs from other agents.
     - `GET /v1/audit/events` and `/export` expose historical commands, paths, sessions, and denial reasons across the whole system.
     - `GET /v1/status` exposes `config_path`, rule counts, and global `call_counts`.
     - `GET /v1/policy/summary` exposes the active rule inventory.
   - For a per-agent least-privilege token model, this is a horizontal data leak.

3. The dashboard authentication flow intentionally persists the bearer token in insecure places.
   - Dashboard is served without auth: `internal/proxy/server.go:365-366`, `internal/dashboard/handler.go:27-35`.
   - Token is stored in `localStorage`: `internal/dashboard/static/index.html:527-529`, `internal/dashboard/static/index.html:651-653`.
   - SSE uses `?token=` in the URL: `internal/dashboard/static/index.html:662-665`.
   - Proxy accepts tokens from query parameters globally: `internal/proxy/auth.go:51-61`.
   - Impact:
     - token ends up in browser storage;
     - token can leak via browser history, reverse-proxy logs, access logs, and URL capture;
     - the product itself warns query tokens leak to logs (`internal/proxy/auth.go:73-77`) but still relies on them for the dashboard SSE path.

### High

4. Audit integrity is wrong for webhook/auto-approved/auto-allowed decisions because the proxy writes duplicate audit events.
   - `internal/proxy/eval_handlers.go:112` writes the initial decision before any post-processing.
   - Webhook path writes a second event after the webhook result: `internal/proxy/eval_handlers.go:132-149`.
   - Auto-approved run path writes a second event after mutating the decision: `internal/proxy/eval_handlers.go:153-165`.
   - Auto-allowed rule path writes a second event after mutating the decision: `internal/proxy/eval_handlers.go:168-180`.
   - Result: audit trail contains an initial `ask`/`webhook` event plus a second final `allow`/`deny` event for one actual action. For a security tool, that corrupts the meaning of the log.

5. The “try a command” REPL is exposed to any agent token, giving the agent a policy oracle.
   - `internal/proxy/eval_handlers.go:367-435` gates `/v1/test` with `checkAuthIdentity`, not admin auth.
   - This lets any agent token probe commands, paths, and sessions against the loaded policy and recover matched policy names/messages.
   - That materially helps an adversarial agent iterate toward bypasses.

### Medium

6. `internal/proxy/webhook.go` documents the wrong default failure mode.
   - Comment says `fail_open` defaults to open: `internal/proxy/webhook.go:19-21`.
   - Engine implementation defaults to fail-closed: `internal/engine/policy.go:182-205`.
   - In a security-sensitive path, contradictory docs around fail-open/fail-closed behavior are not cosmetic. Operators will make the wrong availability/safety assumption.

7. `CommandContains` documentation contradicts runtime behavior.
   - Docs say “must contain ALL specified substrings”: `internal/engine/policy.go:282-287`.
   - Runtime implements OR semantics: `internal/engine/matcher.go:478-489`.
   - That is policy-authoring footgun territory: authors will think they are tightening a rule when they may actually broaden it.

8. The background/runtime metadata files are more permissive than they need to be.
   - `serve.pid` is written `0644`: `cmd/rampart/cli/serve.go:131-133`.
   - `ACTIVE_POLICY.md` is written `0644`: `cmd/rampart/cli/serve.go:620-622`.
   - On their own these are lower-risk than the token leak, but together they expose runtime structure and process info to other local users.

9. `handleAuditEvents` reads the full audit set for a date into memory before filtering/paginating.
   - `internal/proxy/audit_handlers.go:91-107`.
   - The file itself admits this does not scale.
   - Combined with read access for any agent token, this becomes a trivial local DoS/memory-pressure endpoint.

## 2. Website (`docs/index.html`)

### Accuracy issues / false claims

1. “Agents can't disable it” is overstated and contradicted by the current policy/integration model.
   - Claim: `docs/index.html:691-693`.
   - Reality:
     - Standard policy explicitly allows `rampart serve` before later trying to deny it: `policies/standard.yaml:37-62`.
     - Claude Code integration is just a hook in `~/.claude/settings.json`: `cmd/rampart/cli/setup.go:63-71`, `cmd/rampart/cli/setup.go:81-103`.
     - Codex integration is just a wrapper at `~/.local/bin/codex`: `cmd/rampart/cli/setup_codex.go:28-31`, `cmd/rampart/cli/setup_codex.go:58-83`.
     - OpenClaw shim mode explicitly says sub-agents are not intercepted: `cmd/rampart/cli/setup.go:490-495`.
   - An agent that can edit agent config files, PATH wrappers, or invoke the allowed `rampart serve` path can weaken or bypass enforcement. The copy should be narrowed to “raises the bar” rather than “can’t disable it.”

2. The “Approval gates” copy is no longer accurate for `require_approval`.
   - Claim: `docs/index.html:696-699`.
   - Codebase says `require_approval` changed semantics in v0.6.6:
     - `cmd/rampart/cli/upgrade.go:895-899` says it now shows a native Claude Code prompt instead of blocking for dashboard approval.
     - Hook path maps `ActionRequireApproval` to the same native ask flow.
   - The site currently promises a blocking dashboard approval path for `require_approval`, which is false for Claude Code.

3. “Allow everything, block what's dangerous” needs qualification.
   - Claim: `docs/index.html:667-668`.
   - The standard policy only behaves this way because of a late catch-all allow rule: `policies/standard.yaml:1670-1680`.
   - Other shipped/generated policies in the repo use deny-by-default patterns, and per-agent tokens force unmatched calls to default deny in the proxy: `internal/proxy/eval_handlers.go:69-78`.
   - This should be described as profile-dependent, not as a universal Rampart behavior.

4. “Works with everything” is materially broader than the implemented integrations.
   - Claim: `docs/index.html:712-713` and compatibility chips at `docs/index.html:725-735`.
   - The repo has first-class setup paths for Claude Code, Cline, Codex, and OpenClaw, plus generic HTTP/preload/wrap paths. That is not the same as “native” or tested support for Aider, Continue, OpenCode, “Python agents,” or “everything.”
   - This should be demoted to “generic integration possible” unless those integrations are actually maintained/tested.

### UX / trust issues

5. The homepage of a security tool leads with `curl | bash`.
   - `docs/index.html:755-758`.
   - Even if common, it is a trust hit for a product whose pitch is “don’t blindly execute dangerous things.”
   - The page should elevate package-manager / signed-binary install options instead of making pipe-to-shell the hero CTA.

6. The marketing page says “no cloud dependency,” but the page itself depends on third-party network calls for fonts, analytics, and GitHub stars.
   - Fonts in the `<head>`.
   - GitHub stars are fetched at runtime.
   - GoatCounter analytics is loaded at the bottom of the page.
   - This is not a product-runtime bug, but the page is making a “privacy/offline” trust appeal while depending on third-party web services.

## 3. Policies (`policies/standard.yaml`)

### High-risk gaps / mistakes

1. `block-self-modification` contains a real ordering bug: `rampart serve` is allowed before it is denied.
   - Allow rule: `policies/standard.yaml:37-49`.
   - Later deny rule includes the same string: `policies/standard.yaml:52-62`.
   - Engine is first-match-wins within a policy, so `rampart serve ...` will hit the allow and never reach the deny.
   - Concrete consequence: an agent can run variants like `rampart serve --mode disabled` or `rampart serve --addr 0.0.0.0` under the supposedly self-protecting standard policy.

2. The self-modification policy does not cover the actual integration choke points.
   - Claude Code hook config lives in `~/.claude/settings.json`: `cmd/rampart/cli/setup.go:81-103`.
   - Codex wrapper lives in `~/.local/bin/codex`: `cmd/rampart/cli/setup_codex.go:58-83`.
   - OpenClaw shim lives at `~/.local/bin/rampart-shim`: `cmd/rampart/cli/setup.go:499-505`, removable at `cmd/rampart/cli/setup.go:902-907`.
   - Standard policy only blocks `.rampart/**` writes and some `rampart ...` commands: `policies/standard.yaml:63-78`, `policies/standard.yaml:966-980`.
   - Result: the website promise about agents not being able to disable enforcement is not backed by the policy.

3. Response-side credential leak detection ignores fetch/browser/web tools.
   - `block-credential-leaks` only matches `tool: ["exec", "read"]`: `policies/standard.yaml:1131-1144`.
   - But prompt-injection response scanning does include `fetch`, `web_search`, and `mcp`: `policies/standard.yaml:1146-1155`.
   - Concrete gap: if a `fetch`/`web_fetch`/browser-originated response contains an AWS key, the credential-leak deny rule does not fire.

4. macOS keychain policy asks on the generic-password query before the later deny can block plaintext extraction.
   - Ask rule: `policies/standard.yaml:1224-1228` matches `security find-generic-password *`.
   - Later deny tries to block `security find-internet-password -w` and other plaintext dump paths.
   - Because evaluation is top-to-bottom, `security find-generic-password -w ...` gets approval-gated instead of hard-blocked. That is too weak for a credential dump path.

### Coverage gaps

5. Privilege-escalation coverage is too Unix- and `sudo`-centric.
   - Only explicit approval rule is `sudo **`: `policies/standard.yaml:370-374`.
   - Missing common equivalents: `su -c`, `doas`, `runas`, `Start-Process -Verb RunAs`, `sudoedit`, etc.

6. Persistence coverage is incomplete.
   - `require-persistence-approval` covers `crontab`, some `systemctl enable`, and `~/.config/systemd/user/**`: `policies/standard.yaml:376-400`.
   - It misses common persistence paths such as `/etc/systemd/system/**`, `~/.config/autostart/**`, `~/Library/LaunchAgents/**`, `/Library/LaunchDaemons/**`, shell profile drop-ins beyond the generic write block, and Windows Scheduled Tasks (`schtasks`) in the main persistence policy.

7. Credential-access patterns miss a lot of modern secret formats and secret stores.
   - Response regexes only cover a narrow set: `AKIA...`, private keys, `ghp_`, generic `sk-`, Slack, JWT prefixes: `policies/standard.yaml:1137-1143`.
   - Notably absent: AWS secret access key values, `github_pat_`, GitLab `glpat-`, Anthropic/OpenAI newer prefixes, Google service-account JSON markers, Stripe live keys, PEM certificate bundles without “PRIVATE KEY”, etc.
   - For a “standard” security profile, this is thin.

### False-positive risks / pattern quality

8. `**/token*` under read-deny is too broad and will block ordinary files.
   - `policies/standard.yaml:435-445`, especially `**/token*` at line 440.
   - Concrete false positives:
     - `read src/tokenizer.go`
     - `read pkg/token_cache_test.go`
     - `read docs/token-rotation.md`
   - This is a blunt prefix match in a policy that otherwise tries to be precise.

9. Blanket `.env` write blocking will hit normal developer workflows.
   - `block-sensitive-writes` denies `**/.env` and `**/.env.*`.
   - Common legitimate workflows include creating local `.env` files for dev/test. The exception list only spares `example/sample/template` variants.
   - This should likely be `ask` rather than `deny`, or scoped to suspicious destinations.

10. Prompt-injection response patterns are likely to fire on benign documentation, security research, and test fixtures.
   - `policies/standard.yaml:1154-1165` includes broad regexes like `ignore previous instructions`, `forget your instructions`, `your new instructions are`, etc.
   - Those phrases appear in blog posts, red-team docs, benchmark corpora, and prompt-injection tutorials.
   - Requiring approval on every occurrence will create avoidable friction unless this is scoped to remote/untrusted content types or paired with stronger context.

11. The comment quality around policy semantics is already drifting from engine behavior.
   - The `command_contains` engine docs say “ALL specified substrings” but runtime is OR: `internal/engine/policy.go:282-287` vs `internal/engine/matcher.go:478-489`.
   - That increases the risk that future policy authors will write overbroad standard rules by mistake.

## Bottom line

The biggest problems are not exotic parser bugs. They are operational/auth flaws:

- the admin token is leaked by `serve --background`;
- agent tokens can read too much globally;
- the dashboard token handling is much weaker than the rest of the product’s security posture;
- the audit log is inconsistent for several decision paths;
- the website overclaims, especially around “can’t disable it” and approval semantics;
- the standard policy has at least one real self-protection bug (`rampart serve` allow-before-deny), plus meaningful coverage gaps and some avoidable false positives.
