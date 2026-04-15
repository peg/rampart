/**
 * Rampart OpenClaw Plugin
 *
 * Native before_tool_call hook integration for Rampart AI agent firewall.
 * Replaces brittle dist-file patching with the official OpenClaw plugin API.
 *
 * @see https://github.com/peg/rampart
 * @version 0.1.0
 */

import { readFile } from "fs/promises";
import { homedir } from "os";

// ─── Token loading ────────────────────────────────────────────────────────────
// Token is loaded from ~/.rampart/token (written by `rampart serve` on startup).
// This is a local auth token for the Rampart daemon on localhost:9090 only.

let _cachedToken = null;
let _tokenLoadedAt = 0;
const TOKEN_CACHE_TTL_MS = 60_000; // re-read at most once per minute

async function loadToken() {
  const now = Date.now();
  if (_cachedToken !== null && now - _tokenLoadedAt < TOKEN_CACHE_TTL_MS) {
    return _cachedToken;
  }
  try {
    const raw = await readFile(`${homedir()}/.rampart/token`, "utf8");
    _cachedToken = raw.trim();
    _tokenLoadedAt = now;
    return _cachedToken;
  } catch {
    return null;
  }
}

// ─── Params extraction ────────────────────────────────────────────────────────

/**
 * Extract a human-readable "subject" from tool params for approval descriptions.
 * Different tools use different field names for their primary target.
 */
function extractSubject(toolName, params) {
  switch (toolName) {
    case "exec":
      return (
        params.command ??
        params.input?.command ??
        params.script ??
        "<unknown command>"
      );

    case "read":
    case "write":
    case "edit":
      return (
        params.path ??
        params.file ??
        params.filePath ??
        params.file_path ??
        "<unknown path>"
      );

    case "web_fetch":
      return params.url ?? "<unknown url>";

    case "web_search":
      return params.query ?? "<unknown query>";

    case "message":
      return params.message ?? params.action ?? "<unknown message action>";

    case "browser":
      return params.url ?? params.action ?? "<unknown browser action>";

    case "image":
      return params.image ?? params.images?.[0] ?? "<unknown image>";

    default:
      // Try common field names as fallback
      return (
        params.command ??
        params.url ??
        params.path ??
        params.file ??
        params.query ??
        params.message ??
        JSON.stringify(params).slice(0, 120)
      );
  }
}

function truncateForApprovalDescription(text, max = 220) {
  if (typeof text !== "string") return "<unknown>";
  const normalized = text.replace(/\s+/g, " ").trim();
  if (!normalized) return "<unknown>";
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

// ─── Rampart API client ───────────────────────────────────────────────────────

/**
 * Call the Rampart serve endpoint to check if a tool call should be allowed.
 *
 * Request shape (matches Rampart's toolRequest struct):
 *   POST /v1/tool/{toolName}
 *   { agent, session, run_id, params, input? }
 *
 * Returns:
 *   { allowed: true, decision: "allow" }              → allow (pass through)
 *   { allowed: false, decision: "deny", message }     → block
 *   { decision: "ask", message }                     → require OpenClaw approval
 *   null                                              → Rampart unreachable (fail-open)
 */
async function checkWithRampart(toolName, params, ctx, config) {
  const serveUrl = config?.serveUrl ?? "http://localhost:9090";
  const timeoutMs = config?.timeoutMs ?? 3000;

  const token = await loadToken();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    // Rampart's toolRequest expects flat fields: agent, session, run_id, params.
    // (not a nested "context" object)
    const body = JSON.stringify({
      agent:   ctx.agentId   ?? ctx.agent   ?? "",
      session: ctx.sessionKey ?? ctx.sessionId ?? ctx.session ?? "",
      run_id:  ctx.runId     ?? ctx.run_id   ?? "",
      params,
      openclaw_hosted: true,
      skip_pending_approval: true,
    });

    const resp = await fetch(`${serveUrl}/v1/tool/${encodeURIComponent(toolName)}`, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!resp.ok) {
      // 4xx from Rampart: treat 403/401 as deny, fail-open on everything else
      if (resp.status === 403 || resp.status === 401) {
        const text = await resp.text().catch(() => "");
        return { allowed: false, decision: "deny", message: `Rampart: HTTP ${resp.status}${text ? ` — ${text}` : ""}` };
      }
      // 5xx or unexpected — fail-open (warn, not debug, since serve is reachable but broken)
      return { _serveError: true, _status: resp.status };
    }

    return await resp.json();
  } catch (err) {
    clearTimeout(timer);
    if (err?.name === "AbortError") {
      // Timeout — fail-open silently (serve may be slow or overloaded)
      return null;
    }
    if (
      err?.code === "ECONNREFUSED" ||
      err?.code === "ENOENT" ||
      err?.cause?.code === "ECONNREFUSED" ||
      err?.message?.includes("ECONNREFUSED") ||
      err?.message?.includes("fetch failed")
    ) {
      // Rampart serve is not running — fail-open (debug only, not warn)
      return { _unreachable: true };
    }
    // Unknown fetch error — fail-open
    return null;
  }
}

// ─── Audit log ────────────────────────────────────────────────────────────────

async function auditLog(toolName, params, ctx, outcome, config) {
  const serveUrl = config?.serveUrl ?? "http://localhost:9090";
  const token = await loadToken();

  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    await fetch(`${serveUrl}/v1/audit`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        tool: toolName,
        params,
        outcome,
        agent:   ctx.agentId   ?? ctx.agent   ?? "",
        session: ctx.sessionKey ?? ctx.sessionId ?? ctx.session ?? "",
        run_id:  ctx.runId     ?? ctx.run_id   ?? "",
        ts: Date.now(),
      }),
      signal: AbortSignal.timeout(1000), // fire-and-forget, short timeout
    });
  } catch {
    // Audit is best-effort — never fail the agent for it
  }
}

// ─── Plugin entry ─────────────────────────────────────────────────────────────

export const id = "rampart";
export const name = "Rampart";
export const description = "AI agent firewall — YAML policy-as-code for every tool call";
export const version = "0.9.16";

export function register(api) {
  const pluginConfig = api.pluginConfig ?? {};

  // Skip everything if disabled in config
  if (pluginConfig.enabled === false) {
    api.logger.info("[rampart] plugin disabled via config, skipping hook registration");
    return;
  }

  const serveUrl = pluginConfig.serveUrl ?? "http://localhost:9090";
  api.logger.info(`[rampart] v${version} loaded (serve: ${serveUrl})`);

  // Severity emoji for approval embeds
  const severityEmoji = { info: "ℹ️", warning: "⚠️", critical: "🚨" };

  // ── before_tool_call ────────────────────────────────────────────────────────
  api.on("before_tool_call", async (event, ctx) => {
    const { toolName, params } = event;

    const result = await checkWithRampart(toolName, params, ctx, pluginConfig);

    // Serve unreachable → fail-open silently (debug log only)
    if (result?._unreachable) {
      api.logger.debug(`[rampart] serve unreachable — failing open for: ${toolName}`);
      return;
    }

    // null (timeout/unknown error) → fail-open
    if (result === null) {
      api.logger.debug(`[rampart] check timed out or failed — failing open for: ${toolName}`);
      return;
    }

    // Serve returned an error status → warn and fail-open
    if (result?._serveError) {
      api.logger.warn(`[rampart] serve returned HTTP ${result._status} for ${toolName} — failing open`);
      return;
    }

    const decision = result.decision ?? (result.allowed === false ? "deny" : "allow");

    // Debug log every decision (not just blocks/approvals)
    api.logger.debug(`[rampart] ${toolName} → ${decision}${result.policy ? ` (policy: ${result.policy})` : ""}`);
    if (Object.prototype.hasOwnProperty.call(result, "approval_id")) {
      api.logger.warn(`[rampart] unexpected approval_id from Rampart eval for OpenClaw-hosted ${toolName}; this would create dual-queue ownership`);
    }

    switch (decision) {
      case "deny": {
        const reason = result.message ?? result.reason ?? "policy violation";
        api.logger.warn(`[rampart] BLOCKED ${toolName}: ${reason}${result.policy ? ` [${result.policy}]` : ""}`);
        return {
          block: true,
          blockReason: `rampart: ${reason}`,
        };
      }

      case "ask": {
        const subject = extractSubject(toolName, params);
        const subjectPreview = truncateForApprovalDescription(subject, 160);
        const severity = result.severity ?? "warning";
        const emoji = severityEmoji[severity] ?? "⚠️";

        if (toolName === "exec") {
          api.logger.info(`[rampart] exec requires approval via native OpenClaw exec flow (subject: ${subjectPreview})`);
          return {
            params: {
              ...params,
              ask: "always",
            },
          };
        }

        api.logger.info(`[rampart] returning requireApproval for ${toolName} (subject: ${subjectPreview})`);
        return {
          requireApproval: {
            title: `🛡️ Rampart — ${toolName} blocked`,
            description: [
              `**Command:** \`${subjectPreview}\``,
              result.policy  ? `**Policy:** ${truncateForApprovalDescription(result.policy, 64)}` : null,
              result.message ? `**Risk:** ${truncateForApprovalDescription(result.message, 96)}` : `**Risk:** ${emoji} Requires approval`,
            ].filter(Boolean).join("\n"),
            severity,
            timeoutMs: pluginConfig.approvalTimeoutMs ?? 120_000,
            timeoutBehavior: "deny",
            onResolution: async (resolution) => {
              api.logger.info(`[rampart] plugin approval resolved: ${toolName} → ${resolution}`);

              if (resolution === "allow-always") {
                // Write a persistent allow rule via /v1/rules/learn.
                // This works regardless of whether an approval_id exists.
                try {
                  const token = await loadToken();
                  const learnResp = await fetch(`${serveUrl}/v1/rules/learn`, {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      ...(token ? { Authorization: `Bearer ${token}` } : {}),
                    },
                    body: JSON.stringify({ tool: toolName, args: subject, decision: "allow", source: "openclaw-approval" }),
                    signal: AbortSignal.timeout(5000),
                  });
                  if (learnResp.ok) {
                    api.logger.info(`[rampart] always-allow rule written: ${toolName}:${subject}`);
                  } else {
                    api.logger.warn(`[rampart] always-allow rule write failed: HTTP ${learnResp.status}`);
                  }
                } catch (err) {
                  api.logger.warn(`[rampart] always-allow write error: ${err.message}`);
                }
              }
              // For native OpenClaw plugin approvals, OpenClaw itself is the pending approval system.
              // Rampart should not create or resolve a second hidden approval record here, or Discord
              // ends up watching a different queue than the one the user is interacting with.
              //
              // Allow-once and deny are fully handled by OpenClaw's approval outcome for this tool call.
              // Persisting an allow rule is the only side effect we need to send back to Rampart.
            },
          },
        };
      }

      case "watch":
      case "allow":
      default:
        // Allowed — check if Rampart wants to modify params
        if (result.params && typeof result.params === "object") {
          return { params: result.params };
        }
        return; // void = allow as-is
    }
  });

  // ── after_tool_call (audit trail) ──────────────────────────────────────────
  // Register a gateway method so OpenClaw classifies this as a "hybrid-capability"
  // plugin rather than "hook-only". The rampart.status endpoint proxies Rampart
  // serve status through the OpenClaw gateway for dashboard integrations.
  api.registerGatewayMethod("rampart.status", async () => {
    try {
      const token = await loadToken();
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const resp = await fetch(`${serveUrl}/v1/status`, { headers, signal: AbortSignal.timeout(3000) });
      return resp.ok ? await resp.json() : { error: `serve returned ${resp.status}` };
    } catch {
      return { error: "rampart serve unreachable" };
    }
  });

  api.on("after_tool_call", async (event, ctx) => {
    const { toolName, params, error, durationMs } = event;

    // Fire-and-forget — do not block the tool result
    Promise.resolve().then(async () => {
      try {
        api.logger.debug(`[rampart] tool completed: ${toolName} (${durationMs ?? "?"}ms)`);

        // Best-effort audit POST — Rampart serve already logs via before_tool_call path
        await auditLog(
          toolName,
          params,
          ctx,
          {
            type: "result",
            success: !error,
            error: error ?? null,
            durationMs: durationMs ?? null,
          },
          pluginConfig
        );
      } catch {
        // Audit is best-effort — never surface errors here
      }
    });
  });

  api.logger.info("[rampart] hooks registered ✓");
}

// Support both named and default export for OpenClaw plugin loader compatibility
export default { id, name, description, version, register };
