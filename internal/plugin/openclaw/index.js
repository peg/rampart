/**
 * Rampart OpenClaw Plugin
 *
 * Native before_tool_call hook integration for Rampart AI agent firewall.
 * Replaces brittle dist-file patching with the official OpenClaw plugin API.
 *
 * @see https://github.com/peg/rampart
 * @version 1.4.0
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
      return [
        params.action ?? "message",
        params.target ?? params.to ?? params.channelId ?? params.chatId,
        params.message,
      ].filter(Boolean).join(" → ") || "<unknown message action>";

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

function markdownInlineCode(text) {
  const value = truncateForApprovalDescription(text);
  const longestRun = Math.max(0, ...(value.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longestRun + 1);
  return `${fence}${value}${fence}`;
}

function escapeMarkdownText(text) {
  return truncateForApprovalDescription(text).replace(/([\\`*_[\]{}()<>#+\-.!|])/g, "\\$1");
}

function safeLogLabel(value, max = 80) {
  const normalized = String(value ?? "unknown").replace(/[\r\n\t]+/g, " ").trim();
  return normalized.slice(0, max) || "unknown";
}

// OpenClaw has exposed command execution through more than one tool name over
// time. Rampart policy is intentionally written against the stable "exec"
// class, so command-style aliases must be normalized before policy evaluation.
// Otherwise a host exposing a tool as "bash" can bypass exec policies and land
// in allow-unmatched/default handling.
const MAX_BATCH_PATHS = 100;

// Only tool names with an explicit Rampart policy class may cross the service
// boundary. The standard profile intentionally contains a permissive catch-all,
// so forwarding a future/plugin-owned tool name unchanged would turn an unknown
// capability into an implicit allow. Keep this list aligned with the supported
// surface documented for the OpenClaw integration.
const OPENCLAW_TOOL_CLASS = new Map([
  ["exec", "exec"],
  ["bash", "exec"],
  ["shell", "exec"],
  ["terminal", "exec"],
  ["read", "read"],
  ["grep", "read"],
  ["find", "read"],
  ["ls", "read"],
  ["write", "write"],
  ["edit", "edit"],
  ["apply_patch", "edit"],
  ["fetch", "fetch"],
  ["web_fetch", "web_fetch"],
  ["web_search", "web_search"],
  ["browser", "browser"],
  ["message", "message"],
  ["canvas", "canvas"],
  ["process", "process"],
  ["nodes", "nodes"],
  ["cron", "cron"],
  ["gateway", "gateway"],
  ["agents_list", "agents_list"],
  ["sessions_list", "sessions_list"],
  ["sessions_history", "sessions_history"],
  ["sessions_send", "message"],
  ["sessions_spawn", "sessions_spawn"],
  ["sessions_yield", "sessions_yield"],
  ["subagents", "subagents"],
  ["session_status", "session_status"],
  ["image", "image"],
  ["image_generate", "image"],
]);

function collectApplyPatchPaths(params, derivedPaths = []) {
  const patch = params?.input ?? params?.patch;
  if (typeof patch !== "string" || !patch.trim()) {
    return { error: "apply_patch is missing its patch input", paths: [] };
  }

  const prefixes = [
    "*** Add File:",
    "*** Update File:",
    "*** Delete File:",
    "*** Move to:",
  ];
  const paths = [];
  const seen = new Set();
  const addPath = (value) => {
    if (typeof value !== "string") return false;
    const path = value.trim();
    if (!path || path.includes("\0") || path.includes("\n") || path.includes("\r")) return false;
    if (!seen.has(path)) {
      seen.add(path);
      paths.push(path);
    }
    return paths.length <= MAX_BATCH_PATHS;
  };

  for (const rawLine of patch.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    const prefix = prefixes.find((candidate) => line.startsWith(candidate));
    if (!prefix) continue;
    if (!addPath(line.slice(prefix.length))) {
      return { error: `apply_patch has an invalid target or more than ${MAX_BATCH_PATHS} paths`, paths: [] };
    }
  }

  // Include host-derived hints conservatively. They are not authoritative, so
  // the plugin still parses the patch itself; taking the union ensures a host
  // path that our parser recognizes differently cannot be silently omitted.
  if (Array.isArray(derivedPaths)) {
    for (const path of derivedPaths) {
      if (!addPath(path)) {
        return { error: `apply_patch has an invalid target or more than ${MAX_BATCH_PATHS} paths`, paths: [] };
      }
    }
  }

  if (paths.length === 0) {
    return { error: "apply_patch contains no recognized file targets", paths: [] };
  }
  return { error: "", paths };
}

function normalizeExecParams(params) {
  if (!params || typeof params !== "object") return {};
  const normalized = { ...params };
  const command =
    params.command ??
    params.input?.command ??
    params.script ??
    params.cmd ??
    params.args?.command;
  if (typeof command === "string" && !normalized.command) {
    normalized.command = command;
  }
  return normalized;
}

function normalizeToolCall(toolName, params, event = {}) {
  const originalToolName = typeof toolName === "string" && toolName.trim() ? toolName.trim() : "unknown";
  const canonical = originalToolName.toLowerCase();
  const rampartTool = OPENCLAW_TOOL_CLASS.get(canonical);
  if (!rampartTool) {
    return {
      toolName: canonical,
      params: params && typeof params === "object" && !Array.isArray(params) ? params : {},
      originalToolName,
      mapped: false,
      classified: false,
      classificationError: `unsupported OpenClaw tool ${safeLogLabel(originalToolName)}`,
      policyPaths: [],
    };
  }

  let normalizedParams = params && typeof params === "object" && !Array.isArray(params) ? { ...params } : {};
  let policyPaths = [];
  let classificationError = "";
  if (rampartTool === "exec") {
    normalizedParams = normalizeExecParams(normalizedParams);
  } else if (canonical === "apply_patch") {
    const collected = collectApplyPatchPaths(normalizedParams, event?.derivedPaths);
    policyPaths = collected.paths;
    classificationError = collected.error;
    if (!classificationError) {
      normalizedParams.path = policyPaths[0];
      normalizedParams.paths = [...policyPaths];
    }
  } else if (canonical === "sessions_send") {
    // Reuse the message consequence model for cross-session delivery. A
    // session is never the originating provider conversation, so this reaches
    // the managed approval rule instead of silently inheriting message-send
    // compatibility defaults.
    normalizedParams.action = "send";
    normalizedParams.target =
      normalizedParams.sessionKey ??
      normalizedParams.session_key ??
      normalizedParams.label ??
      "<unknown session>";
  }

  return {
    toolName: rampartTool,
    params: normalizedParams,
    originalToolName,
    mapped: canonical !== rampartTool || originalToolName !== canonical,
    classified: classificationError === "",
    classificationError,
    policyPaths,
  };
}

function policyDecisionRank(result) {
  if (
    result === null ||
    result?._unsafeServeUrl ||
    result?._invalidResponse ||
    result?._unreachable ||
    result?._serveError
  ) {
    return 100;
  }
  switch (result?.decision) {
    case "deny": return 4;
    case "ask": return 3;
    case "watch": return 2;
    case "allow": return 1;
    default: return 99;
  }
}

const READ_ONLY_MESSAGE_ACTIONS = new Set([
  "read",
  "reactions",
  "pins",
  "permissions",
  "search",
  "member info",
  "role info",
  "channel info",
  "channel list",
  "thread list",
  "emoji list",
  "event list",
  "voice status",
]);

const ROUTINE_REPLY_ACTIONS = new Set(["send", "reply", "thread reply", "react"]);

function parseConversationTarget(value) {
  if (value === null || value === undefined) return { provider: "", id: "" };
  let target = String(value).trim().toLowerCase();
  const providerMatch = target.match(/^(discord|telegram|slack|signal|matrix|msteams|mattermost|imessage|whatsapp):/);
  const provider = providerMatch?.[1] ?? "";
  if (providerMatch) target = target.slice(providerMatch[0].length);
  target = target.replace(/^(channel|conversation|chat):/, "");
  return { provider, id: target };
}

function sameConversation(target, ctx) {
  const normalizedTarget = parseConversationTarget(target);
  if (!normalizedTarget.id) return false;

  const originProvider = String(
    ctx?.requester?.channel ?? ctx?.messageProvider ?? ctx?.channel ?? "",
  ).trim().toLowerCase();
  if (
    normalizedTarget.provider &&
    originProvider &&
    normalizedTarget.provider !== originProvider
  ) {
    return false;
  }

  const candidates = [
    ctx?.channelId,
    ctx?.chatId,
    ctx?.channelContext?.chat?.id,
  ].map((value) => parseConversationTarget(value).id).filter(Boolean);

  // The target is agent-controlled. Prefix normalization above handles the
  // provider/channel forms Rampart explicitly understands, so accepting a
  // suffix match here would let a target such as "external:12345" impersonate
  // the originating conversation "12345" and bypass cross-conversation
  // approval.
  return candidates.some((candidate) => normalizedTarget.id === candidate);
}

function classifyMessageConsequence(params, ctx) {
  const action = String(params?.action ?? "").trim().toLowerCase();
  if (READ_ONLY_MESSAGE_ACTIONS.has(action)) return "read-only";

  const target =
    params?.target ??
    params?.to ??
    params?.channelId ??
    params?.chatId ??
    params?.recipient ??
    params?.destination;

  if (ROUTINE_REPLY_ACTIONS.has(action) && sameConversation(target, ctx)) {
    return "routine-reply";
  }
  if (ROUTINE_REPLY_ACTIONS.has(action) || action === "broadcast" || action === "poll") {
    return "external-message";
  }
  return "mutation";
}

const READ_ONLY_BROWSER_ACTIONS = new Set([
  "status",
  "tabs",
  "snapshot",
  "screenshot",
  "console",
]);
const NAVIGATING_BROWSER_ACTIONS = new Set(["open", "navigate"]);

const OPENCLAW_CONTROL_TOOLS = new Set([
  "process",
  "nodes",
  "cron",
  "gateway",
  "agents_list",
  "sessions_list",
  "sessions_history",
  "sessions_yield",
  "subagents",
  "session_status",
]);

const READ_ONLY_CONTROL_ACTIONS = new Map([
  ["process", new Set(["list", "poll", "log"])],
  ["nodes", new Set(["list", "status", "describe", "pending"])],
  ["gateway", new Set(["status"])],
  ["subagents", new Set(["list"])],
]);

function classifyControlConsequence(toolName, params) {
  if (toolName === "agents_list" || toolName === "sessions_yield") return "read-only";
  if (toolName === "sessions_list" || toolName === "sessions_history" || toolName === "cron") {
    return "sensitive-read-or-mutation";
  }
  if (toolName === "session_status") {
    return typeof params?.model === "string" && params.model.trim() ? "mutation" : "read-only";
  }
  const action = String(params?.action ?? "").trim().toLowerCase();
  if (READ_ONLY_CONTROL_ACTIONS.get(toolName)?.has(action)) return "read-only";
  return "mutation";
}

function classifyBrowserConsequence(params) {
  const action = String(params?.action ?? "").trim().toLowerCase();
  if (READ_ONLY_BROWSER_ACTIONS.has(action)) return "read-only";
  if (NAVIGATING_BROWSER_ACTIONS.has(action)) return "navigation";
  return "mutation";
}

function addBrowserURLFacts(policyParams) {
  const rawURL = policyParams?.targetUrl ?? policyParams?.url;
  if (typeof rawURL !== "string" || !rawURL.trim()) return;
  try {
    const parsed = new URL(rawURL);
    if (!policyParams.url) policyParams.url = rawURL;
    if (!policyParams.domain) policyParams.domain = parsed.hostname;
    if (!policyParams.scheme) policyParams.scheme = parsed.protocol.replace(/:$/, "");
  } catch {
    // A malformed URL has no derived safe-domain fact and therefore cannot
    // inherit the safe-navigation allow rule.
  }
}

// Add host-derived facts used only for policy evaluation. These fields are
// never returned to OpenClaw as executable tool parameters.
function policyParamsForTool(toolName, params, ctx) {
  const policyParams = { ...(params ?? {}) };

  // Scope the managed Guard layer to calls that actually crossed the native
  // OpenClaw integration. Other Rampart integrations sharing the policy
  // service should not inherit OpenClaw-specific consequence defaults.
  policyParams.rampart_integration = "openclaw";
  if (toolName === "browser") {
    policyParams.rampart_consequence = `openclaw:browser-${classifyBrowserConsequence(policyParams)}`;
    addBrowserURLFacts(policyParams);
    return policyParams;
  }
  if (OPENCLAW_CONTROL_TOOLS.has(toolName)) {
    policyParams.rampart_consequence = `openclaw:control-${classifyControlConsequence(toolName, policyParams)}`;
    return policyParams;
  }
  if (toolName !== "message") return policyParams;

  policyParams.rampart_consequence = `openclaw:${classifyMessageConsequence(policyParams, ctx)}`;
  const originChannel = ctx?.channelId ?? ctx?.chatId ?? ctx?.channelContext?.chat?.id;
  if (originChannel !== undefined && originChannel !== null) {
    policyParams.rampart_origin_channel = String(originChannel);
  }
  return policyParams;
}

function rampartAgentIdentity(ctx) {
  const raw = String(ctx?.agentId ?? ctx?.agent ?? "unknown").trim() || "unknown";
  return raw;
}

function isTrustedServeUrl(value) {
  try {
    const url = new URL(value ?? "http://localhost:9090");
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      url.pathname === "/" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

function toolDisplayName(toolName, originalToolName) {
  const canonical = safeLogLabel(toolName);
  const original = safeLogLabel(originalToolName || toolName);
  return original !== canonical ? `${original}→${canonical}` : canonical;
}

// ─── Rampart API client ───────────────────────────────────────────────────────

const MAX_CONTROL_RESPONSE_BYTES = 1024 * 1024;
const POLICY_DECISIONS = new Set(["allow", "watch", "ask", "deny"]);
const APPROVAL_SEVERITIES = new Set(["info", "warning", "critical"]);

class InvalidControlResponseError extends Error {}

async function readControlResponseText(response) {
  const declaredLength = response?.headers?.get?.("content-length");
  if (declaredLength !== null && declaredLength !== undefined && declaredLength !== "") {
    const parsedLength = Number(declaredLength);
    if (Number.isFinite(parsedLength) && parsedLength > MAX_CONTROL_RESPONSE_BYTES) {
      await response?.body?.cancel?.().catch(() => {});
      throw new InvalidControlResponseError("Rampart response exceeded the size limit");
    }
  }

  // Real Fetch responses expose a byte stream. Count decoded response bytes as
  // they arrive so chunked or compressed replies cannot bypass Content-Length.
  if (response?.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    let text = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value?.byteLength ?? 0;
        if (total > MAX_CONTROL_RESPONSE_BYTES) {
          await reader.cancel().catch(() => {});
          throw new InvalidControlResponseError("Rampart response exceeded the size limit");
        }
        text += decoder.decode(value, { stream: true });
      }
      return text + decoder.decode();
    } finally {
      reader.releaseLock();
    }
  }

  // Test doubles and older host shims may expose only convenience readers. The
  // production Fetch path above performs the limit before buffering the body.
  if (typeof response?.text === "function") {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_CONTROL_RESPONSE_BYTES) {
      throw new InvalidControlResponseError("Rampart response exceeded the size limit");
    }
    return text;
  }
  if (typeof response?.json === "function") {
    const text = JSON.stringify(await response.json());
    if (new TextEncoder().encode(text).byteLength > MAX_CONTROL_RESPONSE_BYTES) {
      throw new InvalidControlResponseError("Rampart response exceeded the size limit");
    }
    return text;
  }
  throw new InvalidControlResponseError("Rampart response body is unreadable");
}

async function readControlResponseJSON(response) {
  const text = await readControlResponseText(response);
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new InvalidControlResponseError("Rampart returned invalid JSON", { cause: err });
  }
}

function isConsistentPolicyDecision(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return false;
  if (!POLICY_DECISIONS.has(result.decision)) return false;
  if (typeof result.allowed !== "boolean") return false;
  return result.allowed === (result.decision === "allow" || result.decision === "watch");
}

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
 *   { allowed: false, decision: "ask", message }     → require OpenClaw approval
 *   null                                              → degraded handling in hook (fail-open only for configured tools)
 */
async function checkWithRampart(toolName, params, ctx, config, { verification = false } = {}) {
  const serveUrl = config?.serveUrl ?? "http://localhost:9090";
  const configuredTimeoutMs = Number(config?.timeoutMs ?? 3000);
  const timeoutMs = Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0
    ? Math.min(configuredTimeoutMs, 30_000)
    : 3000;

  if (!isTrustedServeUrl(serveUrl)) {
    return { _unsafeServeUrl: true };
  }

  const token = await loadToken();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    // Rampart's toolRequest expects flat fields: agent, session, run_id, params.
    // (not a nested "context" object)
    const body = JSON.stringify({
      agent:   rampartAgentIdentity(ctx),
      session: ctx.sessionKey ?? ctx.sessionId ?? ctx.session ?? "",
      run_id:  ctx.runId     ?? ctx.run_id   ?? "",
      params,
      openclaw_hosted: true,
      skip_pending_approval: true,
      verification,
    });

    const endpoint = verification ? "preflight" : "tool";
    const resp = await fetch(`${serveUrl}/v1/${endpoint}/${encodeURIComponent(toolName)}`, {
      method: "POST",
      headers,
      body,
      redirect: "error",
      signal: controller.signal,
    });

    if (!resp.ok) {
      // Authentication failures are explicit denies, and their bodies are
      // bounded/drained without being reflected into logs or approval UI.
      if (resp.status === 403 || resp.status === 401) {
        // Drain the bounded body for connection reuse, but never reflect an
        // authentication response body into host logs or approval UI.
        await readControlResponseText(resp);
        return { allowed: false, decision: "deny", message: `Rampart authentication rejected (HTTP ${resp.status})` };
      }
      await resp?.body?.cancel?.().catch(() => {});
      // Redirects and other client errors indicate an incompatible or invalid
      // control-plane exchange, not an outage eligible for configured fail-open.
      if (resp.status >= 300 && resp.status < 400) {
        return { _invalidResponse: true };
      }
      if (resp.status >= 400 && resp.status < 500) {
        return {
          allowed: false,
          decision: "deny",
          message: `Rampart rejected the policy request (HTTP ${resp.status})`,
        };
      }
      // 5xx or an unexpected transport status uses explicit degraded handling.
      return { _serveError: true, _status: resp.status };
    }

    try {
      const result = await readControlResponseJSON(resp);
      if (!isConsistentPolicyDecision(result)) {
        return { _invalidResponse: true };
      }
      return result;
    } catch {
      return { _invalidResponse: true };
    }
  } catch (err) {
    if (err instanceof InvalidControlResponseError) {
      return { _invalidResponse: true };
    }
    if (err?.name === "AbortError") {
      // Timeout — defer to degraded handling in the hook
      return null;
    }
    const errorText = `${err?.message ?? ""} ${err?.cause?.message ?? ""}`.toLowerCase();
    if (errorText.includes("redirect")) {
      return { _invalidResponse: true };
    }
    if (
      err?.code === "ECONNREFUSED" ||
      err?.code === "ENOENT" ||
      err?.cause?.code === "ECONNREFUSED" ||
      err?.message?.includes("ECONNREFUSED") ||
      err?.message?.includes("fetch failed")
    ) {
      // Rampart serve is not running — defer to degraded handling in the hook
      return { _unreachable: true };
    }
    // Unknown fetch error — defer to degraded handling in the hook
    return null;
  } finally {
    // The authorization timeout covers headers and the complete bounded body,
    // not only the initial Fetch promise.
    clearTimeout(timer);
  }
}

// ─── Plugin entry ─────────────────────────────────────────────────────────────

export const id = "rampart";
export const name = "Rampart";
export const description = "Independent safety guard for unattended AI agent actions";
export const version = "1.4.0";

// OpenClaw runs higher-priority before_tool_call hooks first, so place Rampart
// late among normal plugins as defense in depth. Priority alone is not an
// authoritative final-params boundary: OpenClaw currently gives each hook the
// original event, so other parameter-mutating plugins must be treated as part
// of the trusted host configuration.
const RAMPART_TOOL_HOOK_PRIORITY = -1000;

export function register(api) {
  const pluginConfig = api.pluginConfig ?? {};

  // Skip everything if disabled in config
  if (pluginConfig.enabled === false) {
    api.logger.info("[rampart] plugin disabled via config, skipping hook registration");
    return;
  }

  const serveUrl = pluginConfig.serveUrl ?? "http://localhost:9090";
  const serveURLDisplay = isTrustedServeUrl(serveUrl) ? serveUrl : "<untrusted>";
  api.logger.info(`[rampart] v${version} loaded (serve: ${serveURLDisplay})`);

  // Severity emoji for approval embeds
  const severityEmoji = { info: "ℹ️", warning: "⚠️", critical: "🚨" };

  // ── before_tool_call ────────────────────────────────────────────────────────
  const evaluateToolCall = async (event, ctx, options = {}) => {
    const normalized = normalizeToolCall(event?.toolName, event?.params, event);
    const { toolName, params, originalToolName, mapped, classified, classificationError, policyPaths } = normalized;
    const displayToolName = toolDisplayName(toolName, originalToolName);
    if (!classified) {
      api.logger.warn(`[rampart] blocking unclassified OpenClaw tool ${safeLogLabel(originalToolName)}`);
      return {
        block: true,
        blockReason: `rampart: ${classificationError} — update Rampart or add a typed integration before using this capability`,
      };
    }
    if (mapped) {
      api.logger.info(
        `[rampart] mapped OpenClaw tool ${safeLogLabel(originalToolName)} to Rampart ${safeLogLabel(toolName)}`,
      );
    }

    const basePolicyParams = policyParamsForTool(toolName, params, ctx);
    const policyVariants = policyPaths.length > 0
      ? policyPaths.map((path) => ({ ...basePolicyParams, path }))
      : [basePolicyParams];
    let result;
    let policyParams = basePolicyParams;
    let selectedRank = -1;
    for (const candidateParams of policyVariants) {
      const candidate = await checkWithRampart(toolName, candidateParams, ctx, pluginConfig, options);
      const rank = policyDecisionRank(candidate);
      if (rank > selectedRank) {
        result = candidate;
        policyParams = candidateParams;
        selectedRank = rank;
      }
      if (rank >= 99 || candidate?.decision === "deny") break;
    }

    const configuredFailOpenTools = Array.isArray(pluginConfig.failOpenTools) && pluginConfig.failOpenTools.length > 0
      ? pluginConfig.failOpenTools
      : pluginConfig.failOpen === true
        ? ["read", "web_fetch", "web_search", "image"]
        : [];
    const failOpenTools = new Set(configuredFailOpenTools);
    const shouldFailOpen = failOpenTools.has(toolName);
    const unreachableReason = `[rampart] serve unavailable for ${displayToolName} at ${serveUrl}`;

    if (result?._unsafeServeUrl) {
      api.logger.warn(`[rampart] refusing untrusted serveUrl for ${displayToolName}`);
      return {
        block: true,
        blockReason: "rampart: untrusted policy service URL — managed protection requires loopback",
      };
    }

    if (result?._invalidResponse) {
      api.logger.warn(`[rampart] invalid policy response for ${displayToolName}; blocking tool call`);
      return {
        block: true,
        blockReason: "rampart: invalid policy response — refusing tool call",
      };
    }

    // Serve unreachable → explicit degraded-state handling
    if (result?._unreachable) {
      api.logger.warn(`${unreachableReason} (${shouldFailOpen ? "configured fail-open" : "blocking tool call"})`);
      if (shouldFailOpen) return;
      return {
        block: true,
        blockReason: `rampart: unavailable (${displayToolName}) — policy service down, refusing sensitive tool call`,
      };
    }

    // null (timeout/unknown error) → explicit degraded-state handling
    if (result === null) {
      api.logger.warn(`[rampart] check timed out or failed for ${displayToolName} (${shouldFailOpen ? "configured fail-open" : "blocking tool call"})`);
      if (shouldFailOpen) return;
      return {
        block: true,
        blockReason: `rampart: unavailable (${displayToolName}) — policy check timed out, refusing sensitive tool call`,
      };
    }

    // Serve returned an error status → explicit degraded-state handling
    if (result?._serveError) {
      api.logger.warn(`[rampart] serve returned HTTP ${result._status} for ${displayToolName} (${shouldFailOpen ? "configured fail-open" : "blocking tool call"})`);
      if (shouldFailOpen) return;
      return {
        block: true,
        blockReason: `rampart: unavailable (${displayToolName}) — policy service error ${result._status}, refusing sensitive tool call`,
      };
    }

    const decision = result?.decision;
    if (!POLICY_DECISIONS.has(decision)) {
      api.logger.warn(`[rampart] unknown policy decision for ${displayToolName}: ${String(decision)}`);
      return {
        block: true,
        blockReason: "rampart: unknown policy decision — refusing tool call",
      };
    }

    // Debug log every decision (not just blocks/approvals)
    api.logger.debug(`[rampart] ${displayToolName} → ${decision}`);
    if (Object.prototype.hasOwnProperty.call(result, "approval_id")) {
      api.logger.warn(`[rampart] unexpected approval_id from Rampart eval for OpenClaw-hosted ${displayToolName}; this would create dual-queue ownership`);
    }

    switch (decision) {
      case "deny": {
        const reason = result.message ?? result.reason ?? "policy violation";
        api.logger.warn(`[rampart] BLOCKED ${displayToolName}`);
        return {
          block: true,
          blockReason: `rampart: ${reason}`,
        };
      }

      case "ask": {
        // Batched edits evaluate one path at a time. Describe and persist the
        // path whose restrictive decision actually won, not merely the first
        // target in the patch.
        const subject = extractSubject(toolName, policyParams);
        const subjectPreview = truncateForApprovalDescription(subject, 160);
        const severity = APPROVAL_SEVERITIES.has(result.severity)
          ? result.severity
          : "warning";
        const emoji = severityEmoji[severity];

        api.logger.info(`[rampart] returning requireApproval for ${displayToolName}`);
        return {
          requireApproval: {
            title: `🛡️ Rampart — ${displayToolName} approval required`,
            description: [
              `**Command:** ${markdownInlineCode(subjectPreview)}`,
              result.policy  ? `**Policy:** ${markdownInlineCode(truncateForApprovalDescription(result.policy, 64))}` : null,
              result.message ? `**Risk:** ${escapeMarkdownText(truncateForApprovalDescription(result.message, 96))}` : `**Risk:** ${emoji} Requires approval`,
            ].filter(Boolean).join("\n"),
            severity,
            timeoutMs: pluginConfig.approvalTimeoutMs ?? 120_000,
            timeoutBehavior: "deny",
            onResolution: async (resolution) => {
              api.logger.info(`[rampart] plugin approval resolved: ${displayToolName} → ${safeLogLabel(resolution)}`);

              if (resolution === "allow-always") {
                if (!isTrustedServeUrl(serveUrl)) {
                  api.logger.warn("[rampart] refusing allow-always persistence to an untrusted serveUrl");
                  return;
                }
                const learnPayload = {
                  tool: toolName,
                  args: subject,
                  decision: "allow",
                  source: "openclaw-approval",
                };
                api.logger.info(`[rampart] attempting always-allow persistence for ${displayToolName}`);

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
                    body: JSON.stringify(learnPayload),
                    redirect: "error",
                    signal: AbortSignal.timeout(5000),
                  });
                  await readControlResponseText(learnResp);
                  if (learnResp.ok) {
                    api.logger.info(`[rampart] always-allow rule written for ${displayToolName}`);
                  } else {
                    api.logger.warn(`[rampart] always-allow rule write failed: HTTP ${learnResp.status}`);
                  }
                } catch (err) {
                  api.logger.warn(`[rampart] always-allow write error (${err?.name ?? "Error"})`);
                }
              } else {
                api.logger.info(`[rampart] no durable allow write for resolution=${resolution}`);
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
        return; // void = allow as-is
    }
  };
  const safeEvaluateToolCall = async (event, ctx, options = {}) => {
    try {
      return await evaluateToolCall(event, ctx, options);
    } catch (err) {
      try {
        api.logger.warn(`[rampart] internal policy adapter error; blocking tool call (${err?.name ?? "Error"})`);
      } catch {
        // Logging is not part of the authorization decision.
      }
      return {
        block: true,
        blockReason: "rampart: policy adapter error — refusing tool call",
      };
    }
  };
  api.on("before_tool_call", safeEvaluateToolCall, { priority: RAMPART_TOOL_HOOK_PRIORITY });

  // Expose a small status endpoint for dashboard integrations. Tool enforcement
  // still lives entirely in the typed before_tool_call hook. Rampart serve
  // records the policy decision made by that request in its canonical audit.
  api.registerGatewayMethod("rampart.status", async ({ respond }) => {
    if (!isTrustedServeUrl(serveUrl)) {
      respond(true, { error: "untrusted Rampart serveUrl" });
      return;
    }
    try {
      const token = await loadToken();
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const resp = await fetch(`${serveUrl}/v1/status`, {
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(3000),
      });
      if (!resp.ok) {
        await resp?.body?.cancel?.().catch(() => {});
        respond(true, { error: `serve returned ${resp.status}` });
        return;
      }
      const status = await readControlResponseJSON(resp);
      respond(
        true,
        status && typeof status === "object" && !Array.isArray(status)
          ? status
          : { error: "rampart serve returned an invalid status response" },
      );
    } catch {
      respond(true, { error: "rampart serve unreachable" });
    }
  });

  // Exercise the exact same normalization, policy request, degraded-mode, and
  // decision-mapping code as before_tool_call without asking OpenClaw to run a
  // tool. The canaries are fixed here rather than caller-supplied so this RPC
  // can never become an execution or arbitrary policy-probing surface.
  api.registerGatewayMethod("rampart.verify", async ({ respond }) => {
    const canaryCtx = {
      agentId: "rampart-verification",
      sessionKey: "rampart-verification",
      runId: "rampart-verification",
      channelId: "rampart-verification-origin",
      chatId: "rampart-verification-origin",
    };
    const canaries = [
      {
        id: "routine-command",
        event: { toolName: "exec", params: { command: "pwd" } },
        expected: "allow",
      },
      {
        id: "destructive-command",
        event: { toolName: "exec", params: { command: "rm -rf /" } },
        expected: "deny",
      },
      {
        id: "external-deployment",
        event: { toolName: "exec", params: { command: "git push origin rampart-verification-canary" } },
        expected: "ask",
      },
      {
        id: "cross-conversation-message",
        event: {
          toolName: "message",
          params: { action: "send", target: "channel:rampart-verification-other", message: "safe canary" },
        },
        expected: "ask",
      },
      {
        id: "credential-shell-read",
        event: { toolName: "exec", params: { command: "cat ~/.ssh/id_rampart_verification_canary" } },
        expected: "deny",
      },
      {
        id: "opaque-interpreter",
        event: { toolName: "exec", params: { command: "python3 -c 'print(\"rampart-verification\")'" } },
        expected: "ask",
      },
    ];

    const checks = [];
    for (const canary of canaries) {
      try {
        const result = await safeEvaluateToolCall(canary.event, canaryCtx, { verification: true });
        const actual = result?.block === true
          ? "deny"
          : result?.requireApproval
            ? "ask"
            : "allow";
        checks.push({
          id: canary.id,
          expected: canary.expected,
          actual,
          pass: actual === canary.expected,
        });
      } catch (err) {
        checks.push({
          id: canary.id,
          expected: canary.expected,
          actual: "error",
          pass: false,
          error: err?.message ?? String(err),
        });
      }
    }
    respond(true, {
      schema: "rampart.plugin.verify.v1",
      safeCanaries: true,
      ok: checks.every((check) => check.pass),
      checks,
    });
  });

  api.logger.info("[rampart] hooks registered ✓");
}

// Support both named and default export for OpenClaw plugin loader compatibility
export default { id, name, description, version, register };
