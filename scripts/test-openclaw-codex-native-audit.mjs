#!/usr/bin/env node
/**
 * Live OpenClaw + Codex app-server regression for Rampart native shell coverage.
 *
 * This intentionally exercises the real OpenClaw runtime instead of the plugin
 * unit harness. Passing means:
 *   1. OpenClaw created a Codex app-server session for this run.
 *   2. The session trajectory contains a native Codex `bash` tool call.
 *   3. Rampart wrote a correlated audit event for that command as canonical
 *      tool `exec`.
 *   4. A second safe command reached OpenClaw's native plugin approval queue,
 *      was approved once, resumed, executed, and produced correlated proof.
 *
 * The test may only operate beneath an explicit disposable isolation root. It
 * refuses primary OpenClaw state, workspaces, sessions, memory, and services.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  access,
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const yes = process.env.RAMPART_OPENCLAW_RUNTIME === '1' || process.argv.includes('--yes');

if (!yes) {
  console.error([
    'Refusing to run live OpenClaw runtime regression without explicit opt-in.',
    '',
    'This test uses a prepared disposable OpenClaw state, starts a local Rampart',
    'server, and runs real OpenClaw Codex app-server turns.',
    '',
    'Run intentionally from the repo root with:',
    '  RAMPART_OPENCLAW_RUNTIME=1 \\',
    '  RAMPART_OPENCLAW_ISOLATION_ROOT=/path/to/disposable/root \\',
    '  HOME=/path/to/disposable/root/home \\',
    '  OPENCLAW_STATE_DIR=/path/to/disposable/root/home/.openclaw \\',
    '  OPENCLAW_CONFIG_PATH=/path/to/disposable/root/home/.openclaw/openclaw.json \\',
    '  RAMPART_OPENCLAW_RESTART_SERVICES= \\',
    '  node scripts/test-openclaw-codex-native-audit.mjs',
  ].join('\n'));
  process.exit(2);
}

const port = Number(process.env.RAMPART_OPENCLAW_TEST_PORT || '19090');
const serveUrl = `http://127.0.0.1:${port}`;
const agentId = process.env.RAMPART_OPENCLAW_AGENT || 'main';
const openclawConfigPath = process.env.OPENCLAW_CONFIG_PATH || join(homedir(), '.openclaw', 'openclaw.json');
const openclawStateDir = process.env.OPENCLAW_STATE_DIR || join(homedir(), '.openclaw');
const sessionsDir = join(openclawStateDir, 'agents', agentId, 'sessions');
const tokenPath = join(homedir(), '.rampart', 'token');
const isolationRoot = process.env.RAMPART_OPENCLAW_ISOLATION_ROOT;
const restartServices = (process.env.RAMPART_OPENCLAW_RESTART_SERVICES ?? 'openclaw-gateway.service,openclaw-node.service')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function isWithin(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

if (!isolationRoot) {
  console.error('Refusing OpenClaw runtime regression without RAMPART_OPENCLAW_ISOLATION_ROOT.');
  process.exit(2);
}
for (const [label, path] of [
  ['HOME', homedir()],
  ['OPENCLAW_CONFIG_PATH', openclawConfigPath],
  ['OPENCLAW_STATE_DIR', openclawStateDir],
  ['Rampart token path', tokenPath],
]) {
  if (!isWithin(isolationRoot, path)) {
    console.error(`Refusing OpenClaw runtime regression: ${label} is outside the disposable isolation root.`);
    process.exit(2);
  }
}
if (restartServices.length > 0) {
  console.error('Refusing OpenClaw runtime regression when service restarts are configured.');
  process.exit(2);
}

const runStamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
const marker = `rampart-runtime-codex-shell-${runStamp}`;
const sessionId = marker;
const command = `printf '%s\\n' '${marker}'`;
const prompt = [
  'This is a controlled Rampart/OpenClaw runtime regression test.',
  'Use the native shell/terminal/bash command tool exactly once to run:',
  command,
  'Do not use any other tool. Reply with only the command stdout.',
].join(' ');
const approvalMarker = `rampart-runtime-approved-shell-${runStamp}`;
const approvalSessionId = approvalMarker;
const approvalCommand = `shred --help >/dev/null && printf '%s\\n' '${approvalMarker}'`;
const approvalPrompt = [
  'This is a controlled Rampart/OpenClaw approval and resume regression test.',
  'Use the native shell/terminal/bash command tool exactly once to run:',
  approvalCommand,
  'Wait for approval if requested. Do not use any other tool. Reply with only the command stdout.',
].join(' ');

let tmpRoot;
let auditDir;
let server;
let serverBinary;
let serverLogs = '';
let tokenExisted = false;
let tokenBackup = null;
let cleanupErrors = [];
let activeAgentChild = null;

function redact(text) {
  return String(text ?? '')
    .replace(/(token=)[A-Za-z0-9._~+/-]+/gi, '$1[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+/gi, '$1[REDACTED]')
    .replace(/("Authorization"\s*:\s*")[^"]+/gi, '$1[REDACTED]')
    .replace(/("token"\s*:\s*")[^"]+/gi, '$1[REDACTED]');
}

function fail(message) {
  throw new Error(message);
}

function run(cmd, args = [], opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  return new Promise((resolvePromise, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd ?? repoRoot,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 3_000).unref?.();
      reject(new Error(`${cmd} ${args.join(' ')} timed out after ${timeoutMs}ms\nstdout:\n${redact(stdout)}\nstderr:\n${redact(stderr)}`));
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (code === 0) {
        resolvePromise({ stdout, stderr, code, signal });
      } else {
        reject(new Error(`${cmd} ${args.join(' ')} exited ${code ?? signal}\nstdout:\n${redact(stdout)}\nstderr:\n${redact(stderr)}`));
      }
    });
  });
}

function startCaptured(cmd, args = [], opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const child = spawn(cmd, args, {
    cwd: opts.cwd ?? repoRoot,
    env: opts.env ?? process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  activeAgentChild = child;
  let stdout = '';
  let stderr = '';
  const completion = new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 3_000).unref?.();
      reject(new Error(`${cmd} ${args.join(' ')} timed out after ${timeoutMs}ms\nstdout:\n${redact(stdout)}\nstderr:\n${redact(stderr)}`));
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (activeAgentChild === child) activeAgentChild = null;
      if (code === 0) {
        resolvePromise({ stdout, stderr, code, signal });
      } else {
        reject(new Error(`${cmd} ${args.join(' ')} exited ${code ?? signal}\nstdout:\n${redact(stdout)}\nstderr:\n${redact(stderr)}`));
      }
    });
  });
  return { child, completion };
}

function parseOpenClawJSON(output, label) {
  const lines = String(output ?? '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i].trimStart();
    if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) continue;
    try {
      return JSON.parse(lines.slice(i).join('\n'));
    } catch {
      // Migration notices can themselves begin with "[state-migrations]".
    }
  }
  fail(`${label} did not contain a valid JSON object or array:\n${redact(output).slice(-4000)}`);
}

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function waitForHealth(url, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1500) });
      if (resp.ok) return;
      lastErr = new Error(`healthz HTTP ${resp.status}`);
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  fail(`Rampart health check did not become ready at ${url}: ${lastErr?.message ?? 'unknown error'}\nserver logs:\n${redact(serverLogs).split('\n').slice(-40).join('\n')}`);
}

async function backupToken() {
  tokenBackup = join(tmpRoot, 'rampart-token.backup');
  tokenExisted = await pathExists(tokenPath);
  if (tokenExisted) {
    await copyFile(tokenPath, tokenBackup);
  }
}

async function restoreToken() {
  if (tokenExisted) {
    await copyFile(tokenBackup, tokenPath);
  } else if (await pathExists(tokenPath)) {
    await rm(tokenPath, { force: true });
  }
}

async function validateOpenClawConfiguration() {
  const cfg = JSON.parse(await readFile(openclawConfigPath, 'utf8'));
  const allow = cfg?.plugins?.allow;
  const entry = cfg?.plugins?.entries?.rampart;
  const pluginConfig = entry?.config;
  if (Array.isArray(allow) && !allow.includes('rampart')) {
    fail('Disposable OpenClaw state must include rampart in plugins.allow.');
  }
  if (!entry || entry.enabled === false) {
    fail('Disposable OpenClaw state must have plugins.entries.rampart.enabled=true.');
  }
  if (pluginConfig?.serveUrl !== serveUrl || pluginConfig?.failOpen !== false) {
    fail(`Disposable OpenClaw state must configure Rampart with serveUrl=${serveUrl} and failOpen=false before its isolated gateway starts.`);
  }

  await run('openclaw', ['config', 'validate'], { timeoutMs: 30_000, cwd: repoRoot });
}

async function startRampart() {
  serverBinary = join(tmpRoot, 'rampart-runtime-regression-rampart');
  await run('go', ['build', '-o', serverBinary, './cmd/rampart'], { timeoutMs: 120_000, cwd: repoRoot });

  server = spawn(serverBinary, [
    'serve',
    '--no-openclaw-bridge',
    '--addr', '127.0.0.1',
    '--port', String(port),
    '--audit-dir', auditDir,
  ], {
    cwd: repoRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => { serverLogs += d.toString(); });
  server.stderr.on('data', (d) => { serverLogs += d.toString(); });
  server.on('exit', (code, signal) => {
    if (code !== null && code !== 0) {
      serverLogs += `\n[runtime-regression] rampart serve exited ${code}\n`;
    } else if (signal) {
      serverLogs += `\n[runtime-regression] rampart serve stopped by ${signal}\n`;
    }
  });
  await waitForHealth(serveUrl);
}

async function stopRampart() {
  if (!server || server.exitCode !== null || server.signalCode !== null) return;
  await new Promise((resolvePromise) => {
    const done = () => resolvePromise();
    server.once('exit', done);
    server.kill('SIGTERM');
    setTimeout(() => {
      if (server.exitCode === null && server.signalCode === null) server.kill('SIGKILL');
    }, 5_000).unref?.();
  });
}

function parseJSONLines(content, label) {
  const events = [];
  for (const [idx, line] of content.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line));
    } catch (err) {
      fail(`${label}:${idx + 1}: invalid JSONL: ${err.message}`);
    }
  }
  return events;
}

async function newestAuditEvents() {
  const entries = await readdir(auditDir).catch(() => []);
  const jsonl = [];
  for (const entry of entries) {
    if (!entry.endsWith('.jsonl')) continue;
    const path = join(auditDir, entry);
    const info = await stat(path);
    if (info.isFile()) jsonl.push(path);
  }
  const events = [];
  for (const path of jsonl) {
    events.push(...parseJSONLines(await readFile(path, 'utf8'), path));
  }
  return events;
}

function openClawAgentArgs(turnSessionId, turnPrompt) {
  return [
    'agent',
    '--agent', agentId,
    '--session-id', turnSessionId,
    '--message', turnPrompt,
    '--json',
    '--timeout', process.env.RAMPART_OPENCLAW_AGENT_TIMEOUT || '180',
  ];
}

async function runOpenClawTurn(turnSessionId, turnPrompt, expectedMarker) {
  const result = await run('openclaw', [
    ...openClawAgentArgs(turnSessionId, turnPrompt),
  ], { timeoutMs: Number(process.env.RAMPART_OPENCLAW_AGENT_TIMEOUT_MS || '240000'), cwd: repoRoot });

  const combined = `${result.stdout}\n${result.stderr}`;
  if (!combined.includes(expectedMarker)) {
    fail(`OpenClaw turn completed but output did not include marker ${expectedMarker}. Output:\n${redact(combined).slice(-4000)}`);
  }
}

async function runApprovedOpenClawTurn() {
  const turn = startCaptured('openclaw', openClawAgentArgs(approvalSessionId, approvalPrompt), {
    timeoutMs: Number(process.env.RAMPART_OPENCLAW_AGENT_TIMEOUT_MS || '240000'),
    cwd: repoRoot,
  });
  try {
    const approval = await waitForPluginApproval(approvalMarker, turn);
    await run('openclaw', [
      'gateway',
      'call',
      'plugin.approval.resolve',
      '--params', JSON.stringify({ id: approval.id, decision: 'allow-once' }),
      '--json',
      '--timeout', '15000',
    ], { timeoutMs: 30_000, cwd: repoRoot });
    const result = await turn.completion;
    const combined = `${result.stdout}\n${result.stderr}`;
    if (!combined.includes(approvalMarker)) {
      fail(`Approved OpenClaw turn completed but output did not include marker ${approvalMarker}. Output:\n${redact(combined).slice(-4000)}`);
    }
    return approval;
  } catch (err) {
    if (turn.child.exitCode === null && turn.child.signalCode === null) {
      turn.child.kill('SIGTERM');
    }
    void turn.completion.catch(() => {});
    throw err;
  }
}

async function waitForPluginApproval(expectedMarker, turn, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let lastPayload = null;
  while (Date.now() < deadline) {
    const result = await run('openclaw', [
      'gateway',
      'call',
      'plugin.approval.list',
      '--json',
      '--timeout', '15000',
    ], { timeoutMs: 30_000, cwd: repoRoot });
    const payload = parseOpenClawJSON(result.stdout, 'plugin.approval.list');
    lastPayload = payload;
    const records = Array.isArray(payload)
      ? payload
      : (payload?.pending ?? payload?.approvals ?? payload?.result ?? []);
    const match = Array.isArray(records)
      ? records.find((record) => JSON.stringify(record?.request ?? record).includes(expectedMarker))
      : null;
    if (match?.id) return match;
    if (turn.child.exitCode !== null || turn.child.signalCode !== null) {
      const result = await turn.completion;
      fail(`OpenClaw turn completed before exposing an approval for ${expectedMarker}. Output:\n${redact(`${result.stdout}\n${result.stderr}`).slice(-4000)}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  fail(`OpenClaw did not expose a pending plugin approval for ${expectedMarker}. Last payload: ${redact(JSON.stringify(lastPayload))}`);
}

async function verifyCodexAppServerBinding(turnSessionId) {
  const legacyPath = join(sessionsDir, `${turnSessionId}.jsonl.codex-app-server.json`);
  if (existsSync(legacyPath)) {
    const meta = JSON.parse(await readFile(legacyPath, 'utf8'));
    if (!String(meta.sessionFile || '').endsWith(`${turnSessionId}.jsonl`)) {
      fail(`legacy Codex app-server metadata did not point at this session file: ${legacyPath}`);
    }
    if (!meta.model) {
      fail(`legacy Codex app-server metadata missing model field: ${legacyPath}`);
    }
    return legacyPath;
  }

  const statePath = join(openclawStateDir, 'state', 'openclaw.sqlite');
  if (!existsSync(statePath)) {
    fail(`missing modern Codex plugin-state database and legacy metadata for session ${turnSessionId}`);
  }

  let DatabaseSync;
  try {
    ({ DatabaseSync } = await import('node:sqlite'));
  } catch (err) {
    fail(`cannot inspect modern Codex plugin state with this Node.js runtime: ${err.message}`);
  }

  const database = new DatabaseSync(statePath, { readOnly: true });
  let row;
  try {
    row = database.prepare(`
      SELECT value_json
      FROM plugin_state_entries
      WHERE plugin_id = 'codex'
        AND namespace = 'app-server-thread-bindings'
        AND json_extract(value_json, '$.sessionId') = ?
      ORDER BY created_at DESC
      LIMIT 1
    `).get(turnSessionId);
  } finally {
    database.close();
  }
  if (!row?.value_json) {
    fail(`modern Codex plugin state did not contain a binding for session ${turnSessionId}`);
  }

  const binding = JSON.parse(row.value_json);
  if (binding.sessionId !== turnSessionId || binding.state !== 'active') {
    fail(`modern Codex plugin binding was not active for session ${turnSessionId}`);
  }
  if (!binding.binding?.threadId || !binding.binding?.model) {
    fail(`modern Codex plugin binding was missing thread or model metadata for session ${turnSessionId}`);
  }
  return `${statePath}#codex/app-server-thread-bindings/${turnSessionId}`;
}

async function verifyTrajectoryBashCall(turnSessionId, expectedMarker) {
  const path = join(sessionsDir, `${turnSessionId}.trajectory.jsonl`);
  if (!existsSync(path)) {
    fail(`missing OpenClaw trajectory file: ${path}`);
  }
  const events = parseJSONLines(await readFile(path, 'utf8'), path);
  const bashCall = events.find((evt) => (
    evt?.type === 'tool.call' &&
    evt?.data?.name === 'bash' &&
    JSON.stringify(evt.data.arguments || {}).includes(expectedMarker)
  ));
  if (!bashCall) {
    const toolNames = events
      .filter((evt) => evt?.type === 'tool.call')
      .map((evt) => evt?.data?.name)
      .filter(Boolean);
    fail(`trajectory did not contain a native bash tool.call for ${expectedMarker}; observed tools: ${JSON.stringify(toolNames)}`);
  }
  return path;
}

async function verifyRampartAudit(turnSessionId, expectedMarker, expectedAction) {
  const deadline = Date.now() + 10_000;
  let events = [];
  while (Date.now() < deadline) {
    events = await newestAuditEvents();
    const match = events.find((evt) => {
      const request = JSON.stringify(evt.request || evt.params || {});
      const session = String(evt.session || '').toLowerCase();
      return evt.tool === 'exec' &&
        request.includes(expectedMarker) &&
        session.includes(turnSessionId.toLowerCase()) &&
        (!expectedAction || evt.decision?.action === expectedAction);
    });
    if (match) return match;
    await new Promise((r) => setTimeout(r, 500));
  }
  const compact = events.map((evt) => ({
    tool: evt.tool,
    agent: evt.agent,
    session: evt.session,
    action: evt.decision?.action,
    request: evt.request,
  }));
  fail(`Rampart audit did not contain canonical exec event for native bash marker ${expectedMarker}${expectedAction ? ` with decision ${expectedAction}` : ''}. Observed audit events: ${redact(JSON.stringify(compact, null, 2)).slice(-4000)}`);
}

async function cleanup() {
  if (activeAgentChild && activeAgentChild.exitCode === null && activeAgentChild.signalCode === null) {
    try { activeAgentChild.kill('SIGTERM'); } catch (err) { cleanupErrors.push(`stop OpenClaw test turn: ${err.message}`); }
  }
  try { await stopRampart(); } catch (err) { cleanupErrors.push(`stop rampart: ${err.message}`); }
  try { await restoreToken(); } catch (err) { cleanupErrors.push(`restore rampart token: ${err.message}`); }
  if (tmpRoot && process.env.RAMPART_KEEP_RUNTIME_ARTIFACTS !== '1') {
    try { await rm(tmpRoot, { recursive: true, force: true }); } catch (err) { cleanupErrors.push(`remove tmp: ${err.message}`); }
  }
}

try {
  tmpRoot = await mkdtemp(join(tmpdir(), 'rampart-openclaw-runtime-'));
  auditDir = join(tmpRoot, 'audit');
  await mkdir(auditDir, { recursive: true });
  await writeFile(join(tmpRoot, 'README.txt'), 'Temporary files for Rampart/OpenClaw runtime regression.\n', 'utf8');
  await backupToken();

  console.log(`[runtime-regression] marker=${marker}`);
  console.log(`[runtime-regression] auditDir=${auditDir}`);
  await startRampart();
  console.log(`[runtime-regression] Rampart serve ready at ${serveUrl}`);
  await validateOpenClawConfiguration();
  console.log('[runtime-regression] Disposable OpenClaw plugin configuration validated');
  await runOpenClawTurn(sessionId, prompt, marker);
  const appServerBinding = await verifyCodexAppServerBinding(sessionId);
  const trajectoryPath = await verifyTrajectoryBashCall(sessionId, marker);
  const auditEvent = await verifyRampartAudit(sessionId, marker, 'allow');

  console.log(`[runtime-regression] approvalMarker=${approvalMarker}`);
  const approval = await runApprovedOpenClawTurn();
  const approvalAppServerBinding = await verifyCodexAppServerBinding(approvalSessionId);
  const approvalTrajectoryPath = await verifyTrajectoryBashCall(approvalSessionId, approvalMarker);
  const approvalAuditEvent = await verifyRampartAudit(approvalSessionId, approvalMarker, 'ask');

  console.log(JSON.stringify({
    ok: true,
    marker,
    appServerBinding,
    trajectory: trajectoryPath,
    rampartAudit: {
      id: auditEvent.id,
      tool: auditEvent.tool,
      agent: auditEvent.agent,
      session: auditEvent.session,
      action: auditEvent.decision?.action,
    },
    approvedExecution: {
      marker: approvalMarker,
      approvalId: approval.id,
      resolution: 'allow-once',
      appServerBinding: approvalAppServerBinding,
      trajectory: approvalTrajectoryPath,
      rampartAudit: {
        id: approvalAuditEvent.id,
        tool: approvalAuditEvent.tool,
        agent: approvalAuditEvent.agent,
        session: approvalAuditEvent.session,
        action: approvalAuditEvent.decision?.action,
      },
    },
  }, null, 2));
} catch (err) {
  console.error(`[runtime-regression] FAIL: ${redact(err.stack || err.message)}`);
  console.error(`[runtime-regression] Rampart server log tail:\n${redact(serverLogs).split('\n').slice(-40).join('\n')}`);
  process.exitCode = 1;
} finally {
  await cleanup();
  if (cleanupErrors.length > 0) {
    console.error(`[runtime-regression] cleanup warnings:\n- ${cleanupErrors.map(redact).join('\n- ')}`);
    if (process.exitCode === undefined || process.exitCode === 0) process.exitCode = 1;
  }
  if (tmpRoot && process.env.RAMPART_KEEP_RUNTIME_ARTIFACTS === '1') {
    console.error(`[runtime-regression] kept temp artifacts at ${tmpRoot}`);
  }
}

// OpenClaw/Codex runtime adapters can leave non-critical child-process or stream
// handles alive after the proof has completed. Cleanup above is awaited first;
// then exit explicitly so this regression reports the real pass/fail status
// instead of hanging until an outer harness timeout marks it failed.
process.exit(process.exitCode ?? 0);
