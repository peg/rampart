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
    'This test temporarily enables the Rampart OpenClaw plugin, restarts OpenClaw',
    'user services, starts a local Rampart server, and runs one real OpenClaw',
    'Codex app-server turn.',
    '',
    'Run intentionally from the repo root with:',
    '  RAMPART_OPENCLAW_RUNTIME=1 node scripts/test-openclaw-codex-native-audit.mjs',
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

const marker = `rampart-runtime-codex-shell-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}`;
const sessionId = marker;
const command = `printf '%s\\n' '${marker}'`;
const prompt = [
  'This is a controlled Rampart/OpenClaw runtime regression test.',
  'Use the native shell/terminal/bash command tool exactly once to run:',
  command,
  'Do not use any other tool. Reply with only the command stdout.',
].join(' ');

let tmpRoot;
let auditDir;
let server;
let serverBinary;
let serverLogs = '';
let originalConfig = null;
let configChanged = false;
let tokenExisted = false;
let tokenBackup = null;
let cleanupErrors = [];

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

async function restartOpenClaw(reason) {
  if (restartServices.length === 0) {
    console.warn(`[runtime-regression] Skipping OpenClaw restart for ${reason} because RAMPART_OPENCLAW_RESTART_SERVICES is empty.`);
    return;
  }
  for (const service of restartServices) {
    await run('systemctl', ['--user', 'restart', service], { timeoutMs: 45_000, cwd: repoRoot });
  }
  for (const service of restartServices) {
    await run('systemctl', ['--user', 'is-active', service], { timeoutMs: 15_000, cwd: repoRoot });
  }
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

async function configureOpenClaw() {
  originalConfig = await readFile(openclawConfigPath, 'utf8');
  const cfg = JSON.parse(originalConfig);
  cfg.plugins ??= {};
  cfg.plugins.allow ??= [];
  if (!cfg.plugins.allow.includes('rampart')) cfg.plugins.allow.push('rampart');
  cfg.plugins.entries ??= {};
  cfg.plugins.entries.rampart ??= {};
  cfg.plugins.entries.rampart.enabled = true;
  cfg.plugins.entries.rampart.config ??= {};
  cfg.plugins.entries.rampart.config.serveUrl = serveUrl;
  cfg.plugins.entries.rampart.config.failOpen = false;

  const next = `${JSON.stringify(cfg, null, 2)}\n`;
  if (next !== originalConfig) {
    await writeFile(openclawConfigPath, next, 'utf8');
    configChanged = true;
  }

  await run('openclaw', ['config', 'validate'], { timeoutMs: 30_000, cwd: repoRoot });
  await restartOpenClaw('temporary Rampart plugin enablement');
}

async function restoreOpenClawConfig() {
  if (originalConfig !== null && configChanged) {
    await writeFile(openclawConfigPath, originalConfig, 'utf8');
    await run('openclaw', ['config', 'validate'], { timeoutMs: 30_000, cwd: repoRoot });
    await restartOpenClaw('Rampart plugin config restore');
  }
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

async function runOpenClawTurn() {
  const result = await run('openclaw', [
    'agent',
    '--agent', agentId,
    '--session-id', sessionId,
    '--message', prompt,
    '--json',
    '--timeout', process.env.RAMPART_OPENCLAW_AGENT_TIMEOUT || '180',
  ], { timeoutMs: Number(process.env.RAMPART_OPENCLAW_AGENT_TIMEOUT_MS || '240000'), cwd: repoRoot });

  const combined = `${result.stdout}\n${result.stderr}`;
  if (!combined.includes(marker)) {
    fail(`OpenClaw turn completed but output did not include marker ${marker}. Output:\n${redact(combined).slice(-4000)}`);
  }
}

async function verifyCodexAppServerArtifact() {
  const path = join(sessionsDir, `${sessionId}.jsonl.codex-app-server.json`);
  if (!existsSync(path)) {
    fail(`missing Codex app-server metadata file: ${path}`);
  }
  const meta = JSON.parse(await readFile(path, 'utf8'));
  if (!String(meta.sessionFile || '').endsWith(`${sessionId}.jsonl`)) {
    fail(`Codex app-server metadata did not point at this session file: ${path}`);
  }
  if (!meta.model) {
    fail(`Codex app-server metadata missing model field: ${path}`);
  }
  return path;
}

async function verifyTrajectoryBashCall() {
  const path = join(sessionsDir, `${sessionId}.trajectory.jsonl`);
  if (!existsSync(path)) {
    fail(`missing OpenClaw trajectory file: ${path}`);
  }
  const events = parseJSONLines(await readFile(path, 'utf8'), path);
  const bashCall = events.find((evt) => (
    evt?.type === 'tool.call' &&
    evt?.data?.name === 'bash' &&
    JSON.stringify(evt.data.arguments || {}).includes(marker)
  ));
  if (!bashCall) {
    const toolNames = events
      .filter((evt) => evt?.type === 'tool.call')
      .map((evt) => evt?.data?.name)
      .filter(Boolean);
    fail(`trajectory did not contain a native bash tool.call for ${marker}; observed tools: ${JSON.stringify(toolNames)}`);
  }
  return path;
}

async function verifyRampartAudit() {
  const deadline = Date.now() + 10_000;
  let events = [];
  while (Date.now() < deadline) {
    events = await newestAuditEvents();
    const match = events.find((evt) => {
      const request = JSON.stringify(evt.request || evt.params || {});
      const session = String(evt.session || '').toLowerCase();
      return evt.tool === 'exec' &&
        request.includes(marker) &&
        session.includes(sessionId.toLowerCase());
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
  fail(`Rampart audit did not contain canonical exec event for native bash marker ${marker}. Observed audit events: ${redact(JSON.stringify(compact, null, 2)).slice(-4000)}`);
}

async function cleanup() {
  try { await stopRampart(); } catch (err) { cleanupErrors.push(`stop rampart: ${err.message}`); }
  try { await restoreOpenClawConfig(); } catch (err) { cleanupErrors.push(`restore openclaw config: ${err.message}`); }
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
  await configureOpenClaw();
  console.log('[runtime-regression] OpenClaw plugin temporarily enabled and services restarted');
  await runOpenClawTurn();
  const appServerPath = await verifyCodexAppServerArtifact();
  const trajectoryPath = await verifyTrajectoryBashCall();
  const auditEvent = await verifyRampartAudit();

  console.log(JSON.stringify({
    ok: true,
    marker,
    appServerMetadata: appServerPath,
    trajectory: trajectoryPath,
    rampartAudit: {
      id: auditEvent.id,
      tool: auditEvent.tool,
      agent: auditEvent.agent,
      session: auditEvent.session,
      action: auditEvent.decision?.action,
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
