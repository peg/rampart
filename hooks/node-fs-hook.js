/**
 * Rampart Node.js FS Hook
 *
 * Intercepts fs.readFile(Sync), fs.writeFile(Sync), and fs.promises variants
 * to enforce Rampart policy on file operations. Designed to catch Claude Code's
 * native Read/Write/Edit tools which bypass shell-level hooks.
 *
 * Install: NODE_OPTIONS="--require /path/to/node-fs-hook.js"
 * Config:  RAMPART_URL (default http://127.0.0.1:19090), RAMPART_TOKEN (optional)
 *
 * Fails open if Rampart is unreachable. Caches deny decisions for 1s.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const RAMPART_URL = process.env.RAMPART_URL || 'http://127.0.0.1:19090';
const RAMPART_TOKEN = process.env.RAMPART_TOKEN || '';
const HOME = process.env.HOME || '/home';

// --- Fast-path skip list ---
// These prefixes/patterns are skipped to avoid intercepting Claude Code internals.
const SKIP_PREFIXES = [
  '/tmp/claude-',
  '/tmp/.claude',
  '/proc/',
  '/dev/',
  '/sys/',
];

function shouldCheck(filePath) {
  if (typeof filePath !== 'string') return false;

  // Resolve to absolute
  const abs = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);

  // Skip non-home paths except sensitive system files
  const SENSITIVE = ['/etc/shadow', '/etc/passwd', '/etc/sudoers'];
  if (!abs.startsWith(HOME + '/') && !SENSITIVE.some(s => abs.startsWith(s))) {
    return false;
  }

  // Skip known internal paths
  for (const prefix of SKIP_PREFIXES) {
    if (abs.startsWith(prefix)) return false;
  }

  // Skip node_modules anywhere in path
  if (abs.includes('/node_modules/')) return false;

  // Skip .claude directories (Claude Code config)
  if (abs.includes('/.claude/')) return false;

  return true;
}

// --- Deny cache: path+tool -> { denied: bool, message: string, ts: number } ---
const denyCache = new Map();
const CACHE_TTL_MS = 1000;

function getCached(tool, filePath) {
  const key = tool + ':' + filePath;
  const entry = denyCache.get(key);
  if (entry && (Date.now() - entry.ts) < CACHE_TTL_MS) return entry;
  denyCache.delete(key);
  return null;
}

function setCache(tool, filePath, denied, message) {
  const key = tool + ':' + filePath;
  denyCache.set(key, { denied, message, ts: Date.now() });
  // Prune if cache grows too large
  if (denyCache.size > 500) {
    const now = Date.now();
    for (const [k, v] of denyCache) {
      if (now - v.ts > CACHE_TTL_MS) denyCache.delete(k);
    }
  }
}

// --- Sync policy check via curl ---
function checkPolicySync(tool, filePath) {
  const abs = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
  if (!shouldCheck(abs)) return; // allow

  const cached = getCached(tool, abs);
  if (cached) {
    if (cached.denied) throw new Error(`RAMPART DENIED: ${cached.message}`);
    return;
  }

  try {
    const url = `${RAMPART_URL}/v1/tool/${tool}`;
    const body = JSON.stringify({ path: abs });
    const args = [
      '-s', '-o', '/dev/stdout', '-w', '\n%{http_code}',
      '--max-time', '0.5',
      '-X', 'POST',
      '-H', 'Content-Type: application/json',
    ];
    if (RAMPART_TOKEN) args.push('-H', `Authorization: Bearer ${RAMPART_TOKEN}`);
    args.push('-d', body, url);

    const result = execFileSync('curl', args, {
      encoding: 'utf-8',
      timeout: 600,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const lines = result.trimEnd().split('\n');
    const statusCode = parseInt(lines[lines.length - 1], 10);
    const responseBody = lines.slice(0, -1).join('\n');

    if (statusCode === 403) {
      let msg = 'Operation denied by Rampart policy';
      try { msg = JSON.parse(responseBody).message || msg; } catch (_) {}
      setCache(tool, abs, true, msg);
      throw new Error(`RAMPART DENIED: ${msg}`);
    }

    setCache(tool, abs, false, '');
  } catch (err) {
    if (err.message && err.message.startsWith('RAMPART DENIED')) throw err;
    // Fail open — Rampart unreachable or curl failed
    setCache(tool, abs, false, '');
  }
}

// --- Async policy check ---
async function checkPolicyAsync(tool, filePath) {
  const abs = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
  if (!shouldCheck(abs)) return;

  const cached = getCached(tool, abs);
  if (cached) {
    if (cached.denied) throw new Error(`RAMPART DENIED: ${cached.message}`);
    return;
  }

  try {
    const url = `${RAMPART_URL}/v1/tool/${tool}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 500);
    const headers = { 'Content-Type': 'application/json' };
    if (RAMPART_TOKEN) headers['Authorization'] = `Bearer ${RAMPART_TOKEN}`;

    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ path: abs }),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (resp.status === 403) {
      let msg = 'Operation denied by Rampart policy';
      try { msg = (await resp.json()).message || msg; } catch (_) {}
      setCache(tool, abs, true, msg);
      throw new Error(`RAMPART DENIED: ${msg}`);
    }

    setCache(tool, abs, false, '');
  } catch (err) {
    if (err.message && err.message.startsWith('RAMPART DENIED')) throw err;
    setCache(tool, abs, false, '');
  }
}

// --- Monkey-patch fs ---

const origReadFileSync = fs.readFileSync;
fs.readFileSync = function(filePath, ...args) {
  checkPolicySync('read', String(filePath));
  return origReadFileSync.call(this, filePath, ...args);
};

const origWriteFileSync = fs.writeFileSync;
fs.writeFileSync = function(filePath, ...args) {
  checkPolicySync('write', String(filePath));
  return origWriteFileSync.call(this, filePath, ...args);
};

const origReadFile = fs.readFile;
fs.readFile = function(filePath, ...args) {
  const cb = args[args.length - 1];
  try {
    checkPolicySync('read', String(filePath));
  } catch (err) {
    if (typeof cb === 'function') return cb(err);
    throw err;
  }
  return origReadFile.call(this, filePath, ...args);
};

const origWriteFile = fs.writeFile;
fs.writeFile = function(filePath, ...args) {
  const cb = args[args.length - 1];
  try {
    checkPolicySync('write', String(filePath));
  } catch (err) {
    if (typeof cb === 'function') return cb(err);
    throw err;
  }
  return origWriteFile.call(this, filePath, ...args);
};

// Patch fs.promises
const origPromisesReadFile = fs.promises.readFile;
fs.promises.readFile = async function(filePath, ...args) {
  await checkPolicyAsync('read', String(filePath));
  return origPromisesReadFile.call(this, filePath, ...args);
};

const origPromisesWriteFile = fs.promises.writeFile;
fs.promises.writeFile = async function(filePath, ...args) {
  await checkPolicyAsync('write', String(filePath));
  return origPromisesWriteFile.call(this, filePath, ...args);
};
