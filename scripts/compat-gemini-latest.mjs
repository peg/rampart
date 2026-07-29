#!/usr/bin/env node
/**
 * Check latest Gemini CLI package startup plus Rampart's generated settings
 * shape and adapter behavior.
 *
 * This gate is credential-free and state-isolated. It proves that the latest
 * package starts in isolated state, then separately checks Rampart's generated
 * settings shape and documented deny schema for a destructive BeforeTool
 * payload. The version command is not evidence that Gemini loaded or dispatched
 * the hooks; this does not make a model request or claim live-host proof.
 */

import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildCompatProcessEnv, removeCompatTree } from './compat-process-env.mjs';

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const tempRoot = mkdtempSync(join(tmpdir(), 'rampart-gemini-compat-'));
const tempHome = join(tempRoot, 'home');
const childTemp = join(tempRoot, 'tmp');
const rampartBin = join(tempRoot, process.platform === 'win32' ? 'rampart.exe' : 'rampart');
const args = process.argv.slice(2);
const keepTemp = args.includes('--keep-temp');
const packageArg = args.find((arg) => arg.startsWith('--gemini-package='));
const geminiPackage = packageArg ? packageArg.split('=', 2)[1] : '@google/gemini-cli@latest';

function compatEnv() {
  mkdirSync(childTemp, { recursive: true });
  return buildCompatProcessEnv(process.env, {
    HOME: tempHome,
    USERPROFILE: tempHome,
    TMPDIR: childTemp,
    TMP: childTemp,
    TEMP: childTemp,
    XDG_CONFIG_HOME: join(tempHome, '.config'),
    XDG_CACHE_HOME: join(tempHome, '.cache'),
    XDG_DATA_HOME: join(tempHome, '.local', 'share'),
    XDG_STATE_HOME: join(tempHome, '.local', 'state'),
    GOCACHE: join(childTemp, 'go-build-cache'),
    NO_COLOR: '1',
  });
}

function run(command, commandArgs, { input = undefined, env = compatEnv(), cwd = tempRoot } = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd,
    env,
    input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (result.status !== 0) {
    throw new Error(JSON.stringify({
      command: [command, ...commandArgs].join(' '),
      status: result.status,
      stdout: (result.stdout || '').trim(),
      stderr: (result.stderr || '').trim(),
    }, null, 2));
  }
  return {
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
}

function assertGeneratedSettings() {
  const path = join(tempHome, '.gemini', 'settings.json');
  const settings = JSON.parse(readFileSync(path, 'utf8'));
  for (const event of ['BeforeTool', 'AfterTool']) {
    const entries = settings.hooks?.[event];
    if (!Array.isArray(entries)) {
      throw new Error(`generated Gemini settings are missing ${event}`);
    }
    const rampart = entries.find((entry) =>
      Array.isArray(entry?.hooks) && entry.hooks.some((hook) =>
        typeof hook?.command === 'string' && hook.command.includes('hook --format gemini')));
    if (!rampart || rampart.matcher !== '.*') {
      throw new Error(`generated Gemini ${event} matcher is missing or malformed`);
    }
  }
}

function main() {
  run('go', ['build', '-o', rampartBin, './cmd/rampart'], { cwd: repoRoot });
  run(rampartBin, ['setup', 'gemini']);
  assertGeneratedSettings();

  const version = run('npm', ['exec', '--yes', '--package', geminiPackage, '--', 'gemini', '--version']);
  const hostDiagnostics = `${version.stdout}\n${version.stderr}`;
  if (/invalid.*(setting|hook)|failed to load.*(setting|hook)/i.test(hostDiagnostics)) {
    throw new Error(`latest Gemini CLI rejected Rampart settings: ${hostDiagnostics}`);
  }

  const payload = JSON.stringify({
    session_id: 'rampart-gemini-latest',
    cwd: tempRoot,
    hook_event_name: 'BeforeTool',
    tool_name: 'run_shell_command',
    tool_input: { command: 'rm -rf /' },
  });
  const adapter = run(rampartBin, ['hook', '--format', 'gemini'], { input: payload });
  const decision = JSON.parse(adapter.stdout);
  if (decision.decision !== 'deny' || typeof decision.reason !== 'string') {
    throw new Error(`Gemini adapter did not return a structured deny: ${adapter.stdout}`);
  }

  console.log(JSON.stringify({
    ok: true,
    gemini_source: geminiPackage,
    gemini_version: version.stdout.split(/\r?\n/).filter(Boolean).at(-1),
    generated_settings_shape_valid: true,
    destructive_before_tool_denied: true,
    authenticated_host_tool_call: false,
  }, null, 2));
}

try {
  main();
} finally {
  if (keepTemp) {
    console.error(`kept temporary directory: ${tempRoot}`);
  } else {
    removeCompatTree(tempRoot);
  }
}
