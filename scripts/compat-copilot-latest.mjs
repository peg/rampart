#!/usr/bin/env node
/**
 * Validate Rampart's shared Copilot CLI / VS Code hook integration against the
 * latest published Copilot CLI package.
 *
 * This gate is credential-free and state-isolated. It proves the latest CLI
 * binary starts with an isolated COPILOT_HOME, validates the generated hook
 * file against the documented shared schema, and exercises Rampart's adapter.
 * It does not make a model request or claim authenticated host execution.
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const repoRoot = resolve(new URL('..', import.meta.url).pathname);
const tempRoot = mkdtempSync(join(tmpdir(), 'rampart-copilot-compat-'));
const tempHome = join(tempRoot, 'home');
const copilotHome = join(tempHome, '.copilot');
const rampartBin = join(tempRoot, process.platform === 'win32' ? 'rampart.exe' : 'rampart');
const args = process.argv.slice(2);
const keepTemp = args.includes('--keep-temp');
const packageArg = args.find((arg) => arg.startsWith('--copilot-package='));
const copilotPackage = packageArg ? packageArg.split('=', 2)[1] : '@github/copilot@latest';

function compatEnv() {
  const inherited = {};
  for (const key of [
    'PATH', 'SystemRoot', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP', 'TMPDIR',
    'LANG', 'LC_ALL', 'CI', 'NO_COLOR', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
  ]) {
    if (process.env[key]) inherited[key] = process.env[key];
  }
  return {
    ...inherited,
    HOME: tempHome,
    USERPROFILE: tempHome,
    COPILOT_HOME: copilotHome,
    XDG_CONFIG_HOME: join(tempHome, '.config'),
  };
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

function assertGeneratedHooks() {
  const path = join(copilotHome, 'hooks', 'rampart.json');
  const config = JSON.parse(readFileSync(path, 'utf8'));
  if (config.version !== 1) throw new Error('generated Copilot hook version must be 1');
  for (const event of ['PreToolUse', 'PostToolUse']) {
    const entries = config.hooks?.[event];
    if (!Array.isArray(entries) || entries.length !== 1) {
      throw new Error(`generated Copilot hooks are missing ${event}`);
    }
    const hook = entries[0];
    if (hook.type !== 'command' ||
        typeof hook.bash !== 'string' || !hook.bash.includes('hook --format copilot') ||
        typeof hook.powershell !== 'string' || !hook.powershell.includes('hook --format copilot')) {
      throw new Error(`generated Copilot ${event} hook is malformed`);
    }
  }
}

function main() {
  run('go', ['build', '-o', rampartBin, './cmd/rampart'], { env: process.env, cwd: repoRoot });
  run(rampartBin, ['setup', 'copilot']);
  assertGeneratedHooks();

  const version = run('npm', ['exec', '--yes', '--package', copilotPackage, '--', 'copilot', '--version']);
  const hostDiagnostics = `${version.stdout}\n${version.stderr}`;
  if (/invalid.*(config|hook)|failed to load.*(config|hook)/i.test(hostDiagnostics)) {
    throw new Error(`latest Copilot CLI rejected Rampart configuration: ${hostDiagnostics}`);
  }
  const versionMatch = hostDiagnostics.match(/GitHub Copilot CLI\s+([0-9]+\.[0-9]+\.[0-9]+)/i);
  if (!versionMatch) {
    throw new Error(`could not parse Copilot CLI version: ${hostDiagnostics}`);
  }

  const payload = JSON.stringify({
    session_id: 'rampart-copilot-latest',
    cwd: tempRoot,
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_use_id: 'rampart-copilot-latest',
    tool_input: { command: 'rm -rf /' },
  });
  const adapter = run(rampartBin, ['hook', '--format', 'copilot'], { input: payload });
  const decision = JSON.parse(adapter.stdout);
  if (decision.permissionDecision !== 'deny' ||
      decision.hookSpecificOutput?.permissionDecision !== 'deny') {
    throw new Error(`Copilot adapter did not return CLI and VS Code denials: ${adapter.stdout}`);
  }

  console.log(JSON.stringify({
    ok: true,
    copilot_source: copilotPackage,
    copilot_version: versionMatch[1],
    generated_shared_hooks_valid: true,
    destructive_pre_tool_denied_for_cli: true,
    destructive_pre_tool_denied_for_vscode_schema: true,
    authenticated_host_tool_call: false,
  }, null, 2));
}

try {
  main();
} finally {
  if (keepTemp) {
    console.error(`kept temporary directory: ${tempRoot}`);
  } else {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}
