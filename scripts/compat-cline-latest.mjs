#!/usr/bin/env node
/**
 * Check latest Cline CLI package startup plus Rampart's generated hook files
 * and adapter behavior without credentials or a model request.
 *
 * This is an isolated package/adapter gate, not proof that an authenticated
 * Cline session invoked the hooks.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildCompatProcessEnv, removeCompatTree } from './compat-process-env.mjs';

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const args = process.argv.slice(2);
const tempRoot = mkdtempSync(join(tmpdir(), 'rampart-cline-compat-'));
const tempHome = join(tempRoot, 'home');
const childTemp = join(tempRoot, 'tmp');
const packageRoot = join(tempRoot, 'cline-package');
const rampartBinArg = args.find((arg) => arg.startsWith('--rampart-bin='));
const rampartBin = rampartBinArg
  ? resolve(rampartBinArg.split('=', 2)[1])
  : join(tempRoot, process.platform === 'win32' ? 'rampart.exe' : 'rampart');
const keepTemp = args.includes('--keep-temp');
const packageArg = args.find((arg) => arg.startsWith('--cline-package='));
const clinePackage = packageArg ? packageArg.split('=', 2)[1] : 'cline@latest';

function compatEnv() {
  mkdirSync(childTemp, { recursive: true });
  return buildCompatProcessEnv(process.env, {
    HOME: tempHome,
    USERPROFILE: tempHome,
    TMPDIR: childTemp,
    TMP: childTemp,
    TEMP: childTemp,
    CLINE_DIR: join(tempHome, '.cline'),
    CLINE_DATA_DIR: join(tempHome, '.cline', 'data'),
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
      signal: result.signal,
      error: result.error?.message,
      stdout: (result.stdout || '').trim(),
      stderr: (result.stderr || '').trim(),
    }, null, 2));
  }
  return {
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
}

function runNpm(npmArgs) {
  if (process.platform !== 'win32') return run('npm', npmArgs);
  const searchPath = (process.env.PATH || '').split(';').filter(Boolean);
  for (const directory of searchPath) {
    const npmCLI = join(directory, 'node_modules', 'npm', 'bin', 'npm-cli.js');
    if (existsSync(npmCLI)) return run(process.execPath, [npmCLI, ...npmArgs]);
  }
  throw new Error('could not locate node_modules/npm/bin/npm-cli.js on PATH');
}

function assertGeneratedHooks() {
  const hooksDir = join(tempHome, 'Documents', 'Cline', 'Hooks');
  const suffix = process.platform === 'win32' ? '.ps1' : '';
  for (const event of ['PreToolUse', 'PostToolUse']) {
    const path = join(hooksDir, `${event}${suffix}`);
    const script = readFileSync(path, 'utf8');
    if (!script.includes('Managed by Rampart: Cline hook v2') ||
        !script.includes('hook --format cline')) {
      throw new Error(`generated Cline ${event} hook is missing or malformed: ${path}`);
    }
  }
}

function main() {
  if (!rampartBinArg) {
    run('go', ['build', '-o', rampartBin, './cmd/rampart'], { cwd: repoRoot });
  } else if (!existsSync(rampartBin)) {
    throw new Error(`provided Rampart binary does not exist: ${rampartBin}`);
  }
  run(rampartBin, ['setup', 'cline']);
  assertGeneratedHooks();

  // npm exec currently fails to expose the wrapper package's bin on some npm
  // versions. Install into the disposable tree and invoke the published Node
  // shim directly; the shim then resolves the platform-specific optional
  // dependency exactly as a global installation does.
  runNpm(['install', '--prefix', packageRoot, '--no-save', '--no-audit', '--no-fund', clinePackage]);
  const clineRoot = join(packageRoot, 'node_modules', 'cline');
  const clineManifest = JSON.parse(readFileSync(join(clineRoot, 'package.json'), 'utf8'));
  const clineVersion = clineManifest.version;
  if (typeof clineVersion !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(clineVersion)) {
    throw new Error(`published Cline package has an invalid version: ${JSON.stringify(clineVersion)}`);
  }
  const clineWrapper = join(clineRoot, 'bin', 'cline');
  if (!existsSync(clineWrapper)) {
    throw new Error(`published Cline wrapper is missing: ${clineWrapper}`);
  }
  const version = run(process.execPath, [clineWrapper, '--version']);
  const hostDiagnostics = `${version.stdout}\n${version.stderr}`;
  const reportedVersions = hostDiagnostics.match(/\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\b/g) || [];
  if (!reportedVersions.includes(clineVersion)) {
    throw new Error(`Cline CLI did not report installed package version ${clineVersion}: ${hostDiagnostics}`);
  }

  const payload = JSON.stringify({
    clineVersion,
    hookName: 'tool_call',
    taskId: 'rampart-cline-latest',
    tool_call: {
      id: 'rampart-cline-latest',
      name: 'run_commands',
      input: { commands: ['rm -rf /'] },
    },
  });
  const adapter = run(rampartBin, ['hook', '--format', 'cline'], { input: payload });
  const decision = JSON.parse(adapter.stdout);
  if (decision.cancel !== true) {
    throw new Error(`Cline adapter did not return a structured cancellation: ${adapter.stdout}`);
  }

  console.log(JSON.stringify({
    ok: true,
    cline_source: clinePackage,
    cline_version: clineVersion,
    generated_user_hooks_valid: true,
    destructive_tool_call_cancelled: true,
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
