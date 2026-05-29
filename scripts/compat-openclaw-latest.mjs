#!/usr/bin/env node
/**
 * Validate Rampart's OpenClaw plugin against an isolated OpenClaw state.
 *
 * The script expects an `openclaw` executable on PATH. It sets HOME and
 * OPENCLAW_CONFIG_PATH to a temporary directory so plugin install/config checks
 * do not touch a live OpenClaw gateway or user config.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const repoRoot = resolve(new URL('..', import.meta.url).pathname);
const tempRoot = mkdtempSync(join(tmpdir(), 'rampart-openclaw-compat-'));
const tempHome = join(tempRoot, 'home');
const openclawDir = join(tempHome, '.openclaw');
const configPath = join(openclawDir, 'openclaw.json');
const keepTemp = process.argv.includes('--keep-temp');

function run(command, args, { required = true, env = compatEnv() } = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const record = {
    command: [command, ...args].join(' '),
    status: result.status,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
  if (required && result.status !== 0) {
    const detail = JSON.stringify(record, null, 2);
    throw new Error(`command failed: ${detail}`);
  }
  return record;
}

function compatEnv() {
  return {
    ...process.env,
    HOME: tempHome,
    USERPROFILE: tempHome,
    XDG_CONFIG_HOME: join(tempHome, '.config'),
    OPENCLAW_CONFIG_PATH: configPath,
    RAMPART_TOKEN: 'compat-test-token',
    RAMPART_URL: 'http://127.0.0.1:19090',
  };
}

function setupTempState() {
  mkdirSync(openclawDir, { recursive: true });
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        plugins: {
          entries: {},
        },
        tools: {
          exec: {
            ask: 'off',
          },
        },
      },
      null,
      2,
    ),
  );
}

function commandOutput(record) {
  return record.stdout || record.stderr || '';
}

function main() {
  setupTempState();
  const env = compatEnv();
  const pluginDir = join(repoRoot, 'internal', 'plugin', 'openclaw');

  const version = run('openclaw', ['--version'], { env });
  const install = run('openclaw', ['plugins', 'install', pluginDir], { env });
  const validate = run('openclaw', ['config', 'validate'], { env });
  const inspect = run('openclaw', ['plugins', 'inspect', 'rampart'], { required: false, env });
  const list = inspect.status === 0
    ? { command: 'openclaw plugins list', status: 0, stdout: '', stderr: '' }
    : run('openclaw', ['plugins', 'list'], { env });

  const installedOutput = `${commandOutput(inspect)}\n${commandOutput(list)}\n${commandOutput(install)}`;
  if (!installedOutput.includes('rampart')) {
    throw new Error(`OpenClaw plugin output did not mention rampart: ${installedOutput}`);
  }

  const smoke = run(process.execPath, ['internal/plugin/openclaw/smoke-test.mjs'], { env });
  const approvals = run(process.execPath, ['internal/plugin/openclaw/approval-regression.mjs'], { env });
  const degraded = run(process.execPath, ['internal/plugin/openclaw/degraded-mode-test.mjs'], { env });

  const summary = {
    ok: true,
    temp_home: tempHome,
    openclaw_version: commandOutput(version).split('\n')[0],
    plugin_install_checked: true,
    config_validate_checked: validate.status === 0,
    plugin_inspect_checked: inspect.status === 0,
    plugin_list_checked: inspect.status !== 0 && list.status === 0,
    bundled_plugin_harnesses: {
      smoke: JSON.parse(smoke.stdout),
      approvals: JSON.parse(approvals.stdout),
      degraded: JSON.parse(degraded.stdout),
    },
  };
  console.log(JSON.stringify(summary, null, 2));
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
