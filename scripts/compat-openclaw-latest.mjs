#!/usr/bin/env node
/**
 * Validate Rampart's OpenClaw plugin against an isolated OpenClaw state.
 *
 * By default the script expects an `openclaw` executable on PATH. Pass
 * `--npm-latest` to run through `npm exec --package openclaw@latest` instead.
 * It sets HOME and OPENCLAW_CONFIG_PATH to a temporary directory so plugin
 * install/config checks do not touch a live OpenClaw gateway or user config.
 */

import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  configPathsMatch,
  normalizeConfigPath,
  reportedConfigPath,
} from './compat-openclaw-path.mjs';
import { buildCompatProcessEnv, removeCompatTree } from './compat-process-env.mjs';

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const tempRoot = mkdtempSync(join(tmpdir(), 'rampart-openclaw-compat-'));
const tempHome = join(tempRoot, 'home');
const childTemp = join(tempRoot, 'tmp');
const openclawDir = join(tempHome, '.openclaw');
const configPath = join(openclawDir, 'openclaw.json');
const args = process.argv.slice(2);
const keepTemp = args.includes('--keep-temp');
const useNpmLatest = args.includes('--npm-latest');
const openclawPackageArg = args.find((arg) => arg.startsWith('--openclaw-package='));
const openclawPackage = openclawPackageArg ? openclawPackageArg.split('=', 2)[1] : 'openclaw@latest';

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

function runOpenClaw(openclawArgs, options = {}) {
  if (useNpmLatest) {
    return run('npm', ['exec', '--yes', '--package', openclawPackage, '--', 'openclaw', ...openclawArgs], options);
  }
  return run('openclaw', openclawArgs, options);
}

function compatEnv() {
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
    OPENCLAW_CONFIG_PATH: configPath,
    RAMPART_TOKEN: 'compat-test-token',
    RAMPART_URL: 'http://127.0.0.1:19090',
  });
}

function setupTempState() {
  mkdirSync(openclawDir, { recursive: true });
  mkdirSync(childTemp, { recursive: true });
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

  const version = runOpenClaw(['--version'], { env });
  // OpenClaw 2026.7.2 requires explicit confirmation for local, non-ClawHub
  // plugin sources. --force is also supported by the current stable train, so
  // use the same non-interactive installation path users receive from Rampart.
  const install = runOpenClaw(['plugins', 'install', pluginDir, '--force'], { env });
  const validate = runOpenClaw(['config', 'validate'], { env });
  const configFile = runOpenClaw(['config', 'file'], { env });
  const configFilePath = reportedConfigPath(commandOutput(configFile));
  const configFileMatches = configPathsMatch(configFilePath, configPath, tempHome);
  if (!configFileMatches) {
    throw new Error(
      `OpenClaw config file reported ${JSON.stringify(configFilePath)} `
      + `(${JSON.stringify(normalizeConfigPath(configFilePath, tempHome))}), `
      + `expected ${JSON.stringify(configPath)}`,
    );
  }
  const inspect = runOpenClaw(['plugins', 'inspect', 'rampart'], { required: false, env });
  const list = inspect.status === 0
    ? { command: 'openclaw plugins list', status: 0, stdout: '', stderr: '' }
    : runOpenClaw(['plugins', 'list'], { env });

  const installedOutput = `${commandOutput(inspect)}\n${commandOutput(list)}\n${commandOutput(install)}`;
  if (!installedOutput.includes('rampart')) {
    throw new Error(`OpenClaw plugin output did not mention rampart: ${installedOutput}`);
  }

  const smoke = run(process.execPath, ['internal/plugin/openclaw/smoke-test.mjs'], { env });
  const toolAlias = run(process.execPath, ['internal/plugin/openclaw/tool-alias-test.mjs'], { env });
  const providerSurface = run(process.execPath, ['internal/plugin/openclaw/provider-surface-replay.mjs'], { env });
  const approvals = run(process.execPath, ['internal/plugin/openclaw/approval-regression.mjs'], { env });
  const degraded = run(process.execPath, ['internal/plugin/openclaw/degraded-mode-test.mjs'], { env });

  const summary = {
    ok: true,
    temp_home: tempHome,
    openclaw_version: commandOutput(version).split('\n')[0],
    openclaw_source: useNpmLatest ? openclawPackage : 'PATH',
    plugin_install_checked: true,
    plugin_install_force_checked: true,
    config_validate_checked: validate.status === 0,
    config_file_checked: configFileMatches,
    plugin_inspect_checked: inspect.status === 0,
    plugin_list_checked: inspect.status !== 0 && list.status === 0,
    bundled_plugin_harnesses: {
      smoke: JSON.parse(smoke.stdout),
      tool_alias: JSON.parse(toolAlias.stdout),
      provider_surface: JSON.parse(providerSurface.stdout),
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
    removeCompatTree(tempRoot);
  }
}
