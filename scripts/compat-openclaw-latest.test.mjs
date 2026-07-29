#!/usr/bin/env node

import assert from 'node:assert/strict';
import test from 'node:test';
import { join, resolve } from 'node:path';
import {
  configPathsMatch,
  normalizeConfigPath,
  reportedConfigPath,
} from './compat-openclaw-path.mjs';
import { buildCompatProcessEnv } from './compat-process-env.mjs';

test('normalizes OpenClaw notice-prefixed tilde paths against the isolated home', () => {
  const isolatedHome = resolve('/tmp/rampart-openclaw-compat-test/home');
  const expectedPath = join(isolatedHome, '.openclaw', 'openclaw.json');
  const output = [
    'Migration notices:',
    '- OpenClaw updated the config schema',
    '~/.openclaw/openclaw.json',
  ].join('\n');
  const configFilePath = reportedConfigPath(output);

  assert.equal(configFilePath, '~/.openclaw/openclaw.json');
  assert.equal(normalizeConfigPath(configFilePath, isolatedHome), expectedPath);
  assert.equal(configPathsMatch(configFilePath, expectedPath, isolatedHome), true);
});

test('rejects a config path outside the isolated home', () => {
  const isolatedHome = resolve('/tmp/rampart-openclaw-compat-test/home');
  const expectedPath = join(isolatedHome, '.openclaw', 'openclaw.json');

  assert.equal(configPathsMatch('/home/runner/.openclaw/openclaw.json', expectedPath, isolatedHome), false);
});

test('compatibility child environment excludes ambient credentials', () => {
  const env = buildCompatProcessEnv(
    {
      PATH: '/usr/bin',
      HTTPS_PROXY: 'https://proxy.example:8443',
      HTTP_PROXY: 'http://user:password@proxy.example:8080',
      ALL_PROXY: 'https://proxy.example:8443?token=secret-proxy-token',
      NPM_CONFIG_REGISTRY: 'https://registry.example/npm/#secret-fragment',
      NODE_EXTRA_CA_CERTS: '/etc/company-ca.pem',
      OPENAI_API_KEY: 'secret-openai-key',
      GITHUB_TOKEN: 'secret-github-token',
      NPM_TOKEN: 'secret-npm-token',
      NPM_CONFIG_STRICT_SSL: 'false',
      RAMPART_TOKEN: 'real-rampart-token',
      NODE_OPTIONS: '--require /credential-reader.js',
    },
    {
      HOME: '/tmp/isolated-home',
      RAMPART_TOKEN: 'compat-test-token',
    },
  );

  assert.deepEqual(env, {
    PATH: '/usr/bin',
    NODE_EXTRA_CA_CERTS: '/etc/company-ca.pem',
    HTTPS_PROXY: 'https://proxy.example:8443',
    NO_PROXY: '127.0.0.1,localhost,::1',
    no_proxy: '127.0.0.1,localhost,::1',
    HOME: '/tmp/isolated-home',
    RAMPART_TOKEN: 'compat-test-token',
  });
});
