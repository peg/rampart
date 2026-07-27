#!/usr/bin/env node

import assert from 'node:assert/strict';
import test from 'node:test';
import { join, resolve } from 'node:path';
import {
  configPathsMatch,
  normalizeConfigPath,
  reportedConfigPath,
} from './compat-openclaw-path.mjs';

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
