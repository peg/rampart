// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

// Compatibility harnesses execute third-party CLIs. Pass only environment
// values required to locate runtimes and reach public package registries; do
// not expose the developer or CI runner's credential-bearing environment.
const plainKeys = [
  'PATH',
  'PATHEXT',
  'SYSTEMROOT',
  'WINDIR',
  'COMSPEC',
  'SHELL',
  'TMPDIR',
  'TMP',
  'TEMP',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'TERM',
  'CI',
  'GITHUB_ACTIONS',
  'RUNNER_OS',
  'NO_PROXY',
  'no_proxy',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'NPM_CONFIG_CAFILE',
];

const urlKeys = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'NPM_CONFIG_REGISTRY',
  'NPM_CONFIG_PROXY',
  'NPM_CONFIG_HTTPS_PROXY',
];

function credentialFreeURLSetting(value) {
  const trimmed = value.trim();
  if (!trimmed || trimmed.includes('@')) {
    return '';
  }
  try {
    const parsed = new URL(trimmed);
    // Registry/proxy URL variables are forwarded only in their standard,
    // credential-free form. Query strings and fragments commonly carry opaque
    // access tokens even when URL userinfo is empty.
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      return '';
    }
  } catch {
    // Proxy variables are URLs in supported Node/npm configurations. Dropping
    // an ambiguous value is safer than forwarding a credential-like string.
    return '';
  }
  return trimmed;
}

export function buildCompatProcessEnv(source, overrides) {
  const env = {};
  for (const key of plainKeys) {
    if (source[key]) {
      env[key] = source[key];
    }
  }
  for (const key of urlKeys) {
    const value = source[key] ? credentialFreeURLSetting(source[key]) : '';
    if (value) {
      env[key] = value;
    }
  }
  const noProxy = (source.NO_PROXY || source.no_proxy || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  for (const host of ['127.0.0.1', 'localhost', '::1']) {
    if (!noProxy.includes(host)) {
      noProxy.push(host);
    }
  }
  env.NO_PROXY = noProxy.join(',');
  env.no_proxy = env.NO_PROXY;
  return { ...env, ...overrides };
}
