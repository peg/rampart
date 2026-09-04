import plugin from './index.js';

function createApi() {
  const handlers = {};
  const hookOpts = {};
  const logs = [];
  return {
    handlers,
    hookOpts,
    logs,
    api: {
      pluginConfig: {},
      logger: {
        info: (...a) => logs.push(['info', a.join(' ')]),
        warn: (...a) => logs.push(['warn', a.join(' ')]),
        debug: (...a) => logs.push(['debug', a.join(' ')]),
      },
      on: (name, fn, opts) => { handlers[name] = fn; hookOpts[name] = opts; },
      registerGatewayMethod: () => {},
    },
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function runScenario({ name, toolResult, toolName = 'exec', params = { command: 'sudo true' }, resolution, includeAction = true }) {
  const { api, handlers, hookOpts, logs } = createApi();
  const fetchCalls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, opts = {}) => {
    fetchCalls.push({ url: String(url), opts });
    if (String(url).includes(`/v1/tool/${encodeURIComponent(toolName)}`)) {
      return { ok: true, json: async () => ({ ...toolResult, ...(includeAction ? { action: toolResult.action ?? { version: 1, tool: toolName, params } } : {}) }) };
    }
    if (String(url).includes('/v1/rules/learn')) {
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    throw new Error(`unexpected fetch ${url}`);
  };

  try {
    plugin.register(api);
    const before = handlers['before_tool_call'];
    assert(typeof before === 'function', `${name}: before_tool_call handler missing`);
    const ctx = {
      agentId: 'main',
      sessionKey: 'agent:main:discord:direct:449621595489828865',
      runId: `${name}-run`,
    };
    const result = await before({ toolName, params }, ctx);
    if (resolution && result?.requireApproval?.onResolution) {
      await result.requireApproval.onResolution(resolution);
    }
    return { name, result, fetchCalls, hookOpts, logs };
  } finally {
    global.fetch = originalFetch;
  }
}

const ask = await runScenario({
  name: 'ask-exec',
  toolResult: { decision: 'ask', allowed: false, policy: 'test-policy', message: 'needs approval', severity: 'warning' },
});
assert(ask.result?.requireApproval, 'ask-exec: requireApproval missing');
assert(!ask.result?.params?.ask, 'ask-exec: legacy ask param mutation still present');
assert(ask.result.requireApproval.title.includes('exec approval required'), 'ask-exec: wrong title');
assert(ask.result.requireApproval.pluginId === 'rampart', 'ask-exec: approval plugin ownership missing');
assert(
  JSON.stringify(ask.result.requireApproval.allowedDecisions) === JSON.stringify(['allow-once', 'deny']),
  'ask-exec: allowed approval decisions drifted',
);
assert(ask.result.requireApproval.timeoutReason.includes('denied'), 'ask-exec: explicit timeout reason missing');
assert(ask.result.requireApproval.timeoutBehavior === 'deny', 'ask-exec: stable timeout fallback missing');
assert(ask.hookOpts.before_tool_call?.priority < 0, 'ask-exec: Rampart should run as a late before_tool_call hook');

const deny = await runScenario({
  name: 'deny-exec',
  toolResult: { decision: 'deny', allowed: false, message: 'blocked by policy' },
});
assert(deny.result?.block === true, 'deny-exec: block missing');

const allowAlways = await runScenario({
  name: 'allow-always',
  toolResult: { decision: 'ask', allowed: false, policy: 'test-policy', message: 'needs approval', severity: 'warning' },
  resolution: 'allow-always',
});
const nonPersistentResolutions = [];
for (const resolution of ['allow-once', 'deny', 'timeout', 'cancelled']) {
  const scenario = await runScenario({
    name: `resolution-${resolution}`,
    toolResult: { decision: 'ask', allowed: false, policy: 'test-policy', message: 'needs approval', severity: 'warning' },
    resolution,
  });
  assert(
    !scenario.fetchCalls.some((call) => call.url.includes('/v1/rules/learn')),
    `${scenario.name}: non-persistent resolution unexpectedly created a durable rule`,
  );
  nonPersistentResolutions.push(scenario);
}
assert(
  !JSON.stringify(allowAlways.logs).includes('sudo true'),
  'allow-always: raw command leaked into plugin logs',
);
const learnCall = allowAlways.fetchCalls.find((call) => call.url.includes('/v1/rules/learn'));
assert(!learnCall, 'unsupported allow-always resolution created a permanent rule');
for (const scenario of [ask, deny, allowAlways, ...nonPersistentResolutions]) {
  assert(
    scenario.fetchCalls.every((call) => call.opts.redirect === 'error'),
    `${scenario.name}: control request allowed redirects`,
  );
}

const markdown = await runScenario({
  name: 'approval-markdown-is-escaped',
  params: { command: 'echo `code` **not bold**' },
  toolResult: {
    decision: 'ask',
    allowed: false,
    policy: 'policy`name',
    message: '**urgent** [click](https://example.invalid)',
  },
});
const markdownDescription = markdown.result.requireApproval.description;
assert(markdownDescription.includes('\\u0060code\\u0060'), 'command backticks were not JSON escaped');
assert(markdownDescription.includes('**not bold**'), 'command text was silently discarded');
assert(!markdownDescription.includes('[click]'), 'untrusted policy message entered native Markdown');

const suffix = await runScenario({ name: 'complete-suffix', params: { command: 'echo ' + 'x'.repeat(160) + ' ; echo last-target' }, toolResult: { decision: 'ask', allowed: false } });
assert(suffix.result?.requireApproval?.description.includes('last-target'), 'meaningful suffix missing from native review');
const oversized = await runScenario({ name: 'oversized-review', params: { command: 'echo ' + 'x'.repeat(600) }, toolResult: { decision: 'ask', allowed: false }, resolution: 'allow-always' });
assert(oversized.result?.block && !oversized.result.requireApproval, 'oversized action created an approvable truncated description');
const oldService = await runScenario({ name: 'missing-review-on-downgrade', includeAction: false, toolResult: { decision: 'ask', allowed: false } });
assert(oldService.result?.block, 'older service without redacted review did not fail closed');
const redacted = await runScenario({ name: 'redacted-review', params: { command: 'echo --token=synthetic-private' }, toolResult: { decision: 'ask', allowed: false, action: { version: 1, tool: 'exec', params: { command: 'echo --token=[REDACTED]' } } } });
assert(!JSON.stringify(redacted.result).includes('synthetic-private'), 'plugin displayed raw local params instead of server-redacted review');

console.log(JSON.stringify({
  ok: true,
  scenarios: [
    { name: ask.name, result: ask.result },
    { name: deny.name, result: deny.result },
    { name: allowAlways.name, learnPersisted: false },
    ...nonPersistentResolutions.map((scenario) => ({ name: scenario.name, learnPersisted: false })),
  ],
}, null, 2));
