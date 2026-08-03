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

async function runScenario({ name, toolResult, toolName = 'exec', params = { command: 'sudo true' }, resolution }) {
  const { api, handlers, hookOpts, logs } = createApi();
  const fetchCalls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, opts = {}) => {
    fetchCalls.push({ url: String(url), opts });
    if (String(url).includes(`/v1/tool/${encodeURIComponent(toolName)}`)) {
      return { ok: true, json: async () => toolResult };
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
  JSON.stringify(ask.result.requireApproval.allowedDecisions) === JSON.stringify(['allow-once', 'allow-always', 'deny']),
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
assert(learnCall, 'allow-always: learn endpoint not called');
for (const scenario of [ask, deny, allowAlways, ...nonPersistentResolutions]) {
  assert(
    scenario.fetchCalls.every((call) => call.opts.redirect === 'error'),
    `${scenario.name}: control request allowed redirects`,
  );
}
const learnBody = JSON.parse(learnCall.opts.body);
assert(learnBody.tool === 'exec', 'allow-always: wrong tool persisted');
assert(learnBody.args === 'sudo true', 'allow-always: wrong args persisted');
assert(learnBody.decision === 'allow', 'allow-always: wrong decision persisted');

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
assert(markdownDescription.includes('``echo `code` **not bold**``'), 'command code span was not safely fenced');
assert(markdownDescription.includes('**Policy:** ``policy`name``'), 'policy code span was not safely fenced');
assert(markdownDescription.includes('\\*\\*urgent\\*\\*'), 'risk markdown was not escaped');

console.log(JSON.stringify({
  ok: true,
  scenarios: [
    { name: ask.name, result: ask.result },
    { name: deny.name, result: deny.result },
    { name: allowAlways.name, learnPersisted: true },
    ...nonPersistentResolutions.map((scenario) => ({ name: scenario.name, learnPersisted: false })),
  ],
}, null, 2));
