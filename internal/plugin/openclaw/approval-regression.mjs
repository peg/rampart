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

async function runScenario({ name, toolResult, toolName = 'exec', params = { command: 'sudo true' }, resolution, includeAction = true, context = {}, eventIds = {} }) {
  const { api, handlers, hookOpts, logs } = createApi();
  const fetchCalls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, opts = {}) => {
    fetchCalls.push({ url: String(url), opts });
    if (String(url).includes(`/v1/tool/${encodeURIComponent(toolName)}`)) {
      const request = JSON.parse(opts.body);
      const action = toolResult.action ?? {
        version: 1, tool: toolName, params: request.params, input: request.input,
        agent: request.agent, session: request.session, run_id: request.run_id,
        tool_call_id: request.tool_call_id, workdir: request.params.workdir,
      };
      return { ok: true, json: async () => ({ ...toolResult, ...(includeAction ? { action } : {}) }) };
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
      ...context,
    };
    const result = await before({ toolName, params, ...eventIds }, ctx);
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
for (const original of [null, 'command', []]) {
  const malformed = await runScenario({ name: 'malformed-original-input', toolResult: { decision: 'ask', allowed: false, action: { version: 1, tool: 'exec', params: {}, input: { rampart_original_input: original } } } });
  assert(malformed.result?.block && !malformed.result.requireApproval, 'malformed original action became approvable');
}
const redacted = await runScenario({ name: 'redacted-review', params: { command: 'echo --token=synthetic-private' }, toolResult: { decision: 'ask', allowed: false, action: { version: 1, tool: 'exec', params: { command: 'echo --token=[REDACTED]' } } } });
assert(!JSON.stringify(redacted.result).includes('synthetic-private'), 'plugin displayed raw local params instead of server-redacted review');

function displayedAction(result) {
  const description = result?.requireApproval?.description;
  assert(typeof description === 'string', 'complete execution review missing');
  const match = description.match(/^Action \(redacted\):\n```json\n([\s\S]*)\n```$/);
  assert(match, 'execution arguments lost their fenced JSON presentation');
  return JSON.parse(match[1]);
}

// Long real-world paths and requester facts must fit without spending the
// native description budget on opaque correlation IDs or duplicate workdir.
const workdir = '/srv/operations/monthly-maintenance/production-reporting/customer-services/active/workspace';
const longParams = {
  command: `/usr/bin/cp --backup=numbered ${workdir}/report.json ${workdir.replace('/workspace', '/dead-end')}/report.json`,
  workdir,
};
const longContext = {
  agentId: 'ops', sessionKey: `session-${'s'.repeat(120)}`,
  requester: { channel: 'webchat', senderId: 'cli', senderIsOwner: true },
};
const longEventIds = { runId: `run-${'r'.repeat(120)}`, toolCallId: `call-${'t'.repeat(120)}` };
const longReview = await runScenario({
  name: 'long-execution-review-retains-binding', params: longParams,
  context: longContext, eventIds: longEventIds,
  toolResult: { decision: 'ask', allowed: false }, resolution: 'allow-once',
});
const longDisplayed = displayedAction(longReview.result);
assert(JSON.stringify(longDisplayed.params) === JSON.stringify(longParams), 'long execution arguments changed or were shortened');
assert(longDisplayed.agent === 'ops', 'agent identity missing from execution review');
assert(JSON.stringify(longDisplayed.requester) === JSON.stringify(longContext.requester), 'requester facts missing');
assert(!Object.hasOwn(longDisplayed, 'workdir'), 'identical workdir was repeated');
const longRequest = JSON.parse(longReview.fetchCalls[0].opts.body);
assert(longRequest.session === longContext.sessionKey && longRequest.run_id === longEventIds.runId && longRequest.tool_call_id === longEventIds.toolCallId, 'display compaction changed service/audit correlation');
assert(longRequest.openclaw_hosted === true && longRequest.skip_pending_approval === true, 'native approval ownership changed');
assert(longReview.result.params === undefined, 'approval rewrote executable arguments');
for (const value of [longContext.sessionKey, longEventIds.runId, longEventIds.toolCallId]) {
  assert(!longReview.result.requireApproval.description.includes(value), 'opaque correlation consumed execution-review budget');
}

for (const originalParams of [{ command: 'pwd' }, { command: 'pwd', workdir: '.' }]) {
  const scoped = await runScenario({
    name: 'distinct-execution-context', params: originalParams,
    toolResult: { decision: 'ask', allowed: false, action: {
      version: 1, tool: 'exec', agent: 'ops', agent_depth: 2, workdir: '/srv/operations',
      params: {}, input: { rampart_original_input: originalParams },
    } },
  });
  const displayed = displayedAction(scoped.result);
  assert(displayed.workdir === '/srv/operations' && displayed.agent_depth === 2, 'distinct workdir or delegation depth was discarded');
  assert(JSON.stringify(displayed.params) === JSON.stringify(originalParams), 'original relative workdir changed');
}

const targetParams = { paths: ['/srv/a', '/srv/b'], session: 'target-session', run_id: 'target-run', tool_call_id: 'target-call' };
const targetFacts = { rampart_original_tool: 'apply_patch', rampart_targets: ['/srv/a', '/srv/b'], rampart_requester: { channel: 'webchat', senderId: 'cli' }, rampart_origin_channel: 'operations' };
const targetsReview = await runScenario({
  name: 'execution-fields-named-like-correlation', toolName: 'edit', params: targetParams,
  toolResult: { decision: 'ask', allowed: false, action: {
    version: 1, tool: 'edit', params: targetFacts, input: { rampart_original_input: targetParams },
    session: 'opaque-session', run_id: 'opaque-run', tool_call_id: 'opaque-call',
  } },
});
const targetsDisplayed = displayedAction(targetsReview.result);
assert(JSON.stringify(targetsDisplayed.params) === JSON.stringify(targetParams), 'original arguments named like correlation IDs were discarded');
assert(targetsDisplayed.tool === 'apply_patch' && targetsDisplayed.policy_class === 'edit', 'original tool or policy class missing');
assert(JSON.stringify(targetsDisplayed.targets) === JSON.stringify(targetFacts.rampart_targets), 'derived targets missing');
assert(JSON.stringify(targetsDisplayed.requester) === JSON.stringify(targetFacts.rampart_requester) && targetsDisplayed.origin_channel === 'operations', 'requester or origin missing');

// Exercise the actual final escaped description boundary, including expansion
// of markup and bidi characters. The transport accepts 512, never 513.
const boundaryParams = { command: 'echo <`\u202e' };
const boundaryBase = await runScenario({ name: 'escaped-boundary-base', params: boundaryParams, toolResult: { decision: 'ask', allowed: false } });
const padding = 512 - boundaryBase.result.requireApproval.description.length;
assert(padding > 0, 'boundary fixture unexpectedly too large');
const boundary512 = await runScenario({ name: 'escaped-boundary-512', params: { command: boundaryParams.command + 'x'.repeat(padding) }, toolResult: { decision: 'ask', allowed: false } });
assert(boundary512.result?.requireApproval?.description.length === 512, 'exact native escaped-text boundary was not accepted');
assert(displayedAction(boundary512.result).params.command === boundaryParams.command + 'x'.repeat(padding), 'boundary action was shortened');
const boundary513 = await runScenario({ name: 'escaped-boundary-513', params: { command: boundaryParams.command + 'x'.repeat(padding + 1) }, toolResult: { decision: 'ask', allowed: false } });
assert(boundary513.result?.block && !boundary513.result.requireApproval, 'oversized final escaped text became approvable');

console.log(JSON.stringify({
  ok: true,
  scenarios: [
    { name: ask.name, result: ask.result },
    { name: deny.name, result: deny.result },
    { name: allowAlways.name, learnPersisted: false },
    ...nonPersistentResolutions.map((scenario) => ({ name: scenario.name, learnPersisted: false })),
  ],
}, null, 2));
