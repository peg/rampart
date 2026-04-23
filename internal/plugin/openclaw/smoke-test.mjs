import plugin from './index.js';

const toolResult = process.argv[2] ? JSON.parse(process.argv[2]) : {
  decision: 'ask',
  policy: 'test-policy',
  message: 'needs approval',
  severity: 'warning',
};
const toolName = process.argv[3] || 'exec';
const params = process.argv[4] ? JSON.parse(process.argv[4]) : { command: 'sudo true' };

const handlers = {};
const logs = [];
const api = {
  pluginConfig: {},
  logger: {
    info: (...a) => logs.push(['info', a.join(' ')]),
    warn: (...a) => logs.push(['warn', a.join(' ')]),
    debug: (...a) => logs.push(['debug', a.join(' ')]),
  },
  on: (name, fn) => { handlers[name] = fn; },
  registerGatewayMethod: () => {},
};

const originalFetch = global.fetch;
global.fetch = async (url, opts = {}) => {
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
  if (typeof before !== 'function') throw new Error('before_tool_call handler not registered');
  const result = await before({ toolName, params }, {
    agentId: 'main',
    sessionKey: 'agent:main:discord:direct:449621595489828865',
    runId: 'smoke-test-run',
  });
  console.log(JSON.stringify({ result, logs }, null, 2));
} finally {
  global.fetch = originalFetch;
}
