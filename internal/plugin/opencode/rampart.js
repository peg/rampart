// Rampart OpenCode policy gate
// Managed by rampart setup opencode; template v1.
import { spawn } from "node:child_process";
import path from "node:path";
import { types } from "node:util";

const binary = __RAMPART_BINARY_JSON__;
const maxInput = 4 * 1024 * 1024;
const maxOutput = 64 * 1024;
const unavailable = "Rampart could not evaluate this tool call; execution refused.";

// Accept only the plain JSON data the host dispatcher executes. Accessors and
// custom serialization must not let evaluation see a different representation.
function validateJSON(value, ancestors = new Set(), depth = 0) {
  if (depth > 64) throw new Error(unavailable);
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object" || types.isProxy(value) || ancestors.has(value)) throw new Error(unavailable);
  const prototype = Object.getPrototypeOf(value);
  if (Array.isArray(value) && prototype !== Array.prototype) throw new Error(unavailable);
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) throw new Error(unavailable);
  if ("toJSON" in value) throw new Error(unavailable);
  if (Object.getOwnPropertySymbols(value).length) throw new Error(unavailable);
  ancestors.add(value);
  const keys = Object.getOwnPropertyNames(value);
  if (Array.isArray(value) && keys.length !== value.length + 1) throw new Error(unavailable);
  for (const key of keys) {
    if (Array.isArray(value) && key === "length") continue;
    if (Array.isArray(value) && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) throw new Error(unavailable);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable) throw new Error(unavailable);
    validateJSON(descriptor.value, ancestors, depth + 1);
  }
  ancestors.delete(value);
}

function freezeJSON(value) {
  if (value === null || typeof value !== "object") return;
  for (const item of Object.values(value)) freezeJSON(item);
  Object.freeze(value);
}

function evaluate(payload, directory) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, ["hook", "--format", "opencode", "--mode", "enforce"], {
      cwd: directory, shell: false, stdio: ["pipe", "pipe", "pipe"],
    });
    const chunks = [];
    let bytes = 0;
    let failed = false;
    const fail = () => {
      if (failed) return;
      failed = true;
      child.kill();
      reject(new Error(unavailable));
    };
    const timer = setTimeout(fail, 10000);
    child.on("error", fail);
    child.stdin.on("error", fail);
    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > maxOutput) return fail();
      chunks.push(chunk);
    });
    // Do not forward child diagnostics into the host's logs or model feedback.
    child.stderr.on("data", () => {});
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (failed) return;
      if (code !== 0 || signal !== null) return fail();
      try {
        const reply = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (reply?.decision === "deny") {
          reject(new Error("Rampart refused this tool call; review your policy and audit. Approval-required actions are refused."));
          return;
        }
        if (!reply || reply.decision !== "allow") return fail();
        resolve();
      } catch { fail(); }
    });
    child.stdin.end(payload);
  });
}

export default async function RampartPlugin({ directory }) {
  let config;
  return {
    config: async (value) => { config = value; },
    "tool.execute.before": async (input, output) => {
      if (process.platform !== "linux" && process.platform !== "darwin") throw new Error(unavailable);
      if (input.tool === "bash") {
        // OpenCode names this tool bash even when a different shell is selected.
        const selected = config?.shell ?? process.env.SHELL ?? "/bin/sh";
        if (typeof selected !== "string" || !["sh", "bash", "zsh", "dash", "ksh"].includes(path.basename(selected))) {
          throw new Error("Rampart's OpenCode integration requires a supported POSIX shell.");
        }
      }
      const args = output.args;
      validateJSON(args);
      const snapshot = JSON.stringify(args);
      const payload = JSON.stringify({ tool: input.tool, sessionID: input.sessionID, callID: input.callID, directory, args });
      if (Buffer.byteLength(payload, "utf8") > maxInput) throw new Error(unavailable);
      await evaluate(payload, directory);
      if (output.args !== args) throw new Error(unavailable);
      validateJSON(args);
      if (JSON.stringify(args) !== snapshot) throw new Error(unavailable);
      // The V1 dispatcher executes this original object after later plugins.
      // Freeze the evaluated representation so it cannot change after permission.
      freezeJSON(args);
    },
  };
}
