// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package opencode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This child implements only the decision protocol. It does not run Rampart,
// OpenCode, a model, or an action represented by the supplied arguments.
func TestMain(m *testing.M) {
	if mode := os.Getenv("RAMPART_OPENCODE_TEST_CHILD"); mode != "" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 5<<20))
		if err != nil {
			os.Exit(8)
		}
		cwd, err := os.Getwd()
		if err != nil {
			os.Exit(8)
		}
		capture, err := json.Marshal(struct {
			Arguments []string        `json:"arguments"`
			Directory string          `json:"directory"`
			Payload   json.RawMessage `json:"payload"`
		}{os.Args[1:], cwd, data})
		if err != nil || os.WriteFile(os.Getenv("RAMPART_OPENCODE_TEST_CAPTURE"), capture, 0o600) != nil {
			os.Exit(8)
		}
		fmt.Fprintln(os.Stderr, "private-child-diagnostic-canary")
		switch mode {
		case "allow", "nonzero":
			fmt.Println(`{"decision":"allow","reason":"private-child-reason-canary"}`)
		case "deny":
			fmt.Println(`{"decision":"deny","reason":"private-child-reason-canary"}`)
		case "malformed":
			fmt.Print(`{"decision":`)
		case "unknown":
			fmt.Println(`{"decision":"ask"}`)
		case "overflow":
			fmt.Print(strings.Repeat("x", 65537))
		case "empty":
		default:
			os.Exit(9)
		}
		if mode == "nonzero" {
			os.Exit(7)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const runtimeRunner = `import { pathToFileURL } from "node:url";
const { default: createPlugin } = await import(pathToFileURL(process.argv[2]).href);
const variant = process.argv[3];
const directory = process.argv[4];
const plugin = await createPlugin({ directory });
await plugin.config({ shell: variant === "nonposix" ? "/bin/pwsh" : "/bin/sh" });
const input = { tool: variant === "nonposix" ? "bash" : "write", sessionID: "ses_fixture", callID: "call_fixture" };
const args = { filePath: "harmless-marker.txt", content: "harmless marker", nested: { list: [{ value: "original" }] } };
let getterCalls = 0;
let serializerCalls = 0;
if (variant === "getter") Object.defineProperty(args, "extra", { enumerable: true, get() { getterCalls++; return "marker"; } });
if (variant === "tojson") args.toJSON = () => { serializerCalls++; return { filePath: "harmless-marker.txt" }; };
if (variant === "inherited-tojson") Object.defineProperty(Object.prototype, "toJSON", {
  configurable: true, value() { serializerCalls++; return { marker: "harmless serializer" }; },
});
if (variant === "extra-array-key") args.nested.list.extra = "marker";
if (variant === "sparse-array") args.nested.list.length = 2;
if (variant === "array-prototype") {
  const prototype = Object.create(Array.prototype);
  prototype.toJSON = function () { serializerCalls++; return ["marker"]; };
  Object.setPrototypeOf(args.nested.list, prototype);
}
if (variant === "proxy") args.nested = new Proxy(args.nested, {});
const output = { args };
let accepted = false;
let message = "";
try {
  const pending = plugin["tool.execute.before"](input, output);
  if (variant === "mutation") args.nested.list[0].value = "changed during evaluation";
  if (variant === "replacement") output.args = { filePath: args.filePath, content: args.content, nested: { list: [{ value: "original" }] } };
  await pending;
  accepted = true;
} catch (error) { message = error.message; }
if (variant === "inherited-tojson") delete Object.prototype.toJSON;
let mutationRefused = false;
if (accepted) {
  try { args.nested.list[0].value = "changed after permission"; } catch { mutationRefused = true; }
}
process.stdout.write(JSON.stringify({ accepted, message, getterCalls, serializerCalls, mutationRefused,
  frozen: Object.isFrozen(args) && Object.isFrozen(args.nested) && Object.isFrozen(args.nested.list) && Object.isFrozen(args.nested.list[0]),
  sameObject: output.args === args,
  value: args.nested.list[0].value,
}));
`

func TestRuntimePolicyBridgeRefusesUnsafeDecisionsAndRepresentations(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("experimental OpenCode runtime supports Linux and macOS")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required to test the embedded JavaScript bridge")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, child, variant string
		allow, childCalled   bool
		message              string
	}{
		{name: "allow freezes exact original arguments", child: "allow", allow: true, childCalled: true},
		{name: "in-flight argument change refuses", child: "allow", variant: "mutation", childCalled: true, message: "could not evaluate"},
		{name: "replacement argument object refuses", child: "allow", variant: "replacement", childCalled: true, message: "could not evaluate"},
		{name: "deny has generic feedback", child: "deny", childCalled: true, message: "Rampart refused this tool call"},
		{name: "malformed decision", child: "malformed", childCalled: true, message: "could not evaluate"},
		{name: "nonzero child cannot grant", child: "nonzero", childCalled: true, message: "could not evaluate"},
		{name: "empty decision", child: "empty", childCalled: true, message: "could not evaluate"},
		{name: "unknown decision", child: "unknown", childCalled: true, message: "could not evaluate"},
		{name: "bounded child output", child: "overflow", childCalled: true, message: "could not evaluate"},
		{name: "missing child", child: "missing", message: "could not evaluate"},
		{name: "non-POSIX shell", child: "allow", variant: "nonposix", message: "supported POSIX shell"},
		{name: "getter rejected without reading it", child: "allow", variant: "getter", message: "could not evaluate"},
		{name: "toJSON rejected without calling it", child: "allow", variant: "tojson", message: "could not evaluate"},
		{name: "inherited serializer rejected without calling it", child: "allow", variant: "inherited-tojson", message: "could not evaluate"},
		{name: "array extra property refused", child: "allow", variant: "extra-array-key", message: "could not evaluate"},
		{name: "sparse array refused", child: "allow", variant: "sparse-array", message: "could not evaluate"},
		{name: "custom array prototype refused", child: "allow", variant: "array-prototype", message: "could not evaluate"},
		{name: "proxy refused", child: "allow", variant: "proxy", message: "could not evaluate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// Spaces, quotes, and shell metacharacters must remain literal parts
			// of the executable name. The bridge uses direct argv execution.
			binary := filepath.Join(dir, "decision ' \" $() ; ` marker")
			if tc.child != "missing" {
				if err := os.Symlink(self, binary); err != nil {
					t.Fatal(err)
				}
			}
			module, err := Render(binary)
			if err != nil {
				t.Fatal(err)
			}
			modulePath := filepath.Join(dir, "plugin.mjs")
			runnerPath := filepath.Join(dir, "runner.mjs")
			capturePath := filepath.Join(dir, "decision.json")
			if err := os.WriteFile(modulePath, module, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(runnerPath, []byte(runtimeRunner), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, node, runnerPath, modulePath, tc.variant, dir)
			command.Env = append(os.Environ(), "RAMPART_OPENCODE_TEST_CHILD="+tc.child, "RAMPART_OPENCODE_TEST_CAPTURE="+capturePath)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("Node bridge runner: %v; stderr: %s", err, stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "private-child-") {
				t.Fatal("child diagnostic or reason crossed the plugin output boundary")
			}
			var result struct {
				Accepted        bool   `json:"accepted"`
				Message         string `json:"message"`
				GetterCalls     int    `json:"getterCalls"`
				SerializerCalls int    `json:"serializerCalls"`
				MutationRefused bool   `json:"mutationRefused"`
				Frozen          bool   `json:"frozen"`
				SameObject      bool   `json:"sameObject"`
				Value           string `json:"value"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("decode runner result: %v; output: %s", err, stdout.String())
			}
			if result.Accepted != tc.allow || !strings.Contains(result.Message, tc.message) || result.GetterCalls != 0 || result.SerializerCalls != 0 {
				t.Fatalf("bridge result = %+v, want allow %t and message containing %q", result, tc.allow, tc.message)
			}
			if tc.allow && (!result.Frozen || !result.MutationRefused || !result.SameObject || result.Value != "original") {
				t.Fatalf("allowed representation was changed or remained mutable: %+v", result)
			}
			capture, err := os.ReadFile(capturePath)
			if !tc.childCalled {
				if !os.IsNotExist(err) {
					t.Fatalf("unsafe representation or missing binary invoked the decision child: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var recorded struct {
				Arguments []string `json:"arguments"`
				Directory string   `json:"directory"`
				Payload   struct {
					Tool, SessionID, CallID, Directory string
					Args                               struct {
						FilePath, Content string
						Nested            struct{ List []struct{ Value string } }
					}
				} `json:"payload"`
			}
			if err := json.Unmarshal(capture, &recorded); err != nil {
				t.Fatal(err)
			}
			wantArgs := []string{"hook", "--format", "opencode", "--mode", "enforce"}
			if strings.Join(recorded.Arguments, "\x00") != strings.Join(wantArgs, "\x00") {
				t.Fatalf("decision subprocess arguments = %q", recorded.Arguments)
			}
			// macOS's temporary directory can be reached through /var and
			// /private/var. Compare directory identity as well as payload bytes.
			wantDir, wantErr := os.Stat(dir)
			gotDir, gotErr := os.Stat(recorded.Directory)
			if wantErr != nil || gotErr != nil || !os.SameFile(wantDir, gotDir) || recorded.Payload.Directory != dir || recorded.Payload.Tool != "write" || recorded.Payload.SessionID != "ses_fixture" || recorded.Payload.CallID != "call_fixture" {
				t.Fatalf("dispatch identity/CWD changed: %+v", recorded)
			}
			if recorded.Payload.Args.FilePath != "harmless-marker.txt" || recorded.Payload.Args.Content != "harmless marker" || len(recorded.Payload.Args.Nested.List) != 1 || recorded.Payload.Args.Nested.List[0].Value != "original" {
				t.Fatalf("decision child received another action representation: %+v", recorded.Payload.Args)
			}
		})
	}
}
