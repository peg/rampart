package engine

import (
	"testing"
)

func TestEnvVarInjectionPolicy(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-env-var-injection
    description: "Block dangerous environment variable injection"
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_contains:
            - "LD_PRELOAD="
            - "DYLD_INSERT_LIBRARIES="
            - "NODE_OPTIONS="
            - "JAVA_TOOL_OPTIONS="
            - "PYTHONSTARTUP="
        message: "Dangerous environment variable injection blocked"
`)

	malicious := []struct {
		cmd  string
		desc string
	}{
		{"LD_PRELOAD=/tmp/evil.so curl https://example.com", "LD_PRELOAD prefix"},
		{"NODE_OPTIONS=--require /tmp/evil.js node app.js", "NODE_OPTIONS prefix"},
		{"PYTHONSTARTUP=/tmp/evil.py python3 script.py", "PYTHONSTARTUP prefix"},
		{"JAVA_TOOL_OPTIONS=-javaagent:/tmp/evil.jar java App", "JAVA_TOOL_OPTIONS prefix"},
		{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib ./program", "DYLD_INSERT_LIBRARIES prefix"},
		{"env LD_PRELOAD=/evil.so bash", "env LD_PRELOAD inline"},
		{"export LD_PRELOAD=/evil.so", "export LD_PRELOAD"},
	}

	for _, tc := range malicious {
		d := e.Evaluate(execCall("main", tc.cmd))
		if d.Action != ActionDeny {
			t.Errorf("FAIL [%s]: expected deny for %q, got %v (msg: %s)", tc.desc, tc.cmd, d.Action, d.Message)
		} else {
			t.Logf("PASS [%s]: deny for %q", tc.desc, tc.cmd)
		}
	}

	safe := []struct {
		cmd  string
		desc string
	}{
		{"git status", "git status"},
		{"curl https://api.github.com/repos/peg/rampart", "curl safe URL"},
		{"node app.js", "node without options"},
		{"python3 script.py", "python3 without startup"},
	}

	for _, tc := range safe {
		d := e.Evaluate(execCall("main", tc.cmd))
		if d.Action == ActionDeny {
			t.Errorf("FAIL [%s]: expected allow for %q, got deny (msg: %s)", tc.desc, tc.cmd, d.Message)
		} else {
			t.Logf("PASS [%s]: allow for %q (action: %v)", tc.desc, tc.cmd, d.Action)
		}
	}
}
