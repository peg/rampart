package hardening

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const execApprovalsPre = `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 18e5;
const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "full";
const fallbackAskFallback = params.overrides?.askFallback ?? "full";
`

const execApprovalsPost = `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 12e4;
const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "deny";
const fallbackAskFallback = params.overrides?.askFallback ?? DEFAULT_EXEC_APPROVAL_ASK_FALLBACK;
`

const bashToolsPre = `return [
		"An async command the user already approved has completed.",
].join("\n");
if (!params.decision) {
		if (params.askFallback === "full") return {
			approvedByAsk: true,
			deniedReason: null,
			timedOut: true
		};
		if (params.askFallback === "deny") return {
			approvedByAsk: false,
			deniedReason: "approval-timeout",
			timedOut: true
		};
}
`

const bashToolsPost = `return [
		"An async approved command has completed.",
].join("\n");
if (!params.decision) {
		if (params.askFallback === "deny" || params.askFallback === "full") return {
			approvedByAsk: false,
			deniedReason: "approval-timeout",
			timedOut: true
		};
}
`

func TestInspectPrePatch(t *testing.T) {
	home, dist := setupFixture(t, execApprovalsPre, bashToolsPre, "{}\n")
	state, err := Inspect(home, []string{dist})
	if err != nil {
		t.Fatal(err)
	}
	if !state.Supported {
		t.Fatal("expected supported build shape")
	}
	if state.FallbackSafe || state.CompletionAttributionSafe || state.ApprovalTimeoutAligned {
		t.Fatalf("expected unsafe pre-patch state: %+v", state)
	}
	if !state.PluginApprovalTimeoutAligned {
		t.Fatalf("expected plugin timeout to be aligned by default: %+v", state)
	}
}

func TestApplyPatchesAndAlignsConfig(t *testing.T) {
	home, dist := setupFixture(t, execApprovalsPre, bashToolsPre, "{\"plugins\":{\"entries\":{\"rampart\":{\"config\":{\"approvalTimeoutMs\":300000}}}}}\n")
	result, err := Apply(home, []string{dist})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PatchedFiles) != 2 {
		t.Fatalf("expected 2 patched files, got %+v", result)
	}
	if !result.ConfigUpdated || !result.RestartSuggested {
		t.Fatalf("expected config update + restart suggestion, got %+v", result)
	}
	state, err := Inspect(home, []string{dist})
	if err != nil {
		t.Fatal(err)
	}
	if !state.FallbackSafe || !state.CompletionAttributionSafe || !state.ApprovalTimeoutAligned || !state.PluginApprovalTimeoutAligned {
		t.Fatalf("expected hardened/aligned state, got %+v", state)
	}
	execData := mustRead(t, state.ExecApprovalsPath)
	if !strings.Contains(execData, `DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "deny"`) {
		t.Fatalf("expected fallback patch, got %s", execData)
	}
	bashData := mustRead(t, state.BashToolsPath)
	if !strings.Contains(bashData, `An async approved command has completed.`) {
		t.Fatalf("expected wording patch, got %s", bashData)
	}
}

func TestApplyRejectsUnsupportedShape(t *testing.T) {
	home, dist := setupFixture(t, "const nope = true;", bashToolsPre, "{}\n")
	if _, err := Apply(home, []string{dist}); err == nil {
		t.Fatal("expected unsupported shape error")
	}
}

func TestApplyIsIdempotentWhenAlreadyHardened(t *testing.T) {
	home, dist := setupFixture(t, execApprovalsPost, bashToolsPost, "{\"plugins\":{\"entries\":{\"rampart\":{\"config\":{\"approvalTimeoutMs\":120000}}}}}\n")
	result, err := Apply(home, []string{dist})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PatchedFiles) != 0 || result.ConfigUpdated || result.RestartSuggested {
		t.Fatalf("expected no-op apply result, got %+v", result)
	}
}

func setupFixture(t *testing.T, execText, bashText, config string) (string, string) {
	t.Helper()
	home := t.TempDir()
	dist := filepath.Join(home, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dist, "exec-approvals-test.js"), execText)
	writeFile(t, filepath.Join(dist, "bash-tools-test.js"), bashText)
	writeFile(t, filepath.Join(home, ".openclaw", "openclaw.json"), config)
	return home, dist
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
