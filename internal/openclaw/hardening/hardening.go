package hardening

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DesiredApprovalTimeoutMs = 120000
	backupSuffix             = ".rampart-approval-hardening-backup"
)

type State struct {
	ConfigPath                   string
	DistDir                      string
	ExecApprovalsPath            string
	BashToolsPath                string
	Supported                    bool
	FallbackSafe                 bool
	CompletionAttributionSafe    bool
	ApprovalTimeoutAligned       bool
	PluginApprovalTimeoutAligned bool
}

type ApplyResult struct {
	ConfigUpdated    bool
	PatchedFiles     []string
	RestartSuggested bool
}

type replacement struct {
	old string
	new string
}

type patchTarget struct {
	path         string
	replacements []replacement
}

type openClawConfig struct {
	Plugins struct {
		Entries map[string]struct {
			Config map[string]any `json:"config"`
		} `json:"entries"`
	} `json:"plugins"`
}

func Inspect(home string, distCandidates []string) (State, error) {
	state := State{ConfigPath: filepath.Join(home, ".openclaw", "openclaw.json")}
	if path, ok := findDistFileByShape(distCandidates, "exec-approvals-*.js", supportsExecApprovalsShape); ok {
		state.ExecApprovalsPath = path
		state.DistDir = filepath.Dir(path)
	}
	if path, ok := findDistFileByShape(distCandidates, "bash-tools-*.js", supportsBashToolsShape); ok {
		state.BashToolsPath = path
		if state.DistDir == "" {
			state.DistDir = filepath.Dir(path)
		}
	}
	if state.ExecApprovalsPath == "" || state.BashToolsPath == "" {
		return state, nil
	}

	execText, err := os.ReadFile(state.ExecApprovalsPath)
	if err != nil {
		return state, fmt.Errorf("read exec approvals bundle: %w", err)
	}
	bashText, err := os.ReadFile(state.BashToolsPath)
	if err != nil {
		return state, fmt.Errorf("read bash tools bundle: %w", err)
	}
	state.FallbackSafe = strings.Contains(string(execText), `const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "deny";`) &&
		strings.Contains(string(execText), `const fallbackAskFallback = params.overrides?.askFallback ?? DEFAULT_EXEC_APPROVAL_ASK_FALLBACK;`)
	state.ApprovalTimeoutAligned = strings.Contains(string(execText), `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 12e4;`) ||
		strings.Contains(string(execText), `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 120000;`)
	state.CompletionAttributionSafe = strings.Contains(string(bashText), `"An async approved command has completed."`) &&
		strings.Contains(string(bashText), `if (params.askFallback === "deny" || params.askFallback === "full") return {`)
	state.Supported = supportsExecApprovalsShape(string(execText)) && supportsBashToolsShape(string(bashText))

	aligned, _, err := pluginApprovalTimeoutAligned(state.ConfigPath)
	if err == nil {
		state.PluginApprovalTimeoutAligned = aligned
	}
	return state, nil
}

func Apply(home string, distCandidates []string) (ApplyResult, error) {
	state, err := Inspect(home, distCandidates)
	if err != nil {
		return ApplyResult{}, err
	}
	if state.ExecApprovalsPath == "" || state.BashToolsPath == "" {
		return ApplyResult{}, fmt.Errorf("openclaw approval bundles not found")
	}
	if !state.Supported {
		return ApplyResult{}, fmt.Errorf("unsupported OpenClaw approval bundle shape")
	}

	targets := []patchTarget{
		{
			path: state.ExecApprovalsPath,
			replacements: []replacement{
				{old: `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 18e5;`, new: `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 12e4;`},
				{old: `const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "full";`, new: `const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "deny";`},
				{old: `const fallbackAskFallback = params.overrides?.askFallback ?? "full";`, new: `const fallbackAskFallback = params.overrides?.askFallback ?? DEFAULT_EXEC_APPROVAL_ASK_FALLBACK;`},
			},
		},
		{
			path: state.BashToolsPath,
			replacements: []replacement{
				{old: `"An async command the user already approved has completed."`, new: `"An async approved command has completed."`},
				{old: "if (params.askFallback === \"full\") return {\n\t\t\tapprovedByAsk: true,\n\t\t\tdeniedReason: null,\n\t\t\ttimedOut: true\n\t\t};\n\t\tif (params.askFallback === \"deny\") return {\n\t\t\tapprovedByAsk: false,\n\t\t\tdeniedReason: \"approval-timeout\",\n\t\t\ttimedOut: true\n\t\t};", new: "if (params.askFallback === \"deny\" || params.askFallback === \"full\") return {\n\t\t\tapprovedByAsk: false,\n\t\t\tdeniedReason: \"approval-timeout\",\n\t\t\ttimedOut: true\n\t\t};"},
			},
		},
	}

	result := ApplyResult{}
	for _, target := range targets {
		patched, err := applyReplacements(target)
		if err != nil {
			return ApplyResult{}, err
		}
		if patched {
			result.PatchedFiles = append(result.PatchedFiles, target.path)
		}
	}

	updated, err := ensurePluginApprovalTimeout(state.ConfigPath, DesiredApprovalTimeoutMs)
	if err != nil {
		return ApplyResult{}, err
	}
	result.ConfigUpdated = updated
	result.RestartSuggested = updated || len(result.PatchedFiles) > 0
	return result, nil
}

func findDistFile(candidates []string, pattern string) (string, bool) {
	for _, dir := range candidates {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		sort.Strings(matches)
		if len(matches) > 0 {
			return matches[0], true
		}
	}
	return "", false
}

func findDistFileByShape(candidates []string, pattern string, supports func(string) bool) (string, bool) {
	fallback, fallbackOK := findDistFile(candidates, pattern)
	for _, dir := range candidates {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		sort.Strings(matches)
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if supports(string(data)) {
				return path, true
			}
		}
	}
	return fallback, fallbackOK
}

func supportsExecApprovalsShape(text string) bool {
	return (strings.Contains(text, `const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "full";`) || strings.Contains(text, `const DEFAULT_EXEC_APPROVAL_ASK_FALLBACK = "deny";`)) &&
		(strings.Contains(text, `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 18e5;`) || strings.Contains(text, `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 12e4;`) || strings.Contains(text, `const DEFAULT_EXEC_APPROVAL_TIMEOUT_MS = 120000;`))
}

func supportsBashToolsShape(text string) bool {
	return (strings.Contains(text, `"An async command the user already approved has completed."`) || strings.Contains(text, `"An async approved command has completed."`)) &&
		(strings.Contains(text, `if (params.askFallback === "full") return {`) || strings.Contains(text, `if (params.askFallback === "deny" || params.askFallback === "full") return {`))
}

func applyReplacements(target patchTarget) (bool, error) {
	content, err := os.ReadFile(target.path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", filepath.Base(target.path), err)
	}
	text := string(content)
	modified := text
	changed := false
	for _, rep := range target.replacements {
		if strings.Contains(modified, rep.new) {
			continue
		}
		if !strings.Contains(modified, rep.old) {
			return false, fmt.Errorf("patch %s: expected marker not found", filepath.Base(target.path))
		}
		modified = strings.Replace(modified, rep.old, rep.new, 1)
		changed = true
	}
	if !changed {
		return false, nil
	}
	backupPath := target.path + backupSuffix
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := os.WriteFile(backupPath, content, 0o644); err != nil {
			return false, fmt.Errorf("backup %s: %w", filepath.Base(target.path), err)
		}
	}
	if err := os.WriteFile(target.path, []byte(modified), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", filepath.Base(target.path), err)
	}
	return true, nil
}

func pluginApprovalTimeoutAligned(configPath string) (bool, int, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, DesiredApprovalTimeoutMs, nil
		}
		return false, 0, err
	}
	var cfg openClawConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, 0, err
	}
	entry, ok := cfg.Plugins.Entries["rampart"]
	if !ok || entry.Config == nil {
		return true, DesiredApprovalTimeoutMs, nil
	}
	raw, ok := entry.Config["approvalTimeoutMs"]
	if !ok {
		return true, DesiredApprovalTimeoutMs, nil
	}
	value, ok := asInt(raw)
	if !ok {
		return false, 0, fmt.Errorf("plugins.entries.rampart.config.approvalTimeoutMs is not numeric")
	}
	return value == DesiredApprovalTimeoutMs, value, nil
}

func ensurePluginApprovalTimeout(configPath string, timeoutMs int) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, err
	}
	plugins, _ := raw["plugins"].(map[string]any)
	if plugins == nil {
		plugins = map[string]any{}
		raw["plugins"] = plugins
	}
	entries, _ := plugins["entries"].(map[string]any)
	if entries == nil {
		entries = map[string]any{}
		plugins["entries"] = entries
	}
	entry, _ := entries["rampart"].(map[string]any)
	if entry == nil {
		entry = map[string]any{}
		entries["rampart"] = entry
	}
	config, _ := entry["config"].(map[string]any)
	if config == nil {
		config = map[string]any{}
		entry["config"] = config
	}
	if current, ok := asInt(config["approvalTimeoutMs"]); ok && current == timeoutMs {
		return false, nil
	}
	config["approvalTimeoutMs"] = timeoutMs
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return false, err
	}
	out = append(out, '\n')
	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func asInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}
