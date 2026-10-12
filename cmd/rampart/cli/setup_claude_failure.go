package cli

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

// Claude Code treats a PreToolUse command hook that cannot start, times out,
// exits with an unexpected code, or prints invalid output as a non-blocking
// error unless the hook sets onFailure to "block". Every Rampart-internal
// error leaves the hook with exit code 1, so without onFailure a failure of
// Rampart itself lets the tool call proceed.
//
// Primary documentation: https://code.claude.com/docs/en/hooks (onFailure,
// added in Claude Code 2.1.295).

const (
	claudeHookFailureAuto     = "auto"
	claudeHookFailureBlock    = "block"
	claudeHookFailureContinue = "continue"
)

// claudeVersion is a Claude Code major.minor.patch release.
type claudeVersion [3]int

// claudeOnFailureMinVersion is the first Claude Code release that understands
// the hook onFailure field. An older release may reject a settings file that
// contains an unknown hook field, so it must never be written to one.
var claudeOnFailureMinVersion = claudeVersion{2, 1, 295}

func (v claudeVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

func (v claudeVersion) atLeast(minimum claudeVersion) bool {
	for i := range v {
		if v[i] != minimum[i] {
			return v[i] > minimum[i]
		}
	}
	return true
}

var claudeVersionPattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// parseClaudeVersion extracts the first major.minor.patch triple, for output
// such as "2.1.295 (Claude Code)".
func parseClaudeVersion(output string) (claudeVersion, bool) {
	match := claudeVersionPattern.FindStringSubmatch(output)
	if match == nil {
		return claudeVersion{}, false
	}
	var version claudeVersion
	for i := range version {
		part, err := strconv.Atoi(match[i+1])
		if err != nil || part < 0 {
			return claudeVersion{}, false
		}
		version[i] = part
	}
	return version, true
}

// detectClaudeVersion reports the installed Claude Code version. It is a
// variable so tests never execute a real host.
var detectClaudeVersion = detectClaudeVersionFromPath

func detectClaudeVersionFromPath() (claudeVersion, bool) {
	path, err := execLookPath("claude")
	if err != nil {
		return claudeVersion{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, path, "--version")
	cmd.Env = claudeVersionProbeEnv()
	output, err := cmd.Output()
	if err != nil {
		return claudeVersion{}, false
	}
	return parseClaudeVersion(string(output))
}

// claudeVersionProbeEnv passes only what a version query needs; provider
// credentials and tokens in the caller's environment are never forwarded.
func claudeVersionProbeEnv() []string {
	keep := []string{"PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "LANG"}
	if runtime.GOOS == "windows" {
		keep = append(keep, "SystemRoot", "ComSpec", "PATHEXT")
	}
	env := make([]string, 0, len(keep))
	for _, name := range keep {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// claudeFailurePlan is the resolved onFailure policy for Rampart's PreToolUse hook.
type claudeFailurePlan struct {
	// Block means the hook gets onFailure "block".
	Block bool
	// Notice is a human-readable explanation to print, if any.
	Notice string
}

// planClaudeHookFailure decides whether Rampart's PreToolUse hook fails closed.
//
//   - "continue" removes onFailure (Claude Code's default: failures proceed).
//   - "block" requires a detected Claude Code at or above the minimum version.
//   - "auto" enables it for a fresh install on a supported version, and leaves an
//     existing installation exactly as it is, telling the user how to opt in.
func planClaudeHookFailure(
	mode string,
	installed bool,
	currentlyBlocks bool,
	detect func() (claudeVersion, bool),
) (claudeFailurePlan, error) {
	switch mode {
	case claudeHookFailureContinue:
		return claudeFailurePlan{Block: false}, nil
	case claudeHookFailureBlock:
		version, known := detect()
		if !known {
			return claudeFailurePlan{}, fmt.Errorf(
				"cannot enable fail-closed hooks: the Claude Code version could not be detected (is `claude` on PATH?); fail-closed hooks need Claude Code %s or newer",
				claudeOnFailureMinVersion)
		}
		if !version.atLeast(claudeOnFailureMinVersion) {
			return claudeFailurePlan{}, fmt.Errorf(
				"cannot enable fail-closed hooks: Claude Code %s is older than %s, which introduced the onFailure hook field",
				version, claudeOnFailureMinVersion)
		}
		return claudeFailurePlan{Block: true}, nil
	case claudeHookFailureAuto:
	default:
		return claudeFailurePlan{}, fmt.Errorf("invalid --hook-failure %q (must be auto, block, or continue)", mode)
	}

	if installed && currentlyBlocks {
		return claudeFailurePlan{Block: true}, nil
	}
	version, known := detect()
	supported := known && version.atLeast(claudeOnFailureMinVersion)
	switch {
	case installed && supported:
		return claudeFailurePlan{Notice: fmt.Sprintf(
			"Claude Code %s can fail closed, but this installation still lets tool calls proceed if the Rampart hook fails.\n  Enable with: rampart setup claude-code --hook-failure=block",
			version)}, nil
	case installed:
		return claudeFailurePlan{}, nil
	case supported:
		return claudeFailurePlan{Block: true, Notice: fmt.Sprintf(
			"Hook failures block tool calls (Claude Code %s supports onFailure=block).\n  Undo with: rampart setup claude-code --hook-failure=continue",
			version)}, nil
	case known:
		return claudeFailurePlan{Notice: fmt.Sprintf(
			"Claude Code %s cannot fail closed on hook errors (needs %s or newer), so tool calls proceed if the Rampart hook fails.",
			version, claudeOnFailureMinVersion)}, nil
	default:
		return claudeFailurePlan{Notice: fmt.Sprintf(
			"Could not detect the Claude Code version, so tool calls proceed if the Rampart hook fails.\n  With Claude Code %s or newer, run: rampart setup claude-code --hook-failure=block",
			claudeOnFailureMinVersion)}, nil
	}
}

// claudeRampartPreToolUseHook returns the Rampart-owned PreToolUse command
// hook in settings, if one exists.
func claudeRampartPreToolUseHook(settings claudeSettings) (map[string]any, bool) {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return nil, false
	}
	entries, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return nil, false
	}
	for _, rawMatcher := range entries {
		matcher, ok := rawMatcher.(map[string]any)
		if !ok {
			continue
		}
		rawHooks, _ := matcher["hooks"].([]any)
		for _, rawHook := range rawHooks {
			hook, ok := rawHook.(map[string]any)
			if !ok {
				continue
			}
			command, _ := hook["command"].(string)
			if isRampartClaudeHookCommand(command) {
				return hook, true
			}
		}
	}
	return nil, false
}

// claudeRampartHooksInstalled reports whether any lifecycle event already
// carries a Rampart-owned command hook.
func claudeRampartHooksInstalled(settings claudeSettings) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		entries, _ := hooks[event].([]any)
		for _, rawMatcher := range entries {
			matcher, ok := rawMatcher.(map[string]any)
			if !ok {
				continue
			}
			rawHooks, _ := matcher["hooks"].([]any)
			for _, rawHook := range rawHooks {
				hook, ok := rawHook.(map[string]any)
				if !ok {
					continue
				}
				if command, _ := hook["command"].(string); isRampartClaudeHookCommand(command) {
					return true
				}
			}
		}
	}
	return false
}

// claudePreToolUseBlocksOnFailure reports whether Rampart's PreToolUse hook
// is configured with onFailure "block".
func claudePreToolUseBlocksOnFailure(settings claudeSettings) bool {
	hook, ok := claudeRampartPreToolUseHook(settings)
	if !ok {
		return false
	}
	value, _ := hook["onFailure"].(string)
	return value == claudeHookFailureBlock
}

// buildClaudePreToolUseHook returns Rampart's PreToolUse hook entry. Fields a
// user added to the existing Rampart entry (for example a timeout) are kept;
// only onFailure follows the plan.
func buildClaudePreToolUseHook(settings claudeSettings, command string, plan claudeFailurePlan) map[string]any {
	hook := map[string]any{}
	if existing, ok := claudeRampartPreToolUseHook(settings); ok {
		for key, value := range existing {
			hook[key] = value
		}
	}
	hook["type"] = "command"
	hook["command"] = command
	if plan.Block {
		hook["onFailure"] = claudeHookFailureBlock
	} else {
		delete(hook, "onFailure")
	}
	return hook
}

// claudeFailureModeSummaryForHome reads the user's Claude settings and describes
// the installed failure mode. It returns "" when the settings cannot be read, so
// status output never gains a misleading claim.
func claudeFailureModeSummaryForHome(home string) string {
	path := claudeSettingsPath(home)
	if exists, err := regularConfigFileExists(path); err != nil || !exists {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	settings := make(claudeSettings)
	if err := decodeUserJSON(data, &settings); err != nil {
		return ""
	}
	return claudeFailureModeSummary(settings)
}

// claudeFailureModeSummary describes the installed failure mode for status output.
func claudeFailureModeSummary(settings claudeSettings) string {
	if claudePreToolUseBlocksOnFailure(settings) {
		return "PreToolUse hook failures block the tool call (onFailure=block)."
	}
	return "PreToolUse hook failures do not block the tool call (Claude Code's default); `rampart setup claude-code --hook-failure=block` enables fail-closed on Claude Code " +
		claudeOnFailureMinVersion.String() + " or newer."
}
