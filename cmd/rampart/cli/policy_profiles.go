package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/policies"
)

var builtInProfiles = map[string]bool{
	"standard.yaml":               true,
	"paranoid.yaml":               true,
	"yolo.yaml":                   true,
	"demo.yaml":                   true,
	"block-prompt-injection.yaml": true,
	"research-agent.yaml":         true,
	"mcp-server.yaml":             true,
	"openclaw.yaml":               true,
	"guard.yaml":                  true,
}

type managedPolicyState struct {
	HasVersionStamp    bool
	HasContentHash     bool
	ContentHashMatches bool
	MatchesCurrent     bool
	VersionStamp       string
	VersionOlder       bool
	VersionCurrent     bool
	VersionNewer       bool
	StaleMessage       string
	Installed          []byte
}

const (
	managedPolicyVersionPrefix = "# rampart-policy-version: "
	managedPolicyHashPrefix    = "# rampart-policy-sha256: "
)

func parseManagedPolicyHeaders(data []byte) (version, contentHash string, content []byte) {
	content = data
	for len(content) > 0 {
		idx := bytes.IndexByte(content, '\n')
		if idx < 0 {
			break
		}
		line := string(content[:idx])
		switch {
		case strings.HasPrefix(line, managedPolicyVersionPrefix):
			version = strings.TrimSpace(strings.TrimPrefix(line, managedPolicyVersionPrefix))
		case strings.HasPrefix(line, managedPolicyHashPrefix):
			contentHash = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, managedPolicyHashPrefix)))
		default:
			return version, contentHash, content
		}
		content = content[idx+1:]
	}
	return version, contentHash, content
}

func versionStampedPolicyContent(content []byte) []byte {
	return versionStampedPolicyContentForVersion(content, build.Version)
}

func versionStampedPolicyContentForVersion(content []byte, version string) []byte {
	hash := sha256.Sum256(content)
	stamped := []byte(fmt.Sprintf(
		"%s%s\n%s%x\n",
		managedPolicyVersionPrefix,
		version,
		managedPolicyHashPrefix,
		hash,
	))
	return append(stamped, content...)
}

func builtInPolicyState(path string) (managedPolicyState, error) {
	return builtInPolicyStateForVersion(path, build.Version)
}

func builtInPolicyStateForVersion(path, currentVersion string) (managedPolicyState, error) {
	base := filepath.Base(path)
	if !builtInProfiles[base] {
		return managedPolicyState{}, nil
	}
	profileName := strings.TrimSuffix(base, filepath.Ext(base))
	embedded, err := policies.Profile(profileName)
	if err != nil {
		return managedPolicyState{}, fmt.Errorf("load embedded profile %s: %w", profileName, err)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		return managedPolicyState{}, fmt.Errorf("read installed profile %s: %w", path, err)
	}
	version, contentHash, content := parseManagedPolicyHeaders(installed)
	actualHash := sha256.Sum256(content)
	state := managedPolicyState{
		HasVersionStamp:    version != "",
		HasContentHash:     contentHash != "",
		ContentHashMatches: contentHash != "" && contentHash == fmt.Sprintf("%x", actualHash),
		MatchesCurrent:     bytes.Equal(content, embedded),
		VersionStamp:       version,
		Installed:          installed,
	}
	if version != "" && currentVersion != "" {
		if version == currentVersion {
			state.VersionCurrent = true
		} else if relation, ok := compareStrictSemver(version, currentVersion); ok {
			state.VersionOlder = relation < 0
			state.VersionCurrent = relation == 0
			state.VersionNewer = relation > 0
		}
		if state.VersionOlder && (!state.HasContentHash || state.ContentHashMatches) {
			state.StaleMessage = fmt.Sprintf("from %s, binary is %s", version, currentVersion)
		}
	}
	return state, nil
}
