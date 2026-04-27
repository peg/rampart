package cli

import (
	"bytes"
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
}

type managedPolicyState struct {
	HasVersionStamp bool
	MatchesCurrent  bool
	StaleMessage    string
}

func normalizeManagedPolicyContent(data []byte) []byte {
	const prefix = "# rampart-policy-version: "
	if bytes.HasPrefix(data, []byte(prefix)) {
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			data = data[idx+1:]
		} else {
			return nil
		}
	}
	return data
}

func versionStampedPolicyContent(content []byte) []byte {
	stamped := []byte(fmt.Sprintf("# rampart-policy-version: %s\n", build.Version))
	return append(stamped, content...)
}

func policyHasVersionStamp(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.HasPrefix(data, []byte("# rampart-policy-version: "))
}

func builtInPolicyState(path string) (managedPolicyState, error) {
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
	state := managedPolicyState{
		HasVersionStamp: bytes.HasPrefix(installed, []byte("# rampart-policy-version: ")),
		MatchesCurrent:  bytes.Equal(normalizeManagedPolicyContent(installed), embedded),
		StaleMessage:    checkPolicyVersionStamp(path),
	}
	return state, nil
}
