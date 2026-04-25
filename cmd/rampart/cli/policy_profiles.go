package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func policyHasVersionStamp(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.HasPrefix(data, []byte("# rampart-policy-version: "))
}

func isModifiedBuiltInPolicy(path string) (bool, error) {
	base := filepath.Base(path)
	if !builtInProfiles[base] {
		return false, nil
	}
	profileName := strings.TrimSuffix(base, filepath.Ext(base))
	embedded, err := policies.Profile(profileName)
	if err != nil {
		return false, fmt.Errorf("load embedded profile %s: %w", profileName, err)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read installed profile %s: %w", path, err)
	}
	return !bytes.Equal(normalizeManagedPolicyContent(installed), embedded), nil
}
