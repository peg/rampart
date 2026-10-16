package engine

import (
	"path/filepath"
	"testing"
)

// Search tools read every file beneath their root, so a search rooted in a
// protected credential directory must be denied like a direct read of the
// files it would return. Ordinary project searches must stay allowed.
func TestStandardPolicySearchRootsReachProtectedFiles(t *testing.T) {
	eng := shippedStandardEngine(t)
	home := t.TempDir()
	project := filepath.Join(home, "src", "project")

	search := func(params map[string]any, workDir string) Decision {
		return eng.Evaluate(ToolCall{Agent: "coding-agent", Tool: "read", WorkDir: workDir, Params: params})
	}

	denied := []struct {
		name    string
		params  map[string]any
		workDir string
	}{
		{"grep ssh dir", map[string]any{"pattern": ".", "path": filepath.Join(home, ".ssh"), "output_mode": "content"}, project},
		{"grep ssh dir trailing slash", map[string]any{"pattern": ".", "path": filepath.Join(home, ".ssh") + "/"}, project},
		{"grep ssh dir with key glob", map[string]any{"pattern": ".", "path": filepath.Join(home, ".ssh"), "glob": "id_*"}, project},
		{"glob ssh dir", map[string]any{"pattern": "*", "path": filepath.Join(home, ".ssh")}, project},
		{"grep aws dir", map[string]any{"pattern": "aws_secret", "path": filepath.Join(home, ".aws")}, project},
		{"grep gnupg subdir", map[string]any{"pattern": ".", "path": filepath.Join(home, ".gnupg", "private-keys-v1.d")}, project},
		{"grep config parent of gcloud", map[string]any{"pattern": "refresh_token", "path": filepath.Join(home, ".config")}, project},
		{"grep relative ssh dir", map[string]any{"pattern": ".", "path": ".ssh"}, home},
		{"grep without path in ssh dir", map[string]any{"pattern": "."}, filepath.Join(home, ".ssh")},
		{"grep home with key glob", map[string]any{"pattern": ".", "path": home, "glob": ".ssh/id_*"}, project},
		{"grep etc", map[string]any{"pattern": "root", "path": "/etc"}, project},
		{"regex search ssh dir", map[string]any{"regex": ".", "path": filepath.Join(home, ".ssh")}, project},
		{"query search ssh dir", map[string]any{"Query": ".", "path": filepath.Join(home, ".ssh")}, project},
	}
	for _, tc := range denied {
		t.Run("deny/"+tc.name, func(t *testing.T) {
			if got := search(tc.params, tc.workDir); got.Action != ActionDeny {
				t.Fatalf("search %v = %s (%s), want deny", tc.params, got.Action, got.Message)
			}
		})
	}

	allowed := []struct {
		name    string
		params  map[string]any
		workDir string
	}{
		{"grep project", map[string]any{"pattern": "TODO", "path": project, "output_mode": "content"}, project},
		{"grep without path in project", map[string]any{"pattern": "func main"}, project},
		{"grep project go files", map[string]any{"pattern": "Evaluate", "path": project, "glob": "*.go"}, project},
		{"grep for a protected file name", map[string]any{"pattern": "token.json|id_rsa|.netrc", "path": project}, project},
		{"grep relative subdir", map[string]any{"pattern": "x", "path": "internal/engine"}, project},
		{"grep node_modules", map[string]any{"pattern": "export", "path": filepath.Join(project, "node_modules")}, project},
		{"glob project", map[string]any{"pattern": "**/*.ts", "path": project}, project},
		{"grep tmp", map[string]any{"pattern": "x", "path": "/tmp"}, project},
		{"grep usr include", map[string]any{"pattern": "size_t", "path": "/usr/include"}, project},
	}
	for _, tc := range allowed {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := search(tc.params, tc.workDir); got.Action == ActionDeny {
				t.Fatalf("search %v = deny (%s), want not denied", tc.params, got.Message)
			}
		})
	}

	// File reads keep exact-path semantics.
	if got := search(map[string]any{"path": filepath.Join(home, ".ssh", "id_ed25519")}, project); got.Action != ActionDeny {
		t.Fatalf("read private key = %s, want deny", got.Action)
	}
	if got := search(map[string]any{"path": filepath.Join(home, ".ssh", "known_hosts")}, project); got.Action == ActionDeny {
		t.Fatalf("read known_hosts = deny (%s), want not denied", got.Message)
	}
}

func TestSearchRootPrefixes(t *testing.T) {
	cases := map[string][]string{
		"**/.ssh/id_*": {"**/.ssh"},
		"**/.config/gcloud/legacy_credentials/**": {"**/.config", "**/.config/gcloud", "**/.config/gcloud/legacy_credentials"},
		"/etc/shadow":           {"/etc"},
		"**\\.aws\\credentials": {"**/.aws"},
		"**/token.json":         nil,
		"**/*.pem":              nil,
	}
	for pattern, want := range cases {
		got := searchRootPrefixes(pattern)
		if len(got) != len(want) {
			t.Fatalf("searchRootPrefixes(%q) = %q, want %q", pattern, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("searchRootPrefixes(%q) = %q, want %q", pattern, got, want)
			}
		}
	}
}
