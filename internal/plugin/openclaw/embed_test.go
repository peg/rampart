package openclaw

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"
)

func TestManifestDeclaresStartupActivation(t *testing.T) {
	data, err := PluginFS.ReadFile("openclaw.plugin.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest struct {
		Version    string `json:"version"`
		Activation struct {
			OnStartup      *bool    `json:"onStartup"`
			OnCapabilities []string `json:"onCapabilities"`
		} `json:"activation"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.Activation.OnStartup == nil || !*manifest.Activation.OnStartup {
		t.Fatalf("manifest must declare activation.onStartup=true for before_tool_call startup protection")
	}
	if !contains(manifest.Activation.OnCapabilities, "hook") {
		t.Fatalf("manifest must declare activation.onCapabilities includes hook for control-plane activation planning")
	}
	if got, want := manifest.Version, Version(); got != want {
		t.Fatalf("manifest version = %q, want package version %q", got, want)
	}
}

func TestPackageDeclaresInstallHostFloor(t *testing.T) {
	data, err := PluginFS.ReadFile("package.json")
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	var pkg struct {
		Version  string `json:"version"`
		OpenClaw struct {
			Install struct {
				MinHostVersion string `json:"minHostVersion"`
			} `json:"install"`
		} `json:"openclaw"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if got, want := pkg.OpenClaw.Install.MinHostVersion, ">=2026.3.28"; got != want {
		t.Fatalf("openclaw.install.minHostVersion = %q, want %q", got, want)
	}
	if got, want := pkg.Version, Version(); got != want {
		t.Fatalf("package.json version = %q, want Version() %q", got, want)
	}
}

func TestEmbeddedPluginRuntimeVersionMatchesPackage(t *testing.T) {
	data, err := PluginFS.ReadFile("index.js")
	if err != nil {
		t.Fatalf("read index.js: %v", err)
	}
	matches := regexp.MustCompile(`export const version = "([^"]+)"`).FindSubmatch(data)
	if len(matches) != 2 {
		t.Fatalf("index.js must export a plugin version")
	}
	if got, want := string(matches[1]), Version(); got != want {
		t.Fatalf("index.js version = %q, want package version %q", got, want)
	}
}

func TestGatewayStatusMethodUsesCurrentRespondContract(t *testing.T) {
	data, err := PluginFS.ReadFile("index.js")
	if err != nil {
		t.Fatalf("read index.js: %v", err)
	}
	if !bytes.Contains(data, []byte(`registerGatewayMethod("rampart.status", async ({ respond }) => {`)) {
		t.Fatalf("rampart.status gateway method must accept the Gateway respond callback")
	}
	if !bytes.Contains(data, []byte(`respond(true, resp.ok ? await resp.json() : { error: `)) {
		t.Fatalf("rampart.status gateway method must resolve through respond(true, payload)")
	}
	if !bytes.Contains(data, []byte(`respond(true, { error: "rampart serve unreachable" });`)) {
		t.Fatalf("rampart.status unreachable path must resolve through respond(true, payload)")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
