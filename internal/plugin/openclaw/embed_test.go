package openclaw

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
		License  string `json:"license"`
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
	if got, want := pkg.License, "Apache-2.0"; got != want {
		t.Fatalf("package.json license = %q, want %q", got, want)
	}
}

func TestManifestDeclaresDegradedModeConfig(t *testing.T) {
	data, err := PluginFS.ReadFile("openclaw.plugin.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest struct {
		ConfigSchema struct {
			AdditionalProperties bool `json:"additionalProperties"`
			Properties           map[string]struct {
				Type    string          `json:"type"`
				Default json.RawMessage `json:"default"`
			} `json:"properties"`
		} `json:"configSchema"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	failOpenTools, ok := manifest.ConfigSchema.Properties["failOpenTools"]
	if !ok {
		t.Fatalf("manifest configSchema must declare failOpenTools because plugin runtime reads it")
	}
	if got, want := failOpenTools.Type, "array"; got != want {
		t.Fatalf("failOpenTools type = %q, want %q", got, want)
	}
	var defaults []string
	if err := json.Unmarshal(failOpenTools.Default, &defaults); err != nil {
		t.Fatalf("failOpenTools default must be a string array: %v", err)
	}
	if len(defaults) != 0 {
		t.Fatalf("failOpenTools must default to fail closed, got %v", defaults)
	}
	failOpen, ok := manifest.ConfigSchema.Properties["failOpen"]
	if !ok {
		t.Fatal("manifest configSchema must retain the deprecated failOpen compatibility switch")
	}
	var failOpenDefault bool
	if err := json.Unmarshal(failOpen.Default, &failOpenDefault); err != nil {
		t.Fatalf("failOpen default must be boolean: %v", err)
	}
	if failOpenDefault {
		t.Fatal("failOpen must default to false")
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

func TestCurrentChecksEveryManagedPluginFile(t *testing.T) {
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	if !Current(dir) {
		t.Fatal("freshly extracted plugin should be current")
	}
	manifestPath := filepath.Join(dir, "hooks", "rampart", "HOOK.md")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(data, []byte("\nmodified")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if Current(dir) {
		t.Fatal("nested hook drift was not detected")
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
	if !bytes.Contains(data, []byte(`const status = await readControlResponseJSON(resp);`)) {
		t.Fatalf("rampart.status gateway method must use the bounded control-response decoder")
	}
	if !bytes.Contains(data, []byte(`status && typeof status === "object" && !Array.isArray(status)`)) ||
		!bytes.Contains(data, []byte(`{ error: "rampart serve returned an invalid status response" }`)) {
		t.Fatalf("rampart.status gateway method must validate the decoded payload before responding")
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
