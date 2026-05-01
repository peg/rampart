package openclaw

import (
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
			OnStartup *bool `json:"onStartup"`
		} `json:"activation"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.Activation.OnStartup == nil || !*manifest.Activation.OnStartup {
		t.Fatalf("manifest must declare activation.onStartup=true for before_tool_call startup protection")
	}
	if got, want := manifest.Version, Version(); got != want {
		t.Fatalf("manifest version = %q, want package version %q", got, want)
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
