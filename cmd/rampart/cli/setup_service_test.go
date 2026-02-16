package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestInstallSystemd(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	var out strings.Builder
	cmd.SetOut(&out)

	err := installSystemd(cmd, dir, "/usr/bin/rampart", "/etc/rampart.yaml", "tok123", 9090)
	if err != nil {
		t.Fatal(err)
	}

	servicePath := filepath.Join(dir, ".config", "systemd", "user", "rampart-proxy.service")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal("service file not created")
	}
	content := string(data)
	if !strings.Contains(content, "/usr/bin/rampart") {
		t.Error("missing binary path")
	}
	if !strings.Contains(content, "9090") {
		t.Error("missing port")
	}
	if !strings.Contains(content, "tok123") {
		t.Error("missing token")
	}
}

func TestInstallLaunchd(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	var out strings.Builder
	cmd.SetOut(&out)

	err := installLaunchd(cmd, dir, "/usr/bin/rampart", "/etc/rampart.yaml", "tok456", 8080)
	if err != nil {
		t.Fatal(err)
	}

	plistPath := filepath.Join(dir, "Library", "LaunchAgents", "com.rampart.proxy.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatal("plist file not created")
	}
	content := string(data)
	if !strings.Contains(content, "/usr/bin/rampart") {
		t.Error("missing binary path")
	}
	if !strings.Contains(content, "8080") {
		t.Error("missing port")
	}
}

func TestOpenclawToolsCandidates(t *testing.T) {
	candidates := openclawToolsCandidates()
	if len(candidates) < 2 {
		t.Errorf("expected at least 2 candidates, got %d", len(candidates))
	}
}
