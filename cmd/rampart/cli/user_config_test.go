package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUserConfig_FileAndEnvPrecedence(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	dir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("url: http://config-proxy:7000\nserve_url: http://config-serve:9000\napi: http://config-api:9100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RAMPART_URL", "http://env-proxy:7001/")
	t.Setenv("RAMPART_SERVE_URL", "")
	t.Setenv("RAMPART_API", "http://env-api:9101/")
	t.Setenv("RAMPART_TOKEN", "")

	cfg, err := loadUserConfig()
	if err != nil {
		t.Fatalf("loadUserConfig: %v", err)
	}
	if cfg.URL != "http://env-proxy:7001" {
		t.Fatalf("cfg.URL = %q", cfg.URL)
	}
	if cfg.ServeURL != "http://config-serve:9000" {
		t.Fatalf("cfg.ServeURL = %q", cfg.ServeURL)
	}
	if cfg.APIAddr != "http://env-api:9101" {
		t.Fatalf("cfg.APIAddr = %q", cfg.APIAddr)
	}
	if tok, source := resolveTokenValue(); tok != "tok-file" || source != "file" {
		t.Fatalf("resolveTokenValue() = %q/%q", tok, source)
	}
}

func TestResolveServeURL_UsesConfigServeURL(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("serve_url: http://config-serve:9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RAMPART_URL", "")
	t.Setenv("RAMPART_SERVE_URL", "")

	if got := resolveServeURL(""); got != "http://config-serve:9999" {
		t.Fatalf("resolveServeURL() = %q", got)
	}
}

func TestLoadUserConfig_RejectsUnknownFields(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("serveUrl: http://typo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadUserConfig(); err == nil {
		t.Fatal("expected unknown-field error, got nil")
	}
}

func TestResolveServeURLStrict_RejectsUnknownConfigFields(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("serveUrl: http://typo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := resolveServeURLStrict("", "http://localhost:9090"); err == nil {
		t.Fatal("expected resolveServeURLStrict to return config parse error")
	}
}
