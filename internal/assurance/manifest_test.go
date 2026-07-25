// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package assurance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve assurance test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func TestRepositoryManifest(t *testing.T) {
	root := repositoryRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance", "integrations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(root); err != nil {
		t.Fatal(err)
	}
}

func TestPublicSupportMatrixNamesEveryAssuredIntegration(t *testing.T) {
	root := repositoryRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance", "integrations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "docs-site", "getting-started", "support-matrix.md"))
	if err != nil {
		t.Fatal(err)
	}
	page := strings.ToLower(string(data))
	for _, integration := range manifest.Integrations {
		if !strings.Contains(page, strings.ToLower(integration.DisplayName)) {
			t.Errorf("public support matrix does not name assured integration %q", integration.DisplayName)
		}
	}
}

func TestPublicDocsAvoidKnownAbsoluteBoundaryClaims(t *testing.T) {
	root := repositoryRoot(t)
	targets := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs-site"),
		filepath.Join(root, "docs"),
		filepath.Join(root, "docs", "THREAT-MODEL.md"),
	}
	banned := []string{
		"every command, file access, and network request",
		"every command, file read, network request",
		"every command claude attempts",
		"dangerous commands never run",
		"green across the board means you're fully protected",
		"rampart fully supports windows",
		"rampart fails open by default",
		"pattern matching handles 95%+",
		"yes: every tool call is evaluated",
		"works with every major ai agent",
		"works with every agent",
		"everything is logged",
		"every tool call passes through rampart",
		"everything is audited to a hash-chained trail",
		"works with all dynamically-linked binaries",
		"rampart protects all of them",
		"this intercepts all `os.system()`",
		"this is full protection",
		"1 fully covered",
	}

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			assertNoAbsoluteClaim(t, target, banned)
			continue
		}
		err = filepath.Walk(target, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			ext := filepath.Ext(path)
			if !info.IsDir() && (strings.EqualFold(ext, ".md") || strings.EqualFold(ext, ".html")) {
				assertNoAbsoluteClaim(t, path, banned)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoAbsoluteClaim(t *testing.T, path string, banned []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range banned {
		if strings.Contains(strings.ToLower(string(data)), phrase) {
			t.Errorf("%s contains unqualified boundary claim %q", path, phrase)
		}
	}
}

func TestVerifiedTierCannotUsePolicyOnlyEvidence(t *testing.T) {
	root := repositoryRoot(t)
	manifest := Manifest{
		SchemaVersion:   ManifestSchemaVersion,
		BaselineRelease: "v1.3.0",
		ReviewedAt:      "2026-07-24",
		Integrations: []Integration{{
			ID:           "example",
			DisplayName:  "Example",
			SupportTier:  "verified",
			SetupCommand: "rampart protect example",
			Boundary:     "native_hook",
			Platforms:    []string{"linux"},
			UpstreamCI:   "none",
			Approval:     "native",
			Coverage: map[string]string{
				"shell": "tested", "file_read": "unknown", "file_write": "unknown",
				"network": "unknown", "mcp": "unknown", "subagents": "unknown",
			},
			Degraded: map[string]string{
				"policy_unavailable": "deny", "adapter_error": "deny", "timeout": "deny",
			},
			Verification: Verification{
				Level: "policy_only", Command: "rampart verify policy", SafeCanaries: true,
			},
			Evidence: []Evidence{{
				Path: "cmd/rampart/cli/verify_test.go", Kind: "unit", Proves: "policy behavior",
			}},
			Limitations: []string{"No live host proof."},
		}},
	}
	err := manifest.Validate(root)
	if err == nil || !strings.Contains(err.Error(), "verified tier requires active safe host-boundary canaries") {
		t.Fatalf("expected verified-tier validation failure, got %v", err)
	}
}

func TestEvidenceCannotEscapeRepository(t *testing.T) {
	root := repositoryRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance", "integrations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Integrations[0].Evidence[0].Path = "../outside"
	err = manifest.Validate(root)
	if err == nil || !strings.Contains(err.Error(), "repository-relative") {
		t.Fatalf("expected unsafe evidence path failure, got %v", err)
	}
}

func TestEvidencePathsUsePortableRepositorySyntax(t *testing.T) {
	for _, testCase := range []struct {
		path string
		want bool
	}{
		{path: "cmd/rampart/cli/verify_test.go", want: true},
		{path: "../outside", want: false},
		{path: `..\outside`, want: false},
		{path: "/absolute", want: false},
		{path: "cmd//rampart", want: false},
	} {
		if got := validRepositoryPath(testCase.path); got != testCase.want {
			t.Errorf("validRepositoryPath(%q) = %t, want %t", testCase.path, got, testCase.want)
		}
	}
}
