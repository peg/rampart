// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

// Package assurance validates Rampart's machine-readable security claims.
package assurance

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const ManifestSchemaVersion = "rampart.assurance.v2"

var integrationIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type Manifest struct {
	SchemaVersion   string        `yaml:"schema_version"`
	BaselineRelease string        `yaml:"baseline_release"`
	ReviewedAt      string        `yaml:"reviewed_at"`
	Integrations    []Integration `yaml:"integrations"`
}

type Integration struct {
	ID              string            `yaml:"id"`
	DisplayName     string            `yaml:"display_name"`
	SupportTier     string            `yaml:"support_tier"`
	SetupCommand    string            `yaml:"setup_command"`
	Boundary        string            `yaml:"boundary"`
	Platforms       []string          `yaml:"platforms"`
	AutoProtect     *bool             `yaml:"auto_protect"`
	ServiceRequired bool              `yaml:"service_required"`
	UpstreamCI      string            `yaml:"upstream_ci"`
	Coverage        map[string]string `yaml:"coverage"`
	Degraded        map[string]string `yaml:"degraded"`
	Approval        string            `yaml:"approval"`
	Verification    Verification      `yaml:"verification"`
	Evidence        []Evidence        `yaml:"evidence"`
	Limitations     []string          `yaml:"limitations"`
}

type Verification struct {
	Level        string `yaml:"level"`
	Command      string `yaml:"command"`
	SafeCanaries bool   `yaml:"safe_canaries"`
	HostBoundary bool   `yaml:"host_boundary"`
}

type Evidence struct {
	Path   string `yaml:"path"`
	Kind   string `yaml:"kind"`
	Proves string `yaml:"proves"`
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read assurance manifest: %w", err)
	}
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode assurance manifest: %w", err)
	}
	return &manifest, nil
}

func (m *Manifest) Validate(repoRoot string) error {
	var problems []string
	if m.SchemaVersion != ManifestSchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version must be %q", ManifestSchemaVersion))
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(m.BaselineRelease) {
		problems = append(problems, "baseline_release must be a semantic version prefixed with v")
	}
	if !regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`).MatchString(m.ReviewedAt) {
		problems = append(problems, "reviewed_at must use YYYY-MM-DD")
	}
	if len(m.Integrations) == 0 {
		problems = append(problems, "integrations must not be empty")
	}

	seen := make(map[string]bool, len(m.Integrations))
	for index := range m.Integrations {
		integration := &m.Integrations[index]
		prefix := fmt.Sprintf("integration[%d]", index)
		if integration.ID != "" {
			prefix = "integration " + integration.ID
		}
		if !integrationIDPattern.MatchString(integration.ID) {
			problems = append(problems, prefix+": id must match "+integrationIDPattern.String())
		}
		if seen[integration.ID] {
			problems = append(problems, prefix+": duplicate id")
		}
		seen[integration.ID] = true
		if strings.TrimSpace(integration.DisplayName) == "" {
			problems = append(problems, prefix+": display_name is required")
		}
		if strings.TrimSpace(integration.SetupCommand) == "" {
			problems = append(problems, prefix+": setup_command is required")
		}
		if !oneOf(integration.SupportTier, "verified", "supported", "experimental", "limited") {
			problems = append(problems, prefix+": invalid support_tier "+integration.SupportTier)
		}
		if !oneOf(integration.Boundary, "native_hook", "native_plugin", "process_interposition", "proxy") {
			problems = append(problems, prefix+": invalid boundary "+integration.Boundary)
		}
		if !oneOf(integration.UpstreamCI, "rolling_latest", "pinned", "none") {
			problems = append(problems, prefix+": invalid upstream_ci "+integration.UpstreamCI)
		}
		if !oneOf(integration.Approval, "native", "block_and_retry", "external", "none") {
			problems = append(problems, prefix+": invalid approval "+integration.Approval)
		}
		if len(integration.Platforms) == 0 {
			problems = append(problems, prefix+": platforms must not be empty")
		}
		if integration.AutoProtect == nil {
			problems = append(problems, prefix+": auto_protect must be explicitly true or false")
		}
		for _, platform := range integration.Platforms {
			if !oneOf(platform, "linux", "macos", "windows") {
				problems = append(problems, prefix+": invalid platform "+platform)
			}
		}

		for _, surface := range []string{"shell", "file_read", "file_write", "network", "mcp", "subagents"} {
			value, ok := integration.Coverage[surface]
			if !ok {
				problems = append(problems, prefix+": missing coverage."+surface)
				continue
			}
			if !oneOf(value, "verified", "tested", "partial", "not_covered") {
				problems = append(problems, prefix+": invalid coverage."+surface+" "+value)
			}
		}
		for key := range integration.Coverage {
			if !oneOf(key, "shell", "file_read", "file_write", "network", "mcp", "subagents") {
				problems = append(problems, prefix+": unknown coverage surface "+key)
			}
		}

		for _, failure := range []string{"policy_unavailable", "adapter_error", "timeout"} {
			value, ok := integration.Degraded[failure]
			if !ok {
				problems = append(problems, prefix+": missing degraded."+failure)
				continue
			}
			if !oneOf(value, "deny", "allow", "local", "mixed", "host_defined") {
				problems = append(problems, prefix+": invalid degraded."+failure+" "+value)
			}
		}
		for key := range integration.Degraded {
			if !oneOf(key, "policy_unavailable", "adapter_error", "timeout") {
				problems = append(problems, prefix+": unknown degraded mode "+key)
			}
		}

		if !oneOf(integration.Verification.Level, "active", "policy_only", "static", "none") {
			problems = append(problems, prefix+": invalid verification.level "+integration.Verification.Level)
		}
		if integration.Verification.Level != "none" && strings.TrimSpace(integration.Verification.Command) == "" {
			problems = append(problems, prefix+": verification.command is required")
		}
		if integration.Verification.HostBoundary && integration.Verification.Level != "active" {
			problems = append(problems, prefix+": host_boundary requires active verification")
		}
		if integration.SupportTier == "verified" {
			if integration.Verification.Level != "active" || !integration.Verification.HostBoundary || !integration.Verification.SafeCanaries {
				problems = append(problems, prefix+": verified tier requires active safe host-boundary canaries")
			}
			if integration.Degraded["policy_unavailable"] != "deny" {
				problems = append(problems, prefix+": verified tier must deny when policy is unavailable")
			}
		}
		if integration.AutoProtect != nil && *integration.AutoProtect {
			if integration.SupportTier == "experimental" || integration.SupportTier == "limited" {
				problems = append(problems, prefix+": auto_protect requires verified or supported tier")
			}
			if integration.Verification.Level != "active" || !integration.Verification.SafeCanaries {
				problems = append(problems, prefix+": auto_protect requires active safe verification")
			}
		}

		if len(integration.Evidence) == 0 {
			problems = append(problems, prefix+": evidence must not be empty")
		}
		for evidenceIndex, evidence := range integration.Evidence {
			evidencePrefix := fmt.Sprintf("%s evidence[%d]", prefix, evidenceIndex)
			if !oneOf(evidence.Kind, "unit", "integration", "failure_injection", "upstream_latest") {
				problems = append(problems, evidencePrefix+": invalid kind "+evidence.Kind)
			}
			if strings.TrimSpace(evidence.Proves) == "" {
				problems = append(problems, evidencePrefix+": proves is required")
			}
			if !validRepositoryPath(evidence.Path) {
				problems = append(problems, evidencePrefix+": path must be a clean slash-separated repository-relative path")
				continue
			}
			info, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(evidence.Path)))
			if err != nil {
				problems = append(problems, evidencePrefix+": path does not exist: "+evidence.Path)
			} else if !info.Mode().IsRegular() {
				problems = append(problems, evidencePrefix+": path is not a regular file: "+evidence.Path)
			}
		}

		if needsLimitations(*integration) && len(integration.Limitations) == 0 {
			problems = append(problems, prefix+": limitations are required for incomplete or degraded guarantees")
		}
		for limitationIndex, limitation := range integration.Limitations {
			if strings.TrimSpace(limitation) == "" {
				problems = append(problems, fmt.Sprintf("%s limitations[%d] must not be empty", prefix, limitationIndex))
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid assurance manifest:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}

func validRepositoryPath(value string) bool {
	return value != "" &&
		!strings.Contains(value, `\`) &&
		!path.IsAbs(value) &&
		path.Clean(value) == value &&
		value != ".." &&
		!strings.HasPrefix(value, "../")
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func needsLimitations(integration Integration) bool {
	if integration.SupportTier == "experimental" || integration.SupportTier == "limited" {
		return true
	}
	for _, value := range integration.Coverage {
		if value == "partial" || value == "not_covered" {
			return true
		}
	}
	for _, value := range integration.Degraded {
		if value == "allow" || value == "mixed" || value == "host_defined" {
			return true
		}
	}
	return !integration.Verification.HostBoundary
}
