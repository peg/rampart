// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peg/rampart/internal/build"
)

const (
	verificationReceiptSchemaVersion = "rampart.verification-receipt.v1"
	maxVerificationReceiptBytes      = 64 << 10
	maxPolicyFingerprintBytes        = 2 << 20
	verificationReceiptLifetime      = 7 * 24 * time.Hour
)

type assuranceLevel string

const (
	assuranceDetected        assuranceLevel = "detected"
	assuranceConfigured      assuranceLevel = "configured"
	assurancePolicyVerified  assuranceLevel = "policy_verified"
	assuranceAdapterVerified assuranceLevel = "adapter_verified"
	assuranceHostVerified    assuranceLevel = "host_verified"
	assuranceUnverified      assuranceLevel = "unverified"
	assuranceDegraded        assuranceLevel = "degraded"
)

type verificationReceiptCheck struct {
	ID     string             `json:"id"`
	Status verificationStatus `json:"status"`
}

// verificationReceipt intentionally excludes check messages, command payloads,
// host output, and filesystem paths. It is a local status cache, not an audit
// record or a tamper-resistant attestation.
type verificationReceipt struct {
	SchemaVersion          string                     `json:"schema_version"`
	IntegrationID          string                     `json:"integration_id"`
	AssuranceLevel         assuranceLevel             `json:"assurance_level"`
	CheckedAt              time.Time                  `json:"checked_at"`
	ExpiresAt              time.Time                  `json:"expires_at"`
	RampartVersion         string                     `json:"rampart_version"`
	RampartCommit          string                     `json:"rampart_commit,omitempty"`
	EnvironmentFingerprint string                     `json:"environment_fingerprint"`
	SafeCanaries           bool                       `json:"safe_canaries"`
	Summary                verificationSummary        `json:"summary"`
	Checks                 []verificationReceiptCheck `json:"checks"`
}

type integrationAssuranceStatus struct {
	ID                  string         `json:"id"`
	DisplayName         string         `json:"display_name"`
	Boundary            string         `json:"boundary"`
	ServiceRequired     bool           `json:"service_required"`
	Installed           bool           `json:"installed"`
	Configured          bool           `json:"configured"`
	AssuranceLevel      assuranceLevel `json:"assurance_level"`
	EvidenceSource      string         `json:"evidence_source,omitempty"`
	CheckedAt           *time.Time     `json:"checked_at,omitempty"`
	EvidenceExpiresAt   *time.Time     `json:"evidence_expires_at,omitempty"`
	VerificationCommand string         `json:"verification_command"`
	RecommendedCommand  string         `json:"recommended_command,omitempty"`
	StaleReason         string         `json:"stale_reason,omitempty"`
}

func assuranceLevelForReport(report verificationReport) assuranceLevel {
	if report.Summary.Failed > 0 {
		return assuranceDegraded
	}
	if report.Summary.Unverified > 0 || report.Summary.Checks == 0 {
		return assuranceUnverified
	}
	if report.Target == "policy" {
		return assurancePolicyVerified
	}
	driver, ok := findIntegrationDriver(report.Target)
	if !ok || driver.ProofLevel == "" {
		return assuranceUnverified
	}
	return driver.ProofLevel
}

func verificationReceiptPath(integrationID string) (string, error) {
	driver, ok := findIntegrationDriver(integrationID)
	if !ok || driver.ID != integrationID {
		return "", fmt.Errorf("unknown integration %q", integrationID)
	}
	dir, err := rampartDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "verification", integrationID+".json"), nil
}

func writeVerificationReceipt(report verificationReport) error {
	driver, ok := findIntegrationDriver(report.Target)
	if !ok || driver.ID != report.Target {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	policyEndpoint := report.policyEndpoint
	if policyEndpoint == "" {
		policyEndpoint = resolveServeURL("")
	}
	fingerprint, err := integrationEnvironmentFingerprintAt(driver, home, policyEndpoint)
	if err != nil {
		return err
	}
	checkedAt, err := time.Parse(time.RFC3339, report.GeneratedAt)
	if err != nil {
		return fmt.Errorf("parse verification time: %w", err)
	}
	receipt := verificationReceipt{
		SchemaVersion:          verificationReceiptSchemaVersion,
		IntegrationID:          driver.ID,
		AssuranceLevel:         assuranceLevelForReport(report),
		CheckedAt:              checkedAt,
		ExpiresAt:              checkedAt.Add(verificationReceiptLifetime),
		RampartVersion:         build.Version,
		RampartCommit:          build.Commit,
		EnvironmentFingerprint: fingerprint,
		SafeCanaries:           report.SafeCanaries,
		Summary:                report.Summary,
		Checks:                 make([]verificationReceiptCheck, 0, len(report.Checks)),
	}
	for _, check := range report.Checks {
		receipt.Checks = append(receipt.Checks, verificationReceiptCheck{ID: check.ID, Status: check.Status})
	}
	if err := validateVerificationReceipt(receipt, driver.ID); err != nil {
		return fmt.Errorf("validate receipt: %w", err)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode receipt: %w", err)
	}
	path, err := verificationReceiptPath(driver.ID)
	if err != nil {
		return err
	}
	verificationDir := filepath.Dir(path)
	if info, statErr := os.Lstat(verificationDir); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("verification receipt directory is not a regular directory")
		}
		if err := secureDirPermissions(verificationDir); err != nil {
			return fmt.Errorf("secure verification receipt directory: %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect verification receipt directory: %w", statErr)
	}
	if info, statErr := os.Lstat(path); statErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("verification receipt path is not a regular file")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect verification receipt: %w", statErr)
	}
	if err := atomicWriteRecoverablePrivateFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write verification receipt: %w", err)
	}
	return nil
}

func readVerificationReceipt(integrationID string) (verificationReceipt, error) {
	path, err := verificationReceiptPath(integrationID)
	if err != nil {
		return verificationReceipt{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return verificationReceipt{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return verificationReceipt{}, fmt.Errorf("receipt is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return verificationReceipt{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxVerificationReceiptBytes+1))
	if err != nil {
		return verificationReceipt{}, err
	}
	if len(data) > maxVerificationReceiptBytes {
		return verificationReceipt{}, fmt.Errorf("receipt exceeds %d bytes", maxVerificationReceiptBytes)
	}
	var receipt verificationReceipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return verificationReceipt{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return verificationReceipt{}, fmt.Errorf("receipt contains trailing data")
		}
		return verificationReceipt{}, err
	}
	if err := validateVerificationReceipt(receipt, integrationID); err != nil {
		return verificationReceipt{}, err
	}
	return receipt, nil
}

func validateVerificationReceipt(receipt verificationReceipt, integrationID string) error {
	if receipt.SchemaVersion != verificationReceiptSchemaVersion {
		return fmt.Errorf("unsupported receipt schema")
	}
	if receipt.IntegrationID != integrationID {
		return fmt.Errorf("receipt integration mismatch")
	}
	if receipt.CheckedAt.IsZero() || receipt.ExpiresAt.IsZero() || !receipt.ExpiresAt.After(receipt.CheckedAt) || receipt.ExpiresAt.Sub(receipt.CheckedAt) > verificationReceiptLifetime {
		return fmt.Errorf("invalid receipt lifetime")
	}
	switch receipt.AssuranceLevel {
	case assuranceAdapterVerified, assuranceHostVerified, assuranceUnverified, assuranceDegraded:
	default:
		return fmt.Errorf("invalid assurance level")
	}
	if !receipt.SafeCanaries || strings.TrimSpace(receipt.EnvironmentFingerprint) == "" {
		return fmt.Errorf("receipt lacks safe verification evidence")
	}
	if receipt.Summary.Checks != len(receipt.Checks) {
		return fmt.Errorf("receipt check count mismatch")
	}
	calculated := verificationSummary{Checks: len(receipt.Checks)}
	seen := make(map[string]bool, len(receipt.Checks))
	for _, check := range receipt.Checks {
		if strings.TrimSpace(check.ID) == "" {
			return fmt.Errorf("receipt contains an unnamed check")
		}
		if seen[check.ID] {
			return fmt.Errorf("receipt contains duplicate check %q", check.ID)
		}
		seen[check.ID] = true
		switch check.Status {
		case verificationPass:
			calculated.Passed++
		case verificationFail:
			calculated.Failed++
		case verificationUnverified:
			calculated.Unverified++
		default:
			return fmt.Errorf("receipt contains an invalid check status")
		}
	}
	if calculated != receipt.Summary {
		return fmt.Errorf("receipt summary does not match checks")
	}
	expected := assuranceLevelForReport(verificationReport{Target: integrationID, Summary: calculated})
	if receipt.AssuranceLevel != expected {
		return fmt.Errorf("receipt assurance does not match checks")
	}
	return nil
}

func integrationEnvironmentFingerprint(driver integrationDriver, home string) (string, error) {
	return integrationEnvironmentFingerprintAt(driver, home, resolveServeURL(""))
}

func integrationEnvironmentFingerprintAt(driver integrationDriver, home, policyEndpoint string) (string, error) {
	configured := integrationConfiguredForAssurance(driver, home)
	installed := driver.Installed != nil && driver.Installed(home)
	hash := sha256.New()
	fmt.Fprintf(hash, "%s\n%s\n%s\n%s\n%s\n%s\n%t\n%t\nendpoint:%s\n", driver.ID, driver.Boundary, build.Version, build.Commit, runtime.GOOS, runtime.GOARCH, installed, configured, strings.TrimRight(policyEndpoint, "/"))
	if executable, err := os.Executable(); err == nil {
		resolved := executable
		if value, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
			resolved = value
		}
		if info, statErr := os.Stat(resolved); statErr == nil {
			fmt.Fprintf(hash, "rampart:%s:%d:%d\n", resolved, info.Size(), info.ModTime().UnixNano())
		}
	}

	for _, executable := range driver.Executables {
		path, err := execLookPath(executable)
		if err != nil {
			fmt.Fprintf(hash, "%s:missing\n", executable)
			continue
		}
		resolved := path
		if value, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
			resolved = value
		}
		info, statErr := os.Stat(resolved)
		if statErr != nil {
			return "", fmt.Errorf("inspect %s executable: %w", executable, statErr)
		}
		fmt.Fprintf(hash, "%s:%s:%d:%d\n", executable, resolved, info.Size(), info.ModTime().UnixNano())
	}
	policyDir := filepath.Join(home, ".rampart", "policies")
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(hash, "policies:missing")
			return hex.EncodeToString(hash.Sum(nil)), nil
		}
		return "", fmt.Errorf("inspect policy directory: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		info, statErr := os.Lstat(filepath.Join(policyDir, name))
		if statErr != nil {
			return "", fmt.Errorf("inspect policy %s: %w", name, statErr)
		}
		fmt.Fprintf(hash, "policy:%s:%s:%d:%d\n", name, info.Mode().Type(), info.Size(), info.ModTime().UnixNano())
		if !info.Mode().IsRegular() {
			continue
		}
		file, openErr := os.Open(filepath.Join(policyDir, name))
		if openErr != nil {
			return "", fmt.Errorf("read policy %s: %w", name, openErr)
		}
		copied, copyErr := io.Copy(hash, io.LimitReader(file, maxPolicyFingerprintBytes+1))
		closeErr := file.Close()
		if copyErr != nil {
			return "", fmt.Errorf("fingerprint policy %s: %w", name, copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close policy %s: %w", name, closeErr)
		}
		if copied > maxPolicyFingerprintBytes {
			fmt.Fprintln(hash, "policy-content:truncated")
		} else {
			fmt.Fprintln(hash)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func integrationConfiguredForAssurance(driver integrationDriver, home string) bool {
	if driver.Configured == nil || !driver.Configured(home) {
		return false
	}
	switch driver.ID {
	case "claude-code":
		assessment := claudeHookLoadAssessmentForHome(home)
		return !assessment.Blocked && !assessment.Unverified
	case "copilot":
		workingDir, _ := os.Getwd()
		_, disabled := copilotCLIUserHooksDisabled(home, workingDir)
		return !disabled
	default:
		return true
	}
}

func collectIntegrationAssuranceStatuses(now time.Time, serverRunning bool) []integrationAssuranceStatus {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return []integrationAssuranceStatus{}
	}
	statuses := make([]integrationAssuranceStatus, 0)
	for _, driver := range supportedIntegrationDrivers() {
		installed := driver.Installed != nil && driver.Installed(home)
		configured := integrationConfiguredForAssurance(driver, home)
		if !installed && !configured {
			continue
		}
		receipt, receiptErr := readVerificationReceipt(driver.ID)
		status := integrationAssuranceStatus{
			ID: driver.ID, DisplayName: driver.DisplayName, Boundary: driver.Boundary,
			Installed: installed, Configured: configured, ServiceRequired: driver.ServiceRequired,
			AssuranceLevel:      assuranceDetected,
			VerificationCommand: "rampart verify " + driver.VerifyTarget,
		}
		if driver.AutoProtect {
			status.RecommendedCommand = "rampart protect " + driver.ID
		} else {
			status.RecommendedCommand = "rampart setup " + driver.ID
		}
		if configured {
			status.AssuranceLevel = assuranceConfigured
			status.RecommendedCommand = status.VerificationCommand
		}
		if receiptErr != nil {
			if !os.IsNotExist(receiptErr) {
				status.StaleReason = "verification receipt is unreadable"
			}
			statuses = append(statuses, status)
			continue
		}
		status.CheckedAt = &receipt.CheckedAt
		status.EvidenceExpiresAt = &receipt.ExpiresAt
		status.EvidenceSource = "local_verification_receipt"
		if driver.ServiceRequired && !serverRunning {
			status.StaleReason = "Rampart policy service is unavailable"
			statuses = append(statuses, status)
			continue
		}
		if receipt.CheckedAt.After(now.Add(5 * time.Minute)) {
			status.StaleReason = "verification time is in the future"
			statuses = append(statuses, status)
			continue
		}
		if now.After(receipt.ExpiresAt) {
			status.StaleReason = "verification evidence expired"
			statuses = append(statuses, status)
			continue
		}
		if receipt.RampartVersion != build.Version || receipt.RampartCommit != build.Commit {
			status.StaleReason = "Rampart changed since verification"
			statuses = append(statuses, status)
			continue
		}
		fingerprint, fingerprintErr := integrationEnvironmentFingerprint(driver, home)
		if fingerprintErr != nil || fingerprint != receipt.EnvironmentFingerprint {
			status.StaleReason = "integration environment changed since verification"
			statuses = append(statuses, status)
			continue
		}
		status.AssuranceLevel = receipt.AssuranceLevel
		statuses = append(statuses, status)
	}
	return statuses
}

func printIntegrationAssurance(w io.Writer, statuses []integrationAssuranceStatus, now time.Time) {
	if len(statuses) == 0 {
		return
	}
	fmt.Fprintln(w, "\nAssurance evidence")
	for _, status := range statuses {
		icon := "•"
		switch status.AssuranceLevel {
		case assuranceHostVerified, assuranceAdapterVerified:
			icon = "✓"
		case assuranceDegraded:
			icon = "✗"
		case assuranceUnverified:
			icon = "!"
		}
		label := strings.ToUpper(strings.ReplaceAll(string(status.AssuranceLevel), "_", " "))
		fmt.Fprintf(w, "  %s %-28s %s", icon, status.DisplayName, label)
		if status.CheckedAt != nil && status.StaleReason == "" {
			age := now.Sub(*status.CheckedAt)
			if age < 0 {
				age = 0
			}
			fmt.Fprintf(w, " · checked %s", formatAgo(age))
		}
		fmt.Fprintln(w)
		if status.StaleReason != "" {
			fmt.Fprintf(w, "      Evidence stale: %s; run `%s`\n", status.StaleReason, status.VerificationCommand)
		} else if status.AssuranceLevel == assuranceConfigured || status.AssuranceLevel == assuranceDetected || status.AssuranceLevel == assuranceUnverified || status.AssuranceLevel == assuranceDegraded {
			fmt.Fprintf(w, "      Run `%s`\n", status.RecommendedCommand)
		}
	}
}
