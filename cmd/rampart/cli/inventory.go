// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

const inventorySchemaVersion = "rampart.inventory.v1"

type inventorySnapshot struct {
	SchemaVersion   string                   `json:"schema_version"`
	GeneratedAt     string                   `json:"generated_at"`
	BuildVersion    string                   `json:"build_version"`
	ProtectedAgents []string                 `json:"protected_agents"`
	PolicyInventory inventoryPolicyInventory `json:"policy_inventory"`
	AuditInventory  inventoryAuditInventory  `json:"audit_inventory"`
	Runtime         inventoryRuntime         `json:"runtime"`
}

type inventoryPolicyInventory struct {
	Files        []inventoryPolicyFile `json:"files"`
	LoadedCount  int                   `json:"loaded_count"`
	InvalidCount int                   `json:"invalid_count"`
}

type inventoryPolicyFile struct {
	FileName      string `json:"file_name"`
	Path          string `json:"path"`
	Valid         bool   `json:"valid"`
	LoadStatus    string `json:"load_status"`
	DefaultAction string `json:"default_action,omitempty"`
	PolicyCount   int    `json:"policy_count"`
	Error         string `json:"error,omitempty"`
}

type inventoryAuditInventory struct {
	Directory          string                   `json:"directory"`
	DirectoryAvailable bool                     `json:"directory_available"`
	LogFileCount       int                      `json:"log_file_count"`
	LogFileBytes       int64                    `json:"log_file_bytes"`
	TodayEvents        inventoryAuditEventCount `json:"today_events"`
	Error              string                   `json:"error,omitempty"`
}

type inventoryAuditEventCount struct {
	Allow   int `json:"allow"`
	Deny    int `json:"deny"`
	Watch   int `json:"watch"`
	Pending int `json:"pending"`
	Total   int `json:"total"`
}

type inventoryRuntime struct {
	Server inventoryServer `json:"server"`
}

type inventoryServer struct {
	Reachable bool `json:"reachable"`
}

func newInventoryCmd(opts *rootOptions) *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Show local Rampart inventory",
		Long: `Collect a local-only inventory snapshot of Rampart state.

Includes protected agents, policy file load status, audit footprint, and
whether local rampart serve appears reachable.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			snapshot := collectInventorySnapshot(opts.configPath)
			if jsonOut {
				return writeInventoryJSON(cmd.OutOrStdout(), snapshot)
			}
			return writeInventoryHuman(cmd.OutOrStdout(), snapshot)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output inventory as JSON")
	return cmd
}

func collectInventorySnapshot(configPath string) inventorySnapshot {
	protectedAgents := detectProtectedAgents()
	sort.Strings(protectedAgents)

	version := strings.TrimSpace(build.Version)
	if version == "" {
		version = "dev"
	}

	return inventorySnapshot{
		SchemaVersion:   inventorySchemaVersion,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		BuildVersion:    version,
		ProtectedAgents: protectedAgents,
		PolicyInventory: collectPolicyInventory(configPath),
		AuditInventory:  collectAuditInventory(),
		Runtime: inventoryRuntime{
			Server: inventoryServer{Reachable: detectLocalServeReachable()},
		},
	}
}

func collectPolicyInventory(configPath string) inventoryPolicyInventory {
	paths := collectPolicyPaths(configPath)
	files := make([]inventoryPolicyFile, 0, len(paths))
	loadedCount := 0
	invalidCount := 0

	for _, path := range paths {
		fileInv := inspectPolicyFile(path)
		if fileInv.Valid {
			loadedCount++
		} else if fileInv.LoadStatus == "invalid" || fileInv.LoadStatus == "unreadable" {
			invalidCount++
		}
		files = append(files, fileInv)
	}

	return inventoryPolicyInventory{
		Files:        files,
		LoadedCount:  loadedCount,
		InvalidCount: invalidCount,
	}
}

func collectPolicyPaths(configPath string) []string {
	set := map[string]struct{}{}
	addPath := func(path string) {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			return
		}
		abs, err := filepath.Abs(trimmed)
		if err != nil {
			set[filepath.Clean(trimmed)] = struct{}{}
			return
		}
		set[abs] = struct{}{}
	}

	addPath(configPath)

	policyDir, err := policyInventoryDir()
	if err == nil {
		entries, readErr := os.ReadDir(policyDir)
		if readErr == nil {
			for _, entry := range entries {
				if entry.IsDir() || !isPolicyYAMLFile(entry.Name()) {
					continue
				}
				addPath(filepath.Join(policyDir, entry.Name()))
			}
		}
	}

	paths := make([]string, 0, len(set))
	for path := range set {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func policyInventoryDir() (string, error) {
	dir, err := rampartDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "policies"), nil
}

func inspectPolicyFile(path string) inventoryPolicyFile {
	entry := inventoryPolicyFile{
		FileName:   filepath.Base(path),
		Path:       inventoryDisplayPath(path),
		LoadStatus: "missing",
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			entry.Error = "file not found"
			return entry
		}
		entry.LoadStatus = "unreadable"
		entry.Error = sanitizeInventoryError(err)
		return entry
	}

	if info.IsDir() {
		entry.LoadStatus = "invalid"
		entry.Error = "path is a directory"
		return entry
	}

	cfg, err := engine.NewFileStore(path).Load()
	if err != nil {
		entry.LoadStatus = "invalid"
		entry.Error = sanitizeInventoryError(err)
		return entry
	}

	entry.Valid = true
	entry.LoadStatus = "loaded"
	entry.PolicyCount = len(cfg.Policies)
	if strings.TrimSpace(cfg.DefaultAction) == "" {
		entry.DefaultAction = "deny"
	} else {
		entry.DefaultAction = strings.ToLower(strings.TrimSpace(cfg.DefaultAction))
	}
	return entry
}

func collectAuditInventory() inventoryAuditInventory {
	dir, err := rampartDir()
	if err != nil {
		return inventoryAuditInventory{
			Directory: filepath.ToSlash(filepath.Join("~", ".rampart", "audit")),
			Error:     sanitizeInventoryError(err),
		}
	}

	auditDir := filepath.Join(dir, "audit")
	inv := inventoryAuditInventory{Directory: inventoryDisplayPath(auditDir)}

	entries, err := os.ReadDir(auditDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inv
		}
		inv.Error = sanitizeInventoryError(err)
		return inv
	}

	inv.DirectoryAvailable = true
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		inv.LogFileCount++
		inv.LogFileBytes += info.Size()
	}

	inv.TodayEvents = collectTodayAuditCounts(auditDir)
	return inv
}

func collectTodayAuditCounts(auditDir string) inventoryAuditEventCount {
	today := time.Now().UTC().Format("2006-01-02")
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		return inventoryAuditEventCount{}
	}

	candidates := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".jsonl") || !strings.Contains(name, today) {
			continue
		}
		candidates = append(candidates, filepath.Join(auditDir, name))
	}
	sort.Strings(candidates)

	counts := inventoryAuditEventCount{}
	for _, path := range candidates {
		events, _, readErr := audit.ReadEventsFromOffset(path, 0)
		if readErr != nil {
			continue
		}
		for _, event := range events {
			switch strings.ToLower(strings.TrimSpace(event.Decision.Action)) {
			case "allow":
				counts.Allow++
			case "deny":
				counts.Deny++
			case "watch", "log":
				counts.Watch++
			case "ask", "require_approval", "webhook":
				counts.Pending++
			}
		}
	}
	counts.Total = counts.Allow + counts.Deny + counts.Watch + counts.Pending
	return counts
}

func detectLocalServeReachable() bool {
	for _, serveURL := range localServeCandidates() {
		if isServeRunning(serveURL) {
			return true
		}
	}
	return false
}

func localServeCandidates() []string {
	candidates := make([]string, 0, 8)
	seen := map[string]struct{}{}
	add := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || !isLoopbackURL(trimmed) {
			return
		}
		trimmed = strings.TrimRight(trimmed, "/")
		if _, ok := seen[trimmed]; ok {
			return
		}
		seen[trimmed] = struct{}{}
		candidates = append(candidates, trimmed)
	}

	// Only probe local loopback endpoints to keep inventory strictly local-only.
	if cfg, err := loadUserConfig(); err == nil {
		add(cfg.URL)
		add(cfg.ServeURL)
	}

	if dir, err := rampartDir(); err == nil {
		statePath := filepath.Join(dir, serveStateFile)
		if data, readErr := os.ReadFile(statePath); readErr == nil {
			var state serveState
			if json.Unmarshal(data, &state) == nil {
				add(state.URL)
			}
		}
	}

	for _, port := range []int{defaultServePort, 9091, 8090} {
		add(fmt.Sprintf("http://localhost:%d", port))
		add(fmt.Sprintf("http://127.0.0.1:%d", port))
	}

	return candidates
}

func isLoopbackURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeInventoryJSON(w io.Writer, snapshot inventorySnapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
		return fmt.Errorf("inventory: write JSON output: %w", err)
	}
	return nil
}

func writeInventoryHuman(w io.Writer, snapshot inventorySnapshot) error {
	if _, err := fmt.Fprintf(w, "Rampart inventory (%s)\n", snapshot.GeneratedAt); err != nil {
		return fmt.Errorf("inventory: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Build: %s\n", snapshot.BuildVersion); err != nil {
		return fmt.Errorf("inventory: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Protected agents: %d\n", len(snapshot.ProtectedAgents)); err != nil {
		return fmt.Errorf("inventory: write output: %w", err)
	}
	if _, err := fmt.Fprintf(
		w,
		"Policy files: %d (loaded: %d, invalid: %d)\n",
		len(snapshot.PolicyInventory.Files),
		snapshot.PolicyInventory.LoadedCount,
		snapshot.PolicyInventory.InvalidCount,
	); err != nil {
		return fmt.Errorf("inventory: write output: %w", err)
	}

	auditState := "unavailable"
	if snapshot.AuditInventory.DirectoryAvailable {
		auditState = "available"
	}
	if _, err := fmt.Fprintf(
		w,
		"Audit logs: %s (%d files, %d bytes) today=%d/%d/%d/%d\n",
		auditState,
		snapshot.AuditInventory.LogFileCount,
		snapshot.AuditInventory.LogFileBytes,
		snapshot.AuditInventory.TodayEvents.Allow,
		snapshot.AuditInventory.TodayEvents.Deny,
		snapshot.AuditInventory.TodayEvents.Watch,
		snapshot.AuditInventory.TodayEvents.Pending,
	); err != nil {
		return fmt.Errorf("inventory: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Serve reachable: %t\n", snapshot.Runtime.Server.Reachable); err != nil {
		return fmt.Errorf("inventory: write output: %w", err)
	}
	return nil
}

func inventoryDisplayPath(path string) string {
	cleaned := filepath.Clean(path)
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.ToSlash(cleaned)
	}

	rampartRoot := filepath.Join(home, ".rampart")
	if rel, ok := relativePathInside(rampartRoot, cleaned); ok {
		if rel == "." {
			return "~/.rampart"
		}
		return filepath.ToSlash(filepath.Join("~/.rampart", rel))
	}
	if rel, ok := relativePathInside(home, cleaned); ok {
		if rel == "." {
			return "~"
		}
		return filepath.ToSlash(filepath.Join("~", rel))
	}
	return filepath.ToSlash(cleaned)
}

func relativePathInside(base, target string) (string, bool) {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func sanitizeInventoryError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.Join(strings.Fields(strings.TrimSpace(err.Error())), " ")
	home, homeErr := os.UserHomeDir()
	if homeErr == nil && home != "" {
		msg = strings.ReplaceAll(msg, home, "~")
	}
	if len(msg) > 160 {
		msg = msg[:157] + "..."
	}
	return msg
}

func isPolicyYAMLFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
