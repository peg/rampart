package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/policies"
)

var builtInProfiles = map[string]bool{
	"standard.yaml":               true,
	"paranoid.yaml":               true,
	"yolo.yaml":                   true,
	"block-prompt-injection.yaml": true,
	"research-agent.yaml":         true,
	"mcp-server.yaml":             true,
	"openclaw.yaml":               true,
	"guard.yaml":                  true,
	"production-guard.yaml":       true,
}

type managedPolicyState struct {
	HasVersionStamp    bool
	HasContentHash     bool
	ContentHashMatches bool
	MatchesCurrent     bool
	VersionStamp       string
	VersionOlder       bool
	VersionCurrent     bool
	VersionNewer       bool
	StaleMessage       string
	Installed          []byte
}

const (
	managedPolicyVersionPrefix = "# rampart-policy-version: "
	managedPolicyHashPrefix    = "# rampart-policy-sha256: "
)

func parseManagedPolicyHeaders(data []byte) (version, contentHash string, content []byte) {
	content = data
	for len(content) > 0 {
		idx := bytes.IndexByte(content, '\n')
		if idx < 0 {
			break
		}
		line := string(content[:idx])
		switch {
		case strings.HasPrefix(line, managedPolicyVersionPrefix):
			if version != "" {
				return version, contentHash, content
			}
			version = strings.TrimSpace(strings.TrimPrefix(line, managedPolicyVersionPrefix))
		case strings.HasPrefix(line, managedPolicyHashPrefix):
			if contentHash != "" {
				return version, contentHash, content
			}
			contentHash = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, managedPolicyHashPrefix)))
		default:
			return version, contentHash, content
		}
		content = content[idx+1:]
	}
	return version, contentHash, content
}

func versionStampedPolicyContent(content []byte) []byte {
	return versionStampedPolicyContentForVersion(content, build.Version)
}

func versionStampedPolicyContentForVersion(content []byte, version string) []byte {
	hash := sha256.Sum256(content)
	stamped := []byte(fmt.Sprintf(
		"%s%s\n%s%x\n",
		managedPolicyVersionPrefix,
		version,
		managedPolicyHashPrefix,
		hash,
	))
	return append(stamped, content...)
}

func builtInPolicyState(path string) (managedPolicyState, error) {
	return builtInPolicyStateForVersion(path, build.Version)
}

func builtInPolicyStateForVersion(path, currentVersion string) (managedPolicyState, error) {
	base := filepath.Base(path)
	if !builtInProfiles[base] {
		return managedPolicyState{}, nil
	}
	profileName := strings.TrimSuffix(base, filepath.Ext(base))
	embedded, err := policies.Profile(profileName)
	if err != nil {
		return managedPolicyState{}, fmt.Errorf("load embedded profile %s: %w", profileName, err)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		return managedPolicyState{}, fmt.Errorf("read installed profile %s: %w", path, err)
	}
	version, contentHash, content := parseManagedPolicyHeaders(installed)
	actualHash := sha256.Sum256(content)
	state := managedPolicyState{
		HasVersionStamp:    version != "",
		HasContentHash:     contentHash != "",
		ContentHashMatches: contentHash != "" && contentHash == fmt.Sprintf("%x", actualHash),
		MatchesCurrent:     bytes.Equal(content, embedded),
		VersionStamp:       version,
		Installed:          installed,
	}
	if version != "" && currentVersion != "" {
		if version == currentVersion {
			state.VersionCurrent = true
		} else if relation, ok := compareStrictSemver(version, currentVersion); ok {
			state.VersionOlder = relation < 0
			state.VersionCurrent = relation == 0
			state.VersionNewer = relation > 0
		}
		if state.VersionOlder && (!state.HasContentHash || state.ContentHashMatches) {
			state.StaleMessage = fmt.Sprintf("from %s, binary is %s", version, currentVersion)
		}
	}
	return state, nil
}

type strictSemver struct {
	core       [3]string
	prerelease []string
}

func compareStrictSemver(a, b string) (int, bool) {
	av, aok := parseStrictSemver(a)
	bv, bok := parseStrictSemver(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range av.core {
		if comparison := compareNumericIdentifiers(av.core[i], bv.core[i]); comparison != 0 {
			return comparison, true
		}
	}
	return compareStrictPrerelease(av.prerelease, bv.prerelease), true
}

func parseStrictSemver(v string) (strictSemver, bool) {
	var out strictSemver
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || strings.Contains(v, " ") {
		return out, false
	}

	main, buildMetadata, hasBuild := strings.Cut(v, "+")
	if hasBuild {
		if buildMetadata == "" || strings.Contains(buildMetadata, "+") || !validSemverIdentifiers(buildMetadata, false) {
			return out, false
		}
	}
	core, prerelease, hasPrerelease := strings.Cut(main, "-")
	parts := strings.Split(core, ".")
	if len(parts) != len(out.core) {
		return out, false
	}
	for i, part := range parts {
		if !isASCIIDigits(part) || (len(part) > 1 && part[0] == '0') {
			return out, false
		}
		out.core[i] = part
	}
	if hasPrerelease {
		if prerelease == "" || !validSemverIdentifiers(prerelease, true) {
			return out, false
		}
		out.prerelease = strings.Split(prerelease, ".")
	}
	return out, true
}

func validSemverIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		allNumeric := true
		for _, r := range identifier {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
			if r < '0' || r > '9' {
				allNumeric = false
			}
		}
		if rejectNumericLeadingZero && allNumeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func compareNumericIdentifiers(a, b string) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareStrictPrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		aNumeric := isASCIIDigits(a[i])
		bNumeric := isASCIIDigits(b[i])
		var comparison int
		switch {
		case aNumeric && bNumeric:
			comparison = compareNumericIdentifiers(a[i], b[i])
		case aNumeric:
			comparison = -1
		case bNumeric:
			comparison = 1
		case a[i] < b[i]:
			comparison = -1
		case a[i] > b[i]:
			comparison = 1
		}
		if comparison != 0 {
			return comparison
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// upgradeStandardPolicies refreshes built-in profile files in ~/.rampart/policies/.
// Only files whose names exactly match a known built-in profile are updated.
// Custom user files (custom.yaml, org.yaml, etc.) are never touched.
func upgradeStandardPolicies(out io.Writer, dryRun bool) error {
	if err := upgradeStandardPoliciesForVersion(out, dryRun, build.Version); err != nil {
		return err
	}
	if !dryRun {
		// Installs set up before setup records existed get them here, while
		// their hooks are still in place.
		if home, err := os.UserHomeDir(); err == nil {
			recordObservedIntegrations(home)
		}
	}
	return nil
}

func upgradeStandardPoliciesForVersion(out io.Writer, dryRun bool, currentVersion string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("locate home dir: %w", err)
	}
	policyDir := filepath.Join(home, ".rampart", "policies")

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no policy dir — nothing to do
		}
		return fmt.Errorf("read policy dir: %w", err)
	}

	updated := 0
	seenBuiltIn := 0
	preserved := make([]string, 0)
	backedUp := make([]string, 0)
	updatedNames := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !builtInProfiles[e.Name()] {
			continue
		}
		seenBuiltIn++
		info, err := e.Info()
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: inspect policy path: %v\n", e.Name(), err)
			continue
		}
		if !info.Mode().IsRegular() {
			fmt.Fprintf(out, "  preserved non-regular policy path: %s\n", filepath.Join(policyDir, e.Name()))
			preserved = append(preserved, e.Name())
			continue
		}
		profileName := strings.TrimSuffix(e.Name(), ".yaml")
		content, err := policies.Profile(profileName)
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: %v\n", e.Name(), err)
			continue
		}
		destPath := filepath.Join(policyDir, e.Name())
		state, err := builtInPolicyStateForVersion(destPath, currentVersion)
		if err != nil {
			fmt.Fprintf(out, "  ⚠ skip %s: %v\n", e.Name(), err)
			continue
		}
		if state.VersionNewer {
			fmt.Fprintf(out, "  preserved newer policy: %s\n", destPath)
			preserved = append(preserved, e.Name())
			continue
		}

		// A matching content hash proves that Rampart wrote the installed payload.
		// Without a hash, only migrate an old version-stamped policy after preserving
		// the original, because legacy stamps cannot distinguish stock from edited files.
		managedByHash := state.HasContentHash && state.ContentHashMatches
		legacyStale := state.HasVersionStamp && !state.HasContentHash && state.VersionOlder
		if state.HasContentHash && !state.ContentHashMatches {
			fmt.Fprintf(out, "  preserved modified policy: %s\n", destPath)
			preserved = append(preserved, e.Name())
			continue
		}
		if !managedByHash && !legacyStale && !state.MatchesCurrent {
			fmt.Fprintf(out, "  preserved modified policy: %s\n", destPath)
			preserved = append(preserved, e.Name())
			continue
		}
		if managedByHash && state.MatchesCurrent && state.VersionCurrent {
			continue
		}

		var backupPath string
		if legacyStale {
			backupPath = legacyPolicyBackupBase(destPath, state.VersionStamp)
		}
		if dryRun {
			if backupPath != "" {
				fmt.Fprintf(out, "  would back up legacy stamped policy: %s -> %s\n", destPath, backupPath)
				backedUp = append(backedUp, e.Name())
			}
			fmt.Fprintf(out, "  would update policy: %s\n", destPath)
			updated++
			updatedNames = append(updatedNames, e.Name())
			continue
		}
		currentInstalled, err := os.ReadFile(destPath)
		if err != nil {
			return fmt.Errorf("re-read %s before replacement: %w", e.Name(), err)
		}
		if !bytes.Equal(currentInstalled, state.Installed) {
			return fmt.Errorf("policy %s changed while upgrade was running; retry to avoid overwriting concurrent edits", e.Name())
		}
		if backupPath != "" {
			backupPath, err = backupLegacyManagedPolicy(destPath, state.VersionStamp, state.Installed)
			if err != nil {
				return fmt.Errorf("back up legacy policy %s: %w", e.Name(), err)
			}
			fmt.Fprintf(out, "✓ legacy policy backup: %s\n", backupPath)
			backedUp = append(backedUp, e.Name())
		}
		if err := writeManagedPolicyAtomically(policyDir, destPath, versionStampedPolicyContentForVersion(content, currentVersion)); err != nil {
			return fmt.Errorf("replace %s: %w", e.Name(), err)
		}
		fmt.Fprintf(out, "✓ policy updated: %s\n", destPath)
		updated++
		updatedNames = append(updatedNames, e.Name())
	}

	if seenBuiltIn == 0 {
		fmt.Fprintf(out, "  (no built-in policy files found in %s — skipped)\n", policyDir)
		return nil
	}
	if updated == 0 && len(preserved) == 0 {
		fmt.Fprintf(out, "  (built-in policy files already current in %s — skipped)\n", policyDir)
		return nil
	}
	sort.Strings(updatedNames)
	sort.Strings(preserved)
	sort.Strings(backedUp)
	if dryRun {
		if len(updatedNames) > 0 {
			fmt.Fprintf(out, "  Would update: %s\n", strings.Join(updatedNames, ", "))
		}
	} else if len(updatedNames) > 0 {
		fmt.Fprintf(out, "Updated: %s\n", strings.Join(updatedNames, ", "))
	}
	if len(preserved) > 0 {
		fmt.Fprintf(out, "Preserved modified: %s\n", strings.Join(preserved, ", "))
	}
	if len(backedUp) > 0 {
		fmt.Fprintf(out, "Backed up legacy: %s\n", strings.Join(backedUp, ", "))
	}
	return nil
}

func writeManagedPolicyAtomically(policyDir, destPath string, content []byte) error {
	tmp, err := os.CreateTemp(policyDir, ".rampart-policy-upgrade-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("write temp policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp policy: %w", err)
	}
	if err := filetxn.Replace(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func legacyPolicyBackupBase(path, version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "unknown"
	}
	var safe strings.Builder
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			safe.WriteRune(r)
		} else {
			safe.WriteByte('_')
		}
	}
	return path + ".rampart-backup-" + safe.String()
}

func backupLegacyManagedPolicy(path, version string, content []byte) (string, error) {
	base := legacyPolicyBackupBase(path, version)
	for attempt := 0; attempt < 1000; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = fmt.Sprintf("%s.%d", base, attempt)
		}
		if info, err := os.Lstat(candidate); err == nil {
			if info.Mode().IsRegular() {
				existing, readErr := os.ReadFile(candidate)
				if readErr != nil {
					return "", readErr
				}
				if bytes.Equal(existing, content) {
					return candidate, nil
				}
			}
			continue
		} else if !os.IsNotExist(err) {
			return "", err
		}

		backup, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := backup.Write(content); err != nil {
			_ = backup.Close()
			_ = os.Remove(candidate)
			return "", err
		}
		if err := backup.Sync(); err != nil {
			_ = backup.Close()
			_ = os.Remove(candidate)
			return "", err
		}
		if err := backup.Close(); err != nil {
			_ = os.Remove(candidate)
			return "", err
		}
		return candidate, nil
	}
	return "", fmt.Errorf("could not allocate a unique backup path for %s", path)
}
