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
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newPreloadCmd(_ *rootOptions) *cobra.Command {
	var port int
	var token string
	var mode string
	var failOpen bool
	var agent string
	var session string
	var debug bool

	cmd := &cobra.Command{
		Use:   "preload -- <command> [args...]",
		Short: "Run a command with librampart preloaded",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("preload: command is required (use: rampart preload -- <command> [args...])")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode != "enforce" && mode != "monitor" && mode != "disabled" {
				return fmt.Errorf("preload: invalid mode %q (must be enforce, monitor, or disabled)", mode)
			}

			preloadEnvKey, libPath, err := resolvePreloadLibrary()
			if err != nil {
				return err
			}

			baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
			if envURL := strings.TrimSpace(os.Getenv("RAMPART_URL")); envURL != "" {
				baseURL = strings.TrimRight(envURL, "/")
			}
			if !isPreloadRuntimeReady(cmd.Context(), baseURL) {
				fmt.Fprintf(cmd.ErrOrStderr(), "preload: warning: rampart serve is not reachable at %s/healthz; continuing\n", baseURL)
			}

			resolvedToken := token
			if resolvedToken == "" {
				resolvedToken = os.Getenv("RAMPART_TOKEN")
			}

			sessionID := strings.TrimSpace(session)
			if sessionID == "" {
				sessionID = fmt.Sprintf("preload-%d", os.Getpid())
			}

			childEnv := os.Environ()
			existingPreload := getEnvValue(childEnv, preloadEnvKey)
			if existingPreload != "" {
				childEnv = setEnvValue(childEnv, preloadEnvKey, libPath+":"+existingPreload)
			} else {
				childEnv = setEnvValue(childEnv, preloadEnvKey, libPath)
			}
			childEnv = setEnvValue(childEnv, "RAMPART_URL", baseURL)
			childEnv = setEnvValue(childEnv, "RAMPART_TOKEN", resolvedToken)
			childEnv = setEnvValue(childEnv, "RAMPART_MODE", mode)
			if failOpen {
				childEnv = setEnvValue(childEnv, "RAMPART_FAIL_OPEN", "1")
			} else {
				childEnv = setEnvValue(childEnv, "RAMPART_FAIL_OPEN", "0")
			}
			childEnv = setEnvValue(childEnv, "RAMPART_AGENT", agent)
			childEnv = setEnvValue(childEnv, "RAMPART_SESSION", sessionID)
			if debug {
				childEnv = setEnvValue(childEnv, "RAMPART_DEBUG", "1")
			}
			if runtime.GOOS == "darwin" {
				childEnv = setEnvValue(childEnv, "DYLD_FORCE_FLAT_NAMESPACE", "1")
			}

			targetPath, err := exec.LookPath(args[0])
			if err != nil {
				return fmt.Errorf("preload: resolve command %q: %w", args[0], err)
			}

			if err := syscall.Exec(targetPath, args, childEnv); err != nil {
				return fmt.Errorf("preload: exec %q: %w", args[0], err)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&port, "port", defaultServePort, "Port for rampart serve (default matches 'rampart serve' default)")
	cmd.Flags().StringVar(&token, "token", "", "Auth token (or set RAMPART_TOKEN)")
	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor | disabled")
	cmd.Flags().BoolVar(&failOpen, "fail-open", true, "Whether to fail open")
	cmd.Flags().StringVar(&agent, "agent", "preload", "Agent name for audit")
	cmd.Flags().StringVar(&session, "session", "", "Session ID for audit")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging in the library")

	return cmd
}

func resolvePreloadLibrary() (string, string, error) {
	var preloadEnvKey string
	var libName string
	switch runtime.GOOS {
	case "linux":
		preloadEnvKey = "LD_PRELOAD"
		libName = "librampart.so"
	case "darwin":
		preloadEnvKey = "DYLD_INSERT_LIBRARIES"
		libName = "librampart.dylib"
	default:
		return "", "", fmt.Errorf("preload: unsupported platform %q (expected linux or darwin)", runtime.GOOS)
	}

	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".rampart", "lib", libName))
	}
	candidates = append(candidates, filepath.Join("/usr/local/lib", libName))
	if exe, err := os.Executable(); err == nil {
		resolvedExe := exe
		if realExe, symlinkErr := filepath.EvalSymlinks(exe); symlinkErr == nil {
			resolvedExe = realExe
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(resolvedExe), libName))
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return preloadEnvKey, candidate, nil
		}
	}

	return "", "", fmt.Errorf(
		"preload: %s not found\nsearched:\n  - %s\n  - %s\n  - next to the rampart binary\ninstall librampart to ~/.rampart/lib or /usr/local/lib, or place it beside the rampart binary",
		libName,
		filepath.Join("~", ".rampart", "lib", libName),
		filepath.Join("/usr/local/lib", libName),
	)
}

func isPreloadRuntimeReady(ctx context.Context, baseURL string) bool {
	healthURL := baseURL + "/healthz"
	client := &http.Client{Timeout: 300 * time.Millisecond}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func getEnvValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func setEnvValue(env []string, key, value string) []string {
	prefix := key + "="
	filtered := env[:0]
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, key+"="+value)
}
