// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// parseOpenClawConfigPath extracts the config path from `openclaw config file`.
// Newer OpenClaw releases can print state-migration notices before the path,
// even when banner and notice suppression environment variables are set.
func parseOpenClawConfigPath(output []byte) (string, error) {
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		candidate := strings.Trim(strings.TrimSpace(stripANSI(lines[i])), `"'`)
		lower := strings.ToLower(candidate)
		if candidate == "" || (!strings.HasSuffix(lower, ".json") && !strings.HasSuffix(lower, ".json5")) {
			continue
		}
		expanded := expandHomePath(candidate)
		if filepath.IsAbs(expanded) {
			return filepath.Clean(expanded), nil
		}
	}
	return "", fmt.Errorf("OpenClaw did not return a recognizable absolute JSON config path")
}

// decodeOpenClawJSON decodes the first complete JSON object or array beginning
// on a line boundary. This tolerates OpenClaw migration notices before an
// otherwise valid --json response without accepting arbitrary partial JSON.
func decodeOpenClawJSON(output []byte, dst any) error {
	for offset := 0; offset < len(output); {
		lineEnd := bytes.IndexByte(output[offset:], '\n')
		if lineEnd < 0 {
			lineEnd = len(output) - offset
		}
		line := bytes.TrimSpace(output[offset : offset+lineEnd])
		if len(line) > 0 && (line[0] == '{' || line[0] == '[') {
			var raw json.RawMessage
			decoder := json.NewDecoder(bytes.NewReader(output[offset:]))
			if err := decoder.Decode(&raw); err == nil {
				if err := json.Unmarshal(raw, dst); err == nil {
					return nil
				}
			}
		}
		offset += lineEnd + 1
	}
	return fmt.Errorf("OpenClaw output did not contain a valid JSON object or array")
}

// decodeOpenClawConfigJSON also accepts a complete JSON scalar on its own
// output line. `openclaw config get --json` legitimately returns scalars for
// leaf keys (for example, `"off"`), while gateway responses remain restricted
// to the object/array decoder above.
func decodeOpenClawConfigJSON(output []byte, dst any) error {
	if err := decodeOpenClawJSON(output, dst); err == nil {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace([]byte(stripANSI(lines[i])))
		if len(line) == 0 || line[0] == '{' || line[0] == '[' {
			continue
		}
		var raw json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(line))
		if err := decoder.Decode(&raw); err != nil {
			continue
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			continue
		}
		if err := json.Unmarshal(raw, dst); err == nil {
			return nil
		}
	}
	return fmt.Errorf("OpenClaw output did not contain a valid JSON value")
}

func stripANSI(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); {
		if value[i] == 0x1b && i+1 < len(value) && value[i+1] == '[' {
			i += 2
			for i < len(value) {
				b := value[i]
				i++
				if b >= 0x40 && b <= 0x7e {
					break
				}
			}
			continue
		}
		out.WriteByte(value[i])
		i++
	}
	return out.String()
}
