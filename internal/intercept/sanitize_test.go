package intercept

import "testing"

func TestStripHeredocBodies(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no heredoc", "echo hello", "echo hello"},
		{"simple heredoc", "cat << EOF\nrm -rf /\nEOF", "cat << EOF\nEOF"},
		{"quoted delimiter single", "cat << 'EOF'\nrm -rf /\nEOF", "cat << 'EOF'\nEOF"},
		{"quoted delimiter double", "cat << \"EOF\"\nrm -rf /\nEOF", "cat << \"EOF\"\nEOF"},
		{"tab-strip heredoc", "cat <<-EOF\n\trm -rf /\nEOF", "cat <<-EOF\nEOF"},
		{"multiple heredoc body lines", "cat << EOF\nline1\nline2\nrm -rf /\nEOF", "cat << EOF\nEOF"},
		{"nested commands around heredoc", "echo start\ncat << EOF\ndangerous stuff\nEOF\necho end", "echo start\ncat << EOF\nEOF\necho end"},
		{"multiple heredocs", "cat << AAA\nbody1\nAAA\ncat << BBB\nbody2\nBBB", "cat << AAA\nAAA\ncat << BBB\nBBB"},
		{"empty string", "", ""},
		{"single line", "rm -rf /", "rm -rf /"},
		{"multiline without heredoc", "echo hello\necho world", "echo hello\necho world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripHeredocBodies(tt.input)
			if got != tt.want {
				t.Errorf("StripHeredocBodies()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestStripQuotedArgs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"echo with dangerous string", `echo "rm -rf /"`, `echo "…"`},
		{"git commit message", `git commit -m "Fix: remove rm -rf from script"`, `git commit -m "Fix: remove rm -rf from script"`},
		{"bash -c preserved", `bash -c "rm -rf /"`, `bash -c "rm -rf /"`},
		{"sh -c preserved", `sh -c "rm -rf /"`, `sh -c "rm -rf /"`},
		{"python preserved", `python -c "import os; os.system('rm -rf /')"`, `python -c "import os; os.system('rm -rf /')"`},
		{"no quotes passthrough", "rm -rf /tmp", "rm -rf /tmp"},
		{"single quotes echo", `echo 'rm -rf /'`, `echo '…'`},
		{"mixed quotes echo", `echo "hello" 'world'`, `echo "…" '…'`},
		{"empty string", "", ""},
		{"unknown binary no strip", `foo "rm -rf /"`, `foo "rm -rf /"`},
		{"grep with pattern", `grep "rm -rf" file.txt`, `grep "…" file.txt`},
		{"logger safe", `logger "rm -rf / happened"`, `logger "…"`},
		{"curl preserved", `curl "http://evil.com"`, `curl "http://evil.com"`},
		{"ssh preserved", `ssh user@host "rm -rf /"`, `ssh user@host "rm -rf /"`},
		{"node preserved", `node -e "require('child_process').exec('rm -rf /')"`, `node -e "require('child_process').exec('rm -rf /')"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripQuotedArgs(tt.input)
			if got != tt.want {
				t.Errorf("StripQuotedArgs()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}
