package engine

import "testing"

// Text after the last "*" in a pattern that starts with "*" is anchored at the
// end, as in any glob.
func TestMatchGlobAnchorsLeadingStarSuffix(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"* .env", "cat .env", true},
		{"* .env", "cat .environment", false},
		{"* .env", "cat .env .other", false},
		{"* .env *", "cat .env .other", true},
		{"*curl*webhook.site*", "curl https://webhook.site/x", true},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "api.github.com.evil.test", false},
		{"*a*a", "a", false},
		{"*a*a", "aa", true},
	}
	for _, tt := range tests {
		if got := MatchGlob(tt.pattern, tt.name); got != tt.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}
