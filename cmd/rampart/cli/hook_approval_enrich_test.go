package cli

import "testing"

func TestEnrichApprovalMessage(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		toolInput string
		want      string
	}{
		{
			name:      "npm install",
			message:   "needs approval",
			toolInput: "npm install lodash",
			want:      "needs approval\nPackage info: https://www.npmjs.com/package/lodash",
		},
		{
			name:      "npm scoped and version with flags",
			message:   "needs approval",
			toolInput: "npm i --save-dev @org/pkg@1.2.3",
			want:      "needs approval\nPackage info: https://www.npmjs.com/package/@org%2Fpkg",
		},
		{
			name:      "pip install with pin",
			message:   "needs approval",
			toolInput: "pip install requests==2.31.0",
			want:      "needs approval\nPackage info: https://pypi.org/project/requests/",
		},
		{
			name:      "cargo add with version",
			message:   "needs approval",
			toolInput: "cargo add serde@1.0.210",
			want:      "needs approval\nPackage info: https://crates.io/crates/serde",
		},
		{
			name:      "go get with version",
			message:   "needs approval",
			toolInput: "go get github.com/stretchr/testify@v1.9.0",
			want:      "needs approval\nPackage info: https://pkg.go.dev/github.com/stretchr/testify",
		},
		{
			name:      "gem install",
			message:   "needs approval",
			toolInput: "gem install rails",
			want:      "needs approval\nPackage info: https://rubygems.org/gems/rails",
		},
		{
			name:      "brew install with flag",
			message:   "needs approval",
			toolInput: "brew install --cask firefox",
			want:      "needs approval\nPackage info: https://formulae.brew.sh/formula/firefox",
		},
		{
			name:      "sudo env prefix",
			message:   "needs approval",
			toolInput: "FOO=bar sudo npm install react",
			want:      "needs approval\nPackage info: https://www.npmjs.com/package/react",
		},
		{
			name:      "unknown installer unchanged",
			message:   "needs approval",
			toolInput: "apt install curl",
			want:      "needs approval",
		},
		{
			name:      "missing package unchanged",
			message:   "needs approval",
			toolInput: "npm install --save-dev",
			want:      "needs approval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enrichApprovalMessage(tt.message, tt.toolInput)
			if got != tt.want {
				t.Fatalf("enrichApprovalMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}
