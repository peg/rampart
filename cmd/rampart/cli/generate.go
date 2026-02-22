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
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type templateConditionType string

const (
	condCommandMatches  templateConditionType = "command_matches"
	condCommandContains templateConditionType = "command_contains"
	condPathMatches     templateConditionType = "path_matches"
	condDomainMatches   templateConditionType = "domain_matches"
	condURLMatches      templateConditionType = "url_matches"
)

type intentTemplate struct {
	ID         string
	Keywords   []string
	Tools      []string
	Condition  templateConditionType
	Patterns   []string
	Message    string
	NameSuffix string
}

type intentSpec struct {
	Intent     string
	Strictness string
	Exceptions []string
}

type generatedIntent struct {
	Policy  engine.Policy
	Comment string
}

var (
	pathCaptureRegexp = regexp.MustCompile(`(/[^\s,;]+)`)
	slugRegexp        = regexp.MustCompile(`[^a-z0-9]+`)

	// Keep this list explicit and broad to satisfy pattern-only generation.
	intentTemplates = []intentTemplate{
		{ID: "cmd-curl", Keywords: []string{"curl"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"curl *"}, Message: "curl command blocked", NameSuffix: "curl"},
		{ID: "cmd-wget", Keywords: []string{"wget"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"wget *"}, Message: "wget command blocked", NameSuffix: "wget"},
		{ID: "cmd-git", Keywords: []string{"git", "command"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"git *"}, Message: "git command policy matched", NameSuffix: "git"},
		{ID: "cmd-sudo", Keywords: []string{"sudo"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"sudo **"}, Message: "sudo command policy matched", NameSuffix: "sudo"},
		{ID: "cmd-python-c", Keywords: []string{"python", "-c"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"python -c *", "python3 -c *", "*python* -c *"}, Message: "python -c execution blocked", NameSuffix: "python-c"},
		{ID: "cmd-node-e", Keywords: []string{"node", "-e"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"node -e *"}, Message: "node -e execution blocked", NameSuffix: "node-e"},
		{ID: "cmd-perl-e", Keywords: []string{"perl", "-e"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"perl -e *"}, Message: "perl -e execution blocked", NameSuffix: "perl-e"},
		{ID: "cmd-ruby-e", Keywords: []string{"ruby", "-e"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"ruby -e *"}, Message: "ruby -e execution blocked", NameSuffix: "ruby-e"},
		{ID: "cmd-php-r", Keywords: []string{"php", "-r"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"php -r *"}, Message: "php -r execution blocked", NameSuffix: "php-r"},
		{ID: "cmd-rm-rf", Keywords: []string{"rm", "-rf"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"rm -rf *"}, Message: "Destructive rm blocked", NameSuffix: "rm-rf"},
		{ID: "cmd-dd", Keywords: []string{"dd", "if="}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"dd if=*"}, Message: "dd destructive pattern blocked", NameSuffix: "dd"},
		{ID: "cmd-mkfs", Keywords: []string{"mkfs"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"mkfs*"}, Message: "Filesystem formatting blocked", NameSuffix: "mkfs"},
		{ID: "cmd-wipefs", Keywords: []string{"wipefs"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"wipefs **"}, Message: "Filesystem wipe blocked", NameSuffix: "wipefs"},
		{ID: "cmd-shred", Keywords: []string{"shred"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"shred **"}, Message: "Shred operation blocked", NameSuffix: "shred"},
		{ID: "cmd-crontab-r", Keywords: []string{"crontab", "-r"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"crontab -r", "crontab -r *"}, Message: "Crontab deletion blocked", NameSuffix: "crontab"},
		{ID: "cmd-nc-e", Keywords: []string{"nc", "-e"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"nc -e *", "ncat -e *"}, Message: "netcat exec blocked", NameSuffix: "netcat"},
		{ID: "cmd-curl-pipe-bash", Keywords: []string{"curl", "|", "bash"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"curl ** | bash", "curl ** | sh"}, Message: "Piped curl execution blocked", NameSuffix: "curl-pipe"},
		{ID: "cmd-wget-pipe-bash", Keywords: []string{"wget", "|", "bash"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"wget ** | bash", "wget ** | sh"}, Message: "Piped wget execution blocked", NameSuffix: "wget-pipe"},
		{ID: "cmd-dev-tcp", Keywords: []string{"/dev/tcp"}, Tools: []string{"exec"}, Condition: condCommandContains, Patterns: []string{"/dev/tcp/"}, Message: "Network redirect via /dev/tcp blocked", NameSuffix: "dev-tcp"},
		{ID: "cmd-dev-udp", Keywords: []string{"/dev/udp"}, Tools: []string{"exec"}, Condition: condCommandContains, Patterns: []string{"/dev/udp/"}, Message: "Network redirect via /dev/udp blocked", NameSuffix: "dev-udp"},
		{ID: "pkg-npm-install", Keywords: []string{"npm", "install"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"npm install *", "npm i *"}, Message: "npm install policy matched", NameSuffix: "npm-install"},
		{ID: "pkg-pnpm-add", Keywords: []string{"pnpm", "add"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"pnpm add *"}, Message: "pnpm add policy matched", NameSuffix: "pnpm-add"},
		{ID: "pkg-yarn-add", Keywords: []string{"yarn", "add"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"yarn add *"}, Message: "yarn add policy matched", NameSuffix: "yarn-add"},
		{ID: "pkg-pip-install", Keywords: []string{"pip", "install"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"pip install *", "pip3 install *"}, Message: "pip install policy matched", NameSuffix: "pip-install"},
		{ID: "pkg-apt-install", Keywords: []string{"apt", "install"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"apt install *", "apt-get install *"}, Message: "apt install policy matched", NameSuffix: "apt-install"},
		{ID: "pkg-dnf-install", Keywords: []string{"dnf", "install"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"dnf install *"}, Message: "dnf install policy matched", NameSuffix: "dnf-install"},
		{ID: "pkg-yum-install", Keywords: []string{"yum", "install"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"yum install *"}, Message: "yum install policy matched", NameSuffix: "yum-install"},
		{ID: "pkg-brew-install", Keywords: []string{"brew", "install"}, Tools: []string{"exec"}, Condition: condCommandMatches, Patterns: []string{"brew install *"}, Message: "brew install policy matched", NameSuffix: "brew-install"},
		{ID: "path-etc-write", Keywords: []string{"write", "/etc"}, Tools: []string{"write", "edit"}, Condition: condPathMatches, Patterns: []string{"/etc/**"}, Message: "Write to /etc path policy matched", NameSuffix: "etc-write"},
		{ID: "path-passwd-write", Keywords: []string{"/etc/passwd"}, Tools: []string{"write", "edit"}, Condition: condPathMatches, Patterns: []string{"/etc/passwd"}, Message: "Write to /etc/passwd blocked", NameSuffix: "passwd"},
		{ID: "path-shadow-write", Keywords: []string{"/etc/shadow"}, Tools: []string{"write", "edit"}, Condition: condPathMatches, Patterns: []string{"/etc/shadow"}, Message: "Write to /etc/shadow blocked", NameSuffix: "shadow"},
		{ID: "path-system-write", Keywords: []string{"/usr/bin"}, Tools: []string{"write", "edit"}, Condition: condPathMatches, Patterns: []string{"/usr/bin/**", "/usr/sbin/**"}, Message: "Write to system binary paths blocked", NameSuffix: "system-bin"},
		{ID: "path-env-read", Keywords: []string{".env"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.env", "**/.env.*", "**/.envrc"}, Message: "Environment file access policy matched", NameSuffix: "env"},
		{ID: "path-credential-read", Keywords: []string{"credential"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.aws/credentials", "**/.git-credentials", "**/token*", "**/.netrc"}, Message: "Credential file access policy matched", NameSuffix: "credentials"},
		{ID: "path-ssh-read", Keywords: []string{"ssh", "key"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.ssh/id_*"}, Message: "SSH private key access policy matched", NameSuffix: "ssh-key"},
		{ID: "path-gcloud-read", Keywords: []string{"gcloud", "credential"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.config/gcloud/application_default_credentials.json", "**/.config/gcloud/credentials.db"}, Message: "GCloud credential access policy matched", NameSuffix: "gcloud-creds"},
		{ID: "path-kube-read", Keywords: []string{"kube", "config"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.kube/config"}, Message: "Kubernetes config access policy matched", NameSuffix: "kube-config"},
		{ID: "path-docker-read", Keywords: []string{"docker", "config"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.docker/config.json"}, Message: "Docker config access policy matched", NameSuffix: "docker-config"},
		{ID: "path-gnupg-read", Keywords: []string{"gpg"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/.gnupg/**"}, Message: "GPG keyring access policy matched", NameSuffix: "gnupg"},
		{ID: "path-keychain-read", Keywords: []string{"keychain"}, Tools: []string{"read"}, Condition: condPathMatches, Patterns: []string{"**/Library/Keychains/**"}, Message: "macOS keychain access policy matched", NameSuffix: "keychain"},
		{ID: "domain-pastebin", Keywords: []string{"pastebin"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"pastebin.com", "*.pastebin.com"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "pastebin"},
		{ID: "domain-webhook-site", Keywords: []string{"webhook.site"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"webhook.site", "*.webhook.site"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "webhook-site"},
		{ID: "domain-requestbin", Keywords: []string{"requestbin"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"requestbin.com", "*.requestbin.com"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "requestbin"},
		{ID: "domain-ngrok", Keywords: []string{"ngrok"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"*.ngrok-free.app"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "ngrok"},
		{ID: "domain-transfer", Keywords: []string{"transfer.sh"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"transfer.sh", "*.transfer.sh"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "transfer"},
		{ID: "domain-pipedream", Keywords: []string{"pipedream"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"*.m.pipedream.net"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "pipedream"},
		{ID: "domain-discord-webhook", Keywords: []string{"discord", "webhook"}, Tools: []string{"fetch"}, Condition: condURLMatches, Patterns: []string{"https://discord.com/api/webhooks/*", "https://discordapp.com/api/webhooks/*"}, Message: "Potential data exfiltration URL blocked", NameSuffix: "discord-webhook"},
		{ID: "domain-slack-webhook", Keywords: []string{"slack", "webhook"}, Tools: []string{"fetch"}, Condition: condURLMatches, Patterns: []string{"https://hooks.slack.com/services/*"}, Message: "Potential data exfiltration URL blocked", NameSuffix: "slack-webhook"},
		{ID: "domain-gist", Keywords: []string{"gist"}, Tools: []string{"fetch"}, Condition: condDomainMatches, Patterns: []string{"gist.github.com", "*.gist.github.com"}, Message: "Potential data exfiltration domain blocked", NameSuffix: "gist"},
	}
)

func newPolicyGenerateCmd(_ *rootOptions) *cobra.Command {
	var output string
	var appendMode bool
	var interactive bool
	var strictness string
	var exceptions string

	cmd := &cobra.Command{
		Use:   "generate [DESCRIPTION]",
		Short: "Generate policy YAML from natural language intent",
		Long: `Convert natural language security intent into Rampart policy YAML.

Examples:
  rampart policy generate "block all curl and wget"
  rampart policy generate "require approval for npm installs" --output rampart.yaml --append
  rampart policy generate --interactive --output policy.yaml
`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := resolveIntentSpec(cmd, args, interactive, strictness, exceptions)
			if err != nil {
				return err
			}

			generated, err := buildPolicyFromIntent(spec)
			if err != nil {
				return err
			}

			if appendMode && strings.TrimSpace(output) == "" {
				return fmt.Errorf("policy: --append requires --output")
			}

			if appendMode {
				if err := appendPolicyToFile(output, generated.Policy); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Appended generated policy %q to %s\n", generated.Policy.Name, output)
				return nil
			}

			yamlBytes, err := renderGeneratedConfigYAML(spec, generated.Policy, generated.Comment)
			if err != nil {
				return err
			}

			if strings.TrimSpace(output) == "" {
				_, err = fmt.Fprint(cmd.OutOrStdout(), string(yamlBytes))
				if err != nil {
					return fmt.Errorf("policy: write generated yaml: %w", err)
				}
				return nil
			}

			if err := os.WriteFile(output, yamlBytes, 0o600); err != nil {
				return fmt.Errorf("policy: write output file: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Generated policy written to %s\n", output)
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Write generated YAML to a file")
	cmd.Flags().BoolVar(&appendMode, "append", false, "Append generated policy into existing --output config")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Launch interactive generation wizard")
	cmd.Flags().StringVar(&strictness, "strictness", "balanced", "Policy strictness: strict|balanced|lenient")
	cmd.Flags().StringVar(&exceptions, "exceptions", "", "Comma-separated exceptions to exclude from matching")

	return cmd
}

func resolveIntentSpec(cmd *cobra.Command, args []string, interactive bool, strictness, exceptions string) (intentSpec, error) {
	if interactive {
		return runGenerateWizard(cmd)
	}
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return intentSpec{}, fmt.Errorf("policy: description is required (or use --interactive)")
	}
	return intentSpec{
		Intent:     strings.TrimSpace(args[0]),
		Strictness: normalizeStrictness(strictness),
		Exceptions: parseExceptions(exceptions),
	}, nil
}

func runGenerateWizard(cmd *cobra.Command) (intentSpec, error) {
	in := bufio.NewReader(cmd.InOrStdin())
	out := cmd.OutOrStdout()

	_, _ = fmt.Fprintln(out, "Rampart Policy Generator")
	_, _ = fmt.Fprintln(out, "Enter intent, strictness, and optional exceptions.")

	intent, err := promptLine(in, out, "Intent description")
	if err != nil {
		return intentSpec{}, fmt.Errorf("policy: read intent: %w", err)
	}
	if strings.TrimSpace(intent) == "" {
		return intentSpec{}, fmt.Errorf("policy: intent cannot be empty")
	}

	strictness, err := promptLine(in, out, "Strictness [strict|balanced|lenient] (default: balanced)")
	if err != nil {
		return intentSpec{}, fmt.Errorf("policy: read strictness: %w", err)
	}

	exceptions, err := promptLine(in, out, "Exceptions (comma-separated, optional)")
	if err != nil {
		return intentSpec{}, fmt.Errorf("policy: read exceptions: %w", err)
	}

	return intentSpec{
		Intent:     strings.TrimSpace(intent),
		Strictness: normalizeStrictness(strictness),
		Exceptions: parseExceptions(exceptions),
	}, nil
}

func promptLine(in *bufio.Reader, out io.Writer, label string) (string, error) {
	_, _ = fmt.Fprintf(out, "%s: ", label)
	line, err := in.ReadString('\n')
	if err != nil {
		if line == "" {
			return "", err
		}
	}
	return strings.TrimSpace(line), nil
}

func parseExceptions(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeStrictness(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "strict", "balanced", "lenient":
		return raw
	default:
		return "balanced"
	}
}

func buildPolicyFromIntent(spec intentSpec) (generatedIntent, error) {
	text := strings.ToLower(strings.TrimSpace(spec.Intent))
	if text == "" {
		return generatedIntent{}, fmt.Errorf("policy: empty intent")
	}
	action := parseIntentAction(text)

	selected := matchTemplates(text)
	selected = append(selected, dynamicTemplates(text)...)
	selected = dedupeTemplates(selected)

	if len(selected) == 0 {
		return buildFallbackIntent(spec, action)
	}

	tools := make([]string, 0, 2)
	tools = append(tools, selected[0].Tools...)
	conditionType := selected[0].Condition
	patterns := make([]string, 0, 6)
	nameParts := []string{selected[0].NameSuffix}

	for _, t := range selected {
		if t.Condition != conditionType {
			continue
		}
		if !sameStringSet(t.Tools, tools) {
			continue
		}
		patterns = appendUnique(patterns, t.Patterns...)
		if t.NameSuffix != "" {
			nameParts = append(nameParts, t.NameSuffix)
		}
	}
	if len(patterns) == 0 {
		patterns = appendUnique(patterns, selected[0].Patterns...)
	}

	rule := engine.Rule{Action: action, Message: selected[0].Message}
	if rule.Message == "" {
		rule.Message = defaultRuleMessage(action, conditionType)
	}
	applyCondition(&rule.When, conditionType, patterns)
	applyExceptions(&rule.When, conditionType, spec.Exceptions)
	applyStrictness(&rule, spec.Strictness)

	policy := engine.Policy{
		Name: fmt.Sprintf("generated-%s", slugify(strings.Join(nameParts, "-"))),
		Match: engine.Match{
			Tool: tools,
		},
		Rules: []engine.Rule{rule},
	}

	comment := fmt.Sprintf("action=%s, condition=%s, patterns=%d", rule.Action, string(conditionType), len(patterns))
	return generatedIntent{Policy: policy, Comment: comment}, nil
}

func parseIntentAction(text string) string {
	if containsAllKeywords(text, []string{"require", "approval"}) || containsAllKeywords(text, []string{"needs", "approval"}) {
		return "require_approval"
	}
	if stringContainsAny(text, []string{"watch", "monitor", "log", "audit"}) {
		return "watch"
	}
	if stringContainsAny(text, []string{"allow", "permit"}) {
		return "allow"
	}
	if stringContainsAny(text, []string{"block", "deny", "prevent", "forbid", "reject"}) {
		return "deny"
	}
	return "deny"
}

func matchTemplates(text string) []intentTemplate {
	matches := make([]intentTemplate, 0, 4)
	for _, t := range intentTemplates {
		ok := true
		for _, kw := range t.Keywords {
			if !strings.Contains(text, kw) {
				ok = false
				break
			}
		}
		if ok {
			matches = append(matches, t)
		}
	}
	return matches
}

func dynamicTemplates(text string) []intentTemplate {
	templates := make([]intentTemplate, 0, 4)

	if stringContainsAny(text, []string{"write", "writes", "writing"}) {
		if path := detectPath(text); path != "" {
			templates = append(templates, intentTemplate{
				ID:         "dynamic-write-path",
				Tools:      []string{"write", "edit"},
				Condition:  condPathMatches,
				Patterns:   []string{normalizePathPattern(path)},
				Message:    "Write access policy matched",
				NameSuffix: "write-path",
			})
		}
	}

	commands := detectCommandKeywords(text)
	if len(commands) > 1 {
		patterns := make([]string, 0, len(commands))
		for _, c := range commands {
			patterns = append(patterns, c+" *")
		}
		templates = append(templates, intentTemplate{
			ID:         "dynamic-multi-command",
			Tools:      []string{"exec"},
			Condition:  condCommandMatches,
			Patterns:   patterns,
			Message:    "Command policy matched",
			NameSuffix: "commands",
		})
	}

	if containsAllKeywords(text, []string{"reading", ".env"}) || containsAllKeywords(text, []string{"read", ".env"}) {
		templates = append(templates, intentTemplate{
			ID:         "dynamic-env-read",
			Tools:      []string{"read"},
			Condition:  condPathMatches,
			Patterns:   []string{"**/.env", "**/.env.*", "**/.envrc"},
			Message:    "Environment file access policy matched",
			NameSuffix: "env-read",
		})
	}

	if stringContainsAny(text, []string{"credential", "credentials", "secret files"}) {
		templates = append(templates, intentTemplate{
			ID:         "dynamic-credential-read",
			Tools:      []string{"read"},
			Condition:  condPathMatches,
			Patterns:   []string{"**/.aws/credentials", "**/.git-credentials", "**/token*", "**/.netrc", "**/.npmrc", "**/.pypirc"},
			Message:    "Credential file access policy matched",
			NameSuffix: "credential-read",
		})
	}

	return templates
}

func dedupeTemplates(in []intentTemplate) []intentTemplate {
	out := make([]intentTemplate, 0, len(in))
	seen := map[string]bool{}
	for _, t := range in {
		key := t.ID
		if key == "" {
			key = strings.Join(append([]string{string(t.Condition)}, t.Patterns...), "|")
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func buildFallbackIntent(spec intentSpec, action string) (generatedIntent, error) {
	rule := engine.Rule{
		Action: action,
		When: engine.Condition{
			CommandContains: []string{spec.Intent},
		},
		Message: defaultRuleMessage(action, condCommandContains),
	}
	applyExceptions(&rule.When, condCommandContains, spec.Exceptions)
	applyStrictness(&rule, spec.Strictness)

	policy := engine.Policy{
		Name: fmt.Sprintf("generated-%s", slugify(spec.Intent)),
		Match: engine.Match{
			Tool: engine.StringOrSlice{"exec"},
		},
		Rules: []engine.Rule{rule},
	}

	return generatedIntent{Policy: policy, Comment: "fallback command_contains policy"}, nil
}

func applyCondition(cond *engine.Condition, typ templateConditionType, patterns []string) {
	switch typ {
	case condCommandMatches:
		cond.CommandMatches = appendUnique(nil, patterns...)
	case condCommandContains:
		cond.CommandContains = appendUnique(nil, patterns...)
	case condPathMatches:
		cond.PathMatches = appendUnique(nil, patterns...)
	case condDomainMatches:
		cond.DomainMatches = appendUnique(nil, patterns...)
	case condURLMatches:
		cond.URLMatches = appendUnique(nil, patterns...)
	default:
		cond.CommandContains = appendUnique(nil, patterns...)
	}
}

func applyExceptions(cond *engine.Condition, typ templateConditionType, exceptions []string) {
	if len(exceptions) == 0 {
		return
	}
	switch typ {
	case condPathMatches:
		cond.PathNotMatches = appendUnique(cond.PathNotMatches, exceptions...)
	case condCommandMatches, condCommandContains:
		cond.CommandNotMatches = appendUnique(cond.CommandNotMatches, exceptions...)
	}
}

func applyStrictness(rule *engine.Rule, strictness string) {
	switch strictness {
	case "lenient":
		if rule.Action == "deny" {
			rule.Action = "require_approval"
			rule.Message = strings.TrimSpace(rule.Message + " (lenient mode)")
		}
	case "strict":
		if rule.Action == "watch" {
			rule.Action = "require_approval"
			rule.Message = strings.TrimSpace(rule.Message + " (strict mode)")
		}
	}
}

func defaultRuleMessage(action string, typ templateConditionType) string {
	subject := "operation"
	switch typ {
	case condCommandMatches, condCommandContains:
		subject = "command"
	case condPathMatches:
		subject = "file path"
	case condDomainMatches:
		subject = "domain"
	case condURLMatches:
		subject = "URL"
	}
	switch action {
	case "allow":
		return subject + " allowed by generated policy"
	case "watch":
		return subject + " logged by generated policy"
	case "require_approval":
		return subject + " requires approval"
	default:
		return subject + " blocked by generated policy"
	}
}

func appendPolicyToFile(path string, policy engine.Policy) error {
	var cfg engine.Config
	if data, err := os.ReadFile(path); err == nil {
		if unmarshalErr := yaml.Unmarshal(data, &cfg); unmarshalErr != nil {
			return fmt.Errorf("policy: parse existing output file: %w", unmarshalErr)
		}
	}
	if strings.TrimSpace(cfg.Version) == "" {
		cfg.Version = "1"
	}
	if strings.TrimSpace(cfg.DefaultAction) == "" {
		cfg.DefaultAction = "allow"
	}
	cfg.Policies = append(cfg.Policies, policy)

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("policy: marshal appended config: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("policy: write appended config: %w", err)
	}
	return nil
}

func renderGeneratedConfigYAML(spec intentSpec, policy engine.Policy, explain string) ([]byte, error) {
	cfg := engine.Config{
		Version:       "1",
		DefaultAction: "allow",
		Policies:      []engine.Policy{policy},
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal generated config: %w", err)
	}

	header := fmt.Sprintf("# Generated by: rampart policy generate\n# Intent: %s\n# Strictness: %s\n# Details: %s\n# Generated: %s\n\n",
		spec.Intent,
		spec.Strictness,
		explain,
		time.Now().UTC().Format(time.RFC3339),
	)
	return append([]byte(header), raw...), nil
}

func detectPath(text string) string {
	m := pathCaptureRegexp.FindStringSubmatch(text)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func normalizePathPattern(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if strings.HasSuffix(path, "/") {
		return path + "**"
	}
	if strings.Contains(path, "*") {
		return path
	}
	if strings.Count(path, "/") == 1 {
		return path + "/**"
	}
	return path
}

func detectCommandKeywords(text string) []string {
	known := []string{
		"curl", "wget", "git", "sudo", "npm", "pnpm", "yarn", "pip", "python", "node", "rm",
		"dd", "mkfs", "wipefs", "shred", "kubectl", "docker", "terraform", "helm", "ansible",
	}
	out := make([]string, 0, 4)
	for _, k := range known {
		if strings.Contains(text, k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func stringContainsAny(text string, words []string) bool {
	for _, w := range words {
		if strings.Contains(text, w) {
			return true
		}
	}
	return false
}

func containsAllKeywords(text string, words []string) bool {
	for _, w := range words {
		if !strings.Contains(text, w) {
			return false
		}
	}
	return true
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	am := map[string]bool{}
	for _, x := range a {
		am[x] = true
	}
	for _, y := range b {
		if !am[y] {
			return false
		}
	}
	return true
}

func appendUnique(base []string, values ...string) []string {
	if base == nil {
		base = make([]string, 0, len(values))
	}
	seen := map[string]bool{}
	for _, b := range base {
		seen[b] = true
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		base = append(base, v)
	}
	return base
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "intent"
	}
	b := strings.Builder{}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s = slugRegexp.ReplaceAllString(b.String(), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "intent"
	}
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	if s == "" {
		return "intent"
	}
	return s
}
