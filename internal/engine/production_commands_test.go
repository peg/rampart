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

package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// Commands remain inert strings: these tests do not invoke a CLI or service.
func TestProductionGuardCLI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := NewMemoryStore([]byte("version: \"1\"\ndefault_action: allow\n"), "test:base")
	eng, err := New(NewLayeredStore(base, filepath.Join("..", "..", "policies", "production-guard.yaml"), logger), logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		want    Action
	}{
		{`terraform apply saved.plan`, ActionAsk},
		{`terraform -chdir=infra apply -var 'name=-help' -auto-approve`, ActionAsk},
		{`tofu -chdir=dev destroy`, ActionAsk},
		{`terraform import example.resource id`, ActionAsk},
		{`terraform state mv old new`, ActionAsk},
		{`terraform state rm example.resource`, ActionAsk},
		{`terraform state push state.json`, ActionAsk},
		{`terraform state replace-provider old new`, ActionAsk},
		{`terraform force-unlock lock-id`, ActionAsk},
		{`/usr/local/bin/terraform apply -input=false`, ActionAsk},
		{`env -i command terraform -chdir=infra apply`, ActionAsk},
		{`sh -c 'git status; terraform -chdir=infra apply saved.plan'`, ActionAsk},
		{`printf ok; to'fu' apply`, ActionAsk},
		{`pulumi --cwd infra --stack dev up --yes`, ActionAsk},
		{`pulumi -Cinfra destroy --target urn:test`, ActionAsk},
		{`pulumi refresh --stack production`, ActionAsk},
		{`prisma migrate deploy --schema schema.prisma`, ActionAsk},
		{`npx --no-install prisma migrate deploy --config prisma.config.ts`, ActionAsk},
		{`pnpm exec prisma db push --accept-data-loss`, ActionAsk},
		{`npm exec -- prisma migrate deploy`, ActionAsk},
		{`alembic -c migrations.ini upgrade head`, ActionAsk},
		{`alembic downgrade -1`, ActionAsk},
		{`alembic -x '--sql' upgrade head`, ActionAsk},
		{`kubectl --context production apply -f deployment.yaml`, ActionAsk},
		{`kubectl apply -f deployment.yaml --context=prod`, ActionAsk},
		{`kubectl delete deployment/web -nprod`, ActionAsk},
		{`kubectl --namespace production patch deployment/web --type merge -p '{"spec":{"replicas":2}}'`, ActionAsk},
		{`kubectl replace -f deployment.yaml -n production`, ActionAsk},
		{`kubectl scale deployment/web --replicas=2 --context prod`, ActionAsk},
		{`kubectl -nproduction rollout restart deployment/web`, ActionAsk},
		{`kubectl --context prod --namespace dev apply -f file.yaml`, ActionAsk},
		{`kubectl --context dev --context prod apply -f file.yaml`, ActionAsk},
		{`kubectl apply -f file.yaml --namespace dev -nprod`, ActionAsk},
		{`kubectl apply -f file.yaml --context production --dry-run=none`, ActionAsk},
		{`git status`, ActionAllow},
		{`npm test`, ActionAllow},
		{`terraform -chdir=production plan -destroy -out plan`, ActionAllow},
		{`terraform show production.plan`, ActionAllow},
		{`terraform state list`, ActionAllow},
		{`terraform output`, ActionAllow},
		{`terraform apply -help`, ActionAllow},
		{`terraform -help apply`, ActionAllow},
		{`pulumi preview --stack production`, ActionAllow},
		{`pulumi stack ls`, ActionAllow},
		{`pulumi refresh --preview-only`, ActionAllow},
		{`prisma migrate dev`, ActionAllow},
		{`prisma migrate status`, ActionAllow},
		{`prisma migrate diff`, ActionAllow},
		{`prisma migrate deploy --help`, ActionAllow},
		{`alembic current`, ActionAllow},
		{`alembic upgrade head --sql`, ActionAllow},
		{`kubectl get pods --context production`, ActionAllow},
		{`kubectl rollout status deployment/web -nprod`, ActionAllow},
		{`kubectl apply view-last-applied -f file.yaml --context production`, ActionAllow},
		{`kubectl apply -f production.yaml --context dev`, ActionAllow},
		{`kubectl apply -f file.yaml --context production-east`, ActionAllow},
		{`kubectl apply -f file.yaml`, ActionAllow},
		{`kubectl --context prod --context dev apply -f file.yaml`, ActionAllow},
		{`kubectl apply -f file.yaml -nprod --namespace dev`, ActionAllow},
		{`kubectl apply -f file.yaml --field-manager '--context production'`, ActionAllow},
		{`kubectl apply -f file.yaml --context 'prod --namespace production'`, ActionAllow},
		{`kubectl apply -f file.yaml --context production --dry-run=client`, ActionAllow},
		{`kubectl apply -f file.yaml --context production --dry-run=server`, ActionAllow},
		{`echo 'example; terraform apply'`, ActionAllow},
		{`printf '%s' 'example; kubectl apply --context production'`, ActionAllow},
		{`sh -c "printf '%s' 'example; terraform apply'"`, ActionAllow},
		// Explicit contract limits: no config lookup, variable expansion,
		// arbitrary package runners or unknown option arity inference.
		{`kubectl apply -f file.yaml --context "$CONTEXT"`, ActionAllow},
		{`terraform --future-option example apply`, ActionAllow},
		{`npx --package arbitrary prisma migrate deploy`, ActionAllow},
		{`python -c 'run_migration()'`, ActionAllow},
	} {
		t.Run(tc.command, func(t *testing.T) {
			call := ToolCall{Tool: "exec", Params: map[string]any{"command": tc.command}}
			if got := eng.Evaluate(call).Action; got != tc.want {
				t.Fatalf("action = %s, want %s", got, tc.want)
			}
			if call.Command() != tc.command {
				t.Fatal("matching changed command identity")
			}
		})
	}
	if got := eng.Evaluate(ToolCall{Tool: "mcp", Params: map[string]any{"command": "terraform apply"}}).Action; got != ActionAllow {
		t.Fatal("CLI profile claimed a native MCP mutation")
	}
}

func TestProductionAliasesAreRestrictiveOnly(t *testing.T) {
	cond := Condition{CommandMatches: []string{"terraform apply"}}
	call := ToolCall{Tool: "exec", Params: map[string]any{"command": `terraform -chdir=infra apply saved.plan`}}
	for _, action := range []Action{ActionAllow, ActionWatch, ActionWebhook, ActionAsk, ActionDeny} {
		want := actionRestrictsExecution(action)
		if got := matchConditionForAction(cond, call, nil, action); got != want {
			t.Errorf("%s match = %t, want %t", action, got, want)
		}
		if got, _ := ExplainConditionForAction(cond, call, action); got != want {
			t.Errorf("%s explanation = %t, want %t", action, got, want)
		}
	}
}

func TestRestrictiveOriginalComponentBoundaries(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{`echo 'example; rm -rf /'`, false},
		{`sh -c "printf '%s' 'example; rm -rf /'"`, false},
		{`sh -c 'printf ok; rm -rf /'`, true},
		{`env -i bash -c 'printf ok; sh -c "rm -rf /"'`, true},
		{`printf ok; rm -rf /`, true},
	} {
		if got := matchRestrictiveCommandFirst([]string{"rm -rf /"}, tc.command, ActionDeny) != ""; got != tc.want {
			t.Errorf("%q match = %t, want %t", tc.command, got, tc.want)
		}
	}
}

func TestRestrictiveComponentDepthFailsClosed(t *testing.T) {
	command := "printf ok"
	for range 20 {
		command = "case x in x) " + command + ";; esac"
	}
	if len(command) > maxGlobInputLen {
		t.Fatal("fixture must exercise the depth bound below the input-size bound")
	}
	if got := matchRestrictiveCommandFirst([]string{"unmatched-command"}, command, ActionDeny); got == "" {
		t.Fatal("incomplete component analysis weakened the restriction")
	}
	if restrictiveCommandComponentExcluded([]string{"**"}, command) {
		t.Fatal("incomplete component analysis established an exclusion")
	}
}

func TestProductionGuardOverlayPreservesBaseRestrictions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	for _, name := range []string{"production-guard.yaml", "community/terraform.yaml", "community/kubernetes.yaml"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "policies", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(name)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	eng, err := New(NewMultiStore(filepath.Join("..", "..", "policies", "standard.yaml"), dir, logger), logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		want    Action
	}{
		{`terraform destroy -auto-approve`, ActionDeny},
		{`kubectl delete namespace production`, ActionDeny},
		{`rm -rf /`, ActionDeny},
		{`terraform apply saved.plan`, ActionAsk},
		{`git status`, ActionAllow},
	} {
		if got := eng.Evaluate(ToolCall{Tool: "exec", Params: map[string]any{"command": tc.command}}).Action; got != tc.want {
			t.Errorf("%q action = %s, want %s", tc.command, got, tc.want)
		}
	}
	cfg, err := NewFileStore(filepath.Join("..", "..", "policies", "production-guard.yaml")).Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultAction != "" {
		t.Fatal("overlay must not set the base default action")
	}
}

func FuzzProductionCommandAliases(f *testing.F) {
	for _, command := range []string{`kubectl --context production apply -f file.yaml`, `terraform -chdir=infra apply`, `echo 'example; terraform apply'`, `alembic -x '--sql' upgrade head`} {
		f.Add(command)
	}
	f.Fuzz(func(t *testing.T, command string) {
		visits := 0
		visitProductionCommandAliases(command, func(alias string) bool {
			visits++
			if visits > 1 || alias == "" {
				t.Fatal("invalid or non-terminating alias visitor")
			}
			return false
		})
	})
}

func BenchmarkProductionGuard(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := NewFileStore(filepath.Join("..", "..", "policies", "standard.yaml"))
	overlay := NewLayeredStore(base, filepath.Join("..", "..", "policies", "production-guard.yaml"), logger)
	for _, profile := range []struct {
		name  string
		store PolicyStore
	}{{"standard", base}, {"standard-plus-production", overlay}} {
		eng, err := New(profile.store, logger)
		if err != nil {
			b.Fatal(err)
		}
		for _, input := range []struct{ name, command string }{
			{"routine", `git status --short`},
			{"plan", `terraform -chdir=infra plan -out=plan`},
			{"mutation", `kubectl --context production apply -f deployment.yaml`},
		} {
			b.Run(profile.name+"/"+input.name, func(b *testing.B) {
				call := ToolCall{Tool: "exec", Params: map[string]any{"command": input.command}}
				b.ReportAllocs()
				for b.Loop() {
					eng.Evaluate(call)
				}
			})
		}
	}
}
