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

import "strings"

// These aliases describe a small set of literal CLI mutations. They are used
// only by restrictive rules, including production-guard and existing guard /
// community policies. They never authorize a command or replace its identity.
// Unknown options, expansions and package-runner forms produce no alias.
func visitProductionCommandAliases(command string, visit func(string) bool) {
	if len(command) > maxGlobInputLen {
		return
	}
	words, ok := literalShellWords(command)
	if !ok {
		return
	}
	inv, ok := parseLiteralInvocation(words)
	if !ok {
		return
	}
	args := unwrapLiteralExecutor(inv.args)
	if len(args) == 0 {
		return
	}
	args = unwrapPrismaRunner(args)
	base := shellWrapperBasename(args[0])
	var spec cliOptionSpec
	switch base {
	case "terraform", "tofu":
		spec = cliOptionSpec{
			values:   "-chdir -var -var-file -target -replace -parallelism -lock-timeout -state -state-out -backup -out -config",
			switches: "-help -version -no-color -auto-approve -input -lock -refresh -refresh-only -destroy -compact-warnings -ignore-remote-version -force -allow-missing-config",
		}
	case "pulumi":
		spec = cliOptionSpec{
			values:      "--cwd -C --stack -s --color --config -c --config-file --target --replace --parallel -p --policy-pack --policy-pack-config --message -m --exclude",
			switches:    "--help -h --yes -y --skip-preview --preview-only --diff --json --non-interactive --target-dependents --exclude-dependents --refresh --show-secrets --suppress-outputs",
			shortValues: "Cscpm",
		}
	case "prisma":
		spec = cliOptionSpec{values: "--schema --config", switches: "--help -h --accept-data-loss --force-reset --skip-generate"}
	case "alembic":
		spec = cliOptionSpec{values: "--config -c --name -n -x --tag", switches: "--help -h --raiseerr --sql", shortValues: "cnx"}
	case "kubectl":
		spec = cliOptionSpec{
			values:      "--context --namespace -n --kubeconfig --cluster --user --server -s --as --as-group --request-timeout --filename -f --kustomize -k --selector -l --output -o --type --patch -p --patch-file --replicas --field-manager --resource-version --timeout --grace-period --dry-run --cascade",
			switches:    "--help -h --force --all --all-namespaces -A --overwrite --save-config --server-side --force-conflicts --wait --recursive -R --ignore-not-found --record --local",
			shortValues: "nsfklop",
		}
	default:
		return
	}
	pos, opts, ok := scanCLIOptions(args[1:], spec)
	if !ok || len(pos) == 0 || cliSwitchOn(opts, "--help", "-h", "-help", "-version") {
		return
	}
	emit := func(verb string) { visit(base + " " + verb) }
	switch base {
	case "terraform", "tofu":
		switch pos[0] {
		case "apply", "destroy", "import", "force-unlock":
			emit(pos[0])
		case "state":
			if len(pos) > 1 && cliListed("mv rm push replace-provider", pos[1]) {
				emit("state " + pos[1])
			}
		}
	case "pulumi":
		if cliListed("up destroy refresh", pos[0]) && !cliSwitchOn(opts, "--preview-only") {
			emit(pos[0])
		}
	case "prisma":
		if len(pos) == 2 && (pos[0] == "migrate" && pos[1] == "deploy" || pos[0] == "db" && pos[1] == "push") {
			emit(strings.Join(pos, " "))
		}
	case "alembic":
		if cliListed("upgrade downgrade", pos[0]) && !cliSwitchOn(opts, "--sql") {
			emit(pos[0])
		}
	case "kubectl":
		verb := pos[0]
		if verb == "rollout" && len(pos) > 1 && pos[1] == "restart" {
			verb = "rollout restart"
		} else if !cliListed("apply delete patch replace scale", verb) || verb == "apply" && len(pos) > 1 {
			return
		}
		if opts["--dry-run"] == "client" || opts["--dry-run"] == "server" || cliSwitchOn(opts, "--local") {
			return
		}
		for _, key := range []string{"--context", "--namespace"} {
			// Keep targets as single literal operands in the semantic spelling.
			// This also prevents a quoted value from injecting a second flag.
			if target := opts[key]; target != "" && !strings.ContainsAny(target, " \t\r\n'\"\\;&|<>(){}") {
				if !visit("kubectl " + verb + " " + key + " " + target) {
					return
				}
			}
		}
	}
}

type cliOptionSpec struct {
	values, switches, shortValues string
}

// scanCLIOptions consumes known value operands before considering verbs or
// target flags. Last occurrence wins, including a short/long spelling pair.
// The parser intentionally does not guess the arity of unknown options.
func scanCLIOptions(args []string, spec cliOptionSpec) ([]string, map[string]string, bool) {
	var pos []string
	opts := make(map[string]string)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" || len(arg) > 1 && isUnsignedDigits(arg[1:]) {
			pos = append(pos, arg)
			continue
		}
		key, value, attached := strings.Cut(arg, "=")
		if !attached && len(arg) > 2 && arg[1] != '-' && strings.ContainsRune(spec.shortValues, rune(arg[1])) {
			key, value, attached = arg[:2], arg[2:], true
		}
		switch {
		case cliListed(spec.values, key):
			if !attached {
				if i+1 == len(args) {
					return nil, nil, false
				}
				i++
				value = args[i]
			}
		case cliListed(spec.switches, key):
			if !attached {
				value = "true"
			} else if value != "true" && value != "false" {
				return nil, nil, false
			}
		default:
			return nil, nil, false
		}
		if key == "-n" && cliListed(spec.values, "--namespace") {
			key = "--namespace"
		}
		opts[key] = value
	}
	return pos, opts, true
}

func cliListed(list, value string) bool {
	return value != "" && !strings.ContainsAny(value, " \t\r\n") && strings.Contains(" "+list+" ", " "+value+" ")
}

func cliSwitchOn(opts map[string]string, names ...string) bool {
	for _, name := range names {
		if opts[name] == "true" {
			return true
		}
	}
	return false
}

func unwrapPrismaRunner(args []string) []string {
	if len(args) < 2 {
		return args
	}
	switch shellWrapperBasename(args[0]) {
	case "npx":
		i := 1
		for i < len(args) && cliListed("-y --yes --no-install --", args[i]) {
			i++
		}
		if i < len(args) && args[i] == "prisma" {
			return args[i:]
		}
	case "pnpm":
		if len(args) > 2 && args[1] == "exec" && args[2] == "prisma" {
			return args[2:]
		}
	case "npm":
		if len(args) > 3 && args[1] == "exec" && args[2] == "--" && args[3] == "prisma" {
			return args[3:]
		}
	}
	return args
}
