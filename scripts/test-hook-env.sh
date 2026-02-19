#!/bin/bash
# Diagnostic hook — logs full stdin JSON + env to /tmp/rampart-hook-test.json
# Usage: add to ~/.claude/settings.json PreToolUse temporarily, run any Claude Code command

LOG=/tmp/rampart-hook-test.json
STDIN=$(cat)

python3 -c "
import json, os, sys

stdin = json.loads('$STDIN'.replace(\"'\", \"'\")) if False else json.loads(sys.stdin.read())
env_vars = {k: v for k, v in os.environ.items() if any(x in k.upper() for x in ['CLAUDE', 'RAMPART', 'SESSION', 'CONVERSATION', 'TRACE', 'PARENT'])}

result = {'stdin_fields': list(stdin.keys()), 'stdin': stdin, 'relevant_env': env_vars}
with open('$LOG', 'w') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result, indent=2), file=sys.stderr)
" <<< "$STDIN"

exit 0  # always allow
