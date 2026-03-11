#!/usr/bin/env bash
# Mock claude CLI for eval scenarios.
# Logs all arguments so the test can verify system prompt, model, etc.

LOGDIR="${MOCK_CLAUDE_LOGDIR:-.}"
LOGFILE="$LOGDIR/mock-claude-$(date +%s)-$$.json"

# Use python3 to produce valid JSON from args
python3 -c "
import json, sys
args = sys.argv[1:]

# Parse key flags
system_prompt = ''
model = ''
i = 0
while i < len(args):
    if args[i] == '--system-prompt' and i+1 < len(args):
        system_prompt = args[i+1]
        i += 2
    elif args[i] == '--model' and i+1 < len(args):
        model = args[i+1]
        i += 2
    else:
        i += 1

data = {
    'pid': $$,
    'args': args,
    'model': model,
    'mode': 'print' if '-p' in args else 'interactive',
    'system_prompt_length': len(system_prompt),
    'system_prompt_first_line': system_prompt.split(chr(10))[0] if system_prompt else '',
    'system_prompt': system_prompt,
}
with open('$LOGFILE', 'w') as f:
    json.dump(data, f, indent=2)
" "$@"

# Simulate work
DURATION="${MOCK_CLAUDE_DURATION:-5}"
sleep "$DURATION"
