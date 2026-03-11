#!/usr/bin/env bash
# Mock codex CLI for eval scenarios.
# Logs all arguments so the test can verify system prompt, model, etc.

LOGDIR="${MOCK_CODEX_LOGDIR:-.}"
LOGFILE="$LOGDIR/mock-codex-$(date +%s)-$$.json"

# Read stdin if "-" is the last arg (codex exec reads prompt from stdin)
STDIN_DATA=""
if [ "${!#}" = "-" ]; then
  STDIN_DATA=$(cat)
fi

# Use python3 to produce valid JSON from args
python3 -c "
import json, sys
args = sys.argv[1:]
stdin_data = sys.argv[-1] if len(sys.argv) > 1 else ''

# Parse key flags
model = ''
i = 0
while i < len(args):
    if args[i] == '--model' and i+1 < len(args):
        model = args[i+1]
        i += 2
    else:
        i += 1

data = {
    'pid': $$,
    'args': args,
    'model': model,
    'stdin_length': len('$STDIN_DATA'),
    'stdin_first_line': '$STDIN_DATA'.split(chr(10))[0][:100] if '$STDIN_DATA' else '',
}
with open('$LOGFILE', 'w') as f:
    json.dump(data, f, indent=2)
" "$@"

# Simulate work
DURATION="${MOCK_CODEX_DURATION:-5}"
sleep "$DURATION"
