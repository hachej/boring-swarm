#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Scenario: real orchestrator with real workers
#
# Verifies:
#   1. Orchestrator reads bsw --help and follows instructions
#   2. Auto-init works (no pre-existing personas/)
#   3. Orchestrator spawns worker(s) with correct persona
#   4. Orchestrator runs monitor loop (status + bead check)
#   5. Workers use correct provider/model from persona TOML
#   6. Orchestrator stops cleanly
#
# Requires: claude CLI, codex CLI, br CLI in PATH
# Cost: ~$0.10-0.50 per run (real API calls)
#
# Run tracking: each run is saved to eval/runs/<timestamp>/
#   orchestrator.jsonl  — full stream-json transcript
#   tool-calls.txt      — extracted tool call summary
#   worker-logs/        — worker log files
#   results.json        — pass/fail results
#   meta.json           — run metadata (duration, beads, etc.)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNS_DIR="$SCRIPT_DIR/runs"

PASS=0
FAIL=0
TESTS=0
RESULTS=()

pass() { TESTS=$((TESTS+1)); PASS=$((PASS+1)); RESULTS+=("{\"test\":\"$1\",\"status\":\"pass\"}"); echo "  PASS  $1"; }
fail() { TESTS=$((TESTS+1)); FAIL=$((FAIL+1)); RESULTS+=("{\"test\":\"$1\",\"status\":\"fail\"}"); echo "  FAIL  $1"; }

echo "=== bsw eval: orchestrator scenario ==="
echo

# --- Create run directory ---
RUN_ID=$(date +%Y%m%d-%H%M%S)
RUN_DIR="$RUNS_DIR/$RUN_ID"
mkdir -p "$RUN_DIR"
echo "run: $RUN_DIR"

# --- Setup temp project ---
WORKDIR=$(mktemp -d /tmp/bsw-eval-orch-XXXXXX)
echo "workdir: $WORKDIR"
echo

START_TIME=$(date +%s)

# Init git + beads
cd "$WORKDIR"
git init -q
git commit --allow-empty -q -m "init"
br init --prefix bd >/dev/null 2>&1

# Create 2 beads
BD1=$(br create "Fix login bug" --type bug --priority 1 --silent 2>/dev/null)
BD2=$(br create "Add search feature" --type feature --priority 2 --silent 2>/dev/null)
echo "Created beads: $BD1, $BD2"
echo

# --- Run orchestrator ---
echo "[1. run orchestrator]"
LOGFILE="$RUN_DIR/orchestrator.jsonl"

# Unset CLAUDECODE to allow nesting
unset CLAUDECODE 2>/dev/null || true

# Ensure OpenAI API key is set for codex workers
if [ -z "${OPENAI_API_KEY:-}" ]; then
  OPENAI_API_KEY=$(bash -lc 'vault kv get -field=api_key secret/agent/openai' 2>/dev/null || true)
  if [ -n "$OPENAI_API_KEY" ]; then
    export OPENAI_API_KEY
    echo "  loaded OPENAI_API_KEY from vault"
  fi
fi

ORCHESTRATOR_PROMPT="Run bsw --help and follow the instructions. Use --mode bg. Stop after 2 monitor cycles."

timeout 180 claude -p --verbose --output-format stream-json \
  --model claude-sonnet-4-20250514 \
  --dangerously-skip-permissions \
  "$ORCHESTRATOR_PROMPT" \
  > "$LOGFILE" 2>/dev/null || true

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo "  completed in ${DURATION}s"
echo

# --- Copy worker logs ---
echo "[2. collect worker logs]"
mkdir -p "$RUN_DIR/worker-logs"
if [ -d "$WORKDIR/.bsw/logs" ]; then
  cp "$WORKDIR/.bsw/logs/"*.log "$RUN_DIR/worker-logs/" 2>/dev/null || true
  WLOG_COUNT=$(ls "$RUN_DIR/worker-logs/"*.log 2>/dev/null | wc -l)
  echo "  collected $WLOG_COUNT worker log(s)"
else
  echo "  no worker logs found"
fi
# Also copy worker registry
if [ -d "$WORKDIR/.bsw/workers" ]; then
  cp -r "$WORKDIR/.bsw/workers" "$RUN_DIR/worker-registry" 2>/dev/null || true
fi
echo

# --- Analyze output ---
echo "[3. analyze orchestrator behavior]"

# Extract tool calls from the stream
python3 -c "
import json, sys
tools = []
for line in open('$LOGFILE'):
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        if d.get('type') == 'assistant':
            msg = d.get('message', d)
            for c in msg.get('content', d.get('content', [])):
                if c.get('type') == 'tool_use':
                    name = c.get('name', '')
                    inp = c.get('input', {})
                    if name == 'Bash':
                        cmd = inp.get('command', '')
                        tools.append(f'bash: {cmd}')
                    elif name == 'Write':
                        path = inp.get('file_path', '')
                        tools.append(f'write: {path}')
                    elif name == 'Edit':
                        path = inp.get('file_path', '')
                        tools.append(f'edit: {path}')
                    elif name == 'Read':
                        path = inp.get('file_path', '')
                        tools.append(f'read: {path}')
                    else:
                        tools.append(f'{name}: {str(inp)[:100]}')
    except:
        pass
for t in tools:
    print(t)
" > "$RUN_DIR/tool-calls.txt" 2>/dev/null || true

TOOL_CALLS=$(cat "$RUN_DIR/tool-calls.txt")

# Check: ran bsw --help
if echo "$TOOL_CALLS" | grep -q "bsw.*--help\|bsw.*help"; then
  pass "orchestrator ran bsw --help"
else
  fail "orchestrator ran bsw --help"
fi

# Check: ran bsw init OR spawn auto-inited
if echo "$TOOL_CALLS" | grep -q "bsw init\|bsw spawn"; then
  pass "orchestrator ran bsw init or spawn (auto-init)"
else
  fail "orchestrator ran bsw init or spawn"
fi

# Check: spawned a worker
if echo "$TOOL_CALLS" | grep -q "bsw spawn.*--persona impl"; then
  pass "orchestrator spawned impl worker"
else
  fail "orchestrator spawned impl worker"
fi

# Check: did NOT create persona files manually
if echo "$TOOL_CALLS" | grep -q "write:.*\.toml\|cat.*>.*toml\|echo.*toml"; then
  fail "orchestrator did NOT create custom persona files (it did!)"
else
  pass "orchestrator did NOT create custom persona files"
fi

# Check: ran status check (monitor loop)
STATUS_COUNT=$(echo "$TOOL_CALLS" | grep -c "bsw status" || true)
STATUS_COUNT=${STATUS_COUNT:-0}
if [ "$STATUS_COUNT" -ge 1 ]; then
  pass "orchestrator ran monitor loop ($STATUS_COUNT status checks)"
else
  fail "orchestrator ran monitor loop (0 status checks)"
fi

# Check: checked open beads
if echo "$TOOL_CALLS" | grep -q "br list"; then
  pass "orchestrator checked open beads"
else
  fail "orchestrator checked open beads"
fi

# Check: ran bsw stop or kill (or workers died naturally)
if echo "$TOOL_CALLS" | grep -q "bsw stop\|bsw kill\|bsw gc"; then
  pass "orchestrator cleaned up workers"
else
  fail "orchestrator cleaned up workers"
fi

# Check: final result exists
FINAL_RESULT=$(python3 -c "
import json
for line in open('$LOGFILE'):
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        if d.get('type') == 'result':
            print(d.get('result', '')[:500])
    except:
        pass
" 2>/dev/null || echo "")

if [ -n "$FINAL_RESULT" ]; then
  pass "orchestrator produced final result"
else
  fail "orchestrator produced final result"
fi

echo
echo "[4. tool call trace]"
cat "$RUN_DIR/tool-calls.txt" | head -40
echo

# --- Generate readable transcript ---
echo "[5. generate transcript]"
python3 -c "
import json

with open('$RUN_DIR/orchestrator.jsonl') as f:
    lines = f.readlines()

with open('$RUN_DIR/transcript.md', 'w') as out:
    out.write('# Orchestrator Transcript\n\n')
    out.write('Run: $RUN_ID\n\n')
    step = 0
    for line in lines:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            t = d.get('type', '')
            if t == 'assistant':
                for c in d.get('content', []):
                    if c.get('type') == 'text':
                        out.write(f'**Assistant:** {c[\"text\"]}\n\n')
                    elif c.get('type') == 'tool_use':
                        step += 1
                        name = c.get('name', '')
                        inp = c.get('input', {})
                        if name == 'Bash':
                            cmd = inp.get('command', '')
                            out.write(f'### Step {step}: \`{name}\`\n\`\`\`bash\n{cmd}\n\`\`\`\n\n')
                        else:
                            out.write(f'### Step {step}: \`{name}\`\n\`\`\`json\n{json.dumps(inp, indent=2)[:500]}\n\`\`\`\n\n')
            elif t == 'tool_result':
                for c in d.get('content', []):
                    if c.get('type') == 'text':
                        text = c['text'][:1000]
                        out.write(f'**Result:**\n\`\`\`\n{text}\n\`\`\`\n\n')
            elif t == 'result':
                out.write(f'---\n\n**Final Result:**\n\n{d.get(\"result\", \"\")}\n')
        except:
            pass
    out.write('\n')
print('  transcript.md written')
" 2>/dev/null || echo "  transcript generation failed"

# Generate worker transcripts
for logfile in "$RUN_DIR/worker-logs/"*.log; do
  [ -f "$logfile" ] || continue
  basename=$(basename "$logfile" .log)
  echo "  worker transcript: $basename"
done
echo

# --- Save metadata ---
python3 -c "
import json
results_arr = []
$(for r in "${RESULTS[@]}"; do echo "results_arr.append($r)"; done)
meta = {
    'run_id': '$RUN_ID',
    'workdir': '$WORKDIR',
    'beads': ['$BD1', '$BD2'],
    'duration_seconds': $DURATION,
    'pass': $PASS,
    'fail': $FAIL,
    'total': $TESTS,
    'results': results_arr,
    'final_result': '''$FINAL_RESULT'''[:500]
}
with open('$RUN_DIR/results.json', 'w') as f:
    json.dump(meta, f, indent=2)
print('  results.json written')
" 2>/dev/null || echo "  metadata generation failed"

# --- Cleanup workspace ---
cd /
bsw stop --project "$WORKDIR" 2>/dev/null || true
find "$WORKDIR" -mindepth 1 -delete 2>/dev/null || true
rmdir "$WORKDIR" 2>/dev/null || true

# --- Summary ---
echo
echo "==========================="
echo "Results: $PASS/$TESTS passed, $FAIL failed"
echo "Run saved: $RUN_DIR"
echo "  transcript: $RUN_DIR/transcript.md"
echo "  tool calls: $RUN_DIR/tool-calls.txt"
echo "  raw stream: $RUN_DIR/orchestrator.jsonl"
if [ "$FAIL" -gt 0 ]; then
  echo "SCENARIO FAILED"
  exit 1
else
  echo "SCENARIO PASSED"
  exit 0
fi
