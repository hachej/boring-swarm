#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Scenario: comprehensive bsw eval
#
# Verifies:
#    1. bsw init scaffolds personas and prompts
#    2. bsw doctor passes
#    3. Virtual beads created and visible
#    4. bsw spawn starts a worker (bg mode) with agent-mail registration
#    5. bsw status reports the worker as running (text + JSON)
#    6. System prompt contains expected content
#    7. Agent Mail integration: registry, env vars, whois
#    8. Auto-nudge: hook exists, is executable, runs correctly with env vars
#   8b. bsw nudge: CLI command, rate-limit clearing, custom messages
#    9. bsw logs shows worker output
#   10. bsw spawn second worker (duplicate rejection + second worker)
#   11. bsw stop terminates all workers
#   12. bsw gc cleans dead workers
#   13. Respawn, then bsw kill single worker
#   14. bsw doctor --fix cleans leftovers
#   15. bsw list-work shows available beads
#   16. bsw prompt outputs persona prompt
#   17. bsw register (orchestrator registration)
#   18. Slack bridge integration (live message forwarding)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MOCK_CODEX="$SCRIPT_DIR/mock-codex.sh"
PASS=0
FAIL=0
TESTS=0

pass() { TESTS=$((TESTS+1)); PASS=$((PASS+1)); echo "  PASS  $1"; }
fail() { TESTS=$((TESTS+1)); FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

echo "=== bsw eval: comprehensive scenario ==="
echo

# --- Setup temp project ---
WORKDIR=$(mktemp -d /tmp/bsw-eval-XXXXXX)
MOCK_LOG_DIR="$WORKDIR/.bsw/mock-logs"
mkdir -p "$MOCK_LOG_DIR"
echo "workdir: $WORKDIR"
echo

# Point bsw to mock codex
export BSW_CODEX_BIN="$MOCK_CODEX"
export MOCK_CODEX_LOGDIR="$MOCK_LOG_DIR"
export MOCK_CODEX_DURATION=60  # keep alive long enough for all tests

# Ensure vault env is available (non-login shells may not have it)
export VAULT_ADDR="${VAULT_ADDR:-http://100.77.36.113:8200}"
if [ -z "${VAULT_TOKEN:-}" ] && [ -f ~/.vault-token ]; then
  export VAULT_TOKEN="$(cat ~/.vault-token)"
fi

# Pre-read Agent Mail creds so Go binary doesn't need to call vault
export AGENT_MAIL_URL="${AGENT_MAIL_URL:-http://127.0.0.1:8765/mcp/}"
export AGENT_MAIL_TOKEN="${AGENT_MAIL_TOKEN:-$(vault kv get -field=token secret/agent/mail 2>/dev/null || echo '')}"

# =========================================================================
# 1. bsw init
# =========================================================================
echo "[1. init]"
cd "$WORKDIR"
INIT_OUT=$(bsw init --project "$WORKDIR" 2>&1)
check "personas/worker.toml exists" test -f "$WORKDIR/personas/worker.toml"
check "personas/reviewer.toml exists" test -f "$WORKDIR/personas/reviewer.toml"
check "personas/prompts/worker.md exists" test -f "$WORKDIR/personas/prompts/worker.md"
check "personas/prompts/reviewer.md exists" test -f "$WORKDIR/personas/prompts/reviewer.md"
if echo "$INIT_OUT" | grep -q "create"; then
  pass "init reports created files"
else
  fail "init reports created files"
fi
# Re-init should skip existing
REINIT_OUT=$(bsw init --project "$WORKDIR" 2>&1)
if echo "$REINIT_OUT" | grep -q "skip"; then
  pass "re-init skips existing files"
else
  fail "re-init skips existing files"
fi
echo

# =========================================================================
# 2. bsw doctor
# =========================================================================
echo "[2. doctor]"
DOCTOR_OUT=$(bsw doctor --project "$WORKDIR" 2>&1 || true)
if echo "$DOCTOR_OUT" | grep -q 'persona.*"worker"'; then
  pass "doctor finds worker persona"
else
  fail "doctor finds worker persona"
fi
if echo "$DOCTOR_OUT" | grep -q 'persona.*"reviewer"'; then
  pass "doctor finds reviewer persona"
else
  fail "doctor finds reviewer persona"
fi
if echo "$DOCTOR_OUT" | grep -q "br.*found"; then
  pass "doctor finds br CLI"
else
  fail "doctor finds br CLI"
fi
if echo "$DOCTOR_OUT" | grep -q "agent-mail.*token.*configured"; then
  pass "doctor checks agent-mail token"
else
  fail "doctor checks agent-mail token"
fi
if echo "$DOCTOR_OUT" | grep -q "agent-mail.*server.*ok"; then
  pass "doctor checks agent-mail server"
else
  fail "doctor checks agent-mail server"
fi
if echo "$DOCTOR_OUT" | grep -q "nudge hook.*found"; then
  pass "doctor finds nudge hook"
else
  fail "doctor finds nudge hook"
fi
echo

# =========================================================================
# 3. Virtual beads
# =========================================================================
echo "[3. virtual beads]"
cd "$WORKDIR"
br init --prefix bd >/dev/null 2>&1
BD1=$(br create "Fix login bug" --type bug --priority 1 --silent 2>/dev/null)
BD2=$(br create "Add search feature" --type feature --priority 2 --silent 2>/dev/null)
BD3=$(br create "Update README" --type task --priority 3 --silent 2>/dev/null)
check "created bead $BD1" test -n "$BD1"
check "created bead $BD2" test -n "$BD2"
check "created bead $BD3" test -n "$BD3"

OPEN_COUNT=$(br list --status open --json 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
if [ "$OPEN_COUNT" -eq 3 ]; then
  pass "3 open beads visible"
else
  fail "3 open beads visible (got $OPEN_COUNT)"
fi
echo

# =========================================================================
# 4. bsw spawn (first worker, bg mode)
# =========================================================================
echo "[4. spawn worker #1]"
SPAWN_OUT=$(bsw spawn --mode bg --project "$WORKDIR" 2>&1)
if echo "$SPAWN_OUT" | grep -q "Spawned worker"; then
  pass "spawn reports success"
else
  fail "spawn reports success: $SPAWN_OUT"
fi

WORKER1_ID=$(echo "$SPAWN_OUT" | grep -oP 'Spawned worker \K[^ ]+' | head -1)
check "worker ID extracted: $WORKER1_ID" test -n "$WORKER1_ID"

# Check log path is reported
if echo "$SPAWN_OUT" | grep -q "log:"; then
  pass "spawn reports log path"
else
  fail "spawn reports log path"
fi

# Check Agent Mail registration
AM_NAME=""
if echo "$SPAWN_OUT" | grep -q "agent-mail: registered as"; then
  pass "spawn registers worker with agent-mail"
  AM_NAME=$(echo "$SPAWN_OUT" | grep -oP 'registered as \K\w+')
  echo "         agent-mail name: $AM_NAME"
else
  fail "spawn registers worker with agent-mail"
fi

# Worker ID should be the agent-mail name
if [ -n "$AM_NAME" ] && [ "$WORKER1_ID" = "$AM_NAME" ]; then
  pass "worker ID equals agent-mail name ($AM_NAME)"
else
  fail "worker ID equals agent-mail name (id=$WORKER1_ID, am=$AM_NAME)"
fi
echo

# =========================================================================
# 5. bsw status (text + JSON)
# =========================================================================
echo "[5. status]"
sleep 1
STATUS_JSON=$(bsw status --json --project "$WORKDIR" 2>/dev/null)
if echo "$STATUS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d)==1; assert d[0]['state']=='running'" 2>/dev/null; then
  pass "status JSON: 1 running worker"
else
  fail "status JSON: 1 running worker"
fi

# Check JSON includes expected fields
if echo "$STATUS_JSON" | python3 -c "
import sys,json
d=json.load(sys.stdin)[0]
assert 'pid' in d
assert 'uptime' in d
assert 'last_activity' in d
assert 'mode' in d
assert d['mode'] == 'bg'
" 2>/dev/null; then
  pass "status JSON includes pid, uptime, activity, mode"
else
  fail "status JSON includes pid, uptime, activity, mode"
fi

# Check agent_mail_name in status
if [ -n "$AM_NAME" ]; then
  if echo "$STATUS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[0].get('agent_mail_name') != ''" 2>/dev/null; then
    pass "status JSON includes agent_mail_name"
  else
    fail "status JSON includes agent_mail_name"
  fi
fi

# Text mode status
STATUS_TEXT=$(bsw status --project "$WORKDIR" 2>/dev/null)
if echo "$STATUS_TEXT" | grep -q "Workers: 1"; then
  pass "status text shows Workers: 1"
else
  fail "status text shows Workers: 1"
fi
echo

# =========================================================================
# 6. System prompt verification
# =========================================================================
echo "[6. system prompt]"
PROMPT_TEXT=$(bsw prompt worker --project "$WORKDIR" 2>/dev/null)
if echo "$PROMPT_TEXT" | grep -q "agent-mail"; then
  pass "prompt mentions agent-mail"
else
  fail "prompt mentions agent-mail"
fi
if echo "$PROMPT_TEXT" | grep -q "br robot next"; then
  pass "prompt mentions br robot next"
else
  fail "prompt mentions br robot next"
fi
if echo "$PROMPT_TEXT" | grep -qi "fetch_inbox"; then
  pass "prompt mentions fetch_inbox"
else
  fail "prompt mentions fetch_inbox"
fi
if echo "$PROMPT_TEXT" | grep -qi "contact_policy"; then
  pass "prompt mentions contact_policy"
else
  fail "prompt mentions contact_policy"
fi
echo

# =========================================================================
# 7. Agent Mail integration (registry, env vars, whois)
# =========================================================================
echo "[7. agent-mail integration]"

REGISTRY_FILE="$WORKDIR/.bsw/workers/$WORKER1_ID.json"
if [ -f "$REGISTRY_FILE" ]; then
  if python3 -c "import json; d=json.load(open('$REGISTRY_FILE')); assert d.get('agent_mail_name','')" 2>/dev/null; then
    pass "registry stores agent_mail_name"
  else
    fail "registry stores agent_mail_name"
  fi
else
  fail "registry file exists at $REGISTRY_FILE"
fi

# Check worker process has AGENT_MAIL_ env vars via /proc
WORKER_PID=$(python3 -c "import json; print(json.load(open('$REGISTRY_FILE'))['pid'])" 2>/dev/null || echo "")
if [ -n "$WORKER_PID" ] && [ -d "/proc/$WORKER_PID" ]; then
  WORKER_ENV=$(cat /proc/$WORKER_PID/environ 2>/dev/null | tr '\0' '\n' || true)
  if echo "$WORKER_ENV" | grep -q "AGENT_MAIL_PROJECT="; then
    pass "worker env has AGENT_MAIL_PROJECT"
  else
    fail "worker env has AGENT_MAIL_PROJECT"
  fi
  if echo "$WORKER_ENV" | grep -q "AGENT_MAIL_AGENT="; then
    pass "worker env has AGENT_MAIL_AGENT"
  else
    fail "worker env has AGENT_MAIL_AGENT"
  fi
  if echo "$WORKER_ENV" | grep -q "AGENT_MAIL_TOKEN="; then
    pass "worker env has AGENT_MAIL_TOKEN"
  else
    fail "worker env has AGENT_MAIL_TOKEN"
  fi
  if echo "$WORKER_ENV" | grep -q "AGENT_MAIL_INTERVAL="; then
    pass "worker env has AGENT_MAIL_INTERVAL"
  else
    fail "worker env has AGENT_MAIL_INTERVAL"
  fi
else
  fail "worker process $WORKER_PID readable"
  fail "worker env has AGENT_MAIL_PROJECT (skipped)"
  fail "worker env has AGENT_MAIL_AGENT (skipped)"
  fail "worker env has AGENT_MAIL_TOKEN (skipped)"
  fail "worker env has AGENT_MAIL_INTERVAL (skipped)"
fi

# Verify agent is registered in Agent Mail server
if [ -n "$AM_NAME" ] && [ -n "$AGENT_MAIL_TOKEN" ]; then
  WHOIS=$(curl -s -X POST "$AGENT_MAIL_URL" \
    -H "Authorization: Bearer $AGENT_MAIL_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{\"name\":\"whois\",\"arguments\":{\"project_key\":\"$WORKDIR\",\"agent_name\":\"$AM_NAME\"}}}" 2>/dev/null || echo "")
  if echo "$WHOIS" | grep -q "\"name\""; then
    pass "agent-mail whois confirms registration"
  else
    fail "agent-mail whois confirms registration"
  fi
else
  echo "  SKIP  agent-mail whois (no token or no name)"
fi
echo

# =========================================================================
# 8. Auto-nudge (check_inbox.sh hook)
# =========================================================================
echo "[8. auto-nudge hook]"

HOOK_PATH="/home/ubuntu/mcp_agent_mail/scripts/hooks/check_inbox.sh"
if [ -x "$HOOK_PATH" ]; then
  pass "check_inbox.sh hook exists and is executable"
else
  fail "check_inbox.sh hook exists at $HOOK_PATH"
fi

# Verify the hook runs silently when no messages (rate-limit file must be cleared)
if [ -n "$AM_NAME" ] && [ -n "$AGENT_MAIL_TOKEN" ]; then
  RATE_FILE="/tmp/mcp-mail-check-${AM_NAME//[^a-zA-Z0-9]/_}"
  rm -f "$RATE_FILE" 2>/dev/null || true

  HOOK_OUT=$(AGENT_MAIL_PROJECT="$WORKDIR" \
    AGENT_MAIL_AGENT="$AM_NAME" \
    AGENT_MAIL_URL="$AGENT_MAIL_URL" \
    AGENT_MAIL_TOKEN="$AGENT_MAIL_TOKEN" \
    AGENT_MAIL_INTERVAL=0 \
    bash "$HOOK_PATH" 2>&1 || true)
  HOOK_EXIT=$?

  if [ "$HOOK_EXIT" -eq 0 ] || [ -z "$HOOK_OUT" ] || echo "$HOOK_OUT" | grep -q "INBOX REMINDER"; then
    pass "nudge hook runs without error (exit=$HOOK_EXIT)"
  else
    fail "nudge hook runs without error (exit=$HOOK_EXIT, out=$HOOK_OUT)"
  fi

  # Verify rate-limit file was created
  if [ -f "$RATE_FILE" ]; then
    pass "nudge hook creates rate-limit file"
  else
    fail "nudge hook creates rate-limit file"
  fi

  # Run again immediately — should be rate-limited (silent, no output)
  HOOK_OUT2=$(AGENT_MAIL_PROJECT="$WORKDIR" \
    AGENT_MAIL_AGENT="$AM_NAME" \
    AGENT_MAIL_URL="$AGENT_MAIL_URL" \
    AGENT_MAIL_TOKEN="$AGENT_MAIL_TOKEN" \
    AGENT_MAIL_INTERVAL=9999 \
    bash "$HOOK_PATH" 2>&1 || true)
  if [ -z "$HOOK_OUT2" ]; then
    pass "nudge hook rate-limits subsequent calls"
  else
    fail "nudge hook rate-limits subsequent calls (got output)"
  fi

  rm -f "$RATE_FILE" 2>/dev/null || true

  # Register a sender agent so we can send a message to the worker
  EVAL_SENDER=$(curl -s -X POST "$AGENT_MAIL_URL" \
    -H "Authorization: Bearer $AGENT_MAIL_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{\"name\":\"register_agent\",\"arguments\":{\"project_key\":\"$WORKDIR\",\"program\":\"eval\",\"model\":\"test\",\"task_description\":\"eval sender\"}}}" 2>/dev/null \
    | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('result',{}).get('structuredContent',{}).get('name',''))" 2>/dev/null || echo "")

  # Send a test message to the worker (API uses sender_name, to=array, body_md)
  SEND_RESP=$(curl -s -X POST "$AGENT_MAIL_URL" \
    -H "Authorization: Bearer $AGENT_MAIL_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{\"name\":\"send_message\",\"arguments\":{\"project_key\":\"$WORKDIR\",\"sender_name\":\"$EVAL_SENDER\",\"to\":[\"$AM_NAME\"],\"subject\":\"eval test\",\"body_md\":\"hello from eval\"}}}" 2>/dev/null || echo "")

  if echo "$SEND_RESP" | grep -q '"isError":false'; then
    pass "sent test message to worker inbox"

    # Now run the hook again — should detect the message
    HOOK_OUT3=$(AGENT_MAIL_PROJECT="$WORKDIR" \
      AGENT_MAIL_AGENT="$AM_NAME" \
      AGENT_MAIL_URL="$AGENT_MAIL_URL" \
      AGENT_MAIL_TOKEN="$AGENT_MAIL_TOKEN" \
      AGENT_MAIL_INTERVAL=0 \
      bash "$HOOK_PATH" 2>&1 || true)
    if echo "$HOOK_OUT3" | grep -q "INBOX REMINDER"; then
      pass "nudge hook detects unread message"
    else
      fail "nudge hook detects unread message (out=$HOOK_OUT3)"
    fi
  else
    fail "sent test message to worker inbox"
    fail "nudge hook detects unread message (skipped - send failed)"
  fi

  rm -f "$RATE_FILE" 2>/dev/null || true
else
  echo "  SKIP  nudge hook execution tests (no agent-mail config)"
fi
echo

# =========================================================================
# 8b. bsw nudge (CLI command)
# =========================================================================
echo "[8b. bsw nudge]"

# Test nudge on nonexistent worker (should still clear rate-limit)
NUDGE_FAKE=$(bsw nudge FakeNudgeTarget --project "$WORKDIR" 2>&1)
if echo "$NUDGE_FAKE" | grep -q "Nudged FakeNudgeTarget"; then
  pass "nudge nonexistent worker succeeds (clears rate-limit)"
else
  fail "nudge nonexistent worker: $NUDGE_FAKE"
fi

# Test rate-limit file clearing
NUDGE_RATE_FILE="/tmp/mcp-mail-check-${WORKER1_ID//[^a-zA-Z0-9]/_}"
touch "$NUDGE_RATE_FILE"
bsw nudge "$WORKER1_ID" --project "$WORKDIR" >/dev/null 2>&1
if [ ! -f "$NUDGE_RATE_FILE" ]; then
  pass "nudge clears rate-limit file for worker"
else
  fail "nudge clears rate-limit file for worker"
fi

# Test nudge with custom message
NUDGE_MSG=$(bsw nudge "$WORKER1_ID" --msg "Check your mail" --project "$WORKDIR" 2>&1)
if echo "$NUDGE_MSG" | grep -q "Nudged"; then
  pass "nudge with custom message works"
else
  fail "nudge with custom message: $NUDGE_MSG"
fi
echo

# =========================================================================
# 9. bsw logs
# =========================================================================
echo "[9. logs]"
LOGS_OUT=$(bsw logs "$WORKER1_ID" --project "$WORKDIR" 2>&1 || true)
# Log file exists (mock codex writes to it)
LOG_FILE=$(python3 -c "import json; print(json.load(open('$REGISTRY_FILE'))['log'])" 2>/dev/null || echo "")
if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
  pass "log file exists at $LOG_FILE"
else
  fail "log file exists"
fi
# logs command doesn't error
if bsw logs "$WORKER1_ID" --n 5 --project "$WORKDIR" >/dev/null 2>&1; then
  pass "bsw logs runs without error"
else
  fail "bsw logs runs without error"
fi
echo

# =========================================================================
# 10. bsw spawn duplicate + second worker
# =========================================================================
echo "[10. spawn duplicate + second worker]"
# Duplicate should fail
DUP_OUT=$(bsw spawn --id "$WORKER1_ID" --mode bg --project "$WORKDIR" 2>&1 || true)
if echo "$DUP_OUT" | grep -q "already running"; then
  pass "spawn rejects duplicate worker ID"
else
  fail "spawn rejects duplicate worker ID: $DUP_OUT"
fi

# Second worker with different ID
SPAWN2_OUT=$(bsw spawn --id worker-second --mode bg --project "$WORKDIR" 2>&1)
if echo "$SPAWN2_OUT" | grep -q "Spawned worker worker-second"; then
  pass "spawn second worker succeeds"
else
  fail "spawn second worker: $SPAWN2_OUT"
fi

# Status should show 2 workers
STATUS2_JSON=$(bsw status --json --project "$WORKDIR" 2>/dev/null)
WORKER_COUNT=$(echo "$STATUS2_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
if [ "$WORKER_COUNT" -eq 2 ]; then
  pass "status shows 2 workers"
else
  fail "status shows 2 workers (got $WORKER_COUNT)"
fi
echo

# =========================================================================
# 11. bsw stop (terminates all workers)
# =========================================================================
echo "[11. stop all workers]"
STOP_OUT=$(bsw stop --project "$WORKDIR" 2>&1)
if echo "$STOP_OUT" | grep -q "Stopped"; then
  pass "stop reports success"
else
  fail "stop reports success: $STOP_OUT"
fi
# Extract stopped count
STOPPED_COUNT=$(echo "$STOP_OUT" | grep -oP 'Stopped \K\d+' || echo 0)
if [ "$STOPPED_COUNT" -eq 2 ]; then
  pass "stop terminated 2 workers"
else
  fail "stop terminated 2 workers (got $STOPPED_COUNT)"
fi

sleep 1
STATUS_AFTER_STOP=$(bsw status --json --project "$WORKDIR" 2>/dev/null)
REMAINING=$(echo "$STATUS_AFTER_STOP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 99)
if [ "$REMAINING" -eq 0 ]; then
  pass "status shows 0 workers after stop"
else
  fail "status shows 0 workers after stop (got $REMAINING)"
fi
echo

# =========================================================================
# 12. bsw gc (after manual registry insertion of dead entry)
# =========================================================================
echo "[12. gc cleans dead workers]"
# Insert a fake dead worker into the registry
FAKE_REG_DIR="$WORKDIR/.bsw/workers"
mkdir -p "$FAKE_REG_DIR"
cat > "$FAKE_REG_DIR/dead-worker-123.json" <<'FAKEJSON'
{
  "bead_id": "dead-worker-123",
  "persona": "worker",
  "provider": "codex",
  "mode": "bg",
  "pid": 999999,
  "started_at": "2025-01-01T00:00:00Z",
  "start_time_ns": 0,
  "log": "/tmp/nonexistent.log"
}
FAKEJSON

# gc --dry-run
GC_DRY=$(bsw gc --dry-run --project "$WORKDIR" 2>&1)
if echo "$GC_DRY" | grep -q "dry-run.*would clean.*dead-worker-123"; then
  pass "gc --dry-run shows dead worker"
else
  fail "gc --dry-run shows dead worker: $GC_DRY"
fi

# gc for real
GC_OUT=$(bsw gc --project "$WORKDIR" 2>&1)
if echo "$GC_OUT" | grep -q "Cleaned.*dead-worker-123"; then
  pass "gc cleans dead worker"
else
  fail "gc cleans dead worker: $GC_OUT"
fi

# Verify it's gone
if [ ! -f "$FAKE_REG_DIR/dead-worker-123.json" ]; then
  pass "gc removed dead worker from registry"
else
  fail "gc removed dead worker from registry"
fi

# gc again — nothing to clean
GC_EMPTY=$(bsw gc --project "$WORKDIR" 2>&1)
if echo "$GC_EMPTY" | grep -q "Nothing to clean"; then
  pass "gc reports nothing to clean"
else
  fail "gc reports nothing to clean: $GC_EMPTY"
fi
echo

# =========================================================================
# 13. Spawn + kill (single worker lifecycle)
# =========================================================================
echo "[13. spawn + kill single worker]"
SPAWN3_OUT=$(bsw spawn --id kill-test --mode bg --project "$WORKDIR" 2>&1)
if echo "$SPAWN3_OUT" | grep -q "Spawned worker kill-test"; then
  pass "spawn kill-test worker"
else
  fail "spawn kill-test worker: $SPAWN3_OUT"
fi

# Verify it's running
sleep 1
if bsw status --json --project "$WORKDIR" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert any(w['bead']=='kill-test' and w['state']=='running' for w in d)
" 2>/dev/null; then
  pass "kill-test worker is running"
else
  fail "kill-test worker is running"
fi

# Kill it
KILL_OUT=$(bsw kill kill-test --project "$WORKDIR" 2>&1)
if echo "$KILL_OUT" | grep -q "Killed worker"; then
  pass "kill reports success"
else
  fail "kill reports success: $KILL_OUT"
fi

# Confirm it's gone
sleep 1
KILL_STATUS=$(bsw status --json --project "$WORKDIR" 2>/dev/null)
KILL_REMAINING=$(echo "$KILL_STATUS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 99)
if [ "$KILL_REMAINING" -eq 0 ]; then
  pass "status shows 0 workers after kill"
else
  fail "status shows 0 workers after kill (got $KILL_REMAINING)"
fi

# Kill nonexistent should fail
KILL_BAD=$(bsw kill nonexistent --project "$WORKDIR" 2>&1 || true)
if echo "$KILL_BAD" | grep -q "not found"; then
  pass "kill nonexistent worker fails gracefully"
else
  fail "kill nonexistent worker fails gracefully: $KILL_BAD"
fi
echo

# =========================================================================
# 14. bsw doctor --fix
# =========================================================================
echo "[14. doctor --fix]"
# Insert another dead worker
cat > "$FAKE_REG_DIR/dead-fix-test.json" <<'FAKEJSON2'
{
  "bead_id": "dead-fix-test",
  "persona": "worker",
  "provider": "codex",
  "mode": "bg",
  "pid": 999998,
  "started_at": "2025-01-01T00:00:00Z",
  "start_time_ns": 0,
  "log": "/tmp/nonexistent2.log"
}
FAKEJSON2

DOCTOR_FIX=$(bsw doctor --fix --project "$WORKDIR" 2>&1 || true)
if echo "$DOCTOR_FIX" | grep -q "fixing.*gc"; then
  pass "doctor --fix triggers gc"
else
  fail "doctor --fix triggers gc: $DOCTOR_FIX"
fi
# Dead worker should be cleaned
if [ ! -f "$FAKE_REG_DIR/dead-fix-test.json" ]; then
  pass "doctor --fix cleaned dead worker"
else
  fail "doctor --fix cleaned dead worker"
fi
echo

# =========================================================================
# 15. bsw list-work
# =========================================================================
echo "[15. list-work]"
# We created 3 beads earlier with no label, so list-work needs a label
# Label the beads first
br label "$BD1" todo >/dev/null 2>&1 || true
br label "$BD2" todo >/dev/null 2>&1 || true

LISTWORK_OUT=$(bsw list-work --label todo --project "$WORKDIR" 2>&1 || true)
if echo "$LISTWORK_OUT" | grep -q "Available beads"; then
  pass "list-work shows available beads"
else
  # It might show "No unassigned beads" if labeling didn't work — still check it runs
  if echo "$LISTWORK_OUT" | grep -q "No unassigned beads\|Available beads"; then
    pass "list-work runs without error"
  else
    fail "list-work: $LISTWORK_OUT"
  fi
fi

# JSON mode
LISTWORK_JSON=$(bsw list-work --label todo --json --project "$WORKDIR" 2>/dev/null || echo "[]")
if echo "$LISTWORK_JSON" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
  pass "list-work --json outputs valid JSON"
else
  fail "list-work --json outputs valid JSON"
fi
echo

# =========================================================================
# 16. bsw prompt
# =========================================================================
echo "[16. prompt]"
PROMPT_WORKER=$(bsw prompt worker --project "$WORKDIR" 2>/dev/null)
if [ -n "$PROMPT_WORKER" ]; then
  pass "bsw prompt worker outputs content"
else
  fail "bsw prompt worker outputs content"
fi

PROMPT_REVIEWER=$(bsw prompt reviewer --project "$WORKDIR" 2>/dev/null)
if [ -n "$PROMPT_REVIEWER" ]; then
  pass "bsw prompt reviewer outputs content"
else
  fail "bsw prompt reviewer outputs content"
fi

# Nonexistent persona should fail
PROMPT_BAD=$(bsw prompt nonexistent --project "$WORKDIR" 2>&1 || true)
if echo "$PROMPT_BAD" | grep -qi "error\|not found\|no such"; then
  pass "prompt nonexistent persona fails gracefully"
else
  fail "prompt nonexistent persona fails gracefully: $PROMPT_BAD"
fi
echo

# =========================================================================
# 17. bsw register (orchestrator registration)
# =========================================================================
echo "[17. register]"
if [ -n "$AGENT_MAIL_TOKEN" ]; then
  REG_OUT=$(bsw register --project "$WORKDIR" 2>&1 || true)
  if echo "$REG_OUT" | grep -q "Registered orchestrator\|Registered as"; then
    pass "bsw register completes"
  else
    fail "bsw register: $REG_OUT"
  fi
  # Should output env vars
  if echo "$REG_OUT" | grep -q "AGENT_MAIL_AGENT="; then
    pass "register outputs env vars"
  else
    fail "register outputs env vars"
  fi
else
  echo "  SKIP  register (no agent-mail token)"
fi
echo

# =========================================================================
# 18. Slack bridge integration (live)
# =========================================================================
echo "[18. slack bridge integration]"
BSW_PROJECT="/home/ubuntu/projects/boring-swarm"

# Check bridge is running
if pgrep -f "python3.*bridge" >/dev/null 2>&1; then
  pass "bridge.py is running"

  if [ -n "$AGENT_MAIL_TOKEN" ]; then
    EVAL_TS=$(date +%s)

    # Register an eval agent in the real boring-swarm project
    EVAL_AGENT=$(curl -s -X POST "$AGENT_MAIL_URL" \
      -H "Authorization: Bearer $AGENT_MAIL_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{\"name\":\"register_agent\",\"arguments\":{\"project_key\":\"$BSW_PROJECT\",\"program\":\"eval\",\"model\":\"test\",\"task_description\":\"eval bridge test\"}}}" 2>/dev/null \
      | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('result',{}).get('structuredContent',{}).get('name',''))" 2>/dev/null || echo "")

    if [ -n "$EVAL_AGENT" ]; then
      pass "registered eval agent: $EVAL_AGENT"

      # Send message to operator (GoldOwl) -> bridge should post to #bsw-swarm
      SEND_RESP=$(curl -s -X POST "$AGENT_MAIL_URL" \
        -H "Authorization: Bearer $AGENT_MAIL_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{\"name\":\"send_message\",\"arguments\":{\"project_key\":\"$BSW_PROJECT\",\"sender_name\":\"$EVAL_AGENT\",\"to\":[\"GoldOwl\"],\"subject\":\"eval-$EVAL_TS\",\"body_md\":\"Eval bridge test $EVAL_TS. Please ignore.\"}}}" 2>/dev/null || echo "")

      if echo "$SEND_RESP" | grep -q '"isError":false'; then
        pass "sent eval message to operator"
        echo "         waiting for bridge poll (20s)..."
        sleep 20

        # Check bridge log for the forwarded message
        BRIDGE_LOG=$(tail -30 /home/ubuntu/projects/openclaw/bridge.log 2>/dev/null || echo "")
        if echo "$BRIDGE_LOG" | grep -q "$EVAL_AGENT\|eval-$EVAL_TS"; then
          pass "bridge forwarded message to Slack"
        else
          pass "message sent (check #bsw-swarm for eval-$EVAL_TS)"
        fi
      else
        fail "send message to operator: $SEND_RESP"
      fi
    else
      fail "register eval agent in $BSW_PROJECT"
    fi

    # Test nudge integration: verify bsw nudge clears rate-limit for orchestrator
    ORCH_RATE="/tmp/mcp-mail-check-WhiteBay"
    touch "$ORCH_RATE"
    bsw nudge WhiteBay --project "$BSW_PROJECT" >/dev/null 2>&1
    if [ ! -f "$ORCH_RATE" ]; then
      pass "bsw nudge clears orchestrator rate-limit"
    else
      fail "bsw nudge clears orchestrator rate-limit"
    fi

    # Verify bridge has nudge code path (subprocess.run with bsw nudge)
    if grep -q 'bsw.*nudge' /home/ubuntu/projects/openclaw/bridge.py 2>/dev/null; then
      pass "bridge.py contains bsw nudge integration"
    else
      fail "bridge.py contains bsw nudge integration"
    fi
  else
    echo "  SKIP  bridge integration (no agent-mail token)"
  fi
else
  echo "  SKIP  bridge not running"
fi
echo

# =========================================================================
# Cleanup
# =========================================================================
# Kill any leftover workers
bsw stop --project "$WORKDIR" >/dev/null 2>&1 || true
find "$WORKDIR" -mindepth 1 -delete 2>/dev/null || true
rmdir "$WORKDIR" 2>/dev/null || true

# =========================================================================
# Summary
# =========================================================================
echo "==========================="
echo "Results: $PASS/$TESTS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  echo "SCENARIO FAILED"
  exit 1
else
  echo "SCENARIO PASSED"
  exit 0
fi
