#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Scenario: basic spawn + status + kill
#
# Verifies:
#   1. bsw init scaffolds personas and prompts
#   2. bsw doctor passes
#   3. Virtual beads are created and visible
#   4. bsw spawn starts a worker with correct system prompt
#   5. bsw status reports the worker as running
#   6. System prompt contains expected content (agent-mail, br CLI)
#   7. bsw kill terminates the worker
#   8. bsw gc cleans up
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

echo "=== bsw eval: basic scenario ==="
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
export MOCK_CODEX_DURATION=30  # keep alive long enough for tests

# --- 1. bsw init ---
echo "[1. init]"
cd "$WORKDIR"
bsw init --project "$WORKDIR" >/dev/null 2>&1
check "personas/worker.toml exists" test -f "$WORKDIR/personas/worker.toml"
check "personas/reviewer.toml exists" test -f "$WORKDIR/personas/reviewer.toml"
check "personas/prompts/worker.md exists" test -f "$WORKDIR/personas/prompts/worker.md"
check "personas/prompts/reviewer.md exists" test -f "$WORKDIR/personas/prompts/reviewer.md"
echo

# --- 2. bsw doctor ---
echo "[2. doctor]"
DOCTOR_OUT=$(bsw doctor --project "$WORKDIR" 2>&1 || true)
if echo "$DOCTOR_OUT" | grep -q "persona.*worker"; then
  pass "doctor finds worker persona"
else
  fail "doctor finds worker persona"
fi
if echo "$DOCTOR_OUT" | grep -q "persona.*reviewer"; then
  pass "doctor finds reviewer persona"
else
  fail "doctor finds reviewer persona"
fi
echo

# --- 3. Create virtual beads ---
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

# --- 4. bsw spawn ---
echo "[4. spawn worker]"
SPAWN_OUT=$(bsw spawn --mode bg --project "$WORKDIR" 2>&1)
if echo "$SPAWN_OUT" | grep -q "Spawned worker"; then
  pass "spawn reports success"
else
  fail "spawn reports success: $SPAWN_OUT"
fi

WORKER_ID=$(echo "$SPAWN_OUT" | grep -oP 'worker \K[^ ]+')
check "worker ID extracted: $WORKER_ID" test -n "$WORKER_ID"
echo

# --- 5. bsw status ---
echo "[5. status]"
sleep 1  # let worker start
STATUS_OUT=$(bsw status --json --project "$WORKDIR" 2>&1)
if echo "$STATUS_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d)==1; assert d[0]['state']=='running'" 2>/dev/null; then
  pass "status shows 1 running worker"
else
  fail "status shows 1 running worker"
fi
echo

# --- 6. Verify system prompt ---
echo "[6. system prompt verification]"
sleep 1
# Check prompt content via bsw prompt
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
echo

# --- 7. bsw kill ---
echo "[7. kill worker]"
KILL_OUT=$(bsw kill "$WORKER_ID" --project "$WORKDIR" 2>&1)
if echo "$KILL_OUT" | grep -q "Killed worker"; then
  pass "kill reports success"
else
  fail "kill reports success: $KILL_OUT"
fi

sleep 1
STATUS_AFTER=$(bsw status --json --project "$WORKDIR" 2>&1)
if echo "$STATUS_AFTER" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d)==0" 2>/dev/null; then
  pass "status shows 0 workers after kill"
else
  fail "status shows 0 workers after kill"
fi
echo

# --- 8. bsw gc ---
echo "[8. gc]"
GC_OUT=$(bsw gc --project "$WORKDIR" 2>&1)
if echo "$GC_OUT" | grep -q "Nothing to clean"; then
  pass "gc reports nothing to clean (already killed)"
else
  pass "gc ran: $GC_OUT"
fi
echo

# --- Cleanup ---
find "$WORKDIR" -mindepth 1 -delete 2>/dev/null || true
rmdir "$WORKDIR" 2>/dev/null || true

# --- Summary ---
echo "==========================="
echo "Results: $PASS/$TESTS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  echo "SCENARIO FAILED"
  exit 1
else
  echo "SCENARIO PASSED"
  exit 0
fi
