# bsw v2 — Implementation Plan

**Objective**: Fleet orchestration primitives for orchestrator agents. Keep behavior simple, deterministic, and operationally robust.

**Related**: `DSL.md` defines queue DSL and runtime contracts.

---

## Core Principles

1. **Beads are workflow truth**: labels/comments/assignee define durable workflow state.
2. **Runtime registry is control-plane cache**: process/session metadata is persisted for ops, not workflow truth.
3. **Single owner for mutations**: `bsw` owns assignment + transitions; workers only emit STATE.
4. **Structured IO only**: JSONL events, JSON status; no regex parsing of human text.
5. **Orchestrator-owned policy**: retry/escalation/approval decisions remain outside `bsw`.
6. **Operator-first visibility**: one status payload must expose queue state, bead ownership, session refs, and attention items.

---

## Design Guardrails (What NOT to Do)

- Don't build a workflow engine.
- Don't let workers mutate labels/assignee.
- Don't infer state from terminal UI text.
- Don't hide failure conditions (emit explicit `attention`/`conflict` events).
- Don't auto-retry/escalate inside `bsw`.
- Don't lose provider session refs on restart.

---

## CLI Philosophy

`bsw` is a small set of orchestrator primitives.

```bash
bsw init
bsw doctor
bsw run flows/queue.yaml [--mode oneshot|service]
bsw status --json [--explain]
bsw ping <bead-id>
bsw kill <bead-id>
bsw stop
```

- `oneshot` (default): exits when queue drains.
- `service`: remains running to handle queue refill (parallel-safe).

---

## Output Model

- JSONL runtime events in `.bsw/logs/<queue>-<run-id>.jsonl`
- Same events echoed to stdout
- `bsw status --json` gives full operational snapshot
- Exit code reports run status (only for `oneshot` lifecycle completion)

---

## Architecture (6 Layers)

```text
Orchestrator
  |
bsw
  1) DSL Engine           (strict parse/validate)
  2) Queue Reconciler     (claim, dispatch, transition)
  3) Process Manager      (spawn/kill/exit watch)
  4) State Detector       (provider events + lifecycle + stuck timer)
  5) Cursor/Registry      (idempotency + persisted session refs)
  6) Status/Attention     (overview + actionable problems)
  |
Agents (Claude/Codex)
  |
Beads (labels/comments/assignee)
```

---

## Primitives (What We Build)

### 1. DSL Parser
- Input: `flows/*.yaml`
- Output: `FlowSpec`
- Strict: unknown keys fail parse

### 2. Queue Executor (Claim -> Work -> Transition)
- List beads in `source.label`
- Claim unassigned bead atomically (`assignee="" -> <agent-name>` compare-and-swap)
- Generate `assignment_token=<run-id>:<bead-id>:<attempt>`
- Spawn worker with prompt layering:
  - system prompt from DSL (`workers.prompt`) containing role/global rules
  - runtime context payload from `bsw` containing bead/run/transition context
- Accept first valid terminal STATE for active token
- Apply transition atomically and clear assignee

### 3. Agent State Detector
- Provider stream: Claude JSONL / Codex JSON-RPC
- Process lifecycle: pid exit signal + code
- Stuck timer with invariant: `waiting_input` pauses stuck escalation
- Emit explicit state updates: `active|waiting_input|idle|blocked|exited`

### 4. Idempotency + Replay Safety
- Persist `last_processed_comment_id` per bead
- Only process comments with `id > cursor`
- Ignore stale/duplicate token events (`ignored_stale_state`)

### 5. Process Registry + Resume
- Persist per-bead runtime entry in `.bsw/agents/<bead-id>.json`
- Include provider-normalized session metadata
- On restart: reconcile live process table + registry + bead assignment
- Mark orphaned entries and surface via `attention`

### 6. Status + Attention
- `status --json` includes:
  - queue totals/unassigned/assigned
  - bead ownership + lifecycle hints
  - agent provider/session refs + resume command
  - attention list with suggested action
- `status --json --explain` adds deterministic reason fields for every bead/agent state

### 7. Agent Communication Primitive
- `bsw ping <bead-id>` nudges current assigned agent to check agent-mail
- Orchestrator handles mail content and decision policy

---

## Module Structure

```text
cli/bsw/
  main.go

  dsl/
    types.go
    parser.go
    validator.go

  engine/
    runner.go
    reconciler.go
    transition.go
    cursor.go

  process/
    manager.go
    registry.go

  agent/
    state.go
    claude.go
    codex.go

  beads/
    client.go

  status/
    snapshot.go
    attention.go

  cmd/
    init.go
    doctor.go
    run.go
    status.go
    ping.go
    kill.go
    stop.go
```

---

## Data Formats

### `.bsw/agents/bd-123.json`

```json
{
  "bead_id": "bd-123",
  "role": "implement",
  "pid": 4521,
  "provider": "codex",
  "session_ref": "thread_abc123",
  "resume_command": "codex app-server --thread thread_abc123",
  "agent_name": "GreenLake",
  "assignment_token": "run-20260227-abc123:bd-123:2",
  "started_at": "2026-02-27T10:00:00Z",
  "last_progress_ts": "2026-02-27T10:12:03Z",
  "last_processed_comment_id": 481
}
```

### `.bsw/run.json`

```json
{
  "run_id": "run-20260227-abc123",
  "flow": "flows/implement_queue.yaml",
  "mode": "oneshot",
  "started_at": "2026-02-27T10:00:00Z",
  "status": "running"
}
```

### `bsw status --json`

```json
{
  "run": {
    "run_id": "run-20260227-abc123",
    "flow": "flows/implement_queue.yaml",
    "mode": "oneshot",
    "status": "running"
  },
  "queues": {
    "needs-impl": {"total": 7, "unassigned": 3, "assigned": 4},
    "needs-proof": {"total": 2, "unassigned": 2, "assigned": 0}
  },
  "beads": [
    {
      "bead_id": "bd-123",
      "label": "needs-impl",
      "assignee": "GreenLake",
      "assignment_token": "run-20260227-abc123:bd-123:2",
      "activity_state": "waiting_input",
      "last_state_event": "impl:blocked",
      "last_progress_ts": "2026-02-27T10:12:03Z"
    }
  ],
  "agents": [
    {
      "agent_name": "GreenLake",
      "bead_id": "bd-123",
      "provider": "codex",
      "session_ref": "thread_abc123",
      "resume_command": "codex app-server --thread thread_abc123",
      "pid": 4521,
      "activity_state": "waiting_input"
    }
  ],
  "attention": [
    {
      "bead_id": "bd-123",
      "reason": "waiting_input",
      "suggested_action": "send_mail_then_ping"
    }
  ]
}
```

### `.bsw/logs/implement_queue-<run-id>.jsonl`

```jsonl
{"event":"spawn","bead_id":"bd-123","assignment_token":"run-20260227-abc123:bd-123:2","agent":"GreenLake","provider":"codex","session_ref":"thread_abc123","pid":4521,"ts":"2026-02-27T10:00:00Z"}
{"event":"state","bead_id":"bd-123","assignment_token":"run-20260227-abc123:bd-123:2","value":"impl:done","comment_id":481,"ts":"2026-02-27T10:05:00Z"}
{"event":"transition","bead_id":"bd-123","from":"needs-impl","to":"needs-proof","assignment_token":"run-20260227-abc123:bd-123:2","ts":"2026-02-27T10:05:01Z"}
{"event":"done","bead_id":"bd-123","assignment_token":"run-20260227-abc123:bd-123:2","ts":"2026-02-27T10:05:01Z"}
```

---

## Key Contracts

### STATE Event Contract
Worker emits one of these accepted forms:

```text
STATE <event> assignment=<assignment_token>
state: <event> assignment=<assignment_token>
```

Normalization contract:
- Accept both `STATE ...` and `state: ...`
- Normalize to canonical lowercase before validation (e.g. `STATE PROOF:PASSED` -> `proof:passed`)

`bsw` accepts STATE only when:
- event exists in `transitions`
- assignment token matches active claim
- comment id is newer than cursor

### Prompt Contract
- `workers.prompt` is a system prompt source (role + global invariants).
- `bsw` injects runtime context as separate context payload (bead metadata, token, allowed transitions).
- Runtime payload must not redefine policy rules; policy remains in system prompt.

### Transition Contract
`bsw` performs one atomic bead update:
- remove `source.label`
- add target label from `transitions[event]`
- clear assignee

If precondition fails, emit `transition_conflict`; do not partially update.

### Claim Contract
- `bsw` must claim with compare-and-swap semantics: only claim when bead is still unassigned.
- If claim CAS fails, emit `claim_conflict` and continue to next candidate.
- Worker must never start without a successful claim.
- Release on timeout/crash must be guarded: clear assignee only if current assignee matches the active worker.

### Preflight Contract
- `bsw run` MUST execute `br doctor` before starting queue processing.
- If doctor reports malformed JSONL/config errors, fail fast with actionable error and non-zero exit.
- In `service` mode, re-run doctor periodically (and on detected parse/config errors), emitting `attention: beads_health_failed` on failure.

### Stuck Contract
- If no progress past timeout and state != `waiting_input`: emit `attention: stuck_no_progress`
- If `waiting_input`: pause stuck escalation timer
- No automatic retry/escalation inside `bsw`

### Drain Contract (`no_work_left`)
- In `oneshot` mode, `bsw` must exit only when all are true:
  - source queue has zero unassigned beads
  - source queue has zero assigned beads
  - worker process table has zero running workers for this queue
- On satisfaction, emit `drained` event with queue/process snapshot, then exit `0`.
- If queue is empty but assigned/running remains, do not exit; emit explanatory status reasons.

---

## Orchestrator-Facing Recovery Loop

Given `status.attention[]`:

1. `waiting_input` -> send approval/feedback mail, `bsw ping <bead-id>`
2. `stuck_no_progress` -> inspect `resume_command`; optionally `bsw kill <bead-id>` then rerun queue
3. `orphaned_assignment` -> clear assignment and requeue bead
4. `transition_conflict` -> refresh bead state and decide manual repair

---

## Implementation Order

1. DSL types/parser/validator
2. Beads client (`list`, `update`, `comments`)
3. Assignment + token generation
4. Provider state adapters (Claude/Codex)
5. Process manager + registry persistence
6. Comment cursor + idempotent STATE handler
7. Atomic transition applier
8. Status snapshot + attention generator
9. CLI commands (`run/status/ping/kill/stop`)
10. Integration tests for failure modes

---

## Success Criteria (Phase 1)

- ✅ `bsw run` deterministic in `oneshot` and `service` modes
- ✅ No worker-driven label/assignee mutations
- ✅ Idempotent STATE handling across restart
- ✅ `status --json` exposes queue, bead ownership, provider session refs, attention
- ✅ Stuck detection never false-fires on `waiting_input`
- ✅ Manual resume path available from status for every assigned bead
- ✅ No regex parsing of unstructured output

---

## Open Questions (Before Coding)

1. Exact Codex JSON-RPC events needed for `waiting_input` and `blocked`
2. Exact `br` command shape for single-call transition mutation with preconditions
3. Whether comment ids are globally monotonic or per-bead monotonic
4. Default stuck timeout value and whether it should be configurable
