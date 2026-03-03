# bsw v2 — Queue-Based DSL

Worker queue definitions. Agents execute beads and emit STATE. `bsw` owns assignment and transitions.

---

## Core Concept

**Queue = beads with a specific label** (e.g., `needs-impl`, `needs-proof`)

**DSL defines**:
1. Source queue (bead label)
2. Worker pool (count, provider, model, prompt)
3. Target queues (STATE event -> next label)
4. Role system prompt path (`workers.prompt`)

**That's it.** No workflow engine. No composition. Just queues and transitions.

---

## Execution Ownership (Critical)

Single-owner model for robustness:

- `bsw` owns bead assignment (`assignee`) and label transitions
- Worker owns task execution and emits terminal STATE
- Orchestrator owns policy decisions (retry, escalate, feedback, stop/start)

This prevents double moves, assignment races, and stale-session transitions.

---

## Schema

```yaml
version: 1

name: implement_queue           # human-readable name

source:
  label: needs-impl             # bead label

workers:
  count: 3                      # max parallel workers
  provider: codex               # claude or codex
  model: gpt-5-codex
  effort: high
  prompt: prompts/impl_worker.md # system prompt (role + global rules)

transitions:
  impl:done: needs-proof        # STATE event -> next label
  impl:error: needs-review

timeout: 4h                     # max worker runtime
```

---

## Terminology

| Term | Meaning |
|---|---|
| **Queue** | Beads with a specific label (e.g., `needs-impl`) |
| **Source queue** | Initial label for this queue spec |
| **Worker** | Agent instance processing one claimed bead |
| **Count** | Max parallel workers |
| **Transition** | STATE event -> move bead to new label |
| **Assignment token** | Unique id for one bead claim attempt |
| **Target queue** | Label bead gets after STATE event |

---

## Example: Implementation Queue

```yaml
version: 1

name: implementation_workers

source:
  label: needs-impl

workers:
  count: 3
  provider: codex
  model: gpt-5-codex
  effort: high
  prompt: prompts/impl_worker.md

transitions:
  "impl:done": needs-proof
  "impl:error": needs-review

timeout: 4h
```

**Execution**:
1. `bsw` lists beads with `needs-impl`
2. `bsw` claims unassigned beads atomically (CAS: `assignee="" -> <agent-name>`)
3. `bsw` spawns up to `workers.count`
4. Worker writes `STATE impl:done assignment=<token>`
5. `bsw` validates token/event and applies transition
6. Bead appears in `needs-proof`

---

## Example: Proof Queue

```yaml
version: 1

name: proof_workers

source:
  label: needs-proof

workers:
  count: 2
  provider: codex
  model: gpt-5-codex
  effort: high
  prompt: prompts/impl_proofer.md

transitions:
  "proof:passed": needs-review
  "proof:failed": needs-impl

timeout: 2h
```

**Loop behavior**: `proof:failed` returns bead to `needs-impl`.

---

## Fields

| Field | Type | Required | Purpose |
|---|---|---|---|
| `version` | int | ✅ | DSL version (1) |
| `name` | string | ✅ | Queue name |
| `source.label` | string | ✅ | Source bead label |
| `workers.count` | int | ✅ | Max parallel workers |
| `workers.provider` | string | ✅ | `claude` or `codex` |
| `workers.model` | string | ✅ | Model identifier |
| `workers.effort` | string | ❌ | `low`/`medium`/`high` |
| `workers.prompt` | path | ✅ | Prompt path (relative to `.bsw/`) |
| `transitions` | map | ✅ | STATE event -> target label |
| `timeout` | duration | ❌ | Max worker runtime (`4h`, `30m`) |

---

## Execution Model

**Run modes**:

- `oneshot` (default): exits when queue drained and workers finished
- `service`: stays alive to handle refill (recommended for parallel queues)

**Pull-based processing**:

```text
1. bsw run flows/review_queue.yaml [--mode oneshot|service]

2. Main loop:
   beads = br list --label needs-review

   for each unassigned bead:
     if workers_running < count:
       claim bead (CAS assignee="" -> <agent-name>)
       if claim_conflict: continue
       token = <run-id>:<bead-id>:<attempt>
       spawn worker(bead_id, token)

   worker:
     - Gets bead
     - Works
     - Writes one terminal STATE comment with token
     - Exits

   bsw:
     - Watches new comments (id > cursor)
     - Validates STATE + assignment token
     - Applies transition atomically
     - Clears assignee
     - Emits JSONL events

   if mode=oneshot and queue empty and workers idle:
     stop workers and exit(0)
```

---

## Worker Responsibility

Worker (agent) must:

1. **Get bead**: `br get <bead-id>`
2. **Work**: Execute task from system prompt + runtime context payload
3. **Emit terminal STATE once** (either accepted syntax):
   ```bash
   br comments add <bead-id> "STATE <event> assignment=<token>"
   # or
   br comments add <bead-id> "state: <event> assignment=<token>"
   ```
4. **Exit**: do not change labels/assignee

**Valid STATE events** are exactly the keys in `transitions`.
`bsw` normalizes STATE payload to lowercase canonical form before validation.

## Prompt Layering Contract

`bsw` uses two prompt layers:

1. **System prompt** (from `workers.prompt`)
   - Role behavior and global rules/invariants.
   - Includes hard constraints: no label/assignee mutation, one terminal STATE, assignment token usage.
2. **Runtime context payload** (generated by `bsw`)
   - Bead id/title/description
   - Source label
   - Assignment token
   - Allowed transition keys
   - Optional run metadata (attempt/run id)

Runtime payload is context-only; policy rules stay in system prompt.

---

## Transition Contract

`bsw` applies transitions using one mutation step with preconditions:

- precondition: bead still has `source.label`
- precondition: bead still assigned to current worker/attempt
- mutation: remove `source.label`, add `target.label`, clear assignee

If preconditions fail, `bsw` emits a conflict event and does not partially mutate.

## Claim Contract

`bsw` claims with compare-and-swap semantics:
- precondition: assignee is empty
- mutation: set assignee to worker/agent name

If precondition fails, emit `claim_conflict`, skip bead, continue loop.
Worker must not start without successful claim.

On timeout/crash release:
- guarded clear only if current assignee matches the active worker (no foreign-claim clears)

---

## Idempotency Contract

To survive crashes/restarts without replay bugs:

- `bsw` tracks `last_processed_comment_id` per bead
- only comments with id `> cursor` are processed
- only first terminal STATE for active assignment token is accepted
- stale token comments are ignored and logged as `ignored_stale_state`

---

## Orchestration Pattern

**Sequential execution** (simplest):

```bash
bsw run flows/implement_queue.yaml
bsw run flows/proof_queue.yaml
bsw run flows/review_queue.yaml
```

**Parallel execution** (refill-safe):

```bash
bsw run flows/implement_queue.yaml --mode service &
bsw run flows/proof_queue.yaml --mode service &
bsw run flows/review_queue.yaml --mode service &
wait
```

---

## Constraints

### Required

- Every emitted STATE event must exist in `transitions`
- `transitions` is exhaustive (no fallback/default)
- Unknown YAML keys are parse errors
- Worker never mutates labels/assignee
- `bsw` is the only transition owner
- `bsw run` performs `br doctor` preflight before queue processing
- If preflight fails (malformed JSONL/config), fail fast with actionable error
- In `service` mode, `bsw` periodically re-runs health check and emits `attention: beads_health_failed` on failure

### Bead Lifecycle

1. Bead enters source label
2. `bsw` claims bead and starts worker
3. Worker emits terminal STATE
4. `bsw` transitions bead + clears assignee
5. Next queue picks bead up
6. Continue until terminal state (`closed` or equivalent)

**Note**: Retry/escalation policy remains orchestrator-owned.

---

## Limits (Phase 1)

**Phase 1 supports**:
- ✅ Single queue definition per DSL
- ✅ Sequential chains
- ✅ Backward transitions
- ✅ Concurrency limits (`workers.count`)
- ✅ Timeout per worker
- ✅ Provider/model selection
- ✅ `oneshot` and `service` run modes
- ✅ Idempotent STATE processing with comment cursor + assignment token

**Not in Phase 1 (orchestrator handles)**:
- ❌ Retry strategy
- ❌ Escalation strategy
- ❌ Approval policy
- ❌ Dynamic worker count
- ❌ Multiple source labels
- ❌ Priority/weighted queues

---

## Usage

```bash
# Queue run (default oneshot)
bsw run flows/impl_queue.yaml

# Refill-safe run (parallel topology)
bsw run flows/impl_queue.yaml --mode service

# Full state overview
bsw status --json
bsw status --json --explain

# Nudge assigned agent to check mail
bsw ping <bead-id>

# Force kill assigned worker process
bsw kill <bead-id>

# Graceful shutdown
bsw stop
```

---

## Orchestrator Overview Contract

`bsw status --json` must answer all of these at once:

- Queue state now
- Which bead is in which state/label
- Which agent/session owns each assigned bead
- Which beads need operator action

```json
{
  "queues": {
    "needs-impl": {"total": 7, "unassigned": 3, "assigned": 4},
    "needs-proof": {"total": 2, "unassigned": 2, "assigned": 0},
    "needs-review": {"total": 1, "unassigned": 1, "assigned": 0}
  },
  "beads": [
    {
      "bead_id": "bd-123",
      "label": "needs-impl",
      "assignee": "GreenLake",
      "assignment_token": "run-20260227:bd-123:2",
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
      "activity_state": "waiting_input",
      "reason": "provider_waiting_input"
    }
  ],
  "attention": [
    {
      "bead_id": "bd-123",
      "reason": "waiting_input",
      "suggested_action": "send_mail_then_ping"
    }
  ],
  "explain": {
    "queue_state": "not_drained",
    "drain_reasons": [
      "assigned_beads_remaining",
      "running_workers_remaining"
    ]
  }
}
```

`status --json --explain` contract:
- Adds `reason` for each agent/bead runtime state.
- Adds top-level drain explanation:
  - `queue_state`: `drained|not_drained`
  - `drain_reasons`: deterministic codes (e.g. `unassigned_beads_remaining`, `assigned_beads_remaining`, `running_workers_remaining`).

---

## Fast Recovery Runbook (for Orchestrator Agents)

- `reason=waiting_input`:
  - send required feedback/approval via agent-mail
  - run `bsw ping <bead-id>`
- `reason=stuck_no_progress`:
  - inspect `resume_command` from status
  - optionally resume manually, or `bsw kill <bead-id>` and rerun queue
- `reason=orphaned_assignment`:
  - clear bad assignment and requeue bead
- `reason=ignored_stale_state`:
  - stale worker/session wrote late STATE; no action unless repeated

---

## Agent Communication (agent-mail Integration)

Agents register with agent-mail (MCP). Orchestrator controls communication:

- send feedback/approval
- read responses
- call `bsw ping <bead-id>` to nudge
- decide retry/escalation/abort

`bsw` only provides state, session references, and signaling primitives.

---

## Design Philosophy

- **Simple primitives**: queue runner + status + control
- **Single owner**: `bsw` owns assignment + transitions
- **Worker-focused**: worker does task + emits STATE + exits
- **Durable**: bead labels/comments are workflow truth
- **Operator-friendly**: one status payload + explicit recovery hints
- **No hidden policy**: orchestrator owns retries/escalations
