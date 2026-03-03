# Flow DSL (`.bsw/flows/*.yaml`)

Declarative YAML state machines for AI agent orchestration.
Composable: one file = one machine. Machines call machines.

## Design principles

- **Structure is flow** — list order = sequential, nesting = parallel, `on:` = branching
- **No explicit edges** — transitions are inferred from structure and `on:` maps
- **Kind inference** — state behavior inferred from fields present, not a `kind:` tag
- **Strict validation** — unknown keys are fatal parse errors (prevents silent typo bugs)
- **Composable** — any flow is both a standalone command and a callable sub-machine
- **File-scoped defaults** — each flow is self-contained; parent defaults do not cascade into children

## File structure

```
.bsw/
  flows/                        # WHAT — orchestration structure
    run.yaml                    #   e2e pipeline (composes the others)
    plan.yaml                   #   idea → reviewed plan
    decompose.yaml              #   plan → verified beads
    impl.yaml                   #   foreach over beads
    bead.yaml                   #   one bead: implement → proof → review
    finalize.yaml               #   plan completion gate
  policy.yaml                   # HOW — daemon operational behavior
  config.yaml                   # WHERE — environment, sessions, credentials
  prompts/
    plan_interview.md
    plan_review_external.md
    plan_blend.md
    plan_integrate.md
    plan_decompose_generate.md
    plan_decompose_verify.md
    impl_worker.md
    impl_proofer.md
    impl_reviewer.md
    plan_reviewer.md
```

All `prompt` and `flow` paths in YAML files are resolved relative to `.bsw/`.
For example, `prompt: prompts/plan_interview.md` resolves to `.bsw/prompts/plan_interview.md`.

## Schema

```yaml
version:     int                        # DSL version (current: 1)
defaults:                               # optional, applies to states in THIS file only
  provider:  string                     # defaults do NOT cascade into child flows
  model:     string
  effort:    string
states:      list of state objects      # the machine
```

### State fields

All fields optional except `id`. Unknown fields are rejected at parse time.

| Field | Type | Description |
|---|---|---|
| `id` | string (required) | Unique identifier within this flow |
| `prompt` | file path | Run one agent with this prompt |
| `emits` | list of strings | Events this state can produce (required if `on:` present) |
| `flow` | file path | Run another flow as sub-machine |
| `parallel` | list of states | Run children concurrently |
| `foreach` | object | Dynamic fan-out over work items |
| `foreach.items` | glob/file/query | Source of work items (see item source resolution) |
| `foreach.flow` | file path | Sub-machine to run per item |
| `foreach.workers` | int | Max concurrency (default: `1`) |
| `join` | `"all"` / int / `"any"` | Join condition for `parallel` or `foreach` (default: `"all"`) |
| `on` | map { event: state_id } | Branching — must be exhaustive against `emits` |
| `on_error` | `"fail"` / `"continue"` / `"retry"` | Child failure behavior for `parallel`/`foreach` (default: `"fail"`) |
| `max_retries` | int | Retry count when `on_error: retry` (default: 1) |
| `retry_delay` | duration string | Delay between retries (`"10s"`, `"1m"`) |
| `max_loops` | int | Max times this state's `on:` fires a backward transition (required for backward refs; `-1` = unlimited, `0` = no backward transitions allowed) |
| `timeout` | duration string | Max wall-clock time (`"30m"`, `"2h"`) |
| `provider` | string | Override default provider |
| `model` | string | Override default model |
| `effort` | string | Override default effort |

**Field categories:**
- **Behavior** (mutually exclusive — exactly one, or none for terminal): `prompt`, `flow`, `parallel`, `foreach`
- **Modifiers** (combine freely with any behavior): `emits`, `on`, `on_error`, `max_retries`, `retry_delay`, `max_loops`, `timeout`, `join`, `provider`, `model`, `effort`

### Kind inference

No explicit `kind` field. Behavior inferred from fields present:

| Fields present | Behavior |
|---|---|
| `prompt` | **Task** — spawn one agent, run to completion |
| `flow` | **Sub-machine** — load child flow, run to terminal |
| `parallel` | **Static fan-out** — run children concurrently |
| `foreach` | **Dynamic fan-out** — run sub-flow per work item |
| *(none + no outgoing)* | **Terminal** — return this `id` to parent |

### Transition rules

1. **No `on:` block** → next item in list (sequential by default)
2. **Has `on:` block** → must map every entry in `emits`. `next` is a reserved target keyword meaning "advance to the next state in list order."
3. **`on:` targets** can reference any state `id` in the same flow (forward or backward)
4. **Backward references** create loops. `max_loops` is required on states with backward `on:` targets (prevents infinite loops). Use `max_loops: -1` to explicitly allow unlimited retries. `max_loops: 0` means no backward transitions allowed (useful for dry-run/testing).
5. **Loop exhaustion** — when `max_loops` is reached, backward targets are disabled. The `on:` map is re-evaluated with only forward targets remaining. If no forward target matches, the flow **fails** with `error:max_loops` (no silent fallthrough to the next sequential state).
6. **Terminal states** have no `on:` and no next item. Their `id` is the return value to the parent.

### Event naming conventions

- **Internal events** (from `emits`) are free-form but should be namespaced to the role
  (e.g., `"proof:passed"`, `"impl:done"`). These are local to a flow.
- **Terminal state IDs** serve as the return events for parent flows. Keep these
  generic and semantic (`pass`, `fail`, `done`) since they form the composition contract.
- Internal events and terminal IDs occupy separate namespaces — there is no collision.

### Unrecognized or missing events

Event handling depends on whether `emits` is declared:

- **State has `emits`**: The agent must emit a recognized event. If it exits
  without emitting one, the state fires `error:no_event`. If `timeout` elapses,
  the state fires `error:timeout`. These synthetic events follow normal `on:`
  routing. If not mapped, the flow halts with status `failed`.
- **State has no `emits`** (sequential): Agent process exit with code 0 = success,
  daemon advances to next state. Non-zero exit code = flow halts with `failed`.

### Item source resolution

| Pattern | Resolution |
|---|---|
| `.beads/<label>` | Query `br` for open beads with label `<label>` |
| `*.yaml` / glob pattern | Expand glob relative to `.bsw/` |
| `<path>.jsonl` | Read JSONL file, one item per line |

The daemon re-evaluates `foreach.items` each time the `foreach` state is entered,
so newly created beads are picked up on retry loops.

### Join and error semantics

| `join` | `on_error: fail` (default) | `on_error: continue` | `on_error: retry` |
|---|---|---|---|
| `all` | First child failure fails the parent | Failed children skipped; parent succeeds when all non-failed complete | Failed children retried up to `max_retries`; parent fails if retries exhausted |
| `any` | First child failure fails the parent | First success wins; all-failed = parent fails | Failed children retried; first success wins |
| int N | First child failure fails the parent | Parent succeeds when N children succeed (ignoring failures) | Failed children retried; parent succeeds when N succeed |

When `join: any` succeeds, remaining running children are cancelled (sent graceful shutdown signal, then force-killed after 30s).

### Composition contract

A flow's **public API** is its terminal state IDs. The parent flow branches on them:

```yaml
# parent
- id: finalize
  flow: flows/finalize.yaml
  emits: [pass, fail]
  on:
    pass: done        # finalize.yaml reached terminal "pass"
    fail: impl        # finalize.yaml reached terminal "fail"
```

For `flow` states, `emits` must list the child flow's terminal state IDs.
If a child flow's terminal is renamed, the parent breaks at parse time (strict validation).

## Flow definitions

### `flows/run.yaml` — Full e2e pipeline

```yaml
version: 1

states:
  - id: plan
    flow: flows/plan.yaml

  - id: decompose
    flow: flows/decompose.yaml

  - id: impl
    flow: flows/impl.yaml

  - id: finalize
    flow: flows/finalize.yaml
    max_loops: 3
    emits: [pass, fail]
    on:
      pass: done
      fail: impl

  - id: done
```

```
plan → decompose → impl ⇄ finalize → done
                     ↑         |
                     └─────────┘ (max 3 loops)
```

### `flows/plan.yaml` — Multi-model plan review

```yaml
version: 1

defaults:
  provider: cc
  model: opus

states:
  - id: interview
    prompt: prompts/plan_interview.md

  - id: review
    parallel:
      - id: review_codex
        prompt: prompts/plan_review_external.md
        provider: codex
        model: gpt-5.3-codex
      - id: review_claude
        prompt: prompts/plan_review_external.md
      - id: review_deep
        prompt: prompts/plan_review_external.md
        provider: deep
        model: o4-mini-deep-research
    join: all
    on_error: continue

  - id: blend
    prompt: prompts/plan_blend.md

  - id: integrate
    prompt: prompts/plan_integrate.md

  - id: done
```

```
                     ┌→ review_codex  ─┐
interview ────────→  ├→ review_claude ─┤──→ blend → integrate → done
                     └→ review_deep   ─┘
                      (join: all, on_error: continue)
```

### `flows/decompose.yaml` — Plan to beads with verify loop

```yaml
version: 1

defaults:
  provider: cc
  model: opus

states:
  - id: generate
    prompt: prompts/plan_decompose_generate.md

  - id: verify
    prompt: prompts/plan_decompose_verify.md
    max_loops: 3
    emits: [pass, fail]
    on:
      pass: done
      fail: generate

  - id: done
```

```
generate → verify ──pass──→ done
              │
              └──fail──→ generate (max 3 loops)
```

### `flows/impl.yaml` — Foreach over beads

```yaml
version: 1

states:
  - id: execute
    foreach:
      items: .beads/needs-impl
      flow: flows/bead.yaml
      workers: 4
    join: all
    on_error: continue

  - id: done
```

Spawns up to 4 concurrent workers. Each pulls a bead from the queue and runs it through `bead.yaml`. Failed beads are skipped (`on_error: continue`); the finalize stage catches gaps. When all non-failed beads complete, transitions to `done`.

### `flows/bead.yaml` — One bead lifecycle

```yaml
version: 1

states:
  - id: implement
    prompt: prompts/impl_worker.md
    provider: codex
    model: gpt-5.3-codex
    emits: ["impl:done"]
    on:
      "impl:done": proof

  - id: proof
    prompt: prompts/impl_proofer.md
    provider: cc
    model: opus
    max_loops: 5
    emits: ["proof:passed", "proof:failed"]
    on:
      "proof:passed": review
      "proof:failed": implement

  - id: review
    prompt: prompts/impl_reviewer.md
    provider: cc
    model: opus
    max_loops: 3
    emits: ["review:passed", "review:failed"]
    on:
      "review:passed": done
      "review:failed": implement

  - id: done
```

```
implement → proof ──pass──→ review ──pass──→ done
               │                │
               └──fail──┐      └──fail──→ implement
                        ↓
                    implement (max 5 loops on proof)
```

### `flows/finalize.yaml` — Plan completion gate

```yaml
version: 1

defaults:
  provider: cc
  model: opus

states:
  - id: audit
    prompt: prompts/plan_reviewer.md
    emits: [pass, fail]
    on:
      pass: pass
      fail: fail

  - id: pass
  - id: fail
```

Two terminal states. Parent (`run.yaml`) branches on which one is reached.

## Prompt contracts

| Prompt | Input context | Output artifact | Emits |
|---|---|---|---|
| `plan_interview.md` | User spec file | `.bsw/artifacts/plan_draft.md` | *(sequential, no events)* |
| `plan_review_external.md` | Plan draft | `.bsw/artifacts/review_{id}.md` | *(sequential, no events)* |
| `plan_blend.md` | All review artifacts | `.bsw/artifacts/plan_blended.md` | *(sequential, no events)* |
| `plan_integrate.md` | Blended review + original draft | `.bsw/artifacts/plan_final.md` | *(sequential, no events)* |
| `plan_decompose_generate.md` | Final plan | `.beads/issues.jsonl` (new beads) | *(sequential, no events)* |
| `plan_decompose_verify.md` | Plan + generated beads | Verification report | `pass`, `fail` |
| `impl_worker.md` | Assigned bead | Code changes + evidence | `impl:done` |
| `impl_proofer.md` | Bead + implementation evidence | Gate results | `proof:passed`, `proof:failed` |
| `impl_reviewer.md` | Bead + impl + proof evidence | Review decision | `review:passed`, `review:failed` |
| `plan_reviewer.md` | Plan + all bead evidence | Audit decision | `pass`, `fail` |

Sequential prompts (no `emits`) signal completion by agent process exit. The daemon advances to the next state in list order.

## Runtime state

Flow files are static (checked into git). Runtime position is tracked in a separate state file:

```
.bsw/runs/<run-id>.yaml    # dynamic, gitignored
```

### Run state schema

The `stages` map tracks per-stage status at the top-level flow. For `foreach`
stages, each work item is tracked with its current position *within the child
flow* (e.g., `state: proof` means the bead is at the `proof` state in `bead.yaml`).

```yaml
id: run-20260226-a3f1
flow: flows/run.yaml
started: 2026-02-26T14:30:00Z
status: running                     # running | paused | done | failed

cursor: impl                       # current state in the top-level flow

stages:
  plan:
    status: done
    started: 2026-02-26T14:30:00Z
    finished: 2026-02-26T14:52:00Z

  decompose:
    status: done
    started: 2026-02-26T14:52:00Z
    finished: 2026-02-26T15:01:00Z
    beads_created: 12

  impl:
    status: running
    started: 2026-02-26T15:01:00Z
    beads:                          # per-bead position within bead.yaml
      bd-3a1:
        state: proof                # state ID from bead.yaml
        assignee: worker_2
        cycles: 1                   # backward transitions fired
      bd-3a2:
        state: implement
        assignee: worker_1
        cycles: 0
      bd-3a3:
        state: done
        cycles: 2
      bd-3a4:
        state: implement
        cycles: 5
        flags: [max_loops_reached]  # proof hit max_loops: 5

  finalize:
    status: pending
```

### Queue label derivation

Flows do not declare queue labels explicitly. The daemon derives them from
`bead.yaml` state IDs:

| `bead.yaml` state `id` | Derived label | Assigned to role |
|---|---|---|
| `implement` | `needs-impl` | implement workers |
| `proof` | `needs-proof` | proof workers |
| `review` | `needs-review` | review workers |

Convention: `needs-{state_id}`. The daemon auto-generates labels from
the current state within `bead.yaml` for each active bead.

### Source of truth

| Data | Where | Managed by |
|---|---|---|
| Bead content (title, gates, criteria) | `.beads/issues.jsonl` | `br` CLI |
| Bead STATE/NEXT comments | `.beads/issues.jsonl` | Agents |
| Bead position in flow graph | `.bsw/runs/<id>.yaml` | Daemon (derived from STATE comments) |
| Pipeline position (cursor) | `.bsw/runs/<id>.yaml` | Daemon |
| Worker assignments | `.bsw/runs/<id>.yaml` | Daemon |
| Flow definitions | `.bsw/flows/*.yaml` | User (git) |
| Evidence | `.agent-evidence/` | Agents |

The run state is a **derived cache**. If lost, the daemon reconstructs it by replaying bead comments.

## CLI mapping

```bash
bsw flow run.yaml spec.md           # full e2e
bsw flow plan.yaml spec.md          # just refine the plan
bsw flow decompose.yaml plan.md     # just decompose into beads
bsw flow impl.yaml                  # just execute beads
bsw flow bead.yaml bd-3a1           # one bead (debugging/testing)
bsw flow finalize.yaml              # just verify coverage

# convenience aliases
bsw run spec.md                     # = bsw flow run.yaml spec.md
bsw plan spec.md                    # = bsw flow plan.yaml spec.md
bsw impl                            # = bsw flow impl.yaml
bsw impl --workers 8                # override foreach.workers at runtime
```

## Validation rules

The parser enforces:

1. **Unknown keys rejected** — typo in `promtp:` is a fatal error, not a silent terminal
2. **Mutual exclusivity** — a state can have exactly one *behavior* field: `prompt`, `flow`, `parallel`, `foreach`, or none (terminal). Modifier fields (`emits`, `on`, `on_error`, `max_loops`, `timeout`, `provider`, `model`, `effort`) can combine freely with any behavior.
3. **`emits` required with `on:`** — `on:` without `emits` is a parse error (event vocabulary unknown)
4. **Exhaustive `on:` mapping** — if `on:` is present, every entry in `emits` must appear as a key in `on:`
5. **`on:` targets exist** — every target state ID (and `next`) must resolve within the same flow
6. **Terminal reachability** — at least one terminal state must be reachable
7. **`max_loops` on backward refs** — error if an `on:` target points backward without `max_loops` (use `max_loops: -1` to explicitly allow unlimited)
8. **`foreach`/`parallel` join default** — `join` defaults to `"all"` if omitted on `parallel` or `foreach` states
9. **Composition contract** — for `flow` states with `on:`, `emits` must match child flow's terminal state IDs
10. **`on_error` valid values** — must be `fail`, `continue`, or `retry`. `retry` requires `max_retries`.

## Daemon policy (`.bsw/policy.yaml`)

Flows define **what work to do**. Policy defines **how the daemon operates while doing it**.
These are separate concerns in separate files.

```
.bsw/
  flows/          # WHAT — orchestration structure (git-tracked)
    run.yaml
    bead.yaml
    ...
  policy.yaml     # HOW — daemon operational behavior (git-tracked, env-overridable)
  config.yaml     # WHERE — environment, sessions, credentials (gitignored)
```

### Policy schema

```yaml
# .bsw/policy.yaml

# ── Bead health ──────────────────────────────────

beads:
  stale_timeout: 2h             # bead with no activity for this long is reclaimable
  stale_action: reclaim         # reclaim | escalate | skip
  stuck_cycles: 3               # flag stuck after N backward transitions across all states
  stuck_action: escalate        # escalate | skip | reassign

# ── Worker lifecycle ─────────────────────────────

workers:
  max_idle: 20m                 # kill unassigned pane after this duration
  max_lifetime: 3h              # recycle pane (fresh context) after this
  max_busy_without_progress: 30m  # watchdog for assigned but silent agents
  respawn: true                 # replenish capacity when a pane dies/recycles

# ── Context & token management ───────────────────

context:
  token_threshold: 80%          # recycle agent when context usage hits this
  on_compaction: restart        # restart | continue | escalate
  recovery_sources:             # what to inject on restart
    - beads                     # current bead state + comments
    - evidence                  # latest evidence artifacts
    - agent_mail                # pending inbox messages

# ── Capacity scaling ─────────────────────────────

scaling:
  strategy: queue_depth         # desired workers = min(foreach.workers, queue_depth)
  min_workers: 1                # always keep at least 1 per role
  scale_down_delay: 5m          # wait before killing excess workers

# ── Heartbeat ────────────────────────────────────

heartbeat:
  interval: 30s
  log_file: .bsw/logs/heartbeat.log

# ── Hooks (event-driven side effects) ────────────

hooks:
  on_bead_closed:
    - run: "git add -A && git commit -m 'close {bead_id}'"
  on_all_beads_closed:
    - run: "git push"
  on_stage_complete:
    - run: "echo 'Stage {stage_id} done at {timestamp}' >> .bsw/logs/stages.log"
  on_stale_bead:
    - run: "br comments add {bead_id} 'STALE: reclaiming after {stale_timeout}'"
  on_stuck_bead:
    - run: "br comments add {bead_id} 'STUCK: {stuck_cycles} cycles, escalating'"
  on_agent_recycled:
    - run: "echo 'Recycled {worker_id} at {token_usage}%' >> .bsw/logs/recycle.log"
```

### Policy field reference

#### `beads` — Bead health monitoring

| Field | Type | Default | Description |
|---|---|---|---|
| `stale_timeout` | duration | `2h` | Bead is reclaimable if last comment is older than this |
| `stale_action` | enum | `reclaim` | `reclaim` = reassign to next idle worker. `escalate` = fire `on_stale_bead` hook and flag in run state. `skip` = ignore. |
| `stuck_cycles` | int | `3` | Flag bead stuck after this many backward transitions (across all states, not just one) |
| `stuck_action` | enum | `escalate` | `escalate` = fire `on_stuck_bead` hook. `skip` = mark failed, move on. `reassign` = assign to different worker. |

#### `workers` — Worker/pane lifecycle

| Field | Type | Default | Description |
|---|---|---|---|
| `max_idle` | duration | `20m` | Kill worker pane if unassigned for this long |
| `max_lifetime` | duration | `3h` | Recycle worker pane after this (fresh context window) |
| `max_busy_without_progress` | duration | `30m` | Watchdog: kill worker if assigned but no output |
| `respawn` | bool | `true` | Auto-spawn replacement when a worker is killed/recycled |

#### `context` — Token and context window management

| Field | Type | Default | Description |
|---|---|---|---|
| `token_threshold` | percentage | `80%` | Recycle agent when context usage hits this |
| `on_compaction` | enum | `restart` | `restart` = kill and respawn with recovery context. `continue` = let agent handle it. `escalate` = fire hook, don't auto-restart. |
| `recovery_sources` | list | `[beads, evidence, agent_mail]` | What to inject into restarted agent's context |

#### `scaling` — Dynamic capacity

| Field | Type | Default | Description |
|---|---|---|---|
| `strategy` | enum | `queue_depth` | `queue_depth` = workers = min(foreach.workers, items in queue). `fixed` = always use foreach.workers. |
| `min_workers` | int | `1` | Floor: always keep at least this many workers per role |
| `scale_down_delay` | duration | `5m` | Wait before killing excess workers (avoids flapping) |

#### `heartbeat` — Daemon liveness

| Field | Type | Default | Description |
|---|---|---|---|
| `interval` | duration | `30s` | How often to log queue state + worker health |
| `log_file` | path | `.bsw/logs/heartbeat.log` | Where to write heartbeat entries |

#### `hooks` — Event-driven side effects

Hooks fire shell commands when daemon events occur. Available template variables
depend on the event.

| Hook | Fires when | Template variables |
|---|---|---|
| `on_bead_closed` | A bead reaches terminal state | `{bead_id}`, `{bead_title}`, `{cycles}` |
| `on_all_beads_closed` | All beads in a foreach complete | `{stage_id}`, `{total_beads}`, `{failed_beads}` |
| `on_stage_complete` | A top-level pipeline stage finishes | `{stage_id}`, `{result}`, `{timestamp}` |
| `on_stale_bead` | Bead exceeds `stale_timeout` | `{bead_id}`, `{last_activity}`, `{stale_timeout}` |
| `on_stuck_bead` | Bead exceeds `stuck_cycles` | `{bead_id}`, `{stuck_cycles}`, `{current_state}` |
| `on_agent_recycled` | Worker recycled (lifetime/token/compaction) | `{worker_id}`, `{reason}`, `{token_usage}` |
| `on_flow_complete` | Entire flow run finishes | `{run_id}`, `{status}`, `{duration}` |
| `on_flow_failed` | Flow halts with error | `{run_id}`, `{error}`, `{cursor}` |

### How flows and policy interact

The flow DSL and policy file are independent. The daemon reads both:

```
daemon tick:
  1. Read flow YAML → determine what to do
     - Which states are active? Which beads need work?
     - Apply transitions based on events

  2. Read policy YAML → determine how to do it
     - Check bead health (stale? stuck?)
     - Check worker health (idle? over lifetime? token threshold?)
     - Scale workers up/down per scaling strategy
     - Fire hooks for triggered events

  3. Write run state → persist position + health flags
```

The flow never references the policy. The policy never references specific states.
They compose at runtime through the daemon.

### Separation of concerns

| Question | Answered by |
|---|---|
| What states does a bead go through? | `flows/bead.yaml` |
| How many workers run in parallel? | `flows/impl.yaml` (`foreach.workers`) |
| When is a bead considered stale? | `policy.yaml` (`beads.stale_timeout`) |
| What happens when a worker is idle too long? | `policy.yaml` (`workers.max_idle`) |
| When to recycle for fresh context? | `policy.yaml` (`context.token_threshold`) |
| What to commit and when? | `policy.yaml` (`hooks.on_bead_closed`) |
| Which provider/model to use? | `flows/*.yaml` (per state) |
| Session name and tmux setup? | `config.yaml` |
