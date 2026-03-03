# boring-swarm v2 — Technical Specification

## Core insight

**Beads are the durable state machine.** No workflow engine needed.

```
bead labels    →  current position   (needs-impl / needs-proof / needs-review / closed)
bead comments  →  transition history  (STATE proof:passed, STATE review:failed, ...)
bead assignee  →  ownership           (which agent is working on it)
```

`bsw` crashes → restart → `br list` → complete picture of every bead position → resume.
Claude `--resume <uuid>` restores conversation context. Full durability, zero framework.

---

## What v1 got right and wrong

**Right:** reconstruct state from beads every tick — bead labels are the source of truth.

**Wrong:**
- Fragile agent state detection (tmux transcript parsing, SWARM_STATUS beacons, Codex idle heuristics)
- Flat non-composable TOML state machine
- Polling loop instead of event-driven
- Tmux dependency for process management

**v2 fixes all four. Nothing else changes.**

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  bsw binary (single Go binary)                                   │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ DSL engine  │  │   Process    │  │   State reconciler     │  │
│  │             │  │   manager    │  │                        │  │
│  │ reads flow  │  │              │  │  br list → bead labels │  │
│  │ YAML, drives│  │ spawn/kill/  │  │  → determine what to   │  │
│  │ pipeline    │  │ monitor      │  │    spawn next          │  │
│  │ stages      │  │ agent procs  │  │                        │  │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬─────────────┘  │
│         │                │                      │               │
│  ┌──────▼──────────────────────────────────────▼─────────────┐  │
│  │                   Agent state detector                    │  │
│  │                                                           │  │
│  │  Layer 1: Claude JSONL session file watcher               │  │
│  │           (~/.claude/projects/{path}/{uuid}.jsonl)        │  │
│  │           → active / idle / waiting_input / blocked       │  │
│  │                                                           │  │
│  │  Layer 2: SDK subprocess event stream                     │  │
│  │           Claude: stream-json stdout                      │  │
│  │           Codex:  app-server JSON-RPC stdio               │  │
│  │           → completion, emitted STATE event, cost         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  TUI  (bubbletea)                                        │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘

Source of truth:  beads (br)
Agent context:    Claude --resume <uuid>
Pipeline cursor:  .bsw/run.json  (tiny — just stage + run-id)
```

---

## Stack

| Layer | Technology |
|---|---|
| Language | Go 1.24+ |
| Orchestration | **None** — beads are the state machine |
| Durable state | Beads (`br`) — labels + comments + assignee |
| Pipeline cursor | `.bsw/run.json` — current stage, run-id |
| Agent context | Claude `--resume <uuid>` |
| Claude IPC | `claude -p --output-format stream-json` (Claude Agent SDK wire protocol) |
| Codex IPC | `codex app-server` JSON-RPC 2.0 over stdio (Codex SDK wire protocol) |
| Claude state | JSONL session file watcher (primary) + stdout events (secondary) |
| Codex state | `turn/completed`, `item/*` events from app-server |
| TUI | charmbracelet/bubbletea |
| DSL | `gopkg.in/yaml.v3` |
| Distribution | go-to-wheel → PyPI wheels |

---

## Project structure

```
boring-swarm/
├── v1/                       # preserved v1
├── SPEC_V2.md                # this file
└── cli/
    └── bsw/
        ├── main.go           # cobra CLI entry point
        ├── go.mod
        ├── go.sum
        ├── cmd/
        │   ├── init.go       # bsw init
        │   ├── run.go        # bsw run spec.md
        │   ├── flow.go       # bsw flow <file> [arg]
        │   ├── status.go     # bsw status
        │   ├── tui.go        # bsw tui
        │   └── doctor.go     # bsw doctor
        ├── dsl/
        │   ├── parser.go     # YAML flow parser
        │   ├── validator.go  # strict validation (unknown keys = fatal)
        │   └── types.go      # FlowSpec, StateSpec, PolicySpec
        ├── engine/
        │   ├── runner.go     # DSL interpreter + pipeline stage executor
        │   ├── reconciler.go # reads br list → drives spawns/transitions
        │   └── cursor.go     # run.json read/write
        ├── process/
        │   ├── manager.go    # spawn/kill/monitor agent processes
        │   └── registry.go   # active agents: {bead_id → pid, session_uuid}
        ├── agent/
        │   ├── claude.go     # Claude subprocess (stream-json protocol)
        │   ├── codex.go      # Codex subprocess (app-server JSON-RPC)
        │   ├── watcher.go    # Claude JSONL session file watcher
        │   └── state.go      # ActivityState enum + detection
        ├── beads/
        │   └── client.go     # br CLI wrapper (list, label, assign, comment, close)
        ├── hooks/
        │   └── runner.go     # policy.yaml hook execution
        └── tui/
            ├── model.go
            └── views.go
```

---

## Agent state detection — three layers, zero heuristics

### Layer 1 — Claude JSONL session file (primary)

Claude writes its session history to `~/.claude/projects/<encoded-path>/<uuid>.jsonl`
regardless of how it is started. `bsw` discovers the UUID from the init event and watches
this file directly:

```go
// agent/state.go
type ActivityState int
const (
    ActivityStateUnknown      ActivityState = iota
    ActivityStateActive       // tool_use / progress within idleThreshold
    ActivityStateReady        // result / assistant within idleThreshold
    ActivityStateIdle         // no events for > idleThreshold (default 5m)
    ActivityStateWaitingInput // permission_request — waiting for approval
    ActivityStateBlocked      // error event
    ActivityStateExited       // process dead
)

// agent/watcher.go
func (w *Watcher) State() ActivityState {
    entry, err := readLastJSONLEntry(w.path)
    if err != nil { return ActivityStateUnknown }
    age := time.Since(entry.Timestamp)
    switch entry.Type {
    case "tool_use", "progress":
        if age > w.idleThreshold { return ActivityStateIdle }
        return ActivityStateActive
    case "assistant", "result":
        if age > w.idleThreshold { return ActivityStateIdle }
        return ActivityStateReady
    case "permission_request":
        return ActivityStateWaitingInput // never false-alarm as stuck
    case "error":
        return ActivityStateBlocked
    }
    if !isAlive(w.pid) { return ActivityStateExited }
    return ActivityStateUnknown
}
```

`ActivityStateWaitingInput` is the key improvement over v1 — the stuck timer pauses when
Claude is waiting for a permission approval, not stuck.

### Layer 2 — SDK subprocess event stream (secondary)

`bsw` implements the exact wire protocols used by the official TypeScript SDKs — in Go.

**Claude** (`claude -p --output-format stream-json`):

```
← {"type":"system","subtype":"init","session_id":"uuid-..."}   → start JSONL watcher
← {"type":"assistant","message":{...}}                          → active
← {"type":"result","subtype":"success","total_cost_usd":0.12}  → done, parse STATE
← {"type":"result","subtype":"error_max_turns"}                → fail
```

**Codex** (`codex app-server` — JSON-RPC 2.0 over stdio):

```
→ {"method":"initialize","id":0,"params":{"clientInfo":{...}}}
← {"id":0,"result":{...}}
→ {"method":"initialized","params":{}}
→ {"method":"thread/start","id":1,"params":{"model":"...","cwd":"..."}}
← {"id":1,"result":{"thread":{"id":"thr_abc"}}}
→ {"method":"turn/start","id":2,"params":{"threadId":"thr_abc","input":[...]}}
← {"method":"item/started","params":{...}}          → active
← {"method":"turn/completed","params":{"usage":{...}}}  → done, parse STATE
```

`app-server` advantages over `codex exec --json`:
- Persistent thread across multiple turns (no re-init per step)
- `turn/steer` — inject corrections mid-turn
- `turn/interrupt` — graceful cancel
- Typed approval callbacks — auto-approved in full-auto mode

### Layer 3 — stuck timer (tertiary)

A simple `time.Timer` reset on every SDK event. If it fires and Layer 1 confirms
`ActivityStateWaitingInput`, extend the timer. If it fires and state is `Active` or
`Unknown`, kill the process — it is genuinely stuck.

```go
// process/manager.go
stuckTimer := time.NewTimer(policy.Workers.MaxBusyWithoutProgress)
for {
    select {
    case evt := <-events:
        stuckTimer.Reset(policy.Workers.MaxBusyWithoutProgress)
        if isCompletion(evt) { return parseStateEvent(evt) }

    case <-stuckTimer.C:
        if watcher.State() == ActivityStateWaitingInput {
            stuckTimer.Reset(policy.Workers.MaxBusyWithoutProgress)
            continue
        }
        killProcess(pid)
        return "", ErrStuck
    }
}
```

---

## STATE event contract

Agents signal transitions by writing to bead comments:
```bash
br comments add <bead-id> "STATE proof:passed"
```

The process manager detects this from the SDK event stream: the `br` invocation appears
as a tool_use block in the JSONL stream. Parse the command arguments to extract the STATE
value. Reliable, structured, no regex on transcript text.

On the next reconciler tick, `br list` reflects the updated bead state and the next
agent is spawned accordingly.

---

## Reconciler — event-driven, not polling

```go
// engine/reconciler.go

// Triggered by: STATE comment written by agent, agent process exit, timer
func (r *Reconciler) Reconcile(ctx context.Context, flowSpec *dsl.FlowSpec) error {
    beads, err := r.beads.List()            // br list
    if err != nil { return err }

    for _, bead := range beads {
        switch {
        case bead.HasLabel("needs-impl") && !r.process.HasAgent(bead.ID, "implement"):
            r.process.Spawn(bead, "implement", flowSpec)

        case bead.HasLabel("needs-proof") && !r.process.HasAgent(bead.ID, "proof"):
            r.process.Spawn(bead, "proof", flowSpec)

        case bead.HasLabel("needs-review") && !r.process.HasAgent(bead.ID, "review"):
            r.process.Spawn(bead, "review", flowSpec)
        }
    }

    // Check foreach.workers concurrency limit
    r.enforceWorkerCap(flowSpec)

    // Check pipeline stage completion → advance cursor
    r.maybeAdvanceStage(ctx, beads, flowSpec)

    return nil
}
```

Triggers:
1. **STATE event received** — agent wrote a comment, reconcile immediately
2. **Agent process exits** — reconcile to clean up and reassign if needed
3. **Fallback ticker** — every 30s as a safety net (hybrid mode, same as v1)

---

## Flow DSL

Spec: `v1/docs/FLOW_DSL.md`. Fully preserved. The DSL interpreter drives which
pipeline stages run and in what order. Within each stage, the reconciler drives
which agents to spawn based on bead labels.

### DSL → engine mapping

| DSL concept | Engine behavior |
|---|---|
| `prompt` state | Spawn agent subprocess for each matching bead |
| `flow` state | Load and execute child flow as sub-stage |
| `parallel` list | Spawn all children concurrently, wait for all |
| `foreach` | Reconciler spawns up to `workers` agents against queue label |
| `on:` branching | Switch on STATE event value |
| `emits` | Expected STATE values from agent (`STATE proof:passed`, etc.) |
| `max_loops` | Loop counter per bead, incremented on each backward transition |
| `timeout` | Per-agent stuck timer |
| `on_error: continue` | Failed bead skipped; foreach continues |
| `on_error: retry` | Respawn agent up to `max_retries` times |
| `join: all` | Wait for all beads to reach terminal/closed |
| `join: any` | Advance when first bead completes |

### bead.yaml — unchanged from v2 DSL spec

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
    timeout: 4h

  - id: proof
    prompt: prompts/impl_proofer.md
    provider: cc
    model: opus
    max_loops: 5
    emits: ["proof:passed", "proof:failed"]
    on:
      "proof:passed": review
      "proof:failed": implement
    timeout: 2h

  - id: review
    prompt: prompts/impl_reviewer.md
    provider: cc
    model: opus
    max_loops: 3
    emits: ["review:passed", "review:failed"]
    on:
      "review:passed": done
      "review:failed": implement
    timeout: 2h

  - id: done
```

**How it executes:**
1. Reconciler: `br list --label needs-impl` → spawn implement agents (up to `foreach.workers`)
2. Agent writes `STATE impl:done` → DSL engine fires `on: "impl:done": proof`
3. Engine: `br label add <id> needs-proof`, `br label remove <id> needs-impl`
4. Reconciler: sees `needs-proof` → spawns proof agent
5. Repeat through pipeline

---

## Pipeline cursor

```json
// .bsw/run.json
{
  "run_id": "run-20260227-a3f1",
  "flow": "flows/run.yaml",
  "stage": "impl",
  "started": "2026-02-27T10:00:00Z",
  "status": "running"
}
```

One tiny file. Cursor advances when a pipeline stage completes (all beads closed for
impl stage, etc.). On restart: read `run.json` → know which stage we're in → call
`br list` → know which beads need agents → spawn. Full recovery.

---

## Active agent registry (in-memory, rebuilt on restart)

```go
// process/registry.go
type AgentEntry struct {
    BeadID      string
    Role        string    // implement / proof / review
    PID         int
    SessionUUID string    // Claude session UUID for --resume
    StartedAt   time.Time
}
```

In-memory only. On `bsw` restart: `br list` shows which beads have assignees → respawn
agents for those beads with `claude --resume <uuid>` if UUID is known, or fresh session
if not. Bead comment history tells the new agent what's already been done.

---

## .bsw/ layout (v2)

```
.bsw/
  flows/                    # WHAT — orchestration (git-tracked)
    run.yaml
    plan.yaml
    decompose.yaml
    impl.yaml
    bead.yaml
    finalize.yaml
  policy.yaml               # HOW — lifecycle behavior (git-tracked)
  config.yaml               # WHERE — env, credentials (gitignored)
  prompts/                  # Agent prompt templates (git-tracked)
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
  run.json                  # pipeline cursor (gitignored)
  logs/                     # agent session logs (gitignored)
    agents/<run-id>/<role>-<bead-id>-<ts>.log
  artifacts/                # intermediate plan artifacts (gitignored)
    plan_draft.md
    plan_blended.md
    plan_final.md
```

---

## CLI commands

```bash
bsw init                          # scaffold .bsw/ in current project
bsw doctor                        # validate claude + codex + br binaries

bsw run spec.md                   # full e2e pipeline (flows/run.yaml)
bsw flow flows/bead.yaml bd-3a1   # one bead (debug)
bsw flow flows/plan.yaml spec.md  # just plan phase
bsw flow flows/impl.yaml          # just impl phase

bsw status                        # active agents + bead positions (from br list)
bsw tui                           # bubbletea TUI
bsw stop                          # graceful shutdown (SIGTERM agents, write cursor)
```

### `bsw run` lifecycle

```
bsw run spec.md
  1. Read .bsw/run.json — existing run? resume from cursor stage
  2. Load + validate flows/run.yaml, policy.yaml, config.yaml
  3. Start reconciler (event-driven + 30s fallback ticker)
  4. Execute pipeline stages in order per run.yaml
  5. For each stage: reconciler spawns agents per bead labels, waits for join
  6. SIGINT → SIGTERM all agents → flush logs → write cursor → exit
  7. Restart → read run.json → br list → respawn agents with --resume → continue
```

---

## TUI (bubbletea)

| Tab | Content |
|---|---|
| Pipeline | Stage cursor, timing per stage |
| Beads | Per-bead: current label, assignee, loop count (from comment history) |
| Agents | Active agents: ActivityState, last event type, tokens, uptime |
| Logs | Agent log tail (`.bsw/logs/`) |

TUI data sources: `br list` + JSONL session file watcher + process registry.

---

## Policy (unchanged from v2 DSL spec)

```yaml
# .bsw/policy.yaml
workers:
  max_busy_without_progress: 30m  # stuck timer (Layer 3)
  max_lifetime: 3h                # recycle agent (fresh context)
  max_idle: 20m                   # kill unassigned agent

beads:
  stale_timeout: 2h               # bead with no activity → reclaim
  stuck_cycles: 5                 # max backward transitions before escalate

context:
  token_threshold: 80%            # recycle agent on high token usage
  on_compaction: restart          # restart with --resume on context window hit

hooks:
  on_bead_closed:
    - run: "git add -A && git commit -m 'close {bead_id}'"
  on_all_beads_closed:
    - run: "git push"
  on_flow_complete:
    - run: "echo '{run_id} done' >> .bsw/logs/runs.log"
```

---

## Go dependencies

```
github.com/charmbracelet/bubbletea    # TUI
github.com/charmbracelet/lipgloss     # TUI styling
github.com/spf13/cobra                # CLI commands
gopkg.in/yaml.v3                      # YAML DSL + policy parser
```

No workflow engine. No database driver. No framework.

## External binaries

| Binary | Install | Role |
|---|---|---|
| `claude` | `npm i -g @anthropic-ai/claude-code` | Claude Code agent |
| `codex` | `npm i -g @openai/codex` or brew | Codex agent |
| `br` | beads install | Bead CRUD — durable state |
| `bv` | beads install | Verification runner |

---

## Implementation phases

### Phase 1 — bead lane (core)
- DSL parser for bead.yaml + impl.yaml (`dsl/`)
- Reconciler: `br list` → spawn/kill agents (`engine/reconciler.go`)
- Process manager: spawn Claude/Codex, stream logs (`process/manager.go`)
- Claude runner: stream-json protocol, JSONL watcher, STATE detection (`agent/`)
- Codex runner: app-server JSON-RPC protocol (`agent/codex.go`)
- `bsw init`, `bsw doctor`, `bsw run`, `bsw status`, `bsw stop`

### Phase 2 — full pipeline + TUI
- Plan/decompose/finalize flows + RunWorkflow
- `bsw flow <file> [arg]`
- bubbletea TUI (all four views)
- Policy enforcement (stuck timer, lifecycle hooks)

### Phase 3 — polish
- Crash recovery UX (`--resume` auto-detection)
- PyPI distribution via go-to-wheel

---

## Key design decisions

1. **No workflow engine** — beads are the state machine. `br` labels + comments give
   full durable state. On crash: `br list` reconstructs everything. Zero framework overhead.

2. **Three-layer state detection** — JSONL file watcher (Composio AO insight) as primary,
   SDK event stream as secondary, stuck timer as tertiary. `ActivityStateWaitingInput`
   prevents false stuck alarms. Zero heuristics.

3. **Full SDK wire protocols in Go** — Claude stream-json and Codex app-server JSON-RPC
   implemented directly. Same protocols as official TypeScript SDKs, no Node.js dependency.

4. **Claude `--resume <uuid>`** — agent conversation context survives `bsw` restarts.
   The UUID is logged on agent spawn; bead comments tell the new session what's been done.

5. **Event-driven reconciler** — STATE events trigger immediate reconciliation. 30s
   fallback ticker as safety net. No tight polling loop.

6. **Composable DSL is the product** — the v2 YAML flow DSL differentiates boring-swarm
   from every alternative. Users define any pipeline. The engine interprets it.

7. **No tmux** — agents are background processes. Logs to files. TUI reads logs + bead
   state. Clean, testable, no terminal dependency.
