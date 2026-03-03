# bsw v2 Architectural Review (Aligned)

## Executive Summary

Status: **GO for Phase 1**, with clear implementation gates.

The current v2 design is coherent and robust if implemented exactly as specified in `DSL.md` and `PLAN.md`:

- `bsw` is the single owner of assignment + transitions
- workers emit terminal `STATE` only
- idempotency is guaranteed by comment cursor + assignment token
- orchestrator gets a single operational overview via `bsw status --json`

---

## Design Alignment Check

### 1) Ownership model

- `bsw`: claim bead, validate STATE, transition labels, clear assignee
- worker: get bead, do work, emit one terminal STATE, exit
- orchestrator: policy decisions (retry/escalate/feedback)

**Assessment**: Correct separation of concerns and reduced race surface.

### 2) Transition safety

- transition is one mutation with preconditions
- no split remove/add operations from worker side
- conflicts emit explicit `transition_conflict`

**Assessment**: Correct for avoiding partial-move corruption.

### 3) Replay/idempotency

- process only comments with `id > last_processed_comment_id`
- accept first terminal STATE for active `assignment_token`
- ignore stale/duplicate token events

**Assessment**: Correct crash/restart behavior.

### 4) Queue lifecycle

- `oneshot` mode for deterministic chain steps
- `service` mode for refill-safe parallel topology

**Assessment**: Correct and operationally simple.

### 5) Operations visibility

`bsw status --json` exposes:

- queue counts (`total`, `unassigned`, `assigned`)
- bead ownership + activity state
- provider `session_ref` + `resume_command`
- `attention[]` with suggested operator actions

**Assessment**: Meets orchestrator overview requirement.

---

## Remaining Risks (Implementation-Time)

### P0

1. **Atomic transition command in `br`**
   - Need a single-call mutation with preconditions.
   - If unavailable, implement safe compare-and-swap wrapper with explicit failure events.

2. **Codex state mapping completeness**
   - Must confirm JSON-RPC signals for `waiting_input` vs `blocked` to avoid false stuck alerts.

### P1

3. **Comment id semantics**
   - Confirm whether ids are per-bead or global; cursor logic must match that scope.

4. **Orphan reconciliation policy**
   - Startup reconciliation rules must be deterministic when registry, process table, and bead assignee disagree.

---

## Recommended Acceptance Tests

1. Worker emits valid STATE -> one transition event, one label change, assignee cleared.
2. Worker emits duplicate STATE -> second event ignored.
3. Stale worker emits late STATE with old token -> ignored_stale_state.
4. Restart mid-run -> no replayed transitions after resume.
5. Waiting input > timeout window -> no stuck kill, attention=waiting_input only.
6. No progress and not waiting input -> attention=stuck_no_progress.
7. Parallel `service` mode with upstream refill -> downstream queue keeps draining.
8. `status --json` always includes `session_ref` and `resume_command` for assigned beads.

---

## Production Readiness Gate

Ship Phase 1 when all are true:

- Atomic transition path is implemented and tested
- Codex/Claude state mapping is verified against real provider events
- Idempotency tests pass across process restarts
- `status --json` is stable and consumed by orchestrator end-to-end

If those gates pass, the design is production-safe for orchestrator-agent operation.
