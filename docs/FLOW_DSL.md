# Flow DSL (`.bsw/flow.toml`)

`flow.toml` is the single source of truth for swarm behavior.
It defines:
- worker profiles (provider/model/effort/prompt)
- queue labels and per-role capacity
- lifecycle policy (idle/lifetime/watchdog)
- state transitions and automation actions

## Top-level keys

- `version` (int): DSL version. Current: `1`
- `start` (string): logical start state id (informational + UI)
- `[[states]]` (array): state/worker nodes
- `[[transitions]]` (array): allowed transitions and actions

## `[[states]]`

Required:
- `id`: unique node id (`bead.implement`, `plan.review`)
- `kind`: `bead | worker | plan | terminal`

Common optional keys:
- `label`: bead queue label (for `kind=bead`) or worker label (`commit-queue`, `plan-review`)
- `workers`: desired max panes for this role/profile
- `prompt`: prompt file path used by the role
- `provider`: `codex | cc`
- `model`: model identifier
- `effort`: provider-specific effort/quality hint

Lifecycle policy keys (runtime/daemon):
- `max_idle`: kill unassigned waiting/idle pane after this duration (`15m`, `2h`)
- `max_lifetime`: recycle pane after this duration
- `max_busy_without_progress`: watchdog for assigned panes with no activity
- `respawn`: `"true" | "false"` (capacity replenished by daemon)
- `one_shot`: `"true" | "false"` (retire pane after one completed cycle)

UI/theme keys:
- `color_bg`, `color_fg`: TUI role colors
- `tmux_bg`, `tmux_fg`: tmux pane colors

## `[[transitions]]`

Keys:
- `from`: source state id
- `on`: event or condition
- `to`: target state id
- `guard` (optional): transition guard (currently `run_plan_reviewer_once`)
- `actions`: action list executed by orchestrator

Event conventions:
- `state:impl:done`
- `state:proof:passed`
- `state:proof:failed`
- `state:review:passed`
- `state:review:failed`
- `condition:no_active_bead_work`

Supported actions:
- `clear_assignee`
- `set_label:<needs-*>`
- `remove_label:<needs-*>`
- `close_bead`
- `run_plan_reviewer`
- `set_plan_state:done`
- `stop_daemon`

## Execution model

1. Daemon discovers panes and beads.
2. It reconciles bead transitions from latest `STATE ...` comments.
3. It assigns unassigned `needs-*` beads to matching role workers.
4. Workers execute role prompt + runtime assignment envelope.
5. Lifecycle policy can recycle stuck/idle panes.
6. Plan reviewer can be triggered when no active bead work remains.

## Minimal example

```toml
version = 1
start = "bead.implement"

[[states]]
id = "bead.implement"
kind = "bead"
label = "needs-impl"
workers = 2
prompt = ".bsw/prompts/impl_worker.md"
provider = "codex"
model = "gpt-5.3-codex"
effort = "medium"
max_idle = "20m"
max_lifetime = "3h"
max_busy_without_progress = "30m"
respawn = "true"

[[states]]
id = "bead.proof"
kind = "bead"
label = "needs-proof"
workers = 1
prompt = ".bsw/prompts/impl_proofer.md"
provider = "cc"
model = "opus"
effort = "high"

[[transitions]]
from = "bead.implement"
on = "state:impl:done"
to = "bead.proof"
actions = ["clear_assignee", "set_label:needs-proof", "remove_label:needs-impl"]
```

## Notes for prompt design

Role prompts should stay role-specific (implement/proof/review/etc).
State transition logic should stay in `flow.toml`.
At runtime, `bsw` adds assignment context + transition rules envelope to the role prompt.
