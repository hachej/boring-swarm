# bsw — boring swarm

Process manager for AI agent swarms. Spawn workers, monitor them, keep them running.

Workers are AI coding agents (codex/claude) that pick their own work from a bead queue ([beads_rust](https://github.com/hachej/beads_rust)). The orchestrator spawns them, monitors health, and replaces dead ones.

## Install

```bash
cd cli/bsw
go build -o ~/.local/bin/bsw .
```

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| `br` | Bead queue (work items) | [beads_rust](https://github.com/hachej/beads_rust) |
| `codex` or `claude` | AI coding agent | OpenAI Codex CLI / Claude Code |
| `tmux` | Terminal multiplexing (optional, for interactive mode) | `apt install tmux` |

### Optional: Agent Mail

[mcp-agent-mail](https://github.com/yourusername/mcp-agent-mail) enables messaging between workers and the orchestrator. Set up:

```bash
# Store token in Vault (or export AGENT_MAIL_TOKEN directly)
vault kv put secret/agent/mail token="your-token"

# Verify
bsw doctor
```

When configured, workers auto-register on spawn and get named identities (e.g. `ScarletRobin`, `TopazCrane`).

## Quick start

```bash
# 1. Initialize personas (one-time)
bsw init

# 2. Create work
br init --prefix bd
br create "Fix login bug" --type bug --priority 1

# 3. Spawn workers
bsw spawn              # spawns a worker (bg mode)
bsw spawn              # spawn another
bsw spawn --mode tmux  # or spawn in tmux for interactive view

# 4. Monitor
bsw status             # check health
bsw status --json      # machine-readable
bsw logs <worker-id>   # view output
```

## Commands

```
bsw spawn                         Spawn a worker
bsw status [--json]               Worker health (pid, uptime, activity)
bsw kill <worker-id>              Kill a single worker
bsw stop                          Stop all workers
bsw gc [--dry-run]                Clean up dead/exited workers
bsw logs <worker-id> [--follow]   View worker output
bsw nudge <worker-id>             Send "continue" to stale tmux worker
bsw attach <worker-id>            Attach to tmux worker pane
bsw doctor [--fix]                Check setup (tools, personas, agent-mail)
bsw watch [--interval 30s]        Continuous monitor loop (gc + status)
bsw list-work --label <label>     Show available beads
bsw prompt <persona>              Print a persona's system prompt
bsw multi-status                  Status across multiple projects
bsw init                          Scaffold personas and prompts
```

### Spawn options

```bash
bsw spawn                          # bg mode, auto-generated ID
bsw spawn --mode tmux              # interactive tmux window
bsw spawn --persona reviewer       # use reviewer persona
bsw spawn --id my-worker           # custom worker ID
bsw spawn --session my-session     # join existing tmux session
```

## Worker lifecycle

```
spawn → running → [stale] → kill/gc → respawn
                     ↓
                   nudge (tmux only)
```

**States:** `running`, `stale` (no activity for 10m), `exited(0)`, `exited(1)`, `dead`, `orphan` (tmux pane gone, PID alive)

## Personas

Personas define worker behavior. Located in `personas/` after `bsw init`:

```
personas/
  worker.toml              # provider, model, prompt path
  reviewer.toml
  prompts/
    worker.md              # system prompt instructions
    reviewer.md
```

Example `worker.toml`:
```toml
provider = "codex"
model = ""
prompt = "personas/prompts/worker.md"
```

Workers pick their own beads via `br robot next`, implement them, get reviews, and move to the next.

## Agent Mail integration

When Agent Mail is configured (`AGENT_MAIL_TOKEN` env var or Vault), workers:

- Auto-register on spawn and get a unique name (used as worker ID and tmux window name)
- Receive `AGENT_MAIL_*` env vars for inbox polling
- Check their inbox between beads for orchestrator messages
- Can message the orchestrator when stuck

The `check_inbox.sh` hook (from mcp-agent-mail) runs as a PostToolUse hook, rate-limited to every 2 minutes.

## Orchestrator pattern

The intended usage is an AI orchestrator (e.g. Claude in tmux) that:

1. Spawns workers: `bsw spawn` (repeat as needed)
2. Monitors in a loop: `bsw status --json && br list --status open`
3. Replaces dead workers: `bsw gc && bsw spawn`
4. Nudges stale workers: `bsw nudge <id>`
5. Stops when done: `bsw stop` (when no beads remain)

## Eval

```bash
bash eval/scenario_basic.sh    # 65 tests: full lifecycle + agent-mail
```

## Architecture

```
cli/bsw/
  cmd/           Command implementations (spawn, status, kill, etc.)
  process/       Process management, registry, Agent Mail client
  monitor/       Worker health checking (PID, zombie, tmux pane)
  persona/       Persona TOML loader
  beads/         Beads (br CLI) integration
  templates/     Embedded persona templates
```

Single Go binary, no daemon. All state lives in `.bsw/workers/` as JSON files.
