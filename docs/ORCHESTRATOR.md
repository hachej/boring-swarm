# Orchestrator Pattern for Product Teams

This guide explains how product teams use boring-swarm (`bsw`) to run autonomous AI coding agents.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Orchestrator (you or a dedicated agent)    │
│  bsw register → bsw spawn → bsw watch      │
└──────┬──────────┬──────────┬────────────────┘
       │          │          │
  ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
  │Worker 1│ │Worker 2│ │Worker N│   ← tmux or bg processes
  │codex   │ │claude  │ │codex   │
  └────┬───┘ └───┬────┘ └───┬────┘
       │         │           │
       ▼         ▼           ▼
   ┌──────────────────────────────┐
   │  Work Queue (br / beads)     │
   └──────────────────────────────┘
```

## Lifecycle

1. **Spawn** — `bsw spawn` creates a worker process (tmux or background)
2. **Running** — Worker pulls tasks from the beads queue and works autonomously
3. **Stale** — No log activity for the stale timeout (default: 10 minutes)
4. **Nudge** — `bsw nudge <id>` sends "continue" to a stale tmux worker
5. **Kill** — `bsw kill <id>` terminates an unrecoverable worker
6. **GC** — `bsw gc` cleans up dead/exited worker registry entries
7. **Respawn** — Spawn a fresh worker to replace the dead one

## Quick Start

```bash
# 1. Build and install bsw
cd cli/bsw && go build -o ~/.local/bin/bsw .

# 2. Initialize personas in your project
cd /path/to/your-project
bsw init

# 3. Register as orchestrator (sets up Agent Mail identity)
bsw register

# 4. Spawn workers
bsw spawn -mode tmux          # interactive (can attach/nudge)
bsw spawn -mode bg            # headless background process

# 5. Monitor continuously
bsw watch --interval 30s
```

## Persona Configuration

Personas define worker behavior. They live in `personas/<name>.toml`:

```toml
# personas/worker.toml
provider = "codex"          # codex, claude, gemini
model = ""                  # empty = provider default
prompt = "personas/prompts/worker.md"
```

```toml
# personas/reviewer.toml
provider = "claude"
model = "claude-opus-4-20250514"
prompt = "personas/prompts/reviewer.md"
```

### Persona fields

| Field      | Required | Description                              |
|------------|----------|------------------------------------------|
| `provider` | Yes      | CLI to use: `codex`, `claude`, `gemini`  |
| `model`    | No       | Model override (empty = provider default)|
| `prompt`   | Yes      | Path to system prompt markdown file      |
| `effort`   | No       | Effort level (provider-specific)         |

## Commands Reference

| Command                        | Description                                      |
|--------------------------------|--------------------------------------------------|
| `bsw init`                     | Scaffold persona configs and prompt templates    |
| `bsw spawn [-mode tmux\|bg]`  | Spawn a new worker process                       |
| `bsw status [--json]`         | Show worker health (pid, uptime, activity)       |
| `bsw kill <worker-id>`        | Terminate a specific worker                      |
| `bsw stop`                    | Stop all workers (not your session)              |
| `bsw gc`                      | Clean up dead/exited worker entries              |
| `bsw nudge <worker-id>`       | Send "continue" to a stale tmux worker           |
| `bsw attach <worker-id>`      | Attach to a tmux worker's pane                   |
| `bsw logs <id> [--follow]`    | View worker output log                           |
| `bsw watch [--interval 30s]`  | Continuous gc + status loop                      |
| `bsw doctor [--fix]`          | Check setup (tools, personas, workers, beads)    |
| `bsw review [-bead <id>]`     | Run code review (roborev/claude/gemini/codex)    |
| `bsw register`                | Register orchestrator with Agent Mail + Slack    |
| `bsw multi-status`            | Status across multiple projects                  |

## Configurable Timeouts

All timeouts have sensible defaults and can be overridden via environment variables:

| Variable                  | Default | Description                              |
|---------------------------|---------|------------------------------------------|
| `BSW_STALE_TIMEOUT_SEC`  | 600     | Seconds before a worker is marked stale  |
| `BSW_DOCTOR_TIMEOUT_SEC` | 15      | Seconds for health check operations      |
| `BSW_REVIEW_TIMEOUT_SEC` | 90      | Default review timeout (also `-timeout`) |

## Docker Deployment

```bash
# Build the image
docker build -t bsw .

# Run with Docker Compose
docker compose up -d

# Or run directly
docker run -v $(pwd):/workspace bsw doctor
```

See `docker-compose.yml` for full configuration including Agent Mail and Vault integration.

## Integration Points

### Agent Mail
Workers auto-register with Agent Mail for identity and messaging. Set `AGENT_MAIL_URL` and `AGENT_MAIL_TOKEN` in your environment or Vault.

### Beads (br)
Workers pull tasks from the beads work queue using `br ready --robot --unassigned`. Install `br` (beads_rust) separately.

### Review Protocol
Workers produce `FILES:` and `PROOF:` comments on beads. Run `bsw review -bead <id>` to trigger automated code review of the worker's changes.

## Multi-Project Management

For managing workers across multiple projects:

```bash
# Create .bsw-projects file listing project roots
echo "/home/ubuntu/projects/my-app" >> .bsw-projects
echo "/home/ubuntu/projects/my-lib" >> .bsw-projects

# View status across all projects
bsw multi-status
```
